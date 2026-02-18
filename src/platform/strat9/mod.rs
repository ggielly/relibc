//! Strat9-OS syscall implementation of the platform abstraction layer.
//!
//! This module provides the Strat9-OS specific implementation of the PAL traits.
//! Strat9 is a microkernel where most operations (filesystem, networking, etc.)
//! are performed via IPC to userspace services.

#[cfg(target_arch = "x86_64")]
use core::arch::asm;

use super::{Pal, types::*};
use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        bits_time::timespec,
        errno::{EINVAL, ENOSYS},
        fcntl::{AT_EMPTY_PATH, AT_FDCWD},
        signal::{SIGCHLD, sigevent},
        sys_resource::{rlimit, rusage},
        sys_select::timeval,
        sys_stat::stat,
        sys_statvfs::statvfs,
        sys_time::timezone,
        sys_utsname::utsname,
        time::itimerspec,
        unistd::SEEK_SET,
    },
    ld_so::tcb::OsSpecific,
    out::Out,
};
use core::{num::NonZeroU64, ptr};

pub mod auxv_defs;
mod epoll;
mod ptrace;
mod signal;
mod socket;
pub mod va_list;

// Strat9 syscall numbers (from docs/NATIVE_SYSCALLS.md)
pub const SYS_NULL: usize = 0;
pub const SYS_HANDLE_DUPLICATE: usize = 1;
pub const SYS_HANDLE_CLOSE: usize = 2;
pub const SYS_MEM_MAP: usize = 100;
pub const SYS_MEM_UNMAP: usize = 101;
pub const SYS_IPC_CREATE_PORT: usize = 200;
pub const SYS_IPC_SEND: usize = 201;
pub const SYS_IPC_RECV: usize = 202;
pub const SYS_IPC_CALL: usize = 203;
pub const SYS_IPC_REPLY: usize = 204;
pub const SYS_PROC_EXIT: usize = 300;
pub const SYS_PROC_YIELD: usize = 301;
pub const SYS_FUTEX_WAIT: usize = 302;
pub const SYS_FUTEX_WAKE: usize = 303;
pub const SYS_KILL: usize = 320;
pub const SYS_SIGPROCMASK: usize = 321;
pub const SYS_OPEN: usize = 403;
pub const SYS_WRITE: usize = 404;
pub const SYS_READ: usize = 405;
pub const SYS_CLOSE: usize = 406;
pub const SYS_FCNTL: usize = 407;
pub const SYS_VOLUME_READ: usize = 420;
pub const SYS_VOLUME_WRITE: usize = 421;
pub const SYS_VOLUME_INFO: usize = 422;
pub const SYS_CLOCK_GETTIME: usize = 500;
pub const SYS_DEBUG_LOG: usize = 600;

// Export syscall macro for use in submodules
#[cfg(target_arch = "x86_64")]
#[macro_export]
macro_rules! strat9_syscall {
    ($nr:expr) => {{
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") $nr,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
                options(nostack, preserves_flags)
            )
        }
        ret
    }};
    ($nr:expr, $arg1:expr) => {{
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") $nr,
                in("rdi") $arg1,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
                options(nostack, preserves_flags)
            )
        }
        ret
    }};
    ($nr:expr, $arg1:expr, $arg2:expr) => {{
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") $nr,
                in("rdi") $arg1,
                in("rsi") $arg2,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
                options(nostack, preserves_flags)
            )
        }
        ret
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr) => {{
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") $nr,
                in("rdi") $arg1,
                in("rsi") $arg2,
                in("rdx") $arg3,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
                options(nostack, preserves_flags)
            )
        }
        ret
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr) => {{
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") $nr,
                in("rdi") $arg1,
                in("rsi") $arg2,
                in("rdx") $arg3,
                in("r10") $arg4,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
                options(nostack, preserves_flags)
            )
        }
        ret
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr) => {{
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") $nr,
                in("rdi") $arg1,
                in("rsi") $arg2,
                in("rdx") $arg3,
                in("r10") $arg4,
                in("r8") $arg5,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
                options(nostack, preserves_flags)
            )
        }
        ret
    }};
    ($nr:expr, $arg1:expr, $arg2:expr, $arg3:expr, $arg4:expr, $arg5:expr, $arg6:expr) => {{
        let ret: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                in("rax") $nr,
                in("rdi") $arg1,
                in("rsi") $arg2,
                in("rdx") $arg3,
                in("r10") $arg4,
                in("r8") $arg5,
                in("r9") $arg6,
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
                options(nostack, preserves_flags)
            )
        }
        ret
    }};
}

/// Convert syscall result to Result (negative = error)
pub fn e_raw(sys: u64) -> Result<u64> {
    // In Strat9, errors are returned as negative values (Linux convention)
    if sys > (c_int::MAX as u64) {
        Err(Errno((sys as c_int).wrapping_neg()))
    } else {
        Ok(sys)
    }
}

/// Strat9 syscall implementation of the platform abstraction layer.
pub struct Sys;

impl Pal for Sys {
    fn access(_path: CStr, _mode: c_int) -> Result<()> {
        // TODO: Implement via VFS IPC
        Err(Errno(ENOSYS))
    }

    unsafe fn brk(addr: *mut c_void) -> Result<*mut c_void> {
        // Emulate brk using mmap (Strat9 doesn't have native brk)
        static mut BRK_CUR: *mut c_void = ptr::null_mut();
        unsafe {
            if addr.is_null() {
                if BRK_CUR.is_null() {
                    let initial = Self::mmap(ptr::null_mut(), 65536, 0, 0, -1, 0)?;
                    BRK_CUR = initial.add(65536);
                    return Ok(initial);
                }
                return Ok(BRK_CUR);
            }
            Ok(BRK_CUR)
        }
    }

    fn chdir(_path: CStr) -> Result<()> {
        // TODO: Implement via VFS IPC
        Err(Errno(ENOSYS))
    }

    fn chmod(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn chown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn clock_getres(_clk_id: clockid_t, _tp: Option<Out<timespec>>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn clock_gettime(_clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        let ticks = unsafe { strat9_syscall!(SYS_CLOCK_GETTIME) };
        tp.tv_sec = (ticks / 1000) as i64;
        tp.tv_nsec = ((ticks % 1000) * 1_000_000) as i64;
        Ok(())
    }

    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn close(fildes: c_int) -> Result<()> {
        e_raw(unsafe { strat9_syscall!(SYS_CLOSE, fildes as u64) })?;
        Ok(())
    }

    fn dup(fildes: c_int) -> Result<c_int> {
        e_raw(unsafe { strat9_syscall!(SYS_HANDLE_DUPLICATE, fildes as u64) }).map(|r| r as c_int)
    }

    fn dup2(_fildes: c_int, _fildes2: c_int) -> Result<c_int> {
        Err(Errno(ENOSYS))
    }

    unsafe fn execve(
        _path: CStr,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn fexecve(
        _fildes: c_int,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn exit(status: c_int) -> ! {
        unsafe {
            strat9_syscall!(SYS_PROC_EXIT, status as u64);
        }
        loop {}
    }

    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        // TODO: Implement thread exit
        Self::exit(0)
    }

    fn fchdir(_fildes: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fchmod(_fildes: c_int, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fchmodat(_dirfd: c_int, _path: Option<CStr>, _mode: mode_t, _flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fchown(_fildes: c_int, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fdatasync(_fildes: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fstat(_fildes: c_int, _buf: Out<stat>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fstatat(_fildes: c_int, _path: Option<CStr>, _buf: Out<stat>, _flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fstatvfs(_fildes: c_int, _buf: Out<statvfs>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        e_raw(unsafe { strat9_syscall!(SYS_FCNTL, fildes as u64, cmd as u64, arg) }).map(|r| r as c_int)
    }

    unsafe fn fork() -> Result<pid_t> {
        Err(Errno(ENOSYS))
    }

    fn fpath(_fildes: c_int, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    fn fsync(_fildes: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn ftruncate(_fildes: c_int, _length: off_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()> {
        let deadline_ns = deadline.map_or(0u64, |d| {
            (d.tv_sec as u64) * 1_000_000_000 + (d.tv_nsec as u64)
        });
        e_raw(unsafe { strat9_syscall!(SYS_FUTEX_WAIT, addr as u64, val as u64, deadline_ns) })?;
        Ok(())
    }

    unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32> {
        Ok(e_raw(unsafe { strat9_syscall!(SYS_FUTEX_WAKE, addr as u64, num as u64) })? as u32)
    }

    unsafe fn futimens(_fd: c_int, _times: *const timespec) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn utimens(_path: CStr, _times: *const timespec) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn getcwd(_buf: Out<[u8]>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn getdents(_fd: c_int, _buf: &mut [u8], _opaque_offset: u64) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    fn dir_seek(_fd: c_int, _opaque_offset: u64) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn dent_reclen_offset(_this_dent: &[u8], _offset: usize) -> Option<(u16, u64)> {
        None
    }

    fn getegid() -> gid_t {
        // TODO: Implement
        0
    }

    fn geteuid() -> uid_t {
        // TODO: Implement
        0
    }

    fn getgid() -> gid_t {
        // TODO: Implement
        0
    }

    fn getgroups(_list: Out<[gid_t]>) -> Result<c_int> {
        Err(Errno(ENOSYS))
    }

    fn getpagesize() -> usize {
        4096
    }

    fn getpgid(_pid: pid_t) -> Result<pid_t> {
        Err(Errno(ENOSYS))
    }

    fn getpid() -> pid_t {
        // TODO: Implement
        1
    }

    fn getppid() -> pid_t {
        // TODO: Implement
        1
    }

    fn getpriority(_which: c_int, _who: id_t) -> Result<c_int> {
        Err(Errno(ENOSYS))
    }

    fn getrandom(_buf: &mut [u8], _flags: c_uint) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    fn getresgid(
        _rgid: Option<Out<gid_t>>,
        _egid: Option<Out<gid_t>>,
        _sgid: Option<Out<gid_t>>,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn getresuid(
        _ruid: Option<Out<uid_t>>,
        _euid: Option<Out<uid_t>>,
        _suid: Option<Out<uid_t>>,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn getrlimit(_resource: c_int, _rlim: Out<rlimit>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn setrlimit(_resource: c_int, _rlim: *const rlimit) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn getrusage(_who: c_int, _r_usage: Out<rusage>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn getsid(_pid: pid_t) -> Result<pid_t> {
        Err(Errno(ENOSYS))
    }

    fn gettid() -> pid_t {
        // TODO: Implement
        1
    }

    fn gettimeofday(mut tp: Out<timeval>, _tzp: Option<Out<timezone>>) -> Result<()> {
        let ticks = unsafe { strat9_syscall!(SYS_CLOCK_GETTIME) };
        tp.tv_sec = (ticks / 1000) as i64;
        tp.tv_usec = ((ticks % 1000) * 1000) as i64;
        Ok(())
    }

    fn getuid() -> uid_t {
        // TODO: Implement
        0
    }

    fn lchown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn link(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn lseek(_fildes: c_int, offset: off_t, _whence: c_int) -> Result<off_t> {
        // Simple implementation - just return the offset
        // TODO: Implement proper seek via IPC when VFS supports it
        Ok(offset)
    }

    fn mkdirat(_fildes: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn mkdir(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn mkfifoat(_dir_fd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn mkfifo(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn mknodat(_fildes: c_int, _path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn mknod(_path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn mlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn mlockall(_flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        _flags: c_int,
        _fildes: c_int,
        _off: off_t,
    ) -> Result<*mut c_void> {
        e_raw(unsafe { strat9_syscall!(SYS_MEM_MAP, addr as u64, len as u64, prot as u64) })
            .map(|r| r as *mut c_void)
    }

    unsafe fn mremap(
        _addr: *mut c_void,
        _len: usize,
        _new_len: usize,
        _flags: c_int,
        _args: *mut c_void,
    ) -> Result<*mut c_void> {
        Err(Errno(ENOSYS))
    }

    unsafe fn mprotect(_addr: *mut c_void, _len: usize, _prot: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn msync(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn munlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn madvise(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn munlockall() -> Result<()> {
        Err(Errno(ENOSYS))
    }

    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        e_raw(unsafe { strat9_syscall!(SYS_MEM_UNMAP, addr as u64, len as u64) })?;
        Ok(())
    }

    unsafe fn nanosleep(_rqtp: *const timespec, _rmtp: *mut timespec) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn open(path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
        e_raw(unsafe {
            strat9_syscall!(
                SYS_OPEN,
                path.as_ptr() as u64,
                path.to_bytes().len() as u64,
                oflag as u64
            )
        })
        .map(|r| r as c_int)
    }

    fn pipe2(_fildes: Out<[c_int; 2]>, _flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn posix_fallocate(_fd: c_int, _offset: u64, _length: NonZeroU64) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn posix_getdents(_fildes: c_int, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    unsafe fn rlct_clone(
        _stack: *mut usize,
        _os_specific: &mut OsSpecific,
    ) -> Result<crate::pthread::OsTid, Errno> {
        Err(Errno(ENOSYS))
    }

    unsafe fn rlct_kill(_os_tid: crate::pthread::OsTid, _signal: usize) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn current_os_tid() -> crate::pthread::OsTid {
        crate::pthread::OsTid { thread_id: 1 }
    }

    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        e_raw(unsafe {
            strat9_syscall!(
                SYS_READ,
                fildes as u64,
                buf.as_mut_ptr() as u64,
                buf.len() as u64
            )
        })
    }

    fn pread(_fildes: c_int, _buf: &mut [u8], _offset: off_t) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    fn readlink(_pathname: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    fn readlinkat(_dirfd: c_int, _pathname: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    fn rename(_old: CStr, _new: CStr) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn renameat(_old_dir: c_int, _old_path: CStr, _new_dir: c_int, _new_path: CStr) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn renameat2(
        _old_dir: c_int,
        _old_path: CStr,
        _new_dir: c_int,
        _new_path: CStr,
        _flags: c_uint,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn rmdir(_path: CStr) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn sched_yield() -> Result<()> {
        e_raw(unsafe { strat9_syscall!(SYS_PROC_YIELD) })?;
        Ok(())
    }

    unsafe fn setgroups(_size: size_t, _list: *const gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn setpgid(_pid: pid_t, _pgid: pid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn setpriority(_which: c_int, _who: id_t, _prio: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn setresgid(_rgid: gid_t, _egid: gid_t, _sgid: gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn setresuid(_ruid: uid_t, _euid: uid_t, _suid: uid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn setsid() -> Result<c_int> {
        Err(Errno(ENOSYS))
    }

    fn symlink(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn sync() -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn timer_create(_clock_id: clockid_t, _evp: &sigevent, _timerid: Out<timer_t>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn timer_delete(_timerid: timer_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn timer_gettime(_timerid: timer_t, _value: Out<itimerspec>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn timer_settime(
        _timerid: timer_t,
        _flags: c_int,
        _value: &itimerspec,
        _ovalue: Option<Out<itimerspec>>,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn umask(_mask: mode_t) -> mode_t {
        0o022
    }

    fn uname(_utsname: Out<utsname>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn unlink(_path: CStr) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn waitpid(_pid: pid_t, _stat_loc: Option<Out<c_int>>, _options: c_int) -> Result<pid_t> {
        Err(Errno(ENOSYS))
    }

    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        e_raw(unsafe {
            strat9_syscall!(
                SYS_WRITE,
                fildes as u64,
                buf.as_ptr() as u64,
                buf.len() as u64
            )
        })
    }

    fn pwrite(_fildes: c_int, _buf: &[u8], _offset: off_t) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    fn verify() -> bool {
        // Check if SYS_NULL returns the magic value
        let ret = unsafe { strat9_syscall!(SYS_NULL) };
        ret == 0x57A79 // "STRAT9" magic
    }
}
