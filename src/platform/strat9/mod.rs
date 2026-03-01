use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        signal::sigevent,
        sys_resource::{rlimit, rusage},
        sys_stat::stat,
        sys_statvfs::statvfs,
        sys_time::{timeval, timezone},
        sys_utsname::{UTSLENGTH, utsname},
        time::{itimerspec, timespec},
        unistd::SEEK_SET,
    },
    out::Out,
    platform::{
        pal::{Pal, PalSignal},
        types::*,
    },
};
use core::{arch::asm, ptr};

pub mod auxv_defs;

// time conversion constants
const NANOSECONDS_PER_SECOND: usize = 1_000_000_000;
const MILLISECONDS_PER_SECOND: usize = 1_000;
const MICROSECONDS_PER_MILLISECOND: usize = 1_000;
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
pub const SYS_PROC_WAITPID: usize = 310;
pub const SYS_FUTEX_WAIT: usize = 302;
pub const SYS_FUTEX_WAKE: usize = 303;
pub const SYS_GETPID: usize = 311;
pub const SYS_GETTID: usize = 312;
pub const SYS_KILL: usize = 320;
pub const SYS_SIGPROCMASK: usize = 321;
pub const SYS_OPEN: usize = 403;
pub const SYS_WRITE: usize = 404;
pub const SYS_READ: usize = 405;
pub const SYS_CLOSE: usize = 406;
pub const SYS_FCNTL: usize = 407;
pub const SYS_FSTAT: usize = 408;
pub const SYS_STAT: usize = 409;
pub const SYS_PIPE: usize = 431;
pub const SYS_DUP2: usize = 433;
pub const SYS_CHDIR: usize = 440;
pub const SYS_GETCWD: usize = 442;
pub const SYS_IOCTL: usize = 443;
pub const SYS_VOLUME_READ: usize = 420;
pub const SYS_VOLUME_WRITE: usize = 421;
pub const SYS_VOLUME_INFO: usize = 422;
pub const SYS_CLOCK_GETTIME: usize = 500;
pub const SYS_DEBUG_LOG: usize = 600;

// syscall numbers (time-related)
const SYS_TIME_TICKS: usize = 500;
const SYS_NANOSLEEP: usize = 501;

// syscall numbers (process/thread)
const SYS_PROC_FORK: usize = 302;
const SYS_PROC_WAITPID: usize = 310;
const SYS_PROC_YIELD: usize = 301;
const SYS_GETPID: usize = 311;
const SYS_GETTID: usize = 312;
const SYS_GETPPID: usize = 313;
const SYS_SETPGID: usize = 317;
const SYS_GETPGID: usize = 318;
const SYS_SETSID: usize = 319;
const SYS_GETSID: usize = 332;

// syscall numbers (futex)
const SYS_FUTEX_WAIT: usize = 303;
const SYS_FUTEX_WAKE: usize = 304;

pub struct Sys;

impl Sys {
    pub unsafe fn ioctl(fd: c_int, request: c_ulong, out: *mut c_void) -> Result<c_int> {
        Ok(e_raw(unsafe { strat9_syscall!(SYS_IOCTL, fd as u64, request as u64, out as u64) })? as c_int)
    }
}

impl Pal for Sys {
    fn access(path: CStr, _mode: c_int) -> Result<()> {
        let ret = unsafe { syscall3(403, path.as_ptr() as usize, path.to_bytes().len(), 1) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            unsafe {
                let _ = syscall1(406, ret);
            }
            Ok(())
        }
    }

    unsafe fn brk(addr: *mut c_void) -> Result<*mut c_void> {
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

    fn chdir(path: CStr) -> Result<()> {
        e_raw(unsafe { strat9_syscall!(SYS_CHDIR, path.as_ptr() as u64, path.to_bytes().len() as u64) })?;
        Ok(())
    }

    fn chmod(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn chown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn clock_getres(_clk_id: clockid_t, _tp: Option<Out<timespec>>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn clock_gettime(_clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        let ns = unsafe { syscall0(SYS_TIME_TICKS) };
        tp.tv_sec = (ns / NANOSECONDS_PER_SECOND) as i64;
        tp.tv_nsec = (ns % NANOSECONDS_PER_SECOND) as i64;
        Ok(())
    }

    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn close(fildes: c_int) -> Result<()> {
        let ret = unsafe { syscall1(406, fildes as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    fn dup(fildes: c_int) -> Result<c_int> {
        let ret = unsafe { syscall1(1, fildes as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    fn dup2(fildes: c_int, fildes2: c_int) -> Result<c_int> {
        e_raw(unsafe { strat9_syscall!(SYS_DUP2, fildes as u64, fildes2 as u64) }).map(|r| r as c_int)
    }

    unsafe fn execve(
        _path: CStr,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn fexecve(
        _fildes: c_int,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn exit(status: c_int) -> ! {
        unsafe {
            let _ = syscall1(300, status as usize);
        }
        loop {}
    }

    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        loop {}
    }

    fn fchdir(_fildes: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fchmod(_fildes: c_int, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fchmodat(_dirfd: c_int, _path: Option<CStr>, _mode: mode_t, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fchown(_fildes: c_int, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fdatasync(_fildes: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    fn fstat(fildes: c_int, mut buf: Out<stat>) -> Result<()> {
        e_raw(unsafe { strat9_syscall!(SYS_FSTAT, fildes as u64, buf.as_mut_ptr() as u64) })?;
        Ok(())
    }

    fn fstatat(_fildes: c_int, _path: Option<CStr>, _buf: Out<stat>, _flags: c_int) -> Result<()> {
        if _fildes != AT_FDCWD || _flags != 0 {
            return Err(Errno(EINVAL));
        }
        let path = _path.ok_or(Errno(EINVAL))?;
        let mut buf = _buf;
        e_raw(unsafe {
            strat9_syscall!(
                SYS_STAT,
                path.as_ptr() as u64,
                path.to_bytes().len() as u64,
                buf.as_mut_ptr() as u64
            )
        })?;
        Ok(())
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

    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fstat(_fildes: c_int, _buf: Out<stat>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fstatat(_fildes: c_int, _path: Option<CStr>, _buf: Out<stat>, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fstatvfs(_fildes: c_int, _buf: Out<statvfs>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        let ret = unsafe { syscall3(407, fildes as usize, cmd as usize, arg as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    unsafe fn fork() -> Result<pid_t> {
        let ret = unsafe { syscall0(SYS_PROC_FORK) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as pid_t)
        }
    }

    fn fpath(_fildes: c_int, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn fsync(_fildes: c_int) -> Result<()> {
        Ok(())
    }

    fn ftruncate(_fildes: c_int, _length: off_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()> {
        let timeout_ns = if let Some(ts) = deadline {
            let secs = ts.tv_sec.max(0) as u64;
            let nsec = ts.tv_nsec.max(0) as u64;
            secs.saturating_mul(NANOSECONDS_PER_SECOND as u64)
                .saturating_add(nsec)
        } else {
            0
        };
        let ret = unsafe { syscall3(SYS_FUTEX_WAIT, addr as usize, val as usize, timeout_ns as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32> {
        let ret = unsafe { syscall2(SYS_FUTEX_WAKE, addr as usize, num as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as u32)
        }
    }

    unsafe fn futimens(_fildes: c_int, _times: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn utimens(_path: CStr, _times: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn getcwd(mut buf: Out<[u8]>) -> Result<()> {
        e_raw(unsafe {
            strat9_syscall!(
                SYS_GETCWD,
                buf.as_mut_ptr().as_mut_ptr() as u64,
                buf.as_mut_ptr().len() as u64
            )
        })?;
        Ok(())
    }

    fn getdents(_fildes: c_int, _buf: &mut [u8], _opaque_offset: u64) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn dir_seek(_fildes: c_int, _opaque_offset: u64) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn dent_reclen_offset(_this_dent: &[u8], _offset: usize) -> Option<(u16, u64)> {
        None
    }

    fn getegid() -> gid_t {
        0
    }
    fn geteuid() -> uid_t {
        0
    }
    fn getgid() -> gid_t {
        0
    }
    fn getgroups(_list: Out<[gid_t]>) -> Result<c_int> {
        Ok(0)
    }
    fn getpagesize() -> usize {
        4096
    }
    fn getpgid(_pid: pid_t) -> Result<pid_t> {
        let ret = unsafe { syscall1(SYS_GETPGID, _pid as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as pid_t)
        }
    }
    fn getpid() -> pid_t {
        e_raw(unsafe { strat9_syscall!(SYS_GETPID) })
            .map(|r| r as pid_t)
            .unwrap_or(0)
    }
    fn getppid() -> pid_t {
        let ret = unsafe { syscall0(SYS_GETPPID) };
        if (ret as isize) < 0 { 0 } else { ret as pid_t }
    }
    fn getpriority(_which: c_int, _who: id_t) -> Result<c_int> {
        Ok(0)
    }
    fn getrandom(_buf: &mut [u8], _flags: c_uint) -> Result<usize> {
        Ok(0)
    }
    fn getresgid(
        _rgid: Option<Out<gid_t>>,
        _egid: Option<Out<gid_t>>,
        _sgid: Option<Out<gid_t>>,
    ) -> Result<()> {
        Ok(())
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
        e_raw(unsafe { strat9_syscall!(SYS_GETTID) })
            .map(|r| r as pid_t)
            .unwrap_or(0)
    }

    fn gettimeofday(mut tp: Out<timeval>, _tzp: Option<Out<timezone>>) -> Result<()> {
        let ticks = unsafe { strat9_syscall!(SYS_CLOCK_GETTIME) };
        tp.tv_sec = (ticks / 1000) as i64;
        tp.tv_usec = ((ticks % 1000) * 1000) as i64;
        Ok(())
    }
    fn getrlimit(_resource: c_int, _rlim: Out<rlimit>) -> Result<()> {
        Ok(())
    }
    unsafe fn setrlimit(_resource: c_int, _rlim: *const rlimit) -> Result<()> {
        Ok(())
    }
    fn getrusage(_who: c_int, _r_usage: Out<rusage>) -> Result<()> {
        Ok(())
    }
    fn getsid(_pid: pid_t) -> Result<pid_t> {
        let ret = unsafe { syscall1(SYS_GETSID, _pid as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as pid_t)
        }
    }
    fn gettid() -> pid_t {
        let ret = unsafe { syscall0(SYS_GETTID) };
        if (ret as isize) < 0 { 0 } else { ret as pid_t }
    }
    fn gettimeofday(
        mut tp: Out<timeval>,
        _tzp: Option<Out<crate::header::sys_time::timezone>>,
    ) -> Result<()> {
        let ticks = unsafe { syscall0(SYS_TIME_TICKS) };
        tp.tv_sec = (ticks / MILLISECONDS_PER_SECOND) as i64;
        tp.tv_usec = ((ticks % MILLISECONDS_PER_SECOND) * MICROSECONDS_PER_MILLISECOND) as i64;
        Ok(())
    }
    fn getuid() -> uid_t {
        0
    }

    fn lchown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn link(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn lseek(fildes: c_int, offset: off_t, _whence: c_int) -> Result<off_t> {
        Ok(offset)
    }

    fn mkdirat(_dirfd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mkdir(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mkfifoat(_dir_fd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mkfifo(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mknodat(_fildes: c_int, _path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn mknod(_path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn mlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn mlockall(_flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        _flags: c_int,
        _fildes: c_int,
        _off: off_t,
    ) -> Result<*mut c_void> {
        let ret = unsafe { syscall3(100, addr as usize, len, prot as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as *mut c_void)
        }
    }

    unsafe fn mremap(
        _addr: *mut c_void,
        _len: usize,
        _new_len: usize,
        _flags: c_int,
        _args: *mut c_void,
    ) -> Result<*mut c_void> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn mprotect(_addr: *mut c_void, _len: usize, _prot: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn msync(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn munlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    unsafe fn madvise(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Ok(())
    }

    unsafe fn munlockall() -> Result<()> {
        Ok(())
    }

    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        let ret = unsafe { syscall2(101, addr as usize, len) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> Result<()> {
        let ret = unsafe { syscall2(SYS_NANOSLEEP, rqtp as usize, rmtp as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    fn open(path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
        let ret = unsafe {
            syscall3(
                403,
                path.as_ptr() as usize,
                path.to_bytes().len(),
                oflag as usize,
            )
        };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    fn pipe2(mut fildes: Out<[c_int; 2]>, flags: c_int) -> Result<()> {
        if flags != 0 {
            return Err(Errno(EINVAL));
        }
        e_raw(unsafe { strat9_syscall!(SYS_PIPE, fildes.as_mut_ptr().as_mut_ptr() as u64) })?;
        Ok(())
    }

    fn posix_fallocate(_fd: c_int, _offset: u64, _length: core::num::NonZeroU64) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn posix_getdents(_fildes: c_int, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn rlct_clone(
        _stack: *mut usize,
        _os_specific: &mut crate::ld_so::tcb::OsSpecific,
    ) -> Result<crate::pthread::OsTid, Errno> {
        Err(Errno(crate::error::ENOSYS))
    }

    unsafe fn rlct_kill(_os_tid: crate::pthread::OsTid, _signal: usize) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn current_os_tid() -> crate::pthread::OsTid {
        1
    }

    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        let ret = unsafe { syscall3(405, fildes as usize, buf.as_mut_ptr() as usize, buf.len()) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret)
        }
    }

    fn pread(_fildes: c_int, _buf: &mut [u8], _offset: off_t) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn readlink(_path: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn readlinkat(_dirfd: c_int, _path: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn rename(_old: CStr, _new: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn renameat(_old_dir: c_int, _old_path: CStr, _new_dir: c_int, _new_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn renameat2(
        _old_dir: c_int,
        _old_path: CStr,
        _new_dir: c_int,
        _new_path: CStr,
        _flags: c_uint,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn rmdir(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn sched_yield() -> Result<()> {
        unsafe {
            let _ = syscall0(SYS_PROC_YIELD);
        }
        Ok(())
    }

    unsafe fn setgroups(_size: size_t, _list: *const gid_t) -> Result<()> {
        Ok(())
    }

    fn setpgid(_pid: pid_t, _pgid: pid_t) -> Result<()> {
        let ret = unsafe { syscall2(SYS_SETPGID, _pid as usize, _pgid as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    fn setpriority(_which: c_int, _who: id_t, _prio: c_int) -> Result<()> {
        Ok(())
    }

    fn setresgid(_rgid: gid_t, _egid: gid_t, _sgid: gid_t) -> Result<()> {
        Ok(())
    }

    fn setresuid(_ruid: uid_t, _euid: uid_t, _suid: uid_t) -> Result<()> {
        Ok(())
    }

    fn setsid() -> Result<c_int> {
        let ret = unsafe { syscall0(SYS_SETSID) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    fn symlink(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn sync() -> Result<()> {
        Ok(())
    }

    fn timer_create(_clock_id: clockid_t, _evp: &sigevent, _timerid: Out<timer_t>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn timer_delete(_timerid: timer_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn timer_gettime(_timerid: timer_t, _value: Out<itimerspec>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn timer_settime(
        _timerid: timer_t,
        _flags: c_int,
        _value: &itimerspec,
        _ovalue: Option<Out<itimerspec>>,
    ) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn umask(_mask: mode_t) -> mode_t {
        0o022
    }

    fn uname(_utsname: Out<utsname>) -> Result<()> {
        fn fill(dst: &mut [c_char; UTSLENGTH], src: &[u8]) {
            let n = core::cmp::min(src.len(), UTSLENGTH - 1);
            let mut i = 0;
            while i < n {
                dst[i] = src[i] as c_char;
                i += 1;
            }
            dst[n] = 0;
        }

        let mut u = utsname {
            sysname: [0; UTSLENGTH],
            nodename: [0; UTSLENGTH],
            release: [0; UTSLENGTH],
            version: [0; UTSLENGTH],
            machine: [0; UTSLENGTH],
            domainname: [0; UTSLENGTH],
        };
        fill(&mut u.sysname, b"Strat9");
        fill(&mut u.nodename, b"localhost");
        fill(&mut u.release, b"0.1.0");
        fill(&mut u.version, b"Strat9-OS");
        fill(&mut u.machine, b"x86_64");
        fill(&mut u.domainname, b"localdomain");

        let mut uts = _utsname;
        uts.write(u);
        Ok(())
    }

    fn unlink(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }
    fn waitpid(pid: pid_t, stat_loc: Option<Out<c_int>>, options: c_int) -> Result<pid_t> {

        e_raw(unsafe {
            strat9_syscall!(
                SYS_PROC_WAITPID,
                pid as u64,
                stat_loc.map_or(0, |mut o| o.as_mut_ptr() as usize) as u64,
                options as u64
            )
        })
        .map(|p| p as pid_t)
    }

    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        let ret = unsafe { syscall3(404, fildes as usize, buf.as_ptr() as usize, buf.len()) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret)
        }
    }

    fn pwrite(_fildes: c_int, _buf: &[u8], _offset: off_t) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    fn verify() -> bool {
        true
    }
}

impl PalSignal for Sys {}

// Low-level syscall wrappers
unsafe fn syscall0(num: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

unsafe fn syscall1(num: usize, arg1: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

unsafe fn syscall2(num: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

unsafe fn syscall3(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}
