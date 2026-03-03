use core::arch::asm;
use core::ptr;
use crate::platform::types::*;
use crate::platform::pal::{Pal, PalSignal};
use crate::error::{Errno, Result};
use crate::c_str::CStr;
use crate::header::time::timespec;
use crate::header::sys_stat::stat;
use crate::header::sys_statvfs::statvfs;
use crate::header::sys_resource::{rlimit, rusage};
use crate::header::sys_time::timeval;
use crate::header::sys_utsname::utsname;
use crate::header::time::itimerspec;
use crate::header::signal::sigevent;
use crate::out::Out;

use core::ffi::VaList;

pub mod auxv_defs;
pub mod va_list;

pub struct Sys;

impl Pal for Sys {
    /// Implements access.
    fn access(path: CStr, _mode: c_int) -> Result<()> {
        let ret = unsafe { syscall3(403, path.as_ptr() as usize, path.to_bytes().len(), 1) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            unsafe { let _ = syscall1(406, ret); }
            Ok(())
        }
    }

    /// Implements brk.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
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

    /// Implements chdir.
    fn chdir(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements chmod.
    fn chmod(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements chown.
    fn chown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements clock getres.
    fn clock_getres(_clk_id: clockid_t, _tp: Option<Out<timespec>>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements clock gettime.
    fn clock_gettime(_clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        let ticks = unsafe { syscall0(500) };
        tp.tv_sec = (ticks / 1000) as i64;
        tp.tv_nsec = ((ticks % 1000) * 1_000_000) as i64;
        Ok(())
    }

    /// Implements clock settime.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements close.
    fn close(fildes: c_int) -> Result<()> {
        let ret = unsafe { syscall1(406, fildes as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    /// Implements dup.
    fn dup(fildes: c_int) -> Result<c_int> {
        let ret = unsafe { syscall1(1, fildes as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    /// Implements dup2.
    fn dup2(_fildes: c_int, _fildes2: c_int) -> Result<c_int> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements execve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn execve(_path: CStr, _argv: *const *mut c_char, _envp: *const *mut c_char) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fexecve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fexecve(_fildes: c_int, _argv: *const *mut c_char, _envp: *const *mut c_char) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements exit.
    fn exit(status: c_int) -> ! {
        unsafe {
            let _ = syscall1(300, status as usize);
        }
        loop {}
    }

    /// Implements exit thread.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        loop {}
    }

    /// Implements fchdir.
    fn fchdir(_fildes: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fchmod.
    fn fchmod(_fildes: c_int, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fchmodat.
    fn fchmodat(_dirfd: c_int, _path: Option<CStr>, _mode: mode_t, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fchown.
    fn fchown(_fildes: c_int, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fdatasync.
    fn fdatasync(_fildes: c_int) -> Result<()> {
        Ok(())
    }

    /// Implements flock.
    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fstat.
    fn fstat(_fildes: c_int, _buf: Out<stat>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fstatat.
    fn fstatat(_fildes: c_int, _path: Option<CStr>, _buf: Out<stat>, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fstatvfs.
    fn fstatvfs(_fildes: c_int, _buf: Out<statvfs>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fcntl.
    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        let ret = unsafe { syscall3(407, fildes as usize, cmd as usize, arg as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    /// Implements fork.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fork() -> Result<pid_t> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fpath.
    fn fpath(_fildes: c_int, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements fsync.
    fn fsync(_fildes: c_int) -> Result<()> {
        Ok(())
    }

    /// Implements ftruncate.
    fn ftruncate(_fildes: c_int, _length: off_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements futex wait.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wait(_addr: *mut u32, _val: u32, _deadline: Option<&timespec>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements futex wake.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wake(_addr: *mut u32, _num: u32) -> Result<u32> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements futimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futimens(_fildes: c_int, _times: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements utimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn utimens(_path: CStr, _times: *const timespec) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Returns getcwd.
    fn getcwd(_buf: Out<[u8]>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Returns getdents.
    fn getdents(_fildes: c_int, _buf: &mut [u8], _opaque_offset: u64) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements dir seek.
    fn dir_seek(_fildes: c_int, _opaque_offset: u64) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements dent reclen offset.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn dent_reclen_offset(_this_dent: &[u8], _offset: usize) -> Option<(u16, u64)> {
        None
    }

    /// Returns getegid.
    fn getegid() -> gid_t { 0 }
    /// Returns geteuid.
    fn geteuid() -> uid_t { 0 }
    /// Returns getgid.
    fn getgid() -> gid_t { 0 }
    /// Returns getgroups.
    fn getgroups(_list: Out<[gid_t]>) -> Result<c_int> { Ok(0) }
    /// Returns getpagesize.
    fn getpagesize() -> usize { 4096 }
    /// Returns getpgid.
    fn getpgid(_pid: pid_t) -> Result<pid_t> { Ok(0) }
    /// Returns getpid.
    fn getpid() -> pid_t { 1 }
    /// Returns getppid.
    fn getppid() -> pid_t { 0 }
    /// Returns getpriority.
    fn getpriority(_which: c_int, _who: id_t) -> Result<c_int> { Ok(0) }
    /// Returns getrandom.
    fn getrandom(_buf: &mut [u8], _flags: c_uint) -> Result<usize> { Ok(0) }
    /// Returns getresgid.
    fn getresgid(_rgid: Option<Out<gid_t>>, _egid: Option<Out<gid_t>>, _sgid: Option<Out<gid_t>>) -> Result<()> { Ok(()) }
    /// Returns getresuid.
    fn getresuid(_ruid: Option<Out<uid_t>>, _euid: Option<Out<uid_t>>, _suid: Option<Out<uid_t>>) -> Result<()> { Ok(()) }
    /// Returns getrlimit.
    fn getrlimit(_resource: c_int, _rlim: Out<rlimit>) -> Result<()> { Ok(()) }
    /// Sets setrlimit.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setrlimit(_resource: c_int, _rlim: *const rlimit) -> Result<()> { Ok(()) }
    /// Returns getrusage.
    fn getrusage(_who: c_int, _r_usage: Out<rusage>) -> Result<()> { Ok(()) }
    /// Returns getsid.
    fn getsid(_pid: pid_t) -> Result<pid_t> { Ok(0) }
    /// Returns gettid.
    fn gettid() -> pid_t { 1 }
    /// Returns gettimeofday.
    fn gettimeofday(mut tp: Out<timeval>, _tzp: Option<Out<crate::header::sys_time::timezone>>) -> Result<()> {
        let ticks = unsafe { syscall0(500) };
        tp.tv_sec = (ticks / 1000) as i64;
        tp.tv_usec = ((ticks % 1000) * 1000) as i64;
        Ok(())
    }
    /// Returns getuid.
    fn getuid() -> uid_t { 0 }

    /// Implements lchown.
    fn lchown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements link.
    fn link(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements lseek.
    fn lseek(fildes: c_int, offset: off_t, _whence: c_int) -> Result<off_t> {
        Ok(offset)
    }

    /// Implements mkdirat.
    fn mkdirat(_dirfd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements mkdir.
    fn mkdir(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements mkfifoat.
    fn mkfifoat(_dir_fd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements mkfifo.
    fn mkfifo(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements mknodat.
    fn mknodat(_fildes: c_int, _path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements mknod.
    fn mknod(_path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements mlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    /// Implements mlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlockall(_flags: c_int) -> Result<()> {
        Ok(())
    }

    /// Implements mmap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mmap(addr: *mut c_void, len: usize, prot: c_int, _flags: c_int, _fildes: c_int, _off: off_t) -> Result<*mut c_void> {
        let ret = unsafe { syscall3(100, addr as usize, len, prot as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as *mut c_void)
        }
    }

    /// Implements mremap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mremap(_addr: *mut c_void, _len: usize, _new_len: usize, _flags: c_int, _args: *mut c_void) -> Result<*mut c_void> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements mprotect.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mprotect(_addr: *mut c_void, _len: usize, _prot: c_int) -> Result<()> {
        Ok(())
    }

    /// Implements msync.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn msync(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Ok(())
    }

    /// Implements munlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlock(_addr: *const c_void, _len: usize) -> Result<()> {
        Ok(())
    }

    /// Implements madvise.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn madvise(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> {
        Ok(())
    }

    /// Implements munlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlockall() -> Result<()> {
        Ok(())
    }

    /// Implements munmap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        let ret = unsafe { syscall2(101, addr as usize, len) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(())
        }
    }

    /// Implements nanosleep.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn nanosleep(_rqtp: *const timespec, _rmtp: *mut timespec) -> Result<()> {
        Ok(())
    }

    /// Implements open.
    fn open(path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
        let ret = unsafe { syscall3(403, path.as_ptr() as usize, path.to_bytes().len(), oflag as usize) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret as c_int)
        }
    }

    /// Implements pipe2.
    fn pipe2(_fildes: Out<[c_int; 2]>, _flags: c_int) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements posix fallocate.
    fn posix_fallocate(_fd: c_int, _offset: u64, _length: core::num::NonZeroU64) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements posix getdents.
    fn posix_getdents(_fildes: c_int, _buf: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements rlct clone.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_clone(_stack: *mut usize, _os_specific: &mut crate::ld_so::tcb::OsSpecific) -> Result<crate::pthread::OsTid, Errno> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements rlct kill.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_kill(_os_tid: crate::pthread::OsTid, _signal: usize) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements current os tid.
    fn current_os_tid() -> crate::pthread::OsTid { 1 }

    /// Implements read.
    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        let ret = unsafe { syscall3(405, fildes as usize, buf.as_mut_ptr() as usize, buf.len()) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret)
        }
    }

    /// Implements pread.
    fn pread(_fildes: c_int, _buf: &mut [u8], _offset: off_t) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements readlink.
    fn readlink(_path: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements readlinkat.
    fn readlinkat(_dirfd: c_int, _path: CStr, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements rename.
    fn rename(_old: CStr, _new: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements renameat.
    fn renameat(_old_dir: c_int, _old_path: CStr, _new_dir: c_int, _new_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements renameat2.
    fn renameat2(_old_dir: c_int, _old_path: CStr, _new_dir: c_int, _new_path: CStr, _flags: c_uint) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements rmdir.
    fn rmdir(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements sched yield.
    fn sched_yield() -> Result<()> {
        unsafe { let _ = syscall0(301); }
        Ok(())
    }

    /// Sets setgroups.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setgroups(_size: size_t, _list: *const gid_t) -> Result<()> {
        Ok(())
    }

    /// Sets setpgid.
    fn setpgid(_pid: pid_t, _pgid: pid_t) -> Result<()> {
        Ok(())
    }

    /// Sets setpriority.
    fn setpriority(_which: c_int, _who: id_t, _prio: c_int) -> Result<()> {
        Ok(())
    }

    /// Sets setresgid.
    fn setresgid(_rgid: gid_t, _egid: gid_t, _sgid: gid_t) -> Result<()> {
        Ok(())
    }

    /// Sets setresuid.
    fn setresuid(_ruid: uid_t, _euid: uid_t, _suid: uid_t) -> Result<()> {
        Ok(())
    }

    /// Sets setsid.
    fn setsid() -> Result<c_int> {
        Ok(0)
    }

    /// Implements symlink.
    fn symlink(_path1: CStr, _path2: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements sync.
    fn sync() -> Result<()> {
        Ok(())
    }

    /// Implements timer create.
    fn timer_create(_clock_id: clockid_t, _evp: &sigevent, _timerid: Out<timer_t>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements timer delete.
    fn timer_delete(_timerid: timer_t) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements timer gettime.
    fn timer_gettime(_timerid: timer_t, _value: Out<itimerspec>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements timer settime.
    fn timer_settime(_timerid: timer_t, _flags: c_int, _value: &itimerspec, _ovalue: Option<Out<itimerspec>>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements umask.
    fn umask(_mask: mode_t) -> mode_t { 0o022 }

    /// Implements uname.
    fn uname(_utsname: Out<utsname>) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements unlink.
    fn unlink(_path: CStr) -> Result<()> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements waitpid.
    fn waitpid(_pid: pid_t, _stat_loc: Option<Out<c_int>>, _options: c_int) -> Result<pid_t> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements write.
    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        let ret = unsafe { syscall3(404, fildes as usize, buf.as_ptr() as usize, buf.len()) };
        if (ret as isize) < 0 {
            Err(Errno(-(ret as i32)))
        } else {
            Ok(ret)
        }
    }

    /// Implements pwrite.
    fn pwrite(_fildes: c_int, _buf: &[u8], _offset: off_t) -> Result<usize> {
        Err(Errno(crate::error::ENOSYS))
    }

    /// Implements verify.
    fn verify() -> bool { true }
}

impl PalSignal for Sys {}

// Low-level syscall wrappers
/// Implements syscall0.
///
/// # Safety
/// The caller must uphold the required pointer and ABI invariants.
unsafe fn syscall0(num: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Implements syscall1.
///
/// # Safety
/// The caller must uphold the required pointer and ABI invariants.
unsafe fn syscall1(num: usize, arg1: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Implements syscall2.
///
/// # Safety
/// The caller must uphold the required pointer and ABI invariants.
unsafe fn syscall2(num: usize, arg1: usize, arg2: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Implements syscall3.
///
/// # Safety
/// The caller must uphold the required pointer and ABI invariants.
unsafe fn syscall3(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let mut ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}