use crate::{
    c_str::CStr,
    error::{Errno, Result},
    header::{
        bits_time::timespec,
        signal::sigevent,
        sys_resource::{rlimit, rusage},
        sys_select::timeval,
        sys_stat::stat,
        sys_statvfs::statvfs,
        sys_time::timezone,
        sys_utsname::utsname,
        time::itimerspec,
        unistd::{SEEK_CUR, SEEK_SET},
    },
    out::Out,
    platform::{
        pal::Pal,
        types::*,
    },
};
use core::{arch::asm, ptr};

mod epoll;
mod ptrace;
mod signal;
mod socket;

pub mod auxv_defs;

pub use strat9_abi::syscall::*;

#[macro_export]
macro_rules! strat9_syscall {
    ($num:expr) => {
        unsafe { $crate::platform::sys::syscall0($num) as u64 }
    };
    ($num:expr, $a:expr) => {
        unsafe { $crate::platform::sys::syscall1($num, $a as usize) as u64 }
    };
    ($num:expr, $a:expr, $b:expr) => {
        unsafe { $crate::platform::sys::syscall2($num, $a as usize, $b as usize) as u64 }
    };
    ($num:expr, $a:expr, $b:expr, $c:expr) => {
        unsafe { $crate::platform::sys::syscall3($num, $a as usize, $b as usize, $c as usize) as u64 }
    };
    ($num:expr, $a:expr, $b:expr, $c:expr, $d:expr) => {
        unsafe { $crate::platform::sys::syscall4($num, $a as usize, $b as usize, $c as usize, $d as usize) as u64 }
    };
    ($num:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr) => {
        unsafe {
            $crate::platform::sys::syscall5(
                $num,
                $a as usize,
                $b as usize,
                $c as usize,
                $d as usize,
                $e as usize,
            ) as u64
        }
    };
    ($num:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr) => {
        unsafe {
            $crate::platform::sys::syscall6(
                $num,
                $a as usize,
                $b as usize,
                $c as usize,
                $d as usize,
                $e as usize,
                $f as usize,
            ) as u64
        }
    };
}

const NANOSECONDS_PER_SECOND: usize = 1_000_000_000;
const SYS_TIME_TICKS: usize = SYS_CLOCK_GETTIME;
const AT_FDCWD: c_int = -100;
const EINVAL: c_int = 22;
const ENOSYS: c_int = 38;

/// Convert a raw syscall return value into a Strat9 libc `Result`.
pub fn e_raw(ret: u64) -> Result<u64> {
    let r = ret as i64;
    if r < 0 && r > -4096 {
        Err(Errno(-r as i32))
    } else {
        Ok(ret)
    }
}

/// Implements e.
fn e(ret: usize) -> Result<usize> {
    let r = ret as isize;
    if r < 0 && r > -4096 {
        Err(Errno(-r as i32))
    } else {
        Ok(ret)
    }
}

/// Implements off to usize nonneg.
fn off_to_usize_nonneg(off: off_t) -> Result<usize> {
    if off < 0 {
        return Err(Errno(EINVAL));
    }
    Ok(off as usize)
}

/// Implements filestat to stat.
fn filestat_to_stat(kst: &strat9_abi::data::FileStat, out: *mut stat) {
    unsafe {
        ptr::write_bytes(out, 0, 1);
        (*out).st_ino = kst.st_ino as ino_t;
        (*out).st_mode = kst.st_mode as mode_t;
        (*out).st_nlink = kst.st_nlink as nlink_t;
        (*out).st_size = kst.st_size as off_t;
        (*out).st_blksize = kst.st_blksize as blksize_t;
        (*out).st_blocks = kst.st_blocks as blkcnt_t;
    }
}

pub struct Sys;

impl Sys {
    /// Perform an `ioctl` operation on an open file descriptor.
    pub unsafe fn ioctl(fd: c_int, request: c_ulong, out: *mut c_void) -> Result<c_int> {
        Ok(e_raw(strat9_syscall!(SYS_IOCTL, fd as u64, request as u64, out as u64))? as c_int)
    }
}

impl Pal for Sys {
    /// Implements access.
    fn access(path: CStr, _mode: c_int) -> Result<()> {
        let flags = strat9_abi::flag::OpenFlags::READ.bits() as usize;
        let fd = e(unsafe { syscall3(SYS_OPEN, path.as_ptr() as usize, path.to_bytes().len(), flags) })?;
        unsafe { let _ = syscall1(SYS_CLOSE, fd); }
        Ok(())
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
            let result = e(syscall1(SYS_BRK, addr as usize))?;
            BRK_CUR = result as *mut c_void;
            Ok(BRK_CUR)
        }
    }

    /// Implements chdir.
    fn chdir(path: CStr) -> Result<()> {
        e_raw(strat9_syscall!(SYS_CHDIR, path.as_ptr() as u64, path.to_bytes().len() as u64))?;
        Ok(())
    }

    /// Implements chmod.
    fn chmod(path: CStr, mode: mode_t) -> Result<()> {
        e(unsafe { syscall3(SYS_CHMOD, path.as_ptr() as usize, path.to_bytes().len(), mode as usize) })?;
        Ok(())
    }

    /// Implements chown.
    fn chown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements clock getres.
    fn clock_getres(_clk_id: clockid_t, _tp: Option<Out<timespec>>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements clock gettime.
    fn clock_gettime(_clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        let ns = unsafe { syscall0(SYS_TIME_TICKS) };
        tp.write(timespec {
            tv_sec: (ns / NANOSECONDS_PER_SECOND) as i64,
            tv_nsec: (ns % NANOSECONDS_PER_SECOND) as i64,
        });
        Ok(())
    }

    /// Implements clock settime.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn clock_settime(_clk_id: clockid_t, _tp: *const timespec) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements close.
    fn close(fildes: c_int) -> Result<()> {
        e(unsafe { syscall1(SYS_CLOSE, fildes as usize) })?;
        Ok(())
    }

    /// Implements dup.
    fn dup(fildes: c_int) -> Result<c_int> {
        e(unsafe { syscall1(SYS_DUP, fildes as usize) }).map(|r| r as c_int)
    }

    /// Implements dup2.
    fn dup2(fildes: c_int, fildes2: c_int) -> Result<c_int> {
        e_raw(strat9_syscall!(SYS_DUP2, fildes as u64, fildes2 as u64)).map(|r| r as c_int)
    }

    /// Implements execve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn execve(
        _path: CStr,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        e_raw(strat9_syscall!(
            SYS_PROC_EXECVE,
            _path.as_ptr() as u64,
            _argv as usize as u64,
            _envp as usize as u64
        ))?;
        Ok(())
    }

    /// Implements fexecve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fexecve(
        _fildes: c_int,
        _argv: *const *mut c_char,
        _envp: *const *mut c_char,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements exit.
    fn exit(status: c_int) -> ! {
        unsafe { let _ = syscall1(SYS_PROC_EXIT, status as usize); }
        loop {}
    }

    /// Implements exit thread.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        unsafe { let _ = syscall1(SYS_PROC_EXIT, 0); }
        loop { core::hint::spin_loop(); }
    }

    /// Implements fchdir.
    fn fchdir(fildes: c_int) -> Result<()> {
        e(unsafe { syscall1(SYS_FCHDIR, fildes as usize) })?;
        Ok(())
    }

    /// Implements fchmod.
    fn fchmod(fildes: c_int, mode: mode_t) -> Result<()> {
        e(unsafe { syscall2(SYS_FCHMOD, fildes as usize, mode as usize) })?;
        Ok(())
    }

    /// Implements fchmodat.
    fn fchmodat(_dirfd: c_int, _path: Option<CStr>, _mode: mode_t, _flags: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements fchown.
    fn fchown(_fildes: c_int, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements fdatasync.
    fn fdatasync(_fildes: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements flock.
    fn flock(_fd: c_int, _operation: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements fstat.
    fn fstat(fildes: c_int, mut buf: Out<stat>) -> Result<()> {
        let mut kst = strat9_abi::data::FileStat::zeroed();
        e_raw(strat9_syscall!(SYS_FSTAT, fildes as u64, &mut kst as *mut _ as u64))?;
        filestat_to_stat(&kst, buf.as_mut_ptr());
        Ok(())
    }

    /// Implements fstatat.
    fn fstatat(_fildes: c_int, _path: Option<CStr>, _buf: Out<stat>, _flags: c_int) -> Result<()> {
        if _fildes != AT_FDCWD || _flags != 0 {
            return Err(Errno(EINVAL));
        }
        let path = _path.ok_or(Errno(EINVAL))?;
        let mut buf = _buf;
        let mut kst = strat9_abi::data::FileStat::zeroed();
        e_raw(strat9_syscall!(
            SYS_STAT,
            path.as_ptr() as u64,
            path.to_bytes().len() as u64,
            &mut kst as *mut _ as u64
        ))?;
        filestat_to_stat(&kst, buf.as_mut_ptr());
        Ok(())
    }

    /// Implements fstatvfs.
    fn fstatvfs(_fildes: c_int, _buf: Out<statvfs>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements fcntl.
    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        e_raw(strat9_syscall!(SYS_FCNTL, fildes as u64, cmd as u64, arg)).map(|r| r as c_int)
    }

    /// Implements fork.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fork() -> Result<pid_t> {
        e(unsafe { syscall0(SYS_PROC_FORK) }).map(|r| r as pid_t)
    }

    /// Implements fpath.
    fn fpath(_fildes: c_int, _out: &mut [u8]) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    /// Implements fsync.
    fn fsync(_fildes: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements ftruncate.
    fn ftruncate(fildes: c_int, length: off_t) -> Result<()> {
        let length = off_to_usize_nonneg(length)?;
        e(unsafe { syscall2(SYS_FTRUNCATE, fildes as usize, length) })?;
        Ok(())
    }

    /// Implements futex wait.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()> {
        let deadline_ns = deadline.map_or(0u64, |d| {
            (d.tv_sec as u64) * 1_000_000_000 + (d.tv_nsec as u64)
        });
        e_raw(strat9_syscall!(SYS_FUTEX_WAIT, addr as u64, val as u64, deadline_ns))?;
        Ok(())
    }

    /// Implements futex wake.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32> {
        e(unsafe { syscall2(SYS_FUTEX_WAKE, addr as usize, num as usize) }).map(|r| r as u32)
    }

    /// Implements futimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futimens(_fildes: c_int, _times: *const timespec) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements utimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn utimens(_path: CStr, _times: *const timespec) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Returns getcwd.
    fn getcwd(mut buf: Out<[u8]>) -> Result<()> {
        e_raw(strat9_syscall!(
            SYS_GETCWD,
            buf.as_mut_ptr().as_mut_ptr() as u64,
            buf.as_mut_ptr().len() as u64
        ))?;
        Ok(())
    }

    /// Returns getdents.
    fn getdents(fildes: c_int, buf: &mut [u8], _opaque_offset: u64) -> Result<usize> {
        e(unsafe { syscall3(SYS_GETDENTS, fildes as usize, buf.as_mut_ptr() as usize, buf.len()) })
    }

    /// Implements dir seek.
    fn dir_seek(fildes: c_int, opaque_offset: u64) -> Result<()> {
        e(unsafe { syscall3(SYS_LSEEK, fildes as usize, opaque_offset as usize, SEEK_SET as usize) })?;
        Ok(())
    }

    /// Implements dent reclen offset.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn dent_reclen_offset(this_dent: &[u8], offset: usize) -> Option<(u16, u64)> {
        const HEADER_SIZE: usize = 11;
        if this_dent.len() < HEADER_SIZE {
            return None;
        }
        let name_len = u16::from_le_bytes([this_dent[9], this_dent[10]]) as usize;
        let record_len = HEADER_SIZE + name_len + 1;
        if this_dent.len() < record_len {
            return None;
        }
        Some((record_len as u16, (offset + record_len) as u64))
    }

    /// Returns getegid.
    fn getegid() -> gid_t { 0 }
    /// Returns geteuid.
    fn geteuid() -> uid_t { 0 }
    /// Returns getgid.
    fn getgid() -> gid_t { 0 }
    /// Returns getgroups.
    fn getgroups(_list: Out<[gid_t]>) -> Result<c_int> { Err(Errno(ENOSYS)) }
    /// Returns getpagesize.
    fn getpagesize() -> usize { 4096 }

    /// Returns getpgid.
    fn getpgid(pid: pid_t) -> Result<pid_t> {
        e(unsafe { syscall1(SYS_GETPGID, pid as usize) }).map(|r| r as pid_t)
    }

    /// Returns getpid.
    fn getpid() -> pid_t {
        match e(unsafe { syscall0(SYS_GETPID) }) {
            Ok(v) => v as pid_t,
            Err(_) => 1,
        }
    }

    /// Returns getppid.
    fn getppid() -> pid_t {
        match e(unsafe { syscall0(SYS_GETPPID) }) {
            Ok(v) => v as pid_t,
            Err(_) => 0,
        }
    }

    /// Returns getpriority.
    fn getpriority(_which: c_int, _who: id_t) -> Result<c_int> { Err(Errno(ENOSYS)) }

    /// Returns getrandom.
    fn getrandom(_buf: &mut [u8], _flags: c_uint) -> Result<usize> { Err(Errno(ENOSYS)) }

    /// Returns getresgid.
    fn getresgid(
        _rgid: Option<Out<gid_t>>,
        _egid: Option<Out<gid_t>>,
        _sgid: Option<Out<gid_t>>,
    ) -> Result<()> { Err(Errno(ENOSYS)) }

    /// Returns getresuid.
    fn getresuid(
        _ruid: Option<Out<uid_t>>,
        _euid: Option<Out<uid_t>>,
        _suid: Option<Out<uid_t>>,
    ) -> Result<()> { Err(Errno(ENOSYS)) }

    /// Returns getrlimit.
    fn getrlimit(_resource: c_int, _rlim: Out<rlimit>) -> Result<()> { Err(Errno(ENOSYS)) }

    /// Sets setrlimit.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setrlimit(_resource: c_int, _rlim: *const rlimit) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Returns getrusage.
    fn getrusage(_who: c_int, _r_usage: Out<rusage>) -> Result<()> { Err(Errno(ENOSYS)) }

    /// Returns getsid.
    fn getsid(pid: pid_t) -> Result<pid_t> {
        e(unsafe { syscall1(SYS_GETSID, pid as usize) }).map(|r| r as pid_t)
    }

    /// Returns gettid.
    fn gettid() -> pid_t {
        match e(unsafe { syscall0(SYS_GETTID) }) {
            Ok(v) => v as pid_t,
            Err(_) => 1,
        }
    }

    /// Returns gettimeofday.
    fn gettimeofday(
        mut tp: Out<timeval>,
        _tzp: Option<Out<timezone>>,
    ) -> Result<()> {
        let ns = unsafe { syscall0(SYS_TIME_TICKS) };
        tp.write(timeval {
            tv_sec: (ns / NANOSECONDS_PER_SECOND) as i64,
            tv_usec: ((ns % NANOSECONDS_PER_SECOND) / 1000) as i32,
        });
        Ok(())
    }

    /// Returns getuid.
    fn getuid() -> uid_t { 0 }

    /// Implements lchown.
    fn lchown(_path: CStr, _owner: uid_t, _group: gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements link.
    fn link(path1: CStr, path2: CStr) -> Result<()> {
        e(unsafe { syscall4(SYS_LINK, path1.as_ptr() as usize, path1.to_bytes().len(), path2.as_ptr() as usize, path2.to_bytes().len()) })?;
        Ok(())
    }

    /// Implements lseek.
    fn lseek(fildes: c_int, offset: off_t, whence: c_int) -> Result<off_t> {
        e(unsafe { syscall3(SYS_LSEEK, fildes as usize, offset as usize, whence as usize) }).map(|r| r as off_t)
    }

    /// Implements mkdirat.
    fn mkdirat(dirfd: c_int, path: CStr, mode: mode_t) -> Result<()> {
        if dirfd != AT_FDCWD {
            return Err(Errno(ENOSYS));
        }
        Self::mkdir(path, mode)
    }

    /// Implements mkdir.
    fn mkdir(path: CStr, mode: mode_t) -> Result<()> {
        e(unsafe { syscall3(SYS_MKDIR, path.as_ptr() as usize, path.to_bytes().len(), mode as usize) })?;
        Ok(())
    }

    /// Implements mkfifoat.
    fn mkfifoat(_dir_fd: c_int, _path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements mkfifo.
    fn mkfifo(_path: CStr, _mode: mode_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements mknodat.
    fn mknodat(_fildes: c_int, _path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements mknod.
    fn mknod(_path: CStr, _mode: mode_t, _dev: dev_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements mlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlock(_addr: *const c_void, _len: usize) -> Result<()> { Err(Errno(ENOSYS)) }
    /// Implements mlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlockall(_flags: c_int) -> Result<()> { Err(Errno(ENOSYS)) }

    /// Implements mmap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mmap(
        addr: *mut c_void,
        len: usize,
        prot: c_int,
        flags: c_int,
        fildes: c_int,
        off: off_t,
    ) -> Result<*mut c_void> {
        let off = off_to_usize_nonneg(off)?;
        e(unsafe {
            syscall6(
                SYS_MMAP,
                addr as usize,
                len,
                prot as usize,
                flags as usize,
                fildes as usize,
                off,
            )
        })
        .map(|r| r as *mut c_void)
    }

    /// Implements mremap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mremap(
        _addr: *mut c_void,
        _len: usize,
        _new_len: usize,
        _flags: c_int,
        _args: *mut c_void,
    ) -> Result<*mut c_void> {
        Err(Errno(ENOSYS))
    }

    /// Implements mprotect.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mprotect(_addr: *mut c_void, _len: usize, _prot: c_int) -> Result<()> { Err(Errno(ENOSYS)) }
    /// Implements msync.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn msync(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> { Err(Errno(ENOSYS)) }
    /// Implements munlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlock(_addr: *const c_void, _len: usize) -> Result<()> { Err(Errno(ENOSYS)) }
    /// Implements madvise.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn madvise(_addr: *mut c_void, _len: usize, _flags: c_int) -> Result<()> { Err(Errno(ENOSYS)) }
    /// Implements munlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlockall() -> Result<()> { Err(Errno(ENOSYS)) }

    /// Implements munmap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        e(unsafe { syscall2(SYS_MUNMAP, addr as usize, len) })?;
        Ok(())
    }

    /// Implements nanosleep.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> Result<()> {
        e(unsafe { syscall2(SYS_NANOSLEEP, rqtp as usize, rmtp as usize) })?;
        Ok(())
    }

    /// Implements open.
    fn open(path: CStr, oflag: c_int, _mode: mode_t) -> Result<c_int> {
        let abi_flags = strat9_abi::flag::posix_oflags_to_strat9(oflag as u32);
        e(unsafe {
            syscall3(SYS_OPEN, path.as_ptr() as usize, path.to_bytes().len(), abi_flags.bits() as usize)
        }).map(|r| r as c_int)
    }

    /// Implements openat.
    fn openat(dirfd: c_int, path: CStr, oflag: c_int, mode: mode_t) -> Result<c_int> {
        if dirfd != AT_FDCWD {
            return Err(Errno(ENOSYS));
        }
        Self::open(path, oflag, mode)
    }

    /// Implements pipe2.
    fn pipe2(mut fildes: Out<[c_int; 2]>, flags: c_int) -> Result<()> {
        let known = crate::header::fcntl::O_CLOEXEC | crate::header::fcntl::O_NONBLOCK;
        if flags & !known != 0 {
            return Err(Errno(EINVAL));
        }
        e_raw(strat9_syscall!(SYS_PIPE, fildes.as_mut_ptr() as *mut c_int as u64))?;
        Ok(())
    }

    /// Implements posix fallocate.
    fn posix_fallocate(_fd: c_int, _offset: u64, _length: core::num::NonZeroU64) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements posix getdents.
    fn posix_getdents(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        let current_offset = Self::lseek(fildes, 0, SEEK_CUR as c_int)? as u64;
        Self::getdents(fildes, buf, current_offset)
    }

    /// Implements rlct clone.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_clone(
        _stack: *mut usize,
        _os_specific: &mut crate::ld_so::tcb::OsSpecific,
    ) -> Result<crate::pthread::OsTid, Errno> {
        Err(Errno(ENOSYS))
    }

    /// Implements rlct kill.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_kill(_os_tid: crate::pthread::OsTid, _signal: usize) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements current os tid.
    fn current_os_tid() -> crate::pthread::OsTid {
        crate::pthread::OsTid::default()
    }

    /// Implements read.
    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        e(unsafe { syscall3(SYS_READ, fildes as usize, buf.as_mut_ptr() as usize, buf.len()) })
    }

    /// Implements pread.
    fn pread(fildes: c_int, buf: &mut [u8], offset: off_t) -> Result<usize> {
        let offset = off_to_usize_nonneg(offset)?;
        e(unsafe { syscall4(SYS_PREAD, fildes as usize, buf.as_mut_ptr() as usize, buf.len(), offset) })
    }

    /// Implements readlink.
    fn readlink(path: CStr, out: &mut [u8]) -> Result<usize> {
        e(unsafe { syscall4(SYS_READLINK, path.as_ptr() as usize, path.to_bytes().len(), out.as_mut_ptr() as usize, out.len()) })
    }

    /// Implements readlinkat.
    fn readlinkat(dirfd: c_int, path: CStr, out: &mut [u8]) -> Result<usize> {
        if dirfd != AT_FDCWD {
            return Err(Errno(ENOSYS));
        }
        Self::readlink(path, out)
    }

    /// Implements rename.
    fn rename(old: CStr, new: CStr) -> Result<()> {
        e(unsafe { syscall4(SYS_RENAME, old.as_ptr() as usize, old.to_bytes().len(), new.as_ptr() as usize, new.to_bytes().len()) })?;
        Ok(())
    }

    /// Implements renameat.
    fn renameat(old_dir: c_int, old_path: CStr, new_dir: c_int, new_path: CStr) -> Result<()> {
        if old_dir != AT_FDCWD || new_dir != AT_FDCWD {
            return Err(Errno(ENOSYS));
        }
        Self::rename(old_path, new_path)
    }

    /// Implements renameat2.
    fn renameat2(
        old_dir: c_int,
        old_path: CStr,
        new_dir: c_int,
        new_path: CStr,
        _flags: c_uint,
    ) -> Result<()> {
        if old_dir != AT_FDCWD || new_dir != AT_FDCWD {
            return Err(Errno(ENOSYS));
        }
        Self::rename(old_path, new_path)
    }

    /// Implements rmdir.
    fn rmdir(path: CStr) -> Result<()> {
        e(unsafe { syscall2(SYS_RMDIR, path.as_ptr() as usize, path.to_bytes().len()) })?;
        Ok(())
    }

    /// Implements sched yield.
    fn sched_yield() -> Result<()> {
        unsafe { let _ = syscall0(SYS_PROC_YIELD); }
        Ok(())
    }

    /// Sets setgroups.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setgroups(_size: size_t, _list: *const gid_t) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Sets setpgid.
    fn setpgid(pid: pid_t, pgid: pid_t) -> Result<()> {
        e(unsafe { syscall2(SYS_SETPGID, pid as usize, pgid as usize) })?;
        Ok(())
    }

    /// Sets setpriority.
    fn setpriority(_which: c_int, _who: id_t, _prio: c_int) -> Result<()> { Err(Errno(ENOSYS)) }
    /// Sets setresgid.
    fn setresgid(_rgid: gid_t, _egid: gid_t, _sgid: gid_t) -> Result<()> { Err(Errno(ENOSYS)) }
    /// Sets setresuid.
    fn setresuid(_ruid: uid_t, _euid: uid_t, _suid: uid_t) -> Result<()> { Err(Errno(ENOSYS)) }

    /// Sets setsid.
    fn setsid() -> Result<c_int> {
        e(unsafe { syscall0(SYS_SETSID) }).map(|r| r as c_int)
    }

    /// Implements symlink.
    fn symlink(path1: CStr, path2: CStr) -> Result<()> {
        e(unsafe { syscall4(SYS_SYMLINK, path1.as_ptr() as usize, path1.to_bytes().len(), path2.as_ptr() as usize, path2.to_bytes().len()) })?;
        Ok(())
    }
    /// Implements sync.
    fn sync() -> Result<()> { Err(Errno(ENOSYS)) }

    /// Implements timer create.
    fn timer_create(_clock_id: clockid_t, _evp: &sigevent, _timerid: Out<timer_t>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements timer delete.
    fn timer_delete(_timerid: timer_t) -> Result<()> { Err(Errno(ENOSYS)) }

    /// Implements timer gettime.
    fn timer_gettime(_timerid: timer_t, _value: Out<itimerspec>) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements timer settime.
    fn timer_settime(
        _timerid: timer_t,
        _flags: c_int,
        _value: &itimerspec,
        _ovalue: Option<Out<itimerspec>>,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Implements umask.
    fn umask(mask: mode_t) -> mode_t {
        unsafe { syscall1(SYS_UMASK, mask as usize) as mode_t }
    }

    /// Implements uname.
    fn uname(_utsname: Out<utsname>) -> Result<()> {
        let mut uts = _utsname;
        e_raw(strat9_syscall!(SYS_UNAME, uts.as_mut_ptr() as u64))?;
        Ok(())
    }

    /// Implements unlink.
    fn unlink(path: CStr) -> Result<()> {
        e(unsafe { syscall2(SYS_UNLINK, path.as_ptr() as usize, path.to_bytes().len()) })?;
        Ok(())
    }

    /// Implements waitpid.
    fn waitpid(pid: pid_t, stat_loc: Option<Out<c_int>>, options: c_int) -> Result<pid_t> {
        e_raw(strat9_syscall!(
            SYS_PROC_WAITPID,
            pid as u64,
            stat_loc.map_or(0, |mut o| o.as_mut_ptr() as usize) as u64,
            options as u64
        ))
        .map(|p| p as pid_t)
    }

    /// Implements write.
    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        e(unsafe { syscall3(SYS_WRITE, fildes as usize, buf.as_ptr() as usize, buf.len()) })
    }

    /// Implements pwrite.
    fn pwrite(fildes: c_int, buf: &[u8], offset: off_t) -> Result<usize> {
        let offset = off_to_usize_nonneg(offset)?;
        e(unsafe { syscall4(SYS_PWRITE, fildes as usize, buf.as_ptr() as usize, buf.len(), offset) })
    }

    /// Implements verify.
    fn verify() -> bool { true }
}

/// Invoke a raw syscall with zero arguments.
pub unsafe fn syscall0(num: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Invoke a raw syscall with one argument (`rdi`).
pub unsafe fn syscall1(num: usize, arg1: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Invoke a raw syscall with two arguments (`rdi`, `rsi`).
pub unsafe fn syscall2(num: usize, arg1: usize, arg2: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Invoke a raw syscall with three arguments (`rdi`, `rsi`, `rdx`).
pub unsafe fn syscall3(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Invoke a raw syscall with four arguments (`rdi`, `rsi`, `rdx`, `r10`).
pub unsafe fn syscall4(num: usize, arg1: usize, arg2: usize, arg3: usize, arg4: usize) -> usize {
    let ret;
    unsafe {
        asm!("syscall", inout("rax") num => ret, in("rdi") arg1, in("rsi") arg2, in("rdx") arg3, in("r10") arg4, out("rcx") _, out("r11") _, options(nostack));
    }
    ret
}

/// Invoke a raw syscall with five arguments (`rdi`, `rsi`, `rdx`, `r10`, `r8`).
pub unsafe fn syscall5(
    num: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
) -> usize {
    let ret;
    unsafe {
        asm!(
            "syscall",
            inout("rax") num => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}

/// Invoke a raw syscall with six arguments (`rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`).
pub unsafe fn syscall6(
    num: usize,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
    arg5: usize,
    arg6: usize,
) -> usize {
    let ret;
    unsafe {
        asm!(
            "syscall",
            inout("rax") num => ret,
            in("rdi") arg1,
            in("rsi") arg2,
            in("rdx") arg3,
            in("r10") arg4,
            in("r8") arg5,
            in("r9") arg6,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}
