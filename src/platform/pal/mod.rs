use core::num::NonZeroU64;

use super::types::*;
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
    },
    ld_so::tcb::OsSpecific,
    out::Out,
    pthread,
};

pub use self::epoll::PalEpoll;
mod epoll;

pub use self::ptrace::PalPtrace;
mod ptrace;

pub use self::signal::PalSignal;
mod signal;

pub use self::socket::PalSocket;
mod socket;

/// Platform abstraction layer, a platform-agnostic abstraction over syscalls.
pub trait Pal {
    /// Implements access.
    fn access(path: CStr, mode: c_int) -> Result<()>;

    /// Implements brk.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn brk(addr: *mut c_void) -> Result<*mut c_void>;

    /// Implements chdir.
    fn chdir(path: CStr) -> Result<()>;

    /// Implements chmod.
    fn chmod(path: CStr, mode: mode_t) -> Result<()>;

    /// Implements chown.
    fn chown(path: CStr, owner: uid_t, group: gid_t) -> Result<()>;

    /// Implements clock getres.
    fn clock_getres(clk_id: clockid_t, tp: Option<Out<timespec>>) -> Result<()>;

    // TODO: maybe remove tp and change signature to -> Result<timespec>?
    /// Implements clock gettime.
    fn clock_gettime(clk_id: clockid_t, tp: Out<timespec>) -> Result<()>;

    /// Implements clock settime.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn clock_settime(clk_id: clockid_t, tp: *const timespec) -> Result<()>;

    /// Implements close.
    fn close(fildes: c_int) -> Result<()>;

    /// Implements dup.
    fn dup(fildes: c_int) -> Result<c_int>;

    /// Implements dup2.
    fn dup2(fildes: c_int, fildes2: c_int) -> Result<c_int>;

    /// Implements execve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn execve(path: CStr, argv: *const *mut c_char, envp: *const *mut c_char) -> Result<()>;
    /// Implements fexecve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fexecve(
        fildes: c_int,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> Result<()>;

    /// Implements exit.
    fn exit(status: c_int) -> !;

    /// Implements exit thread.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn exit_thread(stack_base: *mut (), stack_size: usize) -> !;

    /// Implements fchdir.
    fn fchdir(fildes: c_int) -> Result<()>;

    /// Implements fchmod.
    fn fchmod(fildes: c_int, mode: mode_t) -> Result<()>;
    /// Implements fchmodat.
    fn fchmodat(dirfd: c_int, path: Option<CStr>, mode: mode_t, flags: c_int) -> Result<()>;

    /// Implements fchown.
    fn fchown(fildes: c_int, owner: uid_t, group: gid_t) -> Result<()>;

    /// Implements fdatasync.
    fn fdatasync(fildes: c_int) -> Result<()>;

    /// Implements flock.
    fn flock(fd: c_int, operation: c_int) -> Result<()>;

    /// Implements fstat.
    fn fstat(fildes: c_int, buf: Out<stat>) -> Result<()>;

    /// Implements fstatat.
    fn fstatat(fildes: c_int, path: Option<CStr>, buf: Out<stat>, flags: c_int) -> Result<()>;

    /// Implements fstatvfs.
    fn fstatvfs(fildes: c_int, buf: Out<statvfs>) -> Result<()>;

    /// Implements fcntl.
    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int>;

    /// Implements fork.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fork() -> Result<pid_t>;

    /// Implements fpath.
    fn fpath(fildes: c_int, out: &mut [u8]) -> Result<usize>;

    /// Implements fsync.
    fn fsync(fildes: c_int) -> Result<()>;

    /// Implements ftruncate.
    fn ftruncate(fildes: c_int, length: off_t) -> Result<()>;

    /// Implements futex wait.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()>;
    /// Implements futex wake.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32>;

    /// Implements futimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futimens(fd: c_int, times: *const timespec) -> Result<()>;

    /// Implements utimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn utimens(path: CStr, times: *const timespec) -> Result<()>;

    /// Returns getcwd.
    fn getcwd(buf: Out<[u8]>) -> Result<()>;

    /// Returns getdents.
    fn getdents(fd: c_int, buf: &mut [u8], opaque_offset: u64) -> Result<usize>;
    /// Implements dir seek.
    fn dir_seek(fd: c_int, opaque_offset: u64) -> Result<()>;

    // SAFETY: This_dent must satisfy platform-specific size and alignment constraints. On Linux,
    // this means the buffer came from a valid getdents64 invocation, whereas on Redox, every
    // possible this_dent slice is safe (and will be validated).
    /// Implements dent reclen offset.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn dent_reclen_offset(this_dent: &[u8], offset: usize) -> Option<(u16, u64)>;

    // Always successful
    /// Returns getegid.
    fn getegid() -> gid_t;

    // Always successful
    /// Returns geteuid.
    fn geteuid() -> uid_t;

    // Always successful
    /// Returns getgid.
    fn getgid() -> gid_t;

    /// Returns getgroups.
    fn getgroups(list: Out<[gid_t]>) -> Result<c_int>;

    /* Note that this is distinct from the legacy POSIX function
     * getpagesize(), which returns a c_int. On some Linux platforms,
     * page size may be determined through a syscall ("getpagesize"). */
    /// Returns getpagesize.
    fn getpagesize() -> usize;

    /// Returns getpgid.
    fn getpgid(pid: pid_t) -> Result<pid_t>;

    // Always successful
    /// Returns getpid.
    fn getpid() -> pid_t;

    // Always successful
    /// Returns getppid.
    fn getppid() -> pid_t;

    /// Returns getpriority.
    fn getpriority(which: c_int, who: id_t) -> Result<c_int>;

    /// Returns getrandom.
    fn getrandom(buf: &mut [u8], flags: c_uint) -> Result<usize>;

    /// Returns getresgid.
    fn getresgid(
        rgid: Option<Out<gid_t>>,
        egid: Option<Out<gid_t>>,
        sgid: Option<Out<gid_t>>,
    ) -> Result<()>;

    /// Returns getresuid.
    fn getresuid(
        ruid: Option<Out<uid_t>>,
        euid: Option<Out<uid_t>>,
        suid: Option<Out<uid_t>>,
    ) -> Result<()>;

    /// Returns getrlimit.
    fn getrlimit(resource: c_int, rlim: Out<rlimit>) -> Result<()>;

    /// Sets setrlimit.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setrlimit(resource: c_int, rlim: *const rlimit) -> Result<()>;

    /// Returns getrusage.
    fn getrusage(who: c_int, r_usage: Out<rusage>) -> Result<()>;

    /// Returns getsid.
    fn getsid(pid: pid_t) -> Result<pid_t>;

    // Always successful
    /// Returns gettid.
    fn gettid() -> pid_t;

    /// Returns gettimeofday.
    fn gettimeofday(tp: Out<timeval>, tzp: Option<Out<timezone>>) -> Result<()>;

    /// Returns getuid.
    fn getuid() -> uid_t;

    /// Implements lchown.
    fn lchown(path: CStr, owner: uid_t, group: gid_t) -> Result<()>;

    /// Implements link.
    fn link(path1: CStr, path2: CStr) -> Result<()>;

    /// Implements lseek.
    fn lseek(fildes: c_int, offset: off_t, whence: c_int) -> Result<off_t>;

    /// Implements mkdirat.
    fn mkdirat(fildes: c_int, path: CStr, mode: mode_t) -> Result<()>;

    /// Implements mkdir.
    fn mkdir(path: CStr, mode: mode_t) -> Result<()>;

    /// Implements mkfifoat.
    fn mkfifoat(dir_fd: c_int, path: CStr, mode: mode_t) -> Result<()>;

    /// Implements mkfifo.
    fn mkfifo(path: CStr, mode: mode_t) -> Result<()>;

    /// Implements mknodat.
    fn mknodat(fildes: c_int, path: CStr, mode: mode_t, dev: dev_t) -> Result<()>;

    /// Implements mknod.
    fn mknod(path: CStr, mode: mode_t, dev: dev_t) -> Result<()>;

    /// Implements mlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlock(addr: *const c_void, len: usize) -> Result<()>;

    /// Implements mlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlockall(flags: c_int) -> Result<()>;

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
    ) -> Result<*mut c_void>;

    /// Implements mremap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mremap(
        addr: *mut c_void,
        len: usize,
        new_len: usize,
        flags: c_int,
        args: *mut c_void,
    ) -> Result<*mut c_void>;

    /// Implements mprotect.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> Result<()>;

    /// Implements msync.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn msync(addr: *mut c_void, len: usize, flags: c_int) -> Result<()>;

    /// Implements munlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlock(addr: *const c_void, len: usize) -> Result<()>;

    /// Implements madvise.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn madvise(addr: *mut c_void, len: usize, flags: c_int) -> Result<()>;

    /// Implements munlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlockall() -> Result<()>;

    /// Implements munmap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()>;

    /// Implements nanosleep.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> Result<()>;

    /// Implements open.
    fn open(path: CStr, oflag: c_int, mode: mode_t) -> Result<c_int>;

    /// Implements openat.
    fn openat(dirfd: c_int, path: CStr, oflag: c_int, mode: mode_t) -> Result<c_int>;

    /// Implements pipe2.
    fn pipe2(fildes: Out<[c_int; 2]>, flags: c_int) -> Result<()>;

    /// Implements posix fallocate.
    fn posix_fallocate(fd: c_int, offset: u64, length: NonZeroU64) -> Result<()>;

    /// Implements posix getdents.
    fn posix_getdents(fildes: c_int, buf: &mut [u8]) -> Result<usize>;

    /// Implements rlct clone.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_clone(
        stack: *mut usize,
        os_specific: &mut OsSpecific,
    ) -> Result<pthread::OsTid, Errno>;
    /// Implements rlct kill.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_kill(os_tid: pthread::OsTid, signal: usize) -> Result<()>;

    /// Implements current os tid.
    fn current_os_tid() -> pthread::OsTid;

    /// Implements read.
    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize>;
    /// Implements pread.
    fn pread(fildes: c_int, buf: &mut [u8], offset: off_t) -> Result<usize>;

    /// Implements readlink.
    fn readlink(pathname: CStr, out: &mut [u8]) -> Result<usize>;

    /// Implements readlinkat.
    fn readlinkat(dirfd: c_int, pathname: CStr, out: &mut [u8]) -> Result<usize>;

    /// Implements rename.
    fn rename(old: CStr, new: CStr) -> Result<()>;
    /// Implements renameat.
    fn renameat(old_dir: c_int, old_path: CStr, new_dir: c_int, new_path: CStr) -> Result<()>;
    /// Implements renameat2.
    fn renameat2(
        old_dir: c_int,
        old_path: CStr,
        new_dir: c_int,
        new_path: CStr,
        flags: c_uint,
    ) -> Result<()>;

    /// Implements rmdir.
    fn rmdir(path: CStr) -> Result<()>;

    /// Implements sched yield.
    fn sched_yield() -> Result<()>;

    /// Sets setgroups.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setgroups(size: size_t, list: *const gid_t) -> Result<()>;

    /// Sets setpgid.
    fn setpgid(pid: pid_t, pgid: pid_t) -> Result<()>;

    /// Sets setpriority.
    fn setpriority(which: c_int, who: id_t, prio: c_int) -> Result<()>;

    /// Sets setresgid.
    fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) -> Result<()>;

    /// Sets setresuid.
    fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> Result<()>;

    /// Sets setsid.
    fn setsid() -> Result<c_int>;

    /// Implements symlink.
    fn symlink(path1: CStr, path2: CStr) -> Result<()>;

    /// Implements sync.
    fn sync() -> Result<()>;

    /// Implements timer create.
    fn timer_create(clock_id: clockid_t, evp: &sigevent, timerid: Out<timer_t>) -> Result<()>;

    /// Implements timer delete.
    fn timer_delete(timerid: timer_t) -> Result<()>;

    /// Implements timer gettime.
    fn timer_gettime(timerid: timer_t, value: Out<itimerspec>) -> Result<()>;

    /// Implements timer settime.
    fn timer_settime(
        timerid: timer_t,
        flags: c_int,
        value: &itimerspec,
        ovalue: Option<Out<itimerspec>>,
    ) -> Result<()>;

    // Always successful
    /// Implements umask.
    fn umask(mask: mode_t) -> mode_t;

    /// Implements uname.
    fn uname(utsname: Out<utsname>) -> Result<()>;

    /// Implements unlink.
    fn unlink(path: CStr) -> Result<()>;

    /// Implements waitpid.
    fn waitpid(pid: pid_t, stat_loc: Option<Out<c_int>>, options: c_int) -> Result<pid_t>;

    /// Implements write.
    fn write(fildes: c_int, buf: &[u8]) -> Result<usize>;
    /// Implements pwrite.
    fn pwrite(fildes: c_int, buf: &[u8], offset: off_t) -> Result<usize>;

    /// Implements verify.
    fn verify() -> bool;
}
