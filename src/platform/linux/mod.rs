#[cfg(target_arch = "x86_64")]
use core::arch::asm;

use super::{Pal, types::*};
use crate::{
    c_str::CStr,
    header::{
        dirent::dirent,
        errno::{EINVAL, EIO},
        fcntl::{AT_EMPTY_PATH, AT_FDCWD, AT_REMOVEDIR},
        signal::{SIGCHLD, sigevent},
        sys_resource::{rlimit, rusage},
        sys_select::timeval,
        sys_stat::{S_IFIFO, stat},
        sys_statvfs::statvfs,
        sys_time::timezone,
        time::itimerspec,
        unistd::{SEEK_CUR, SEEK_SET},
    },
    ld_so::tcb::OsSpecific,
    out::Out,
};
use core::{num::NonZeroU64, ptr};
// use header::sys_times::tms;
use crate::{
    error::{Errno, Result},
    header::{bits_time::timespec, sys_utsname::utsname},
};

mod epoll;
mod ptrace;
mod signal;
mod socket;

const SYS_CLONE: usize = 56;
const CLONE_VM: usize = 0x0100;
const CLONE_FS: usize = 0x0200;
const CLONE_FILES: usize = 0x0400;
const CLONE_SIGHAND: usize = 0x0800;
const CLONE_THREAD: usize = 0x00010000;

#[repr(C)]
#[derive(Default)]
struct linux_statfs {
    f_type: c_long,       /* type of file system (see below) */
    f_bsize: c_long,      /* optimal transfer block size */
    f_blocks: fsblkcnt_t, /* total data blocks in file system */
    f_bfree: fsblkcnt_t,  /* free blocks in fs */
    f_bavail: fsblkcnt_t, /* free blocks available to unprivileged user */
    f_files: fsfilcnt_t,  /* total file nodes in file system */
    f_ffree: fsfilcnt_t,  /* free file nodes in fs */
    f_fsid: c_long,       /* file system id */
    f_namelen: c_long,    /* maximum length of filenames */
    f_frsize: c_long,     /* fragment size (since Linux 2.6) */
    f_flags: c_long,
    f_spare: [c_long; 4],
}

// TODO
const ERRNO_MAX: usize = 4095;

/// Implements e raw.
pub fn e_raw(sys: usize) -> Result<usize> {
    if sys > ERRNO_MAX.wrapping_neg() {
        Err(Errno(sys.wrapping_neg() as _))
    } else {
        Ok(sys)
    }
}

/// Linux syscall implementation of the platform abstraction layer.
pub struct Sys;

impl Sys {
    /// Implements ioctl.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    pub unsafe fn ioctl(fd: c_int, request: c_ulong, out: *mut c_void) -> Result<c_int> {
        // TODO: Somehow support varargs to syscall??
        Ok(e_raw(syscall!(IOCTL, fd, request, out))? as c_int)
    }

    // fn times(out: *mut tms) -> clock_t {
    //     unsafe { syscall!(TIMES, out) as clock_t }
    // }
}

impl Pal for Sys {
    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    /// Implements access.
    fn access(path: CStr, mode: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(ACCESS, path.as_ptr(), mode) }).map(|_| ())
    }

    #[cfg(target_arch = "aarch64")]
    /// Implements access.
    fn access(path: CStr, mode: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(FACCESSAT, AT_FDCWD, path.as_ptr(), mode, 0) }).map(|_| ())
    }

    /// Implements brk.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn brk(addr: *mut c_void) -> Result<*mut c_void> {
        Ok(e_raw(unsafe { syscall!(BRK, addr) })? as *mut c_void)
    }

    /// Implements chdir.
    fn chdir(path: CStr) -> Result<()> {
        e_raw(unsafe { syscall!(CHDIR, path.as_ptr()) }).map(|_| ())
    }

    /// Implements chmod.
    fn chmod(path: CStr, mode: mode_t) -> Result<()> {
        e_raw(unsafe { syscall!(FCHMODAT, AT_FDCWD, path.as_ptr(), mode, 0) }).map(|_| ())
    }

    /// Implements chown.
    fn chown(path: CStr, owner: uid_t, group: gid_t) -> Result<()> {
        let flags: c_int = 0;
        e_raw(unsafe {
            syscall!(
                FCHOWNAT,
                AT_FDCWD,
                path.as_ptr(),
                owner as u32,
                group as u32,
                flags
            )
        })
        .map(|_| ())
    }

    /// Implements clock getres.
    fn clock_getres(clk_id: clockid_t, res: Option<Out<timespec>>) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                CLOCK_GETRES,
                clk_id,
                res.map_or(core::ptr::null_mut(), |mut p| p.as_mut_ptr())
            )
        })
        .map(|_| ())
    }

    /// Implements clock gettime.
    fn clock_gettime(clk_id: clockid_t, mut tp: Out<timespec>) -> Result<()> {
        e_raw(unsafe { syscall!(CLOCK_GETTIME, clk_id, tp.as_mut_ptr()) }).map(|_| ())
    }

    /// Implements clock settime.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn clock_settime(clk_id: clockid_t, tp: *const timespec) -> Result<()> {
        e_raw(syscall!(CLOCK_SETTIME, clk_id, tp)).map(|_| ())
    }

    /// Implements close.
    fn close(fildes: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(CLOSE, fildes) }).map(|_| ())
    }

    /// Implements dup.
    fn dup(fildes: c_int) -> Result<c_int> {
        e_raw(unsafe { syscall!(DUP, fildes) }).map(|f| f as c_int)
    }

    /// Implements dup2.
    fn dup2(fildes: c_int, fildes2: c_int) -> Result<c_int> {
        e_raw(unsafe { syscall!(DUP3, fildes, fildes2, 0) }).map(|f| f as c_int)
    }

    /// Implements execve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn execve(path: CStr, argv: *const *mut c_char, envp: *const *mut c_char) -> Result<()> {
        e_raw(syscall!(EXECVE, path.as_ptr(), argv, envp))?;
        unreachable!()
    }
    /// Implements fexecve.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fexecve(
        fildes: c_int,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> Result<()> {
        let empty = b"\0";
        let empty_ptr = empty.as_ptr().cast::<c_char>();
        e_raw(syscall!(
            EXECVEAT,
            fildes,
            empty_ptr,
            argv,
            envp,
            AT_EMPTY_PATH
        ))?;
        unreachable!()
    }

    /// Implements exit.
    fn exit(status: c_int) -> ! {
        unsafe {
            syscall!(EXIT, status);
        }
        loop {}
    }
    /// Implements exit thread.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn exit_thread(_stack_base: *mut (), _stack_size: usize) -> ! {
        // TODO
        Self::exit(0)
    }

    /// Implements fchdir.
    fn fchdir(fildes: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(FCHDIR, fildes) }).map(|_| ())
    }

    /// Implements fchmod.
    fn fchmod(fildes: c_int, mode: mode_t) -> Result<()> {
        e_raw(unsafe { syscall!(FCHMOD, fildes, mode) }).map(|_| ())
    }

    /// Implements fchmodat.
    fn fchmodat(dirfd: c_int, path: Option<CStr>, mode: mode_t, flags: c_int) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                FCHMODAT,
                dirfd,
                path.map_or(core::ptr::null(), |p| p.as_ptr()),
                mode,
                flags
            )
        })
        .map(|_| ())
    }

    /// Implements fchown.
    fn fchown(fildes: c_int, owner: uid_t, group: gid_t) -> Result<()> {
        e_raw(unsafe { syscall!(FCHOWN, fildes, owner, group) }).map(|_| ())
    }

    /// Implements fdatasync.
    fn fdatasync(fildes: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(FDATASYNC, fildes) }).map(|_| ())
    }

    /// Implements flock.
    fn flock(fd: c_int, operation: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(FLOCK, fd, operation) }).map(|_| ())
    }

    /// Implements fstat.
    fn fstat(fildes: c_int, mut buf: Out<stat>) -> Result<()> {
        let empty = b"\0";
        let empty_ptr = empty.as_ptr().cast::<c_char>();
        e_raw(unsafe {
            syscall!(
                NEWFSTATAT,
                fildes,
                empty_ptr,
                buf.as_mut_ptr(),
                AT_EMPTY_PATH
            )
        })
        .map(|_| ())
    }

    /// Implements fstatat.
    fn fstatat(fildes: c_int, path: Option<CStr>, mut buf: Out<stat>, flags: c_int) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                NEWFSTATAT,
                fildes,
                path.map_or(core::ptr::null(), |s| s.as_ptr()),
                buf.as_mut_ptr(),
                flags
            )
        })
        .map(|_| ())
    }

    /// Implements fstatvfs.
    fn fstatvfs(fildes: c_int, mut buf: Out<statvfs>) -> Result<()> {
        let buf = buf.as_mut_ptr();

        let mut kbuf = linux_statfs::default();
        let kbuf_ptr = &raw mut kbuf;
        e_raw(unsafe { syscall!(FSTATFS, fildes, kbuf_ptr) })?;

        if !buf.is_null() {
            unsafe {
                (*buf).f_bsize = kbuf.f_bsize as c_ulong;
                (*buf).f_frsize = if kbuf.f_frsize != 0 {
                    kbuf.f_frsize
                } else {
                    kbuf.f_bsize
                } as c_ulong;
                (*buf).f_blocks = kbuf.f_blocks;
                (*buf).f_bfree = kbuf.f_bfree;
                (*buf).f_bavail = kbuf.f_bavail;
                (*buf).f_files = kbuf.f_files;
                (*buf).f_ffree = kbuf.f_ffree;
                (*buf).f_favail = kbuf.f_ffree;
                (*buf).f_fsid = kbuf.f_fsid as c_ulong;
                (*buf).f_flag = kbuf.f_flags as c_ulong;
                (*buf).f_namemax = kbuf.f_namelen as c_ulong;
            }
        }
        Ok(())
    }

    /// Implements fcntl.
    fn fcntl(fildes: c_int, cmd: c_int, arg: c_ulonglong) -> Result<c_int> {
        Ok(e_raw(unsafe { syscall!(FCNTL, fildes, cmd, arg) })? as c_int)
    }

    /// Implements fork.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn fork() -> Result<pid_t> {
        Ok(e_raw(unsafe { syscall!(CLONE, SIGCHLD, 0, 0, 0, 0) })? as pid_t)
    }

    /// Implements fpath.
    fn fpath(fildes: c_int, out: &mut [u8]) -> Result<usize> {
        let proc_path = format!("/proc/self/fd/{}\0", fildes).into_bytes();
        Self::readlink(CStr::from_bytes_with_nul(&proc_path).unwrap(), out)
    }

    /// Implements fsync.
    fn fsync(fildes: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(FSYNC, fildes) }).map(|_| ())
    }

    /// Implements ftruncate.
    fn ftruncate(fildes: c_int, length: off_t) -> Result<()> {
        e_raw(unsafe { syscall!(FTRUNCATE, fildes, length) }).map(|_| ())
    }

    #[inline]
    /// Implements futex wait.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wait(addr: *mut u32, val: u32, deadline: Option<&timespec>) -> Result<()> {
        let deadline = deadline.map_or(0, |d| ptr::from_ref(d) as usize);
        e_raw(unsafe {
            syscall!(
                FUTEX, addr,       // uaddr
                9,          // futex_op: FUTEX_WAIT_BITSET
                val,        // val
                deadline,   // timeout: deadline
                0,          // uaddr2/val2: 0/NULL
                0xffffffff  // val3: FUTEX_BITSET_MATCH_ANY
            )
        })
        .map(|_| ())
    }
    #[inline]
    /// Implements futex wake.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futex_wake(addr: *mut u32, num: u32) -> Result<u32> {
        e_raw(unsafe {
            syscall!(FUTEX, addr, 1 /* FUTEX_WAKE */, num)
        })
        .map(|n| n as u32)
    }

    /// Implements futimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn futimens(fd: c_int, times: *const timespec) -> Result<()> {
        e_raw(unsafe { syscall!(UTIMENSAT, fd, ptr::null::<c_char>(), times, 0) }).map(|_| ())
    }

    /// Implements utimens.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn utimens(path: CStr, times: *const timespec) -> Result<()> {
        e_raw(unsafe { syscall!(UTIMENSAT, AT_FDCWD, path.as_ptr(), times, 0) }).map(|_| ())
    }

    /// Returns getcwd.
    fn getcwd(mut buf: Out<[u8]>) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                GETCWD,
                buf.as_mut_ptr().as_mut_ptr(),
                buf.as_mut_ptr().len()
            )
        })?;
        Ok(())
    }

    /// Returns getdents.
    fn getdents(fd: c_int, buf: &mut [u8], _off: u64) -> Result<usize> {
        e_raw(unsafe { syscall!(GETDENTS64, fd, buf.as_mut_ptr(), buf.len()) })
    }
    /// Implements dir seek.
    fn dir_seek(fd: c_int, off: u64) -> Result<()> {
        e_raw(unsafe { syscall!(LSEEK, fd, off, SEEK_SET) })?;
        Ok(())
    }
    /// Implements dent reclen offset.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn dent_reclen_offset(this_dent: &[u8], offset: usize) -> Option<(u16, u64)> {
        let dent = this_dent.as_ptr().cast::<dirent>();
        Some((unsafe { (*dent).d_reclen }, unsafe { (*dent).d_off } as u64))
    }

    /// Returns getegid.
    fn getegid() -> gid_t {
        // Always successful
        unsafe { syscall!(GETEGID) as gid_t }
    }

    /// Returns geteuid.
    fn geteuid() -> uid_t {
        // Always successful
        unsafe { syscall!(GETEUID) as uid_t }
    }

    /// Returns getgid.
    fn getgid() -> gid_t {
        // Always successful
        unsafe { syscall!(GETGID) as gid_t }
    }

    /// Returns getgroups.
    fn getgroups(mut list: Out<[gid_t]>) -> Result<c_int> {
        Ok(e_raw(unsafe {
            syscall!(
                GETGROUPS,
                list.len() as c_int,
                list.as_mut_ptr().as_mut_ptr()
            )
        })? as c_int)
    }

    /// Returns getpagesize.
    fn getpagesize() -> usize {
        4096
    }

    /// Returns getpgid.
    fn getpgid(pid: pid_t) -> Result<pid_t> {
        Ok(e_raw(unsafe { syscall!(GETPGID, pid) })? as pid_t)
    }

    /// Returns getpid.
    fn getpid() -> pid_t {
        // Always successful
        unsafe { syscall!(GETPID) as pid_t }
    }

    /// Returns getppid.
    fn getppid() -> pid_t {
        // Always successful
        unsafe { syscall!(GETPPID) as pid_t }
    }

    /// Returns getpriority.
    fn getpriority(which: c_int, who: id_t) -> Result<c_int> {
        Ok(e_raw(unsafe { syscall!(GETPRIORITY, which, who) })? as c_int)
    }

    /// Returns getrandom.
    fn getrandom(buf: &mut [u8], flags: c_uint) -> Result<usize> {
        e_raw(unsafe { syscall!(GETRANDOM, buf.as_mut_ptr(), buf.len(), flags) })
    }

    /// Returns getrlimit.
    fn getrlimit(resource: c_int, mut rlim: Out<rlimit>) -> Result<()> {
        e_raw(unsafe { syscall!(GETRLIMIT, resource, rlim.as_mut_ptr()) }).map(|_| ())
    }

    /// Returns getresgid.
    fn getresgid(
        rgid: Option<Out<gid_t>>,
        egid: Option<Out<gid_t>>,
        sgid: Option<Out<gid_t>>,
    ) -> Result<()> {
        unsafe {
            e_raw(syscall!(
                GETRESGID,
                rgid.map_or(0, |mut r| r.as_mut_ptr() as usize),
                egid.map_or(0, |mut r| r.as_mut_ptr() as usize),
                sgid.map_or(0, |mut r| r.as_mut_ptr() as usize)
            ))
            .map(|_| ())
        }
    }
    /// Returns getresuid.
    fn getresuid(
        ruid: Option<Out<uid_t>>,
        euid: Option<Out<uid_t>>,
        suid: Option<Out<uid_t>>,
    ) -> Result<()> {
        unsafe {
            e_raw(syscall!(
                GETRESUID,
                ruid.map_or(0, |mut r| r.as_mut_ptr() as usize),
                euid.map_or(0, |mut r| r.as_mut_ptr() as usize),
                suid.map_or(0, |mut r| r.as_mut_ptr() as usize)
            ))
            .map(|_| ())
        }
    }

    /// Sets setrlimit.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setrlimit(resource: c_int, rlimit: *const rlimit) -> Result<()> {
        e_raw(syscall!(SETRLIMIT, resource, rlimit)).map(|_| ())
    }

    /// Returns getrusage.
    fn getrusage(who: c_int, mut r_usage: Out<rusage>) -> Result<()> {
        e_raw(unsafe { syscall!(GETRUSAGE, who, r_usage.as_mut_ptr()) })?;
        Ok(())
    }

    /// Returns getsid.
    fn getsid(pid: pid_t) -> Result<pid_t> {
        Ok(e_raw(unsafe { syscall!(GETSID, pid) })? as pid_t)
    }

    /// Returns gettid.
    fn gettid() -> pid_t {
        // Always successful
        unsafe { syscall!(GETTID) as pid_t }
    }

    /// Returns gettimeofday.
    fn gettimeofday(mut tp: Out<timeval>, tzp: Option<Out<timezone>>) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                GETTIMEOFDAY,
                tp.as_mut_ptr(),
                tzp.map_or(0, |mut p| p.as_mut_ptr() as usize)
            )
        })
        .map(|_| ())
    }

    /// Returns getuid.
    fn getuid() -> uid_t {
        unsafe { syscall!(GETUID) as uid_t }
    }

    #[cfg(any(target_arch = "x86_64", target_arch = "x86"))]
    /// Implements lchown.
    fn lchown(path: CStr, owner: uid_t, group: gid_t) -> Result<()> {
        e_raw(unsafe { syscall!(LCHOWN, path.as_ptr(), owner, group) }).map(|_| ())
    }

    #[cfg(target_arch = "aarch64")]
    /// Implements lchown.
    fn lchown(path: CStr, owner: uid_t, group: gid_t) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                FCHOWNAT,
                AT_FDCWD,
                path.as_ptr(),
                owner as u32,
                group as u32,
                crate::header::fcntl::AT_SYMLINK_NOFOLLOW
            )
        })
        .map(|_| ())
    }

    /// Implements link.
    fn link(path1: CStr, path2: CStr) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                LINKAT,
                AT_FDCWD,
                path1.as_ptr(),
                AT_FDCWD,
                path2.as_ptr(),
                0
            )
        })
        .map(|_| ())
    }

    /// Implements lseek.
    fn lseek(fildes: c_int, offset: off_t, whence: c_int) -> Result<off_t> {
        e_raw(unsafe { syscall!(LSEEK, fildes, offset, whence) }).map(|o| o as off_t)
    }

    /// Implements mkdirat.
    fn mkdirat(dir_fildes: c_int, path: CStr, mode: mode_t) -> Result<()> {
        e_raw(unsafe { syscall!(MKDIRAT, dir_fildes, path.as_ptr(), mode) }).map(|_| ())
    }

    /// Implements mkdir.
    fn mkdir(path: CStr, mode: mode_t) -> Result<()> {
        Sys::mkdirat(AT_FDCWD, path, mode)
    }

    /// Implements mknodat.
    fn mknodat(dir_fildes: c_int, path: CStr, mode: mode_t, dev: dev_t) -> Result<()> {
        // Note: dev_t is c_long (i64) and __kernel_dev_t is u32; So we need to cast it
        //       and check for overflow
        let k_dev: c_uint = dev as c_uint;
        if dev_t::from(k_dev) != dev {
            return Err(Errno(EINVAL));
        }

        e_raw(unsafe { syscall!(MKNODAT, dir_fildes, path.as_ptr(), mode, k_dev) }).map(|_| ())
    }

    /// Implements mknod.
    fn mknod(path: CStr, mode: mode_t, dev: dev_t) -> Result<()> {
        Sys::mknodat(AT_FDCWD, path, mode, dev)
    }

    /// Implements mkfifoat.
    fn mkfifoat(dir_fd: c_int, path: CStr, mode: mode_t) -> Result<()> {
        Sys::mknodat(dir_fd, path, mode | S_IFIFO, 0)
    }

    /// Implements mkfifo.
    fn mkfifo(path: CStr, mode: mode_t) -> Result<()> {
        Sys::mknod(path, mode | S_IFIFO, 0)
    }

    /// Implements mlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlock(addr: *const c_void, len: usize) -> Result<()> {
        e_raw(unsafe { syscall!(MLOCK, addr, len) }).map(|_| ())
    }

    /// Implements mlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mlockall(flags: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(MLOCKALL, flags) }).map(|_| ())
    }

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
        Ok(e_raw(syscall!(MMAP, addr, len, prot, flags, fildes, off))? as *mut c_void)
    }

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
    ) -> Result<*mut c_void> {
        Ok(e_raw(syscall!(MREMAP, addr, len, new_len, flags, args))? as *mut c_void)
    }

    /// Implements mprotect.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn mprotect(addr: *mut c_void, len: usize, prot: c_int) -> Result<()> {
        e_raw(syscall!(MPROTECT, addr, len, prot)).map(|_| ())
    }

    /// Implements msync.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn msync(addr: *mut c_void, len: usize, flags: c_int) -> Result<()> {
        e_raw(syscall!(MSYNC, addr, len, flags)).map(|_| ())
    }

    /// Implements munlock.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlock(addr: *const c_void, len: usize) -> Result<()> {
        e_raw(syscall!(MUNLOCK, addr, len)).map(|_| ())
    }

    /// Implements munlockall.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munlockall() -> Result<()> {
        e_raw(unsafe { syscall!(MUNLOCKALL) }).map(|_| ())
    }

    /// Implements munmap.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn munmap(addr: *mut c_void, len: usize) -> Result<()> {
        e_raw(syscall!(MUNMAP, addr, len)).map(|_| ())
    }

    /// Implements madvise.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn madvise(addr: *mut c_void, len: usize, flags: c_int) -> Result<()> {
        e_raw(syscall!(MADVISE, addr, len, flags)).map(|_| ())
    }

    /// Implements nanosleep.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn nanosleep(rqtp: *const timespec, rmtp: *mut timespec) -> Result<()> {
        e_raw(unsafe { syscall!(NANOSLEEP, rqtp, rmtp) }).map(|_| ())
    }

    /// Implements open.
    fn open(path: CStr, oflag: c_int, mode: mode_t) -> Result<c_int> {
        e_raw(unsafe { syscall!(OPENAT, AT_FDCWD, path.as_ptr(), oflag, mode) })
            .map(|fd| fd as c_int)
    }

    /// Implements openat.
    fn openat(dirfd: c_int, path: CStr, oflag: c_int, mode: mode_t) -> Result<c_int> {
        e_raw(unsafe { syscall!(OPENAT, dirfd, path.as_ptr(), oflag, mode) }).map(|fd| fd as c_int)
    }

    /// Implements pipe2.
    fn pipe2(mut fildes: Out<[c_int; 2]>, flags: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(PIPE2, fildes.as_mut_ptr(), flags) }).map(|_| ())
    }

    /// Implements posix fallocate.
    fn posix_fallocate(fd: c_int, offset: u64, length: NonZeroU64) -> Result<()> {
        let length = length.get();
        e_raw(unsafe { syscall!(FALLOCATE, fd, 0, offset, length) }).map(|_| ())
    }

    /// Implements posix getdents.
    fn posix_getdents(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        let current_offset = Self::lseek(fildes, 0, SEEK_CUR)? as u64;
        let bytes_read = Self::getdents(fildes, buf, current_offset)?;
        if bytes_read == 0 {
            return Ok(0);
        }
        let mut bytes_processed = 0;
        let mut next_offset = current_offset;

        while bytes_processed < bytes_read {
            let remaining_slice = &buf[bytes_processed..];
            let (reclen, opaque_next) =
                unsafe { Self::dent_reclen_offset(remaining_slice, bytes_processed) }
                    .ok_or(Errno(EIO))?;
            if reclen == 0 {
                return Err(Errno(EIO));
            }

            bytes_processed += reclen as usize;
            next_offset = opaque_next;
        }

        Self::lseek(fildes, next_offset as off_t, SEEK_SET)?;
        Ok(bytes_read)
    }

    #[cfg(target_arch = "x86_64")]
    /// Implements rlct clone.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_clone(
        stack: *mut usize,
        _os_specific: &mut OsSpecific,
    ) -> Result<crate::pthread::OsTid> {
        let flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD;
        let pid;
        unsafe {
            asm!("
                # Call clone syscall
                syscall

                # Check if child or parent
                test rax, rax
                jnz 2f

                # Load registers
                pop rax
                pop rdi
                pop rsi
                pop rdx
                pop rcx
                pop r8
                pop r9

                # Call entry point
                call rax

                # Exit
                mov rax, 60
                xor rdi, rdi
                syscall

                # Invalid instruction on failure to exit
                ud2

                # Return PID if parent
                2:
                ",
                inout("rax") SYS_CLONE => pid,
                inout("rdi") flags => _,
                inout("rsi") stack => _,
                inout("rdx") 0 => _,
                inout("r10") 0 => _,
                inout("r8") 0 => _,
                //TODO: out("rbx") _,
                out("rcx") _,
                out("r9") _,
                out("r11") _,
                out("r12") _,
                out("r13") _,
                out("r14") _,
                out("r15") _,
            );
        }
        let tid = e_raw(pid)?;

        Ok(crate::pthread::OsTid { thread_id: tid })
    }

    #[cfg(target_arch = "aarch64")]
    /// Implements rlct clone.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_clone(
        stack: *mut usize,
        _os_specific: &mut OsSpecific,
    ) -> Result<crate::pthread::OsTid> {
        todo!("rlct_clone not implemented for aarch64 yet")
    }

    /// Implements rlct kill.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn rlct_kill(os_tid: crate::pthread::OsTid, signal: usize) -> Result<()> {
        let tgid = Self::getpid();
        e_raw(unsafe { syscall!(TGKILL, tgid, os_tid.thread_id, signal) }).map(|_| ())
    }

    /// Implements current os tid.
    fn current_os_tid() -> crate::pthread::OsTid {
        crate::pthread::OsTid {
            thread_id: unsafe { syscall!(GETTID) },
        }
    }

    /// Implements read.
    fn read(fildes: c_int, buf: &mut [u8]) -> Result<usize> {
        e_raw(unsafe { syscall!(READ, fildes, buf.as_mut_ptr(), buf.len()) })
    }
    /// Implements pread.
    fn pread(fildes: c_int, buf: &mut [u8], off: off_t) -> Result<usize> {
        e_raw(unsafe { syscall!(PREAD64, fildes, buf.as_mut_ptr(), buf.len(), off) })
    }

    /// Implements readlink.
    fn readlink(pathname: CStr, out: &mut [u8]) -> Result<usize> {
        e_raw(unsafe {
            syscall!(
                READLINKAT,
                AT_FDCWD,
                pathname.as_ptr(),
                out.as_mut_ptr(),
                out.len()
            )
        })
    }

    /// Implements readlinkat.
    fn readlinkat(dirfd: c_int, pathname: CStr, out: &mut [u8]) -> Result<usize> {
        e_raw(unsafe {
            syscall!(
                READLINKAT,
                dirfd,
                pathname.as_ptr(),
                out.as_mut_ptr(),
                out.len()
            )
        })
    }

    /// Implements rename.
    fn rename(old: CStr, new: CStr) -> Result<()> {
        e_raw(unsafe { syscall!(RENAMEAT, AT_FDCWD, old.as_ptr(), AT_FDCWD, new.as_ptr()) })
            .map(|_| ())
    }

    /// Implements renameat.
    fn renameat(old_dir: c_int, old_path: CStr, new_dir: c_int, new_path: CStr) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                RENAMEAT,
                old_dir,
                old_path.as_ptr(),
                new_dir,
                new_path.as_ptr()
            )
        })
        .map(|_| ())
    }

    /// Implements renameat2.
    fn renameat2(
        old_dir: c_int,
        old_path: CStr,
        new_dir: c_int,
        new_path: CStr,
        flags: c_uint,
    ) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                RENAMEAT2,
                old_dir,
                old_path.as_ptr(),
                new_dir,
                new_path.as_ptr(),
                flags
            )
        })
        .map(|_| ())
    }

    /// Implements rmdir.
    fn rmdir(path: CStr) -> Result<()> {
        e_raw(unsafe { syscall!(UNLINKAT, AT_FDCWD, path.as_ptr(), AT_REMOVEDIR) }).map(|_| ())
    }

    /// Implements sched yield.
    fn sched_yield() -> Result<()> {
        e_raw(unsafe { syscall!(SCHED_YIELD) }).map(|_| ())
    }

    /// Sets setgroups.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setgroups(size: size_t, list: *const gid_t) -> Result<()> {
        e_raw(unsafe { syscall!(SETGROUPS, size, list) }).map(|_| ())
    }

    /// Sets setpgid.
    fn setpgid(pid: pid_t, pgid: pid_t) -> Result<()> {
        e_raw(unsafe { syscall!(SETPGID, pid, pgid) }).map(|_| ())
    }

    /// Sets setpriority.
    fn setpriority(which: c_int, who: id_t, prio: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(SETPRIORITY, which, who, prio) }).map(|_| ())
    }

    /// Sets setresgid.
    fn setresgid(rgid: gid_t, egid: gid_t, sgid: gid_t) -> Result<()> {
        e_raw(unsafe { syscall!(SETRESGID, rgid, egid, sgid) }).map(|_| ())
    }

    /// Sets setresuid.
    fn setresuid(ruid: uid_t, euid: uid_t, suid: uid_t) -> Result<()> {
        e_raw(unsafe { syscall!(SETRESUID, ruid, euid, suid) }).map(|_| ())
    }

    /// Sets setsid.
    fn setsid() -> Result<c_int> {
        e_raw(unsafe { syscall!(SETSID) }).map(|s| s as c_int)
    }

    /// Implements symlink.
    fn symlink(path1: CStr, path2: CStr) -> Result<()> {
        e_raw(unsafe { syscall!(SYMLINKAT, path1.as_ptr(), AT_FDCWD, path2.as_ptr()) }).map(|_| ())
    }

    /// Implements sync.
    fn sync() -> Result<()> {
        e_raw(unsafe { syscall!(SYNC) }).map(|_| ())
    }

    /// Implements timer create.
    fn timer_create(clock_id: clockid_t, evp: &sigevent, mut timerid: Out<timer_t>) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                TIMER_CREATE,
                clock_id,
                ptr::addr_of!(evp),
                timerid.as_mut_ptr()
            )
        })
        .map(|_| ())
    }

    /// Implements timer delete.
    fn timer_delete(timerid: timer_t) -> Result<()> {
        e_raw(unsafe { syscall!(TIMER_DELETE, timerid) }).map(|_| ())
    }

    /// Implements timer gettime.
    fn timer_gettime(timerid: timer_t, mut value: Out<itimerspec>) -> Result<()> {
        e_raw(unsafe { syscall!(TIMER_GETTIME, timerid, value.as_mut_ptr()) }).map(|_| ())
    }

    /// Implements timer settime.
    fn timer_settime(
        timerid: timer_t,
        flags: c_int,
        value: &itimerspec,
        ovalue: Option<Out<itimerspec>>,
    ) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                TIMER_SETTIME,
                timerid,
                flags,
                ptr::addr_of!(value),
                match ovalue {
                    None => ptr::null_mut(),
                    Some(mut o) => o.as_mut_ptr(),
                }
            )
        })
        .map(|_| ())
    }

    /// Implements umask.
    fn umask(mask: mode_t) -> mode_t {
        unsafe { syscall!(UMASK, mask) as mode_t }
    }

    /// Implements uname.
    fn uname(mut utsname: Out<utsname>) -> Result<()> {
        e_raw(unsafe { syscall!(UNAME, utsname.as_mut_ptr(), 0) }).map(|_| ())
    }

    /// Implements unlink.
    fn unlink(path: CStr) -> Result<()> {
        e_raw(unsafe { syscall!(UNLINKAT, AT_FDCWD, path.as_ptr(), 0) }).map(|_| ())
    }

    /// Implements waitpid.
    fn waitpid(pid: pid_t, stat_loc: Option<Out<c_int>>, options: c_int) -> Result<pid_t> {
        e_raw(unsafe {
            syscall!(
                WAIT4,
                pid,
                stat_loc.map_or(core::ptr::null_mut(), |mut o| o.as_mut_ptr()),
                options,
                0
            )
        })
        .map(|p| p as pid_t)
    }

    /// Implements write.
    fn write(fildes: c_int, buf: &[u8]) -> Result<usize> {
        e_raw(unsafe { syscall!(WRITE, fildes, buf.as_ptr(), buf.len()) })
    }
    /// Implements pwrite.
    fn pwrite(fildes: c_int, buf: &[u8], off: off_t) -> Result<usize> {
        e_raw(unsafe { syscall!(PWRITE64, fildes, buf.as_ptr(), buf.len(), off) })
    }

    /// Implements verify.
    fn verify() -> bool {
        // GETPID on Linux is 39, which does not exist on Redox
        e_raw(unsafe { sc::syscall5(sc::nr::GETPID, !0, !0, !0, !0, !0) }).is_ok()
    }
}
