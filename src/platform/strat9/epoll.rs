use super::super::{PalEpoll, types::*};
use crate::{
    error::Result,
    header::{signal::sigset_t, sys_epoll::epoll_event},
};
use crate::strat9_syscall;
// TODO: Real epoll requires kernel-side fd interest tracking.
// Current impl is a minimal stub: create1 allocates a pipe fd,
// ctl is a no-op, and pwait sleeps for the timeout duration.

impl PalEpoll for super::Sys {
    /// Create an epoll handle (currently backed by a pipe fd stub).
    fn epoll_create1(_flags: c_int) -> Result<c_int> {
        let mut fds = [0i32; 2];
        super::e_raw(strat9_syscall!(super::SYS_PIPE, fds.as_mut_ptr() as u64))?;
        unsafe { super::syscall1(super::SYS_CLOSE, fds[1] as usize); }
        Ok(fds[0])
    }

    /// Update epoll interest set (stubbed to no-op on Strat9).
    unsafe fn epoll_ctl(
        _epfd: c_int,
        _op: c_int,
        _fd: c_int,
        _event: *mut epoll_event,
    ) -> Result<()> {
        // TODO: Track fd interest set in kernel
        Ok(())
    }

    /// Wait for epoll events (currently timeout-based stub).
    unsafe fn epoll_pwait(
        _epfd: c_int,
        _events: *mut epoll_event,
        _maxevents: c_int,
        timeout: c_int,
        _sigmask: *const sigset_t,
    ) -> Result<usize> {
        // TODO: Poll registered fds via kernel SYS_POLL
        if timeout == 0 {
            return Ok(0);
        }
        let wait_ms = if timeout < 0 { 100 } else { timeout };
        let ts = crate::header::bits_time::timespec {
            tv_sec: (wait_ms / 1000) as i64,
            tv_nsec: ((wait_ms % 1000) as i64) * 1_000_000,
        };
        super::e(unsafe { super::syscall2(super::SYS_NANOSLEEP, &ts as *const _ as usize, 0) })?;
        Ok(0)
    }
}
