//! Epoll implementation for Strat9-OS.
//!
//! This module implements the PalEpoll trait for Strat9-OS.
//! Epoll is not natively supported in the Strat9 microkernel,
//! so these functions return ENOSYS.
//!
//! In the future, epoll could be emulated via IPC to a select/poll service.

use super::super::{Pal, PalEpoll, types::*};
use crate::{
    error::Result,
    header::{signal::sigset_t, sys_epoll::epoll_event},
};

impl PalEpoll for super::Sys {
    fn epoll_create1(_flags: c_int) -> Result<c_int> {
        // Strat9 doesn't have native epoll support
        // TODO: Could be implemented via IPC to an event service
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn epoll_ctl(
        _epfd: c_int,
        _op: c_int,
        _fd: c_int,
        _event: *mut epoll_event,
    ) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn epoll_pwait(
        _epfd: c_int,
        _events: *mut epoll_event,
        _maxevents: c_int,
        _timeout: c_int,
        _sigmask: *const sigset_t,
    ) -> Result<usize> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }
}
