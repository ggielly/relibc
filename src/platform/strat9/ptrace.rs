//! Ptrace implementation for Strat9-OS.
//!
//! This module implements the PalPtrace trait for Strat9-OS.
//! Ptrace is not natively supported in the Strat9 microkernel,
//! so this function returns ENOSYS.
//!
//! In the future, ptrace could be implemented via IPC to a debug service.

use super::super::{Pal, PalPtrace, types::*};
use crate::error::Result;

impl PalPtrace for super::Sys {
    unsafe fn ptrace(
        _request: c_int,
        _pid: pid_t,
        _addr: *mut c_void,
        _data: *mut c_void,
    ) -> Result<c_int> {
        // Strat9 doesn't have native ptrace support
        // TODO: Could be implemented via IPC to a debug service
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }
}
