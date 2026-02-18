//! Signal handling implementation for Strat9-OS.
//!
//! This module implements the PalSignal trait for Strat9-OS.
//! Some functions are stubs that return ENOSYS until the kernel
//! implements the corresponding syscalls.

use super::super::{Pal, PalSignal, types::*};
use super::Sys;
use crate::header::{
    bits_time::timespec,
    errno::ENOSYS,
    signal::{sigaction, siginfo_t, sigset_t, sigval, stack_t},
    sys_time::itimerval,
};
use super::{e_raw, SYS_KILL, SYS_SIGPROCMASK};
use crate::strat9_syscall as syscall;

impl PalSignal for Sys {
    fn getitimer(_which: c_int, _out: &mut itimerval) -> Result<()> {
        // TODO: Implement when kernel supports interval timers
        Err(Errno(ENOSYS))
    }

    fn kill(pid: pid_t, sig: c_int) -> Result<()> {
        // Uses SYS_KILL (320) from the kernel
        e_raw(unsafe { syscall!(SYS_KILL, pid as u64, sig as u64) })?;
        Ok(())
    }

    fn sigqueue(_pid: pid_t, _sig: c_int, _val: sigval) -> Result<()> {
        // TODO: Implement when kernel supports sigqueue
        Err(Errno(ENOSYS))
    }

    fn killpg(_pgrp: pid_t, _sig: c_int) -> Result<()> {
        // TODO: Implement kill process group
        Err(Errno(ENOSYS))
    }

    fn raise(_sig: c_int) -> Result<()> {
        // TODO: Implement raise (kill with current PID)
        Err(Errno(ENOSYS))
    }

    fn setitimer(_which: c_int, _new: &itimerval, _old: Option<&mut itimerval>) -> Result<()> {
        // TODO: Implement when kernel supports interval timers
        Err(Errno(ENOSYS))
    }

    fn sigaction(
        _sig: c_int,
        _act: Option<&sigaction>,
        _oact: Option<&mut sigaction>,
    ) -> Result<()> {
        // TODO: Implement when kernel supports signal handlers
        Err(Errno(ENOSYS))
    }

    unsafe fn sigaltstack(_ss: Option<&stack_t>, _old_ss: Option<&mut stack_t>) -> Result<()> {
        // TODO: Implement signal alternate stack
        Err(Errno(ENOSYS))
    }

    fn sigpending(_set: &mut sigset_t) -> Result<()> {
        // TODO: Implement pending signals query
        Err(Errno(ENOSYS))
    }

    fn sigprocmask(
        how: c_int,
        set: Option<&sigset_t>,
        oset: Option<&mut sigset_t>,
    ) -> Result<()> {
        // Uses SYS_SIGPROCMASK (321) from the kernel
        // how: 0=BLOCK, 1=UNBLOCK, 2=SETMASK
        let set_ptr = set.map_or(0u64, |s| s as *const _ as u64);
        let oset_ptr = oset.map_or(0u64, |o| o as *mut _ as u64);

        e_raw(unsafe { syscall!(SYS_SIGPROCMASK, how as u64, set_ptr, oset_ptr) })?;
        Ok(())
    }

    fn sigsuspend(_mask: &sigset_t) -> Errno {
        // TODO: Implement sigsuspend - always fails as per spec
        // This should wait for a signal
        Errno(ENOSYS)
    }

    fn sigtimedwait(
        _set: &sigset_t,
        _sig: Option<&mut siginfo_t>,
        _tp: Option<&timespec>,
    ) -> Result<c_int> {
        // TODO: Implement timed signal wait
        Err(Errno(ENOSYS))
    }
}
