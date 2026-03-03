//! Signal handling implementation for Strat9-OS.
//!
//! This module implements the PalSignal trait for Strat9-OS.
//! Some functions are stubs that return ENOSYS until the kernel
//! implements the corresponding syscalls.

use super::super::{PalSignal, types::*};
use super::Sys;
use crate::error::{Errno, Result};
use crate::header::{
    bits_time::timespec,
    signal::{sigaction, siginfo_t, sigset_t, sigval, stack_t},
    sys_time::itimerval,
};
use super::e_raw;
use crate::strat9_syscall as syscall;

impl PalSignal for Sys {
    /// Read the current value of an interval timer.
    fn getitimer(which: c_int, out: &mut itimerval) -> Result<()> {
        e_raw(syscall!(super::SYS_GETITIMER, which as u64, out as *mut _ as u64))?;
        Ok(())
    }

    /// Send a signal to a specific process.
    fn kill(pid: pid_t, sig: c_int) -> Result<()> {
        e_raw(syscall!(super::SYS_KILL, pid as u64, sig as u64))?;
        Ok(())
    }

    /// Queue a signal with an application-defined value.
    fn sigqueue(pid: pid_t, sig: c_int, val: sigval) -> Result<()> {
        e_raw(syscall!(super::SYS_SIGQUEUE, pid as u64, sig as u64, val.sival_ptr as u64))?;
        Ok(())
    }

    /// Send a signal to all members of a process group.
    fn killpg(pgrp: pid_t, sig: c_int) -> Result<()> {
        e_raw(syscall!(super::SYS_KILLPG, pgrp as u64, sig as u64))?;
        Ok(())
    }

    /// Send a signal to the current process.
    fn raise(sig: c_int) -> Result<()> {
        let pid = syscall!(super::SYS_GETPID) as pid_t;
        Self::kill(pid, sig)
    }

    /// Set an interval timer and optionally fetch the previous value.
    fn setitimer(which: c_int, new: &itimerval, old: Option<&mut itimerval>) -> Result<()> {
        let old_ptr = old.map_or(0u64, |o| o as *mut _ as u64);
        e_raw(syscall!(super::SYS_SETITIMER, which as u64, new as *const _ as u64, old_ptr))?;
        Ok(())
    }

    /// Install or query a signal handler action.
    fn sigaction(
        sig: c_int,
        act: Option<&sigaction>,
        oact: Option<&mut sigaction>,
    ) -> Result<()> {
        let act_ptr = act.map_or(0u64, |a| a as *const _ as u64);
        let oact_ptr = oact.map_or(0u64, |o| o as *mut _ as u64);
        e_raw(syscall!(super::SYS_SIGACTION, sig as u64, act_ptr, oact_ptr))?;
        Ok(())
    }

    /// Configure an alternate signal stack.
    unsafe fn sigaltstack(ss: Option<&stack_t>, old_ss: Option<&mut stack_t>) -> Result<()> {
        let ss_ptr = ss.map_or(0u64, |s| s as *const _ as u64);
        let old_ptr = old_ss.map_or(0u64, |o| o as *mut _ as u64);
        e_raw(syscall!(super::SYS_SIGALTSTACK, ss_ptr, old_ptr))?;
        Ok(())
    }

    /// Return the set of pending signals.
    fn sigpending(set: &mut sigset_t) -> Result<()> {
        e_raw(syscall!(super::SYS_SIGPENDING, set as *mut _ as u64))?;
        Ok(())
    }

    /// Examine and/or update the calling thread signal mask.
    fn sigprocmask(
        how: c_int,
        set: Option<&sigset_t>,
        oset: Option<&mut sigset_t>,
    ) -> Result<()> {
        let set_ptr = set.map_or(0u64, |s| s as *const _ as u64);
        let oset_ptr = oset.map_or(0u64, |o| o as *mut _ as u64);
        e_raw(syscall!(super::SYS_SIGPROCMASK, how as u64, set_ptr, oset_ptr))?;
        Ok(())
    }

    /// Replace mask and suspend execution until signal delivery.
    fn sigsuspend(mask: &sigset_t) -> Errno {
        let ret = syscall!(super::SYS_SIGSUSPEND, mask as *const _ as u64);
        match e_raw(ret) {
            Ok(_) => Errno(crate::header::errno::EINTR),
            Err(e) => e,
        }
    }

    /// Wait for a signal in a set with an optional timeout.
    fn sigtimedwait(
        set: &sigset_t,
        sig: Option<&mut siginfo_t>,
        tp: Option<&timespec>,
    ) -> Result<c_int> {
        let sig_ptr = sig.map_or(0u64, |s| s as *mut _ as u64);
        let tp_ptr = tp.map_or(0u64, |t| t as *const _ as u64);
        e_raw(syscall!(super::SYS_SIGTIMEDWAIT, set as *const _ as u64, sig_ptr, tp_ptr))
            .map(|r| r as c_int)
    }
}
