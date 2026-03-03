use super::super::{Pal, types::*};
use crate::{
    error::{Errno, Result},
    header::{
        bits_time::timespec,
        signal::{sigaction, siginfo_t, sigset_t, sigval, stack_t},
        sys_time::itimerval,
    },
};

pub trait PalSignal: Pal {
    /// Returns getitimer.
    fn getitimer(which: c_int, out: &mut itimerval) -> Result<()>;

    /// Implements kill.
    fn kill(pid: pid_t, sig: c_int) -> Result<()>;

    /// Implements sigqueue.
    fn sigqueue(pid: pid_t, sig: c_int, val: sigval) -> Result<()>;

    /// Implements killpg.
    fn killpg(pgrp: pid_t, sig: c_int) -> Result<()>;

    /// Implements raise.
    fn raise(sig: c_int) -> Result<()>;

    /// Sets setitimer.
    fn setitimer(which: c_int, new: &itimerval, old: Option<&mut itimerval>) -> Result<()>;

    /// Implements sigaction.
    fn sigaction(sig: c_int, act: Option<&sigaction>, oact: Option<&mut sigaction>) -> Result<()>;

    /// Implements sigaltstack.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn sigaltstack(ss: Option<&stack_t>, old_ss: Option<&mut stack_t>) -> Result<()>;

    /// Implements sigpending.
    fn sigpending(set: &mut sigset_t) -> Result<()>;

    /// Implements sigprocmask.
    fn sigprocmask(how: c_int, set: Option<&sigset_t>, oset: Option<&mut sigset_t>) -> Result<()>;

    /// Implements sigsuspend.
    fn sigsuspend(mask: &sigset_t) -> Errno; // always fails

    /// Implements sigtimedwait.
    fn sigtimedwait(
        set: &sigset_t,
        sig: Option<&mut siginfo_t>,
        tp: Option<&timespec>,
    ) -> Result<c_int>;
}
