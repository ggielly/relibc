use core::{
    mem,
    ptr::{self, addr_of},
};

use super::{
    super::{
        PalSignal,
        types::{c_int, pid_t},
    },
    Sys, e_raw,
};
use crate::{
    error::{Errno, Result},
    header::{
        bits_time::timespec,
        signal::{SA_RESTORER, SI_QUEUE, sigaction, siginfo_t, sigset_t, sigval, stack_t},
        sys_time::itimerval,
    },
};

impl PalSignal for Sys {
    /// Returns getitimer.
    fn getitimer(which: c_int, out: &mut itimerval) -> Result<()> {
        unsafe {
            e_raw(syscall!(GETITIMER, which, ptr::from_mut(out)))?;
        }
        Ok(())
    }

    /// Implements kill.
    fn kill(pid: pid_t, sig: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(KILL, pid, sig) })?;
        Ok(())
    }
    /// Implements sigqueue.
    fn sigqueue(pid: pid_t, sig: c_int, val: sigval) -> Result<()> {
        let info = siginfo_t {
            si_addr: core::ptr::null_mut(),
            si_code: SI_QUEUE,
            si_errno: 0,
            si_pid: 0, // TODO: GETPID?
            si_signo: sig,
            si_status: 0,
            si_uid: 0, // TODO: GETUID?
            si_value: val,
        };
        e_raw(unsafe { syscall!(RT_SIGQUEUEINFO, pid, sig, addr_of!(info)) }).map(|_| ())
    }

    /// Implements killpg.
    fn killpg(pgrp: pid_t, sig: c_int) -> Result<()> {
        e_raw(unsafe { syscall!(KILL, -(pgrp as isize) as pid_t, sig) })?;
        Ok(())
    }

    /// Implements raise.
    fn raise(sig: c_int) -> Result<()> {
        let tid = e_raw(unsafe { syscall!(GETTID) })? as pid_t;
        e_raw(unsafe { syscall!(TKILL, tid, sig) })?;
        Ok(())
    }

    /// Sets setitimer.
    fn setitimer(which: c_int, new: &itimerval, old: Option<&mut itimerval>) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                SETITIMER,
                which,
                ptr::from_ref(new),
                old.map_or_else(ptr::null_mut, ptr::from_mut)
            )
        })?;
        Ok(())
    }

    /// Implements sigaction.
    fn sigaction(
        sig: c_int,
        act: Option<&sigaction>,
        oact: Option<&mut sigaction>,
    ) -> Result<(), Errno> {
        unsafe extern "C" {
            /// Implements restore rt.
            fn __restore_rt();
        }
        let act = act.map(|act| {
            let mut act_clone = act.clone();
            act_clone.sa_flags |= SA_RESTORER as c_int;
            act_clone.sa_restorer = Some(__restore_rt);
            act_clone
        });
        e_raw(unsafe {
            syscall!(
                RT_SIGACTION,
                sig,
                act.as_ref().map_or_else(ptr::null, ptr::from_ref),
                oact.map_or_else(ptr::null_mut, ptr::from_mut),
                mem::size_of::<sigset_t>()
            )
        })
        .map(|_| ())
    }

    /// Implements sigaltstack.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn sigaltstack(ss: Option<&stack_t>, old_ss: Option<&mut stack_t>) -> Result<()> {
        e_raw(syscall!(
            SIGALTSTACK,
            ss.map_or_else(ptr::null, ptr::from_ref),
            old_ss.map_or_else(ptr::null_mut, ptr::from_mut)
        ))
        .map(|_| ())
    }

    /// Implements sigpending.
    fn sigpending(set: &mut sigset_t) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                RT_SIGPENDING,
                ptr::from_mut::<sigset_t>(set) as usize,
                mem::size_of::<sigset_t>()
            )
        })
        .map(|_| ())
    }

    /// Implements sigprocmask.
    fn sigprocmask(how: c_int, set: Option<&sigset_t>, oset: Option<&mut sigset_t>) -> Result<()> {
        e_raw(unsafe {
            syscall!(
                RT_SIGPROCMASK,
                how,
                set.map_or_else(ptr::null, ptr::from_ref),
                oset.map_or_else(ptr::null_mut, ptr::from_mut),
                mem::size_of::<sigset_t>()
            )
        })
        .map(|_| ())
    }

    /// Implements sigsuspend.
    fn sigsuspend(mask: &sigset_t) -> Errno {
        unsafe {
            e_raw(syscall!(
                RT_SIGSUSPEND,
                ptr::from_ref::<sigset_t>(mask),
                size_of::<sigset_t>()
            ))
            .expect_err("must fail")
        }
    }

    /// Implements sigtimedwait.
    fn sigtimedwait(
        set: &sigset_t,
        sig: Option<&mut siginfo_t>,
        tp: Option<&timespec>,
    ) -> Result<c_int> {
        unsafe {
            e_raw(syscall!(
                RT_SIGTIMEDWAIT,
                ptr::from_ref(set),
                sig.map_or_else(ptr::null_mut, ptr::from_mut),
                tp.map_or_else(ptr::null, ptr::from_ref),
                size_of::<sigset_t>()
            ))
            .map(|s| s as c_int)
        }
    }
}
