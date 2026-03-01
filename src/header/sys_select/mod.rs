//! `sys/select.h` implementation.
//!
//! See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/sys_select.h.html>.

#[cfg(target_os = "strat9")]
use alloc::vec::Vec;
use core::mem;

use cbitset::BitSet;

use crate::{
    fs::File,
    header::{
        errno,
        sys_epoll::{
            EPOLL_CLOEXEC, EPOLL_CTL_ADD, EPOLLERR, EPOLLIN, EPOLLOUT, epoll_create1, epoll_ctl,
            epoll_data, epoll_event, epoll_wait,
        },
    },
    platform::{
        self,
        types::{c_int, suseconds_t, time_t},
    },
};
#[cfg(target_os = "strat9")]
use crate::header::poll::{POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI, nfds_t, poll, pollfd};

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/sys_select.h.html>.
///
#[repr(C)]
#[derive(Default)]
pub struct timeval {
    pub tv_sec: time_t,
    pub tv_usec: suseconds_t,
}

// fd_set is also defined in C because cbindgen is incompatible with mem::size_of booo

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/sys_select.h.html>.
pub const FD_SETSIZE: usize = 1024;
type bitset = BitSet<[u64; FD_SETSIZE / (8 * mem::size_of::<u64>())]>;

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/sys_select.h.html>.
#[repr(C)]
pub struct fd_set {
    pub fds_bits: bitset,
}

pub fn select_epoll(
    nfds: c_int,
    readfds: Option<&mut fd_set>,
    writefds: Option<&mut fd_set>,
    exceptfds: Option<&mut fd_set>,
    timeout: Option<&mut timeval>,
) -> c_int {
    if nfds < 0 || nfds > FD_SETSIZE as i32 {
        platform::ERRNO.set(errno::EINVAL);
        return -1;
    };

    let ep = {
        let epfd = epoll_create1(EPOLL_CLOEXEC);
        if epfd < 0 {
            return -1;
        }
        File::new(epfd)
    };

    let mut read_bitset: Option<&mut bitset> = readfds.map(|fd_set| &mut fd_set.fds_bits);
    let mut write_bitset: Option<&mut bitset> = writefds.map(|fd_set| &mut fd_set.fds_bits);
    let mut except_bitset: Option<&mut bitset> = exceptfds.map(|fd_set| &mut fd_set.fds_bits);

    // Keep track of the number of file descriptors that do not support epoll
    let mut not_epoll = 0;
    for fd in 0..nfds {
        let mut events = 0;

        if let Some(ref fd_set) = read_bitset {
            if fd_set.contains(fd as usize) {
                events |= EPOLLIN;
            }
        }

        if let Some(ref fd_set) = write_bitset {
            if fd_set.contains(fd as usize) {
                events |= EPOLLOUT;
            }
        }

        if let Some(ref fd_set) = except_bitset {
            if fd_set.contains(fd as usize) {
                events |= EPOLLERR;
            }
        }

        if events > 0 {
            let mut event = epoll_event {
                events,
                data: epoll_data { fd },
                ..Default::default()
            };
            if unsafe { epoll_ctl(*ep, EPOLL_CTL_ADD, fd, &mut event) } < 0 {
                if platform::ERRNO.get() == errno::EPERM {
                    not_epoll += 1;
                } else {
                    return -1;
                }
            } else {
                if let Some(ref mut fd_set) = read_bitset {
                    if fd_set.contains(fd as usize) {
                        fd_set.remove(fd as usize);
                    }
                }

                if let Some(ref mut fd_set) = write_bitset {
                    if fd_set.contains(fd as usize) {
                        fd_set.remove(fd as usize);
                    }
                }

                if let Some(ref mut fd_set) = except_bitset {
                    if fd_set.contains(fd as usize) {
                        fd_set.remove(fd as usize);
                    }
                }
            }
        }
    }

    let mut events: [epoll_event; 32] = unsafe { mem::zeroed() };
    let epoll_timeout = if not_epoll > 0 {
        // Do not wait if any non-epoll file descriptors were found
        0
    } else {
        match timeout {
            Some(timeout) => {
                //TODO: Check for overflow
                ((timeout.tv_sec as c_int) * 1000) + ((timeout.tv_usec as c_int) / 1000)
            }
            None => -1,
        }
    };
    let res = unsafe {
        epoll_wait(
            *ep,
            events.as_mut_ptr(),
            events.len() as c_int,
            epoll_timeout,
        )
    };
    if res < 0 {
        return -1;
    }

    let mut count = not_epoll;
    for event in events.iter().take(res as usize) {
        let fd = unsafe { event.data.fd };
        // TODO: Error status when fd does not match?
        if fd >= 0 && fd < FD_SETSIZE as c_int {
            if event.events & EPOLLIN > 0 {
                if let Some(ref mut fd_set) = read_bitset {
                    fd_set.insert(fd as usize);
                    count += 1;
                }
            }
            if event.events & EPOLLOUT > 0 {
                if let Some(ref mut fd_set) = write_bitset {
                    fd_set.insert(fd as usize);
                    count += 1;
                }
            }
            if event.events & EPOLLERR > 0 {
                if let Some(ref mut fd_set) = except_bitset {
                    fd_set.insert(fd as usize);
                    count += 1;
                }
            }
        }
    }
    count
}

#[cfg(target_os = "strat9")]
fn select_poll(
    nfds: c_int,
    mut readfds: Option<&mut fd_set>,
    mut writefds: Option<&mut fd_set>,
    mut exceptfds: Option<&mut fd_set>,
    timeout: Option<&mut timeval>,
) -> c_int {
    if nfds < 0 || nfds > FD_SETSIZE as i32 {
        platform::ERRNO.set(errno::EINVAL);
        return -1;
    }

    let timeout_ms = if let Some(tmo) = timeout {
        if tmo.tv_sec > (c_int::MAX / 1000) as _ {
            c_int::MAX
        } else {
            ((tmo.tv_sec as c_int) * 1000) + ((tmo.tv_usec as c_int) / 1000)
        }
    } else {
        -1
    };

    let mut fds: Vec<pollfd> = Vec::new();
    for fd in 0..nfds {
        let mut events: i16 = 0;
        if let Some(set) = readfds.as_ref() {
            if set.fds_bits.contains(fd as usize) {
                events |= POLLIN;
            }
        }
        if let Some(set) = writefds.as_ref() {
            if set.fds_bits.contains(fd as usize) {
                events |= POLLOUT;
            }
        }
        if let Some(set) = exceptfds.as_ref() {
            if set.fds_bits.contains(fd as usize) {
                events |= POLLPRI;
            }
        }
        if events != 0 {
            fds.push(pollfd {
                fd,
                events,
                revents: 0,
            });
        }
    }

    let res = unsafe { poll(fds.as_mut_ptr(), fds.len() as nfds_t, timeout_ms) };
    if res < 0 {
        return -1;
    }

    if let Some(set) = readfds.as_mut() {
        for fd in 0..nfds {
            set.fds_bits.remove(fd as usize);
        }
    }
    if let Some(set) = writefds.as_mut() {
        for fd in 0..nfds {
            set.fds_bits.remove(fd as usize);
        }
    }
    if let Some(set) = exceptfds.as_mut() {
        for fd in 0..nfds {
            set.fds_bits.remove(fd as usize);
        }
    }

    let mut count = 0;
    for pfd in fds.iter() {
        if (pfd.revents & POLLNVAL) != 0 {
            platform::ERRNO.set(errno::EBADF);
            return -1;
        }

        let mut ready = false;
        if (pfd.revents & (POLLIN | POLLHUP)) != 0 {
            if let Some(set) = readfds.as_mut() {
                set.fds_bits.insert(pfd.fd as usize);
            }
            ready = true;
        }
        if (pfd.revents & POLLOUT) != 0 {
            if let Some(set) = writefds.as_mut() {
                set.fds_bits.insert(pfd.fd as usize);
            }
            ready = true;
        }
        if (pfd.revents & (POLLPRI | POLLERR)) != 0 {
            if let Some(set) = exceptfds.as_mut() {
                set.fds_bits.insert(pfd.fd as usize);
            }
            ready = true;
        }

        if ready {
            count += 1;
        }
    }

    count
}

/// See <https://pubs.opengroup.org/onlinepubs/9799919799/functions/pselect.html>.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    nfds: c_int,
    readfds: *mut fd_set,
    writefds: *mut fd_set,
    exceptfds: *mut fd_set,
    timeout: *mut timeval,
) -> c_int {
    trace_expr!(
        {
            #[cfg(target_os = "strat9")]
            {
                select_poll(
                    nfds,
                    if readfds.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *readfds })
                    },
                    if writefds.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *writefds })
                    },
                    if exceptfds.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *exceptfds })
                    },
                    if timeout.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *timeout })
                    }
                )
            }
            #[cfg(not(target_os = "strat9"))]
            {
                select_epoll(
                    nfds,
                    if readfds.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *readfds })
                    },
                    if writefds.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *writefds })
                    },
                    if exceptfds.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *exceptfds })
                    },
                    if timeout.is_null() {
                        None
                    } else {
                        Some(unsafe { &mut *timeout })
                    }
                )
            }
        },
        "select({}, {:p}, {:p}, {:p}, {:p})",
        nfds,
        readfds,
        writefds,
        exceptfds,
        timeout
    )
}
