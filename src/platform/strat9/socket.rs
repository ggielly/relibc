//! Socket implementation for Strat9-OS.
//!
//! This module implements the PalSocket trait for Strat9-OS.
//! Sockets are not natively supported in the Strat9 microkernel,
//! so these functions return ENOSYS.
//!
//! In the future, sockets will be implemented via IPC to the net-stack component.

use super::super::{Pal, PalSocket, types::*};
use crate::{
    error::Result,
    header::sys_socket::{msghdr, sockaddr, socklen_t},
};

impl PalSocket for super::Sys {
    unsafe fn accept(
        _socket: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<c_int> {
        // Strat9 doesn't have native socket support
        // TODO: Implement via IPC to net-stack component
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn bind(
        _socket: c_int,
        _address: *const sockaddr,
        _address_len: socklen_t,
    ) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn connect(
        _socket: c_int,
        _address: *const sockaddr,
        _address_len: socklen_t,
    ) -> Result<c_int> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn getpeername(
        _socket: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn getsockname(
        _socket: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn getsockopt(
        _socket: c_int,
        _level: c_int,
        _option_name: c_int,
        _option_value: *mut c_void,
        _option_len: *mut socklen_t,
    ) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    fn listen(_socket: c_int, _backlog: c_int) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn recvfrom(
        _socket: c_int,
        _buf: *mut c_void,
        _len: size_t,
        _flags: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<usize> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn recvmsg(_socket: c_int, _msg: *mut msghdr, _flags: c_int) -> Result<usize> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn sendmsg(_socket: c_int, _msg: *const msghdr, _flags: c_int) -> Result<usize> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn sendto(
        _socket: c_int,
        _buf: *const c_void,
        _len: size_t,
        _flags: c_int,
        _dest_addr: *const sockaddr,
        _dest_len: socklen_t,
    ) -> Result<usize> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn setsockopt(
        _socket: c_int,
        _level: c_int,
        _option_name: c_int,
        _option_value: *const c_void,
        _option_len: socklen_t,
    ) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    fn shutdown(_socket: c_int, _how: c_int) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    unsafe fn socket(_domain: c_int, _kind: c_int, _protocol: c_int) -> Result<c_int> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }

    fn socketpair(
        _domain: c_int,
        _kind: c_int,
        _protocol: c_int,
        _sv: &mut [c_int; 2],
    ) -> Result<()> {
        Err(crate::error::Errno(crate::header::errno::ENOSYS))
    }
}
