use super::super::{PalSocket, types::*};
use crate::{
    error::{Errno, Result},
    header::sys_socket::{msghdr, sockaddr, socklen_t},
};
use crate::strat9_syscall;
const ENOSYS: c_int = 38;
const EAFNOSUPPORT: c_int = 97;
const AF_UNIX: c_int = 1;

// TODO: Full BSD socket API requires kernel socket syscalls or
// a /net/ scheme-based approach. Only socketpair(AF_UNIX) works
// (backed by kernel pipes). recvfrom/sendto delegate to read/write.

impl PalSocket for super::Sys {
    // TODO: Requires kernel accept() or IPC to net-stack
    /// Accept a pending connection on a listening socket.
    unsafe fn accept(
        _socket: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<c_int> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel bind() or IPC to net-stack
    /// Bind a socket to a local address.
    unsafe fn bind(
        _socket: c_int,
        _address: *const sockaddr,
        _address_len: socklen_t,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel connect() or IPC to net-stack
    /// Connect a socket to a remote address.
    unsafe fn connect(
        _socket: c_int,
        _address: *const sockaddr,
        _address_len: socklen_t,
    ) -> Result<c_int> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel socket metadata
    /// Get the peer address of a connected socket.
    unsafe fn getpeername(
        _socket: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel socket metadata
    /// Get the local address of a socket.
    unsafe fn getsockname(
        _socket: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel socket options tracking
    /// Read a socket option value.
    unsafe fn getsockopt(
        _socket: c_int,
        _level: c_int,
        _option_name: c_int,
        _option_value: *mut c_void,
        _option_len: *mut socklen_t,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel listen queue
    /// Mark a socket as passive for incoming connections.
    fn listen(_socket: c_int, _backlog: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    /// Receive bytes from a socket into a contiguous buffer.
    unsafe fn recvfrom(
        socket: c_int,
        buf: *mut c_void,
        len: size_t,
        _flags: c_int,
        _address: *mut sockaddr,
        _address_len: *mut socklen_t,
    ) -> Result<usize> {
        super::e(unsafe { super::syscall3(super::SYS_READ, socket as usize, buf as usize, len) })
    }

    // TODO: Requires scatter-gather I/O support
    /// Receive a message using scatter-gather buffers.
    unsafe fn recvmsg(_socket: c_int, _msg: *mut msghdr, _flags: c_int) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires scatter-gather I/O support
    /// Send a message using scatter-gather buffers.
    unsafe fn sendmsg(_socket: c_int, _msg: *const msghdr, _flags: c_int) -> Result<usize> {
        Err(Errno(ENOSYS))
    }

    /// Send bytes from a contiguous buffer to a socket.
    unsafe fn sendto(
        socket: c_int,
        buf: *const c_void,
        len: size_t,
        _flags: c_int,
        _dest_addr: *const sockaddr,
        _dest_len: socklen_t,
    ) -> Result<usize> {
        super::e(unsafe { super::syscall3(super::SYS_WRITE, socket as usize, buf as usize, len) })
    }

    // TODO: Requires kernel socket option tracking
    /// Set a socket option value.
    unsafe fn setsockopt(
        _socket: c_int,
        _level: c_int,
        _option_name: c_int,
        _option_value: *const c_void,
        _option_len: socklen_t,
    ) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel half-close support on pipes
    /// Shut down part or all of a full-duplex connection.
    fn shutdown(_socket: c_int, _how: c_int) -> Result<()> {
        Err(Errno(ENOSYS))
    }

    // TODO: Requires kernel socket() or /net/ scheme
    /// Create a socket endpoint.
    unsafe fn socket(_domain: c_int, _kind: c_int, _protocol: c_int) -> Result<c_int> {
        Err(Errno(ENOSYS))
    }

    // TODO: This creates a unidirectional pipe, not a true bidirectional
    // socketpair. sv[0] is read-only, sv[1] is write-only. Full socketpair
    // semantics require a kernel bidirectional channel primitive.
    /// Create a pair of connected local sockets.
    fn socketpair(
        domain: c_int,
        _kind: c_int,
        _protocol: c_int,
        sv: &mut [c_int; 2],
    ) -> Result<()> {
        if domain != AF_UNIX {
            return Err(Errno(EAFNOSUPPORT));
        }
        super::e_raw(strat9_syscall!(super::SYS_PIPE, sv.as_mut_ptr() as u64))?;
        Ok(())
    }
}
