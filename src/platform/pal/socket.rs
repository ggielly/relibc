use crate::{
    error::Result,
    header::sys_socket::{msghdr, sockaddr, socklen_t},
    platform::{Pal, types::*},
};

pub trait PalSocket: Pal {
    /// Implements accept.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn accept(
        socket: c_int,
        address: *mut sockaddr,
        address_len: *mut socklen_t,
    ) -> Result<c_int>;

    /// Implements bind.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn bind(socket: c_int, address: *const sockaddr, address_len: socklen_t) -> Result<()>;

    /// Implements connect.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn connect(
        socket: c_int,
        address: *const sockaddr,
        address_len: socklen_t,
    ) -> Result<c_int>;

    /// Returns getpeername.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn getpeername(
        socket: c_int,
        address: *mut sockaddr,
        address_len: *mut socklen_t,
    ) -> Result<()>;

    /// Returns getsockname.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn getsockname(
        socket: c_int,
        address: *mut sockaddr,
        address_len: *mut socklen_t,
    ) -> Result<()>;

    /// Returns getsockopt.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn getsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *mut c_void,
        option_len: *mut socklen_t,
    ) -> Result<()>;

    /// Implements listen.
    fn listen(socket: c_int, backlog: c_int) -> Result<()>;

    /// Implements recvfrom.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn recvfrom(
        socket: c_int,
        buf: *mut c_void,
        len: size_t,
        flags: c_int,
        address: *mut sockaddr,
        address_len: *mut socklen_t,
    ) -> Result<usize>;

    /// Implements recvmsg.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn recvmsg(socket: c_int, msg: *mut msghdr, flags: c_int) -> Result<usize>;

    /// Implements sendmsg.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn sendmsg(socket: c_int, msg: *const msghdr, flags: c_int) -> Result<usize>;

    /// Implements sendto.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn sendto(
        socket: c_int,
        buf: *const c_void,
        len: size_t,
        flags: c_int,
        dest_addr: *const sockaddr,
        dest_len: socklen_t,
    ) -> Result<usize>;

    /// Sets setsockopt.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn setsockopt(
        socket: c_int,
        level: c_int,
        option_name: c_int,
        option_value: *const c_void,
        option_len: socklen_t,
    ) -> Result<()>;

    /// Implements shutdown.
    fn shutdown(socket: c_int, how: c_int) -> Result<()>;

    /// Implements socket.
    ///
    /// # Safety
    /// The caller must uphold the required pointer and ABI invariants.
    unsafe fn socket(domain: c_int, kind: c_int, protocol: c_int) -> Result<c_int>;

    /// Implements socketpair.
    fn socketpair(domain: c_int, kind: c_int, protocol: c_int, sv: &mut [c_int; 2]) -> Result<()>;
}
