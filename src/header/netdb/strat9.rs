use crate::{
    error::Errno,
    fs::File,
    header::{errno, fcntl},
    io::{BufRead, BufReader},
};
use alloc::string::String;

pub fn get_dns_server() -> Result<String, Errno> {
    // In Strat9-OS, DNS configuration might be handled differently
    // For now, we'll use a similar approach to Linux but this could be
    // adapted to use Strat9-OS-specific mechanisms later
    let file = File::open(c"/etc/resolv.conf".into(), fcntl::O_RDONLY).map(BufReader::new)?;

    for line in file.lines().map_while(Result::ok) {
        if let Some(dns) = line.strip_prefix("nameserver ") {
            return Ok(dns.into());
        }
    }

    Err(Errno(errno::EIO).sync())
}