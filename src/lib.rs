use std::{ffi::CStr, io, net::Ipv4Addr};

use libc::{AF_INET, IFF_LOOPBACK, IFF_LOWER_UP, getifaddrs, ifaddrs, sockaddr_in};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ipv4Interface {
    pub name: String,
    pub ip: Ipv4Addr,
    pub flags: u32,
}

impl Ipv4Interface {
    /// Returns `true` if this is a loopback address (127.0.0.0)
    pub fn is_loopback(&self) -> bool {
        self.flags & IFF_LOOPBACK as u32 != 0
    }

    /// Returns `true` if the Interface is operational and has detected acquisition of carrier.
    pub fn is_lower_up(&self) -> bool {
        self.flags & IFF_LOWER_UP as u32 != 0
    }
}

/// Collect all IPv4 network interfaces that are considered up.
pub fn interfaces() -> Result<Vec<Ipv4Interface>, io::Error> {
    let mut ifaddrs = std::ptr::null_mut();
    let ret = unsafe { getifaddrs(&raw mut ifaddrs) };
    if ret == -1 {
        return Err(io::Error::last_os_error());
    }

    let addrs = collect(ifaddrs);
    Ok(addrs.into_iter().filter_map(to_interface).collect())
}

fn collect(mut ifaddrs: *mut ifaddrs) -> Vec<ifaddrs> {
    let mut addrs = Vec::new();

    while let Some(addr) = unsafe { ifaddrs.as_ref() } {
        addrs.push(*addr);
        ifaddrs = addr.ifa_next;
    }
    addrs
}

fn to_interface(addr: ifaddrs) -> Option<Ipv4Interface> {
    let sockaddr = unsafe { addr.ifa_addr.as_ref()? };
    if i32::from(sockaddr.sa_family) != AF_INET {
        return None;
    }

    let flags = addr.ifa_flags;
    let name = unsafe { CStr::from_ptr(addr.ifa_name) };
    let sockaddir_in = unsafe { addr.ifa_addr.cast::<sockaddr_in>().as_ref()? };
    let ip = Ipv4Addr::from_bits(u32::from_be(sockaddir_in.sin_addr.s_addr));

    Some(Ipv4Interface {
        name: name.to_string_lossy().to_string(),
        ip,
        flags,
    })
}
