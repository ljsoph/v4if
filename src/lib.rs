#[cfg(target_family = "windows")]
pub use winders::*;

#[cfg(target_family = "unix")]
pub use linux::*;

#[cfg(target_family = "unix")]
pub mod linux {
    use libc::{AF_INET, IFF_LOOPBACK, IFF_LOWER_UP, getifaddrs, ifaddrs, sockaddr_in};
    use std::{ffi::CStr, io, net::Ipv4Addr};

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

        /// Returns `true` if the address is link-local (169.254.0.0)
        pub fn is_link_local(&self) -> bool {
            self.ip.is_link_local()
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
}

#[cfg(target_family = "windows")]
pub mod winders {
    use std::io;
    use std::net::Ipv4Addr;

    use windows::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
    use windows::Win32::Foundation::ERROR_SUCCESS;
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_ANYCAST;
    use windows::Win32::NetworkManagement::IpHelper::GAA_FLAG_SKIP_DNS_SERVER;
    use windows::Win32::NetworkManagement::IpHelper::GetAdaptersAddresses;
    use windows::Win32::NetworkManagement::IpHelper::IF_TYPE_SOFTWARE_LOOPBACK;
    use windows::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH;
    use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
    use windows::Win32::Networking::WinSock::AF_INET;
    use windows::Win32::Networking::WinSock::SOCKADDR_IN;

    #[derive(Clone, Debug, Eq, PartialEq)]
    pub struct Ipv4Interface {
        pub name: String,
        pub ip: Ipv4Addr,
        pub if_type: u32,
        pub oper_status: i32,
    }

    impl Ipv4Interface {
        /// Returns `true` if this is a loopback address (127.0.0.0)
        pub fn is_loopback(&self) -> bool {
            self.if_type == IF_TYPE_SOFTWARE_LOOPBACK
        }

        /// Returns `true` if the Interface is up and able to pass packets
        pub fn is_up(&self) -> bool {
            self.oper_status == IfOperStatusUp.0
        }

        /// Returns `true` if the address is link-local (169.254.0.0)
        pub fn is_link_local(&self) -> bool {
            self.ip.is_link_local()
        }
    }

    /// Collect all IPv4 network interfaces that are considered up.
    pub fn interfaces() -> Result<Vec<Ipv4Interface>, io::Error> {
        unsafe {
            // We don't know what the actual size requirement is, so we start with the recommended 15kb
            // buffer and if we overflow on the first attempt `buffer_size` will be populated
            // with the correct size and we can call `GetAdaptersAddress` again.
            let mut buffer_size = 15000u32;
            let family = AF_INET.0 as u32;
            let mut buffer;
            let mut ifaddrs;

            loop {
                buffer = vec![0u8; buffer_size as usize];
                ifaddrs = buffer.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH;

                let res = GetAdaptersAddresses(
                    family,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_DNS_SERVER,
                    None,
                    Some(ifaddrs),
                    &mut buffer_size,
                );
                dbg!(family, ifaddrs, buffer_size, res);

                match WIN32_ERROR(res) {
                    ERROR_SUCCESS => break,
                    ERROR_BUFFER_OVERFLOW => continue,
                    _ => {
                        return Err(io::Error::last_os_error());
                    }
                }
            }

            let addrs = collect(ifaddrs);
            Ok(addrs.into_iter().filter_map(to_interface).collect())
        }
    }

    fn collect(mut addrs_ptr: *mut IP_ADAPTER_ADDRESSES_LH) -> Vec<IP_ADAPTER_ADDRESSES_LH> {
        let mut addrs = Vec::new();
        while let Some(addr) = unsafe { addrs_ptr.as_ref() } {
            addrs.push(*addr);
            addrs_ptr = addr.Next;
        }

        addrs
    }

    fn to_interface(addr: IP_ADAPTER_ADDRESSES_LH) -> Option<Ipv4Interface> {
        unsafe {
            let name = addr.FriendlyName.to_string().ok()?;
            let if_type = addr.IfType;
            let oper_status = addr.OperStatus.0;
            let unicast_addr = addr.FirstUnicastAddress.as_ref()?;
            let sockaddr_in = unicast_addr
                .Address
                .lpSockaddr
                .cast::<SOCKADDR_IN>()
                .as_ref()?;
            let ip = Ipv4Addr::from_bits(u32::from_be(sockaddr_in.sin_addr.S_un.S_addr));

            Some(Ipv4Interface {
                name,
                ip,
                if_type,
                oper_status,
            })
        }
    }
}
