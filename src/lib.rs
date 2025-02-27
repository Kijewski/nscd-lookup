// SPDX-FileCopyrightText: 2025 René Kijewski <crates.io@k6i.de>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

use std::ffi::CStr;
use std::io::{Error, ErrorKind, IoSlice, Read, Result, Write};
use std::iter::FusedIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::unix::net::UnixStream;

use bytemuck::checked::try_cast_slice;
use bytemuck::{CheckedBitPattern, Pod, Zeroable, bytes_of, bytes_of_mut};

/// Look up an [`IpAddr`] using [nscd].
///
/// `buf` is a re-usable buffer that may grow to up to 8192 bytes.
/// The returned iterator captures a reference to the buffer.
///
/// [nscd]: https://man7.org/linux/man-pages/man8/nscd.8.html
#[inline]
pub fn lookup(host: impl AsRef<[u8]>, buf: &mut Vec<u8>) -> Result<Option<IpAddrIterator<'_>>> {
    do_lookup(host.as_ref(), buf)
}

fn do_lookup<'a>(host: &[u8], buf: &'a mut Vec<u8>) -> Result<Option<IpAddrIterator<'a>>> {
    // The socket cannot be re-used; nscd expects a new connection per request.
    let mut sock = UnixStream::connect(PATH_NSCDSOCKET)?;

    // send request
    let req = RequestHeader {
        version: NSCD_VERSION,
        r#type: GETAI,
        key_len: host.len().try_into().unwrap(),
    };

    let mut slices = [IoSlice::new(bytes_of(&req)), IoSlice::new(host)];
    let mut slices = slices.as_mut_slice();
    while !slices.is_empty() {
        let written = sock.write_vectored(slices)?;
        if written == 0 {
            return Err(Error::new(
                ErrorKind::BrokenPipe,
                "could not write all data",
            ));
        }
        IoSlice::advance_slices(&mut slices, written);
    }

    // read response header and check if response is sane
    let mut resp = AiResponseHeader::zeroed();
    sock.read_exact(bytes_of_mut(&mut resp))?;

    if resp.version != NSCD_VERSION {
        return unexpected_nscd_response();
    } else if resp.found != 1 || resp.error != 0 || resp.naddrs == 0 || resp.addrslen == 0 {
        return Ok(None);
    } else if resp.naddrs < 0 || resp.addrslen < 0 || resp.canonlen < 0 || resp.canonlen > 254 {
        return unexpected_nscd_response();
    }

    let Some(data_len) = Some(resp.naddrs)
        .and_then(|l| l.checked_add(resp.addrslen))
        .and_then(|l| l.checked_add(resp.canonlen))
    else {
        return unexpected_nscd_response();
    };
    let data_len = data_len as u32 as usize;
    if data_len > MAX_DATA_LEN {
        return unexpected_nscd_response();
    }

    // read response body
    buf.resize(data_len, 0);
    sock.read_exact(buf.as_mut_slice())?;
    drop(sock);

    // read canonical name
    let slice = buf.as_slice();
    let (slice, canon) = if resp.canonlen != 0 {
        match slice
            .len()
            .checked_sub(resp.canonlen.try_into().unwrap_or(usize::MAX))
            .and_then(|at| slice.split_at_checked(at))
            .and_then(|(slice, canon)| Some((slice, CStr::from_bytes_with_nul(canon).ok()?)))
        {
            Some((slice, canon)) => (slice, Some(canon)),
            None => return unexpected_nscd_response(),
        }
    } else {
        (slice, None)
    };

    // make sure that all address families are `AF_INET` or `AF_INET6`
    let Some((slice, families)) = slice
        .len()
        .checked_sub(resp.naddrs.try_into().unwrap_or(usize::MAX))
        .and_then(|at| slice.split_at_checked(at))
        .and_then(|(slice, families)| Some((slice, try_cast_slice(families).ok()?)))
    else {
        return unexpected_nscd_response();
    };

    // make sure that the lengths of all addresses combined equals the length of the buffer
    let expected_len: usize = families
        .iter()
        .map(|&family| match family {
            Family::V4 => size_of::<Ipv4Addr>(),
            Family::V6 => size_of::<Ipv6Addr>(),
        })
        .sum();
    if expected_len != slice.len() {
        return unexpected_nscd_response();
    }

    Ok(Some(IpAddrIterator {
        canon,
        families,
        slice,
    }))
}

fn unexpected_nscd_response() -> Result<Option<IpAddrIterator<'static>>> {
    Err(Error::new(
        ErrorKind::Unsupported,
        "unexpected nscd response",
    ))
}

/// An iterator of [`IpAddr`]esses, returned by [`lookup()`].
#[derive(Debug, Default, Clone, Copy)]
pub struct IpAddrIterator<'a> {
    families: &'a [Family],
    slice: &'a [u8],
    canon: Option<&'a CStr>,
}

impl Iterator for IpAddrIterator<'_> {
    type Item = IpAddr;

    fn next(&mut self) -> Option<Self::Item> {
        let [family, families @ ..] = self.families else {
            return None;
        };
        self.families = families;

        match family {
            Family::V4 => {
                let bits;
                (bits, self.slice) = self.slice.split_at_checked(size_of::<Ipv4Addr>())?;
                let bits = u32::from_be_bytes(bits.try_into().unwrap());
                Some(IpAddr::V4(Ipv4Addr::from_bits(bits)))
            }
            Family::V6 => {
                let bits;
                (bits, self.slice) = self.slice.split_at_checked(size_of::<Ipv6Addr>())?;
                let bits = u128::from_be_bytes(bits.try_into().unwrap());
                Some(IpAddr::V6(Ipv6Addr::from_bits(bits)))
            }
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.len()))
    }
}

impl FusedIterator for IpAddrIterator<'_> {}

impl ExactSizeIterator for IpAddrIterator<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.families.len()
    }
}

impl<'a> IpAddrIterator<'a> {
    /// The canonical name of the host.
    #[inline]
    pub fn canon(&self) -> Option<&'a CStr> {
        self.canon
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, CheckedBitPattern)]
#[repr(u8)]
#[allow(dead_code)] // constructed by [`try_cast_slice()`]
enum Family {
    V4 = 2,
    V6 = 10,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct RequestHeader {
    version: i32,
    r#type: i32,
    key_len: i32,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct AiResponseHeader {
    version: i32,
    found: i32,
    naddrs: NscdSsize,
    addrslen: NscdSsize,
    canonlen: NscdSsize,
    error: i32,
}

// typedef in `nscd-types.h`
type NscdSsize = i32;

// constants in `nscd-client.h`
const PATH_NSCDSOCKET: &str = "/var/run/nscd/socket";
const GETAI: i32 = 14;
const NSCD_VERSION: i32 = 2;

const MAX_DATA_LEN: usize = 8192; // This is not a constant in nscd, just a safety check.
