use std::ffi::CStr;
use std::io::{IoSlice, IoSliceMut};
use std::iter::FusedIterator;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;
use std::os::fd::{BorrowedFd, OwnedFd};

use bytemuck::checked::try_cast_slice;
use bytemuck::{CheckedBitPattern, Pod, Zeroable, bytes_of, bytes_of_mut};
use rustix::io::{Errno, ReadWriteFlags, preadv2, pwritev2};
use rustix::net::{
    AddressFamily, SocketAddrUnix, SocketFlags, SocketType, connect_unix, socket_with,
};

pub(crate) fn connect() -> Result<OwnedFd, SocketError> {
    let addr = SocketAddrUnix::new(PATH_NSCDSOCKET).map_err(|_| SocketError::Addr)?;
    let sock = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::CLOEXEC,
        None,
    )
    .map_err(SocketError::Open)?;
    connect_unix(&sock, &addr).map_err(SocketError::Connect)?;
    Ok(sock)
}

#[derive(Debug, Clone, Copy, thiserror::Error, displaydoc::Display)]
pub enum SocketError {
    /// Could not open socket
    Open(#[source] Errno),
    /// Nscd socket address was invalid
    Addr,
    /// Could not connect to nscd socket
    Connect(#[source] Errno),
}

pub(crate) fn write_request(
    nowait: bool,
    sock: BorrowedFd<'_>,
    io: &mut IoState,
    host: &[u8],
) -> Result<ControlFlow<()>, RequestError> {
    let req = RequestHeader {
        version: NSCD_VERSION,
        r#type: GETAI,
        key_len: host.len().try_into().unwrap(),
    };

    let mut slices = [IoSlice::new(bytes_of(&req)), IoSlice::new(host)];
    write_all(nowait, sock, io, &mut slices).map_err(RequestError::Write)
}

#[derive(Debug, Clone, Copy, thiserror::Error, displaydoc::Display)]
pub enum RequestError {
    /// Could not send request
    Write(#[source] WriteError),
}

pub(crate) fn read_header(
    sock: BorrowedFd<'_>,
    io: &mut IoState,
    resp: &mut AiResponseHeader,
) -> Result<ControlFlow<IsEmpty, ()>, HeaderError> {
    let mut slices = [IoSliceMut::new(bytes_of_mut(resp))];
    if read_all(sock, io, &mut slices)?.is_continue() {
        return Ok(ControlFlow::Continue(()));
    }

    if resp.version != NSCD_VERSION {
        return Err(HeaderError::Version(resp.version));
    } else if resp.found != 1 || resp.error != 0 || resp.naddrs == 0 || resp.addrslen == 0 {
        return Ok(ControlFlow::Break(IsEmpty::Empty));
    } else if resp.naddrs < 0 || resp.addrslen < 0 || resp.canonlen < 0 || resp.canonlen > 254 {
        return Err(HeaderError::Data);
    }

    let Some(data_len) = Some(resp.naddrs)
        .and_then(|l| l.checked_add(resp.addrslen))
        .and_then(|l| l.checked_add(resp.canonlen))
    else {
        return Err(HeaderError::TooBig);
    };
    let data_len = data_len as u32 as usize;
    if data_len > MAX_DATA_LEN {
        return Err(HeaderError::TooBig);
    }

    Ok(ControlFlow::Break(IsEmpty::HasData(data_len)))
}

#[derive(Debug, Clone, Copy, thiserror::Error, displaydoc::Display)]
pub enum HeaderError {
    /// Could not read header
    Read(#[from] ReadError),
    /// Wrong version {0:x}, expected {NSCD_VERSION:x}
    Version(i32),
    /// nscd response not understood
    Data,
    /// nscd response unreasonable large
    TooBig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IsEmpty {
    Empty,
    HasData(usize),
}

pub(crate) fn read_data(
    sock: BorrowedFd<'_>,
    io: &mut IoState,
    buf: &mut [u8],
) -> Result<ControlFlow<()>, DataError> {
    let mut slices = [IoSliceMut::new(buf)];
    Ok(read_all(sock, io, &mut slices)?)
}

pub(crate) fn interpret_data<'a>(
    resp: &AiResponseHeader,
    buf: &'a mut [u8],
) -> Result<IpAddrIterator<'a>, DataError> {
    // read canonical name
    let slice = &*buf;
    let (slice, canon) = if resp.canonlen != 0 {
        match slice
            .len()
            .checked_sub(resp.canonlen.try_into().unwrap_or(usize::MAX))
            .and_then(|at| slice.split_at_checked(at))
            .and_then(|(slice, canon)| Some((slice, CStr::from_bytes_with_nul(canon).ok()?)))
        {
            Some((slice, canon)) => (slice, Some(canon)),
            None => return Err(DataError::Canon),
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
        return Err(DataError::Family);
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
        return Err(DataError::DataLength {
            actual: slice.len(),
            expected: expected_len,
        });
    }

    Ok(IpAddrIterator {
        canon,
        families,
        slice,
    })
}

#[derive(Debug, Clone, Copy, thiserror::Error, displaydoc::Display)]
pub enum DataError {
    /// Could not read header
    Read(#[from] ReadError),
    /// Could not extract canonical name
    Canon,
    /// Response contained address families other than AF_INET / AF_INET6
    Family,
    /// Actual length of IP addresses {actual} != expected length {expected}
    DataLength { actual: usize, expected: usize },
}

/// An iterator of [`IpAddr`]esses, returned by [`lookup()`][crate::sync::lookup].
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
pub(crate) enum Family {
    V4 = 2,
    V6 = 10,
}

fn write_all(
    nowait: bool,
    sock: BorrowedFd<'_>,
    state: &mut IoState,
    mut slices: &mut [IoSlice<'_>],
) -> Result<ControlFlow<()>, WriteError> {
    if state.pos > 0 {
        IoSlice::advance_slices(&mut slices, state.pos);
    }

    let flags = if nowait {
        ReadWriteFlags::NOWAIT
    } else {
        ReadWriteFlags::empty()
    };
    match pwritev2(sock, slices, u64::MAX, flags) {
        Ok(n) if n > 0 => {
            IoSlice::advance_slices(&mut slices, n);
            if slices.is_empty() {
                Ok(ControlFlow::Break(()))
            } else {
                state.pos += n;
                state.had_zero = true;
                state.had_intr = true;
                Ok(ControlFlow::Continue(()))
            }
        }
        Ok(_) => {
            if state.had_zero {
                Err(WriteError(None))
            } else {
                state.had_zero = true;
                Ok(ControlFlow::Continue(()))
            }
        }
        Err(Errno::INTR) if !state.had_intr => {
            state.had_intr = true;
            Ok(ControlFlow::Continue(()))
        }
        Err(err) => Err(WriteError(Some(err))),
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error, displaydoc::Display)]
#[error("Could not write data to socket")]
pub struct WriteError(#[source] pub Option<Errno>);

fn read_all(
    sock: BorrowedFd<'_>,
    state: &mut IoState,
    mut slices: &mut [IoSliceMut<'_>],
) -> Result<ControlFlow<()>, ReadError> {
    if state.pos > 0 {
        IoSliceMut::advance_slices(&mut slices, state.pos);
    }

    match preadv2(sock, slices, u64::MAX, ReadWriteFlags::NOWAIT) {
        Ok(n) if n > 0 => {
            IoSliceMut::advance_slices(&mut slices, n);
            if slices.is_empty() {
                Ok(ControlFlow::Break(()))
            } else {
                state.pos += n;
                state.had_zero = true;
                state.had_intr = true;
                Ok(ControlFlow::Continue(()))
            }
        }
        Ok(_) => {
            if state.had_zero {
                Err(ReadError(None))
            } else {
                state.had_zero = true;
                Ok(ControlFlow::Continue(()))
            }
        }
        Err(Errno::INTR) if !state.had_intr => {
            state.had_intr = true;
            Ok(ControlFlow::Continue(()))
        }
        Err(err) => Err(ReadError(Some(err))),
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error, displaydoc::Display)]
/// Could not read data from socket
pub struct ReadError(#[source] pub Option<Errno>);

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct IoState {
    pos: usize,
    had_zero: bool,
    had_intr: bool,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable)]
#[repr(C)]
struct RequestHeader {
    version: i32,
    r#type: i32,
    key_len: i32,
}

#[derive(Debug, Clone, Copy, Pod, Zeroable, Default)]
#[repr(C)]
pub(crate) struct AiResponseHeader {
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
const PATH_NSCDSOCKET: &CStr = c"/var/run/nscd/socket";
const GETAI: i32 = 14;
const NSCD_VERSION: i32 = 2;

const MAX_DATA_LEN: usize = 8192; // This is not a constant in nscd, just a safety check.
