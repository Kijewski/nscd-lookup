//! Synchronous / blocking host name look up

use std::ops::ControlFlow;
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;

use crate::protocol::{
    AiResponseHeader, DataError, HeaderError, IoState, IpAddrIterator, IsEmpty, RequestError,
    SocketError, connect, interpret_data, read_data, read_header, write_request,
};

/// Look up a host name, synchronously
///
/// This function looks up `host` using [nscd](https://man7.org/linux/man-pages/man8/nscd.8.html),
/// stores the response in `buf`, and returns an iterator over the data.
/// The result is `None` if there were no IP addresses associated with domain name.
///
/// If the timeout is `None`, then [`DEFAULT_TIMEOUT`] is used.
#[inline]
pub fn lookup(
    host: impl AsRef<[u8]>,
    buf: &mut Vec<u8>,
    timeout: Option<Duration>,
) -> Result<Option<IpAddrIterator<'_>>, Error> {
    do_lookup(host.as_ref(), buf, timeout.unwrap_or(DEFAULT_TIMEOUT))
}

#[allow(clippy::ptr_arg)] // false positive
fn do_lookup<'a>(
    host: &[u8],
    buf: &'a mut Vec<u8>,
    timeout: Duration,
) -> Result<Option<IpAddrIterator<'a>>, Error> {
    let deadline = Instant::now() + timeout;

    let sock = connect().map_err(Error::Socket)?;

    let mut io = IoState::default();
    while write_request(false, sock.as_fd(), &mut io, host)?.is_continue() {
        continue;
    }

    io = IoState::default();
    let mut resp = AiResponseHeader::default();
    let data_len = loop {
        await_readable(&sock, deadline)?;
        match read_header(sock.as_fd(), &mut io, &mut resp)? {
            ControlFlow::Continue(()) => continue,
            ControlFlow::Break(IsEmpty::Empty) => return Ok(None),
            ControlFlow::Break(IsEmpty::HasData(data_len)) => break data_len,
        }
    };
    buf.resize(data_len, 0);

    io = IoState::default();
    loop {
        await_readable(&sock, deadline)?;
        if read_data(sock.as_fd(), &mut io, buf)?.is_break() {
            break;
        }
    }

    Ok(Some(interpret_data(&resp, buf)?))
}

fn await_readable(sock: &OwnedFd, deadline: Instant) -> Result<(), Error> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Err(Error::Timeout(None));
    };

    let millis = remaining.subsec_nanos().div_ceil(1_000_000);
    let millis = remaining
        .as_secs()
        .saturating_mul(1_000)
        .saturating_add(millis as u64)
        .clamp(1, i32::MAX as u64) as i32;
    let events = PollFlags::IN
        | PollFlags::PRI
        | PollFlags::RDNORM
        | PollFlags::RDBAND
        | PollFlags::ERR
        | PollFlags::HUP;
    let mut fds = [PollFd::new(sock, events)];
    if poll(&mut fds, millis).map_err(|err| Error::Timeout(Some(err)))? == 0 {
        return Err(Error::Timeout(None));
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, thiserror::Error, displaydoc::Display)]
/// An error returned by [`lookup()`]
pub enum Error {
    /// Could not use socket
    Socket(#[from] SocketError),
    /// Could not send request
    Request(#[from] RequestError),
    /// Could not receive response header
    Header(#[from] HeaderError),
    /// Could not receive response data
    Data(#[from] DataError),
    /// Timeout while waiting for response
    Timeout(#[source] Option<Errno>),
}

/// Default timeout for [`lookup()`]'s `timeout` parameter.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
