//! Synchronous / blocking host name look up

use std::ops::ControlFlow;
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::Errno;

use crate::protocol::{
    AiResponseHeader, DataError, HeaderError, IoState, IpAddrIterator, IsEmpty, RequestError,
    SocketError, interpret_data, open_socket, read_data, read_header, write_request,
};

/// Look up a host name, synchronously.
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

fn do_lookup<'a>(
    host: &[u8],
    buf: &'a mut Vec<u8>,
    timeout: Duration,
) -> Result<Option<IpAddrIterator<'a>>, Error> {
    let deadline = Instant::now() + timeout;

    let sock = open_socket().map_err(Error::Socket)?;

    let mut io = IoState::default();
    loop {
        await_writable(&sock, deadline)?;
        if write_request(sock.as_fd(), &mut io, host)?.is_break() {
            break;
        }
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

fn await_writable(sock: &OwnedFd, deadline: Instant) -> Result<(), Error> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Err(Error::Timeout(None));
    };

    let timeout = Timespec::try_from(remaining).map_err(|_| Error::Timeout(None))?;
    let events = PollFlags::IN
        | PollFlags::OUT
        | PollFlags::WRNORM
        | PollFlags::WRBAND
        | PollFlags::ERR
        | PollFlags::HUP;
    let mut fds = [PollFd::new(sock, events)];
    if poll(&mut fds, Some(&timeout)).map_err(|err| Error::Timeout(Some(err)))? == 0 {
        return Err(Error::Timeout(None));
    }

    Ok(())
}

fn await_readable(sock: &OwnedFd, deadline: Instant) -> Result<(), Error> {
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Err(Error::Timeout(None));
    };

    let timeout = Timespec::try_from(remaining).map_err(|_| Error::Timeout(None))?;
    let events = PollFlags::IN
        | PollFlags::PRI
        | PollFlags::RDNORM
        | PollFlags::RDBAND
        | PollFlags::ERR
        | PollFlags::HUP;
    let mut fds = [PollFd::new(sock, events)];
    if poll(&mut fds, Some(&timeout)).map_err(|err| Error::Timeout(Some(err)))? == 0 {
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
