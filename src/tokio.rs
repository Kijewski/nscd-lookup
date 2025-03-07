//! Use [`tokio`] to asynchronously look up host names

use std::io::ErrorKind;
use std::ops::ControlFlow;
use std::os::fd::AsFd;
use std::os::unix::prelude::BorrowedFd;
use std::time::Duration;

use rustix::io::Errno;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::protocol::{
    AiResponseHeader, DataError, HeaderError, IoState, IpAddrIterator, IsEmpty, ReadError,
    RequestError, WriteError, interpret_data, open_socket, read_data, read_header, write_request,
};
pub use crate::sync::DEFAULT_TIMEOUT;
use crate::sync::Error as SyncError;

/// Look up a host name, asynchronously.
///
/// This function looks up `host` using [nscd](https://man7.org/linux/man-pages/man8/nscd.8.html),
/// stores the response in `buf`, and returns an iterator over the data.
/// The result is `None` if there were no IP addresses associated with domain name.
///
/// If the timeout is `None`, then [`DEFAULT_TIMEOUT`] is used.
#[inline]
pub async fn lookup(
    host: impl AsRef<[u8]>,
    buf: &mut Vec<u8>,
    timeout: Option<Duration>,
) -> Result<Option<IpAddrIterator<'_>>, Error> {
    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);
    tokio::time::timeout(timeout, do_lookup(host.as_ref(), buf))
        .await
        .map_err(|_| Error::Sync(SyncError::Timeout(None)))?
}

async fn do_lookup<'a>(
    host: &[u8],
    buf: &'a mut Vec<u8>,
) -> Result<Option<IpAddrIterator<'a>>, Error> {
    if let Some(resp) = fill_buf(host, buf).await? {
        let iter = interpret_data(&resp, buf).map_err(|err| Error::Sync(SyncError::Data(err)))?;
        Ok(Some(iter))
    } else {
        Ok(None)
    }
}

pub(crate) async fn fill_buf(
    host: &[u8],
    buf: &mut Vec<u8>,
) -> Result<Option<AiResponseHeader>, Error> {
    let sock = open_socket().map_err(|err| Error::Sync(SyncError::Socket(err)))?;
    let sock = AsyncFd::new(sock.as_fd()).map_err(Error::New)?;

    let mut io = IoState::default();
    while try_io(&sock, Interest::WRITABLE, |sock: BorrowedFd<'_>| {
        write_request(sock, &mut io, host)
    })
    .await?
    .is_continue()
    {
        continue;
    }

    io = IoState::default();
    let mut resp = AiResponseHeader::default();
    let data_len = loop {
        match try_io(&sock, Interest::READABLE, |sock: BorrowedFd<'_>| {
            read_header(sock, &mut io, &mut resp)
        })
        .await?
        {
            ControlFlow::Continue(()) => continue,
            ControlFlow::Break(IsEmpty::Empty) => return Ok(None),
            ControlFlow::Break(IsEmpty::HasData(data_len)) => break data_len,
        }
    };
    buf.resize(data_len, 0);

    io = IoState::default();
    while try_io(&sock, Interest::READABLE, |sock: BorrowedFd<'_>| {
        read_data(sock, &mut io, buf)
    })
    .await?
    .is_continue()
    {
        continue;
    }

    Ok(Some(resp))
}

async fn try_io<T, E, F>(
    sock: &AsyncFd<BorrowedFd<'_>>,
    interest: Interest,
    f: F,
) -> Result<ControlFlow<T, ()>, Error>
where
    F: FnOnce(BorrowedFd<'_>) -> Result<ControlFlow<T, ()>, E>,
    E: IsWouldblock + Into<SyncError>,
{
    let mut guard = sock.ready(interest).await.map_err(Error::Writable)?;
    let result = guard.try_io(|sock| {
        let result = f(sock.as_fd());
        match result {
            Ok(cf) => Ok(Ok(cf)),
            Err(err) => {
                if err.is_wouldblock() {
                    Err(std::io::Error::new(
                        ErrorKind::WouldBlock,
                        Errno::WOULDBLOCK,
                    ))
                } else {
                    Ok(Err(err))
                }
            }
        }
    });
    let Ok(result) = result else {
        return Ok(ControlFlow::Continue(()));
    };
    result
        .map_err(Error::Writable)?
        .map_err(|err| Error::Sync(err.into()))
}

/// An error returned by [`lookup()`]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Same errors as in [`sync::Error`][SyncError]
    #[error(transparent)]
    Sync(#[from] SyncError),
    /// Cannot use socket with tokio
    #[error("Cannot use socket with tokio")]
    New(#[source] std::io::Error),
    /// Could not wait for socket to become writable
    #[error("Could not wait for socket to become writable")]
    Writable(#[source] std::io::Error),
    /// Could not wait for socket to become readable
    #[error("Could not wait for socket to become readable")]
    Readable(#[source] std::io::Error),
}

trait IsWouldblock {
    fn is_wouldblock(&self) -> bool;
}

impl<T: IsWouldblock> IsWouldblock for &T {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        <T as IsWouldblock>::is_wouldblock(self)
    }
}

impl<T: IsWouldblock> IsWouldblock for Option<T> {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        match self {
            Some(err) => err.is_wouldblock(),
            None => false,
        }
    }
}

impl IsWouldblock for RequestError {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        match self {
            RequestError::Write(err) => err.is_wouldblock(),
        }
    }
}

impl IsWouldblock for HeaderError {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        match self {
            HeaderError::Read(err) => err.is_wouldblock(),
            HeaderError::Version(_) | HeaderError::Data | HeaderError::TooBig => false,
        }
    }
}

impl IsWouldblock for DataError {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        match self {
            DataError::Read(err) => err.is_wouldblock(),
            DataError::Canon | DataError::Family | DataError::DataLength { .. } => false,
        }
    }
}

impl IsWouldblock for WriteError {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        self.0.is_wouldblock()
    }
}

impl IsWouldblock for ReadError {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        self.0.is_wouldblock()
    }
}

impl IsWouldblock for Errno {
    #[inline]
    fn is_wouldblock(&self) -> bool {
        matches!(*self, Errno::WOULDBLOCK)
    }
}
