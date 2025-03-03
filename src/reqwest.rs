//! Compatibility with [`reqwest`].

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use ouroboros::self_referencing;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};

use crate::IpAddrIterator;
use crate::protocol::interpret_data;
use crate::tokio::fill_buf;

/// A [`dns_resolver`][reqwest::ClientBuilder::dns_resolver] for [`reqwest::Client`] that uses nscd.
pub fn resolver() -> Arc<Resolver> {
    static RESOLVER: OnceLock<Arc<Resolver>> = OnceLock::new();

    Arc::clone(RESOLVER.get_or_init(|| Arc::new(Resolver)))
}

/// Use [`resolver()`].
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Resolver;

impl Resolve for Resolver {
    #[inline]
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(resolve(name))
    }
}

async fn resolve(name: Name) -> Result<Addrs, Box<dyn std::error::Error + Send + Sync>> {
    let mut buf = Vec::new();
    if let Some(resp) = fill_buf(name.as_str().as_bytes(), &mut buf).await? {
        let addrs = ResolvedAddrs::try_new(buf, |buf| interpret_data(&resp, buf))?;
        Ok(Box::new(addrs))
    } else {
        Err(Box::new(NoResults(name)))
    }
}

#[self_referencing]
struct ResolvedAddrs {
    buf: Vec<u8>,
    #[borrows(buf)]
    #[covariant]
    iter: IpAddrIterator<'this>,
}

impl Iterator for ResolvedAddrs {
    type Item = SocketAddr;

    fn next(&mut self) -> Option<Self::Item> {
        self.with_iter_mut(|iter| Some(SocketAddr::new(iter.next()?, 0)))
    }
}

/// No IP addresses found for {0:?}
#[derive(Debug, thiserror::Error, displaydoc::Display)]
struct NoResults(Name);
