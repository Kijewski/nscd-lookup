// SPDX-FileCopyrightText: 2025 René Kijewski <crates.io@k6i.de>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]

mod protocol;
#[cfg(feature = "reqwest")]
pub mod reqwest;
pub mod sync;
#[cfg(feature = "tokio")]
pub mod tokio;

pub use crate::protocol::IpAddrIterator;
