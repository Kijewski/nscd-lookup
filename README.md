# nscd-lookup – look up IP addresses using nscd

[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/Kijewski/nscd-lookup/ci.yml?branch=main&style=flat-square&logo=github&logoColor=white "GitHub Workflow Status")](https://github.com/Kijewski/nscd-lookup/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/nscd-lookup?logo=rust&style=flat-square "Crates.io")](https://crates.io/crates/nscd-lookup)
[![docs.rs](https://img.shields.io/docsrs/nscd-lookup?logo=docsdotrs&style=flat-square&logoColor=white "docs.rs")](https://docs.rs/nscd-lookup/)

Explicitly querying [`nscd`](https://man7.org/linux/man-pages/man8/nscd.8.html) might come in handy
if your program runs in a container or jail without direct internet access, but you still need to
look up a domain name for some reason.

```rust,ignore
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nscd_lookup::sync::lookup;

let localhost: Vec<IpAddr> = lookup("localhost", &mut Vec::new(), None)
    .expect("should be able to look up addresses")
    .expect("address list should not be empty")
    .collect();
assert!(localhost.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
assert!(localhost.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
```

Or with the feature `"tokio"`:

```rust,ignore
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nscd_lookup::tokio::lookup;

let localhost: Vec<IpAddr> = lookup("localhost", &mut Vec::new(), None)
    .await
    .expect("should be able to look up addresses")
    .expect("address list should not be empty")
    .collect();
assert!(localhost.contains(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
assert!(localhost.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
```

The feature `"reqwest"` enables a resolver that can be used in reqwest clients.
