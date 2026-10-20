//! Working out which address a request came from.
//!
//! Rate limiting is only as good as this answer. If a client can choose
//! the address it is counted against, the limits mean nothing, so the
//! rules here are deliberately strict:
//!
//! * The address is the peer of the TCP connection, full stop, unless
//!   that peer is inside [`TrustedProxies`] - empty by default, so
//!   `X-Forwarded-For` is ignored outright until an operator says which
//!   proxies exist.
//! * When the peer *is* a trusted proxy, the list is read **right to
//!   left**. Entries are appended by each hop, so the right-hand end is
//!   what our own infrastructure wrote and the left-hand end is whatever
//!   the original client sent - which it can set to anything. Reading
//!   the left-most entry is the classic spoofing bug.
//! * Trusted entries are skipped while walking left, so a chain of our
//!   own proxies resolves to the client in front of them.
//! * Anything unparseable stops the walk and falls back to the peer.
//!   Continuing past it would let a client append garbage to make us
//!   read one entry further left - the entry it controls.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;

use crate::config::{unmap_v4, TrustedProxies};
use crate::error::{ApiError, ErrorKind};
use crate::state::AppState;

/// Header the resolution above reads.
pub const FORWARDED_FOR: &str = "x-forwarded-for";

/// The address a request is attributed to.
pub struct ClientAddr(pub IpAddr);

impl ClientAddr {
    pub fn ip(&self) -> IpAddr {
        self.0
    }

    /// The key this address is rate limited under.
    pub fn rate_limit_key(&self) -> ClientKey {
        ClientKey::from_ip(self.0)
    }
}

/// A normalized address, as rate limits count it.
///
/// IPv4 is counted per address. IPv6 is counted per `/64`, because a
/// single residential or hosted IPv6 assignment is routinely a whole
/// `/64` or larger - counting per address would let one client walk
/// through billions of addresses and never hit a limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientKey(IpAddr);

impl ClientKey {
    pub fn from_ip(addr: IpAddr) -> Self {
        // Unmap first. Without this an IPv4 peer arriving as
        // ::ffff:a.b.c.d from a dual-stack listener would be truncated
        // to the ::ffff:0:0/64 prefix - putting every IPv4 client on the
        // planet into one shared bucket.
        match unmap_v4(addr) {
            IpAddr::V4(v4) => Self(IpAddr::V4(v4)),
            IpAddr::V6(v6) => {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                Self(IpAddr::V6(Ipv6Addr::from(octets)))
            }
        }
    }
}

/// Resolves the client address from the peer address and the
/// `X-Forwarded-For` entries, honoring `trusted`.
///
/// `forwarded` yields the raw header values, in the order they arrived.
pub fn resolve<'a>(
    peer: IpAddr,
    forwarded: impl Iterator<Item = &'a str>,
    trusted: &TrustedProxies,
) -> IpAddr {
    let peer = unmap_v4(peer);

    // The common case: no proxies configured, or this peer is not one.
    if trusted.is_empty() || !trusted.contains(peer) {
        return peer;
    }

    let entries: Vec<&str> = forwarded
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect();

    for entry in entries.iter().rev() {
        match parse_entry(entry) {
            Some(addr) => {
                let addr = unmap_v4(addr);
                if trusted.contains(addr) {
                    // One of our own hops; keep walking left.
                    continue;
                }
                return addr;
            }
            // Fail safe rather than skipping it.
            None => return peer,
        }
    }

    // Every entry was a trusted proxy, or there were none.
    peer
}

/// Parses one `X-Forwarded-For` entry.
///
/// Accepts a bare address, and also `addr:port` or `[v6]:port`, which
/// some proxies emit.
fn parse_entry(entry: &str) -> Option<IpAddr> {
    // Bare address first, which is also the only form a bare IPv6
    // address can take without being ambiguous with addr:port.
    if let Ok(addr) = entry.parse::<IpAddr>() {
        return Some(addr);
    }

    if let Some(rest) = entry.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        // Either nothing or a port may follow the bracket.
        if !(after.is_empty() || after.starts_with(':')) {
            return None;
        }
        return inner.parse::<Ipv6Addr>().ok().map(IpAddr::V6);
    }

    let (host, _port) = entry.rsplit_once(':')?;
    host.parse::<Ipv4Addr>().ok().map(IpAddr::V4)
}

impl FromRequestParts<AppState> for ClientAddr {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Set by `into_make_service_with_connect_info`. Its absence is a
        // wiring mistake, and failing closed is the only safe answer:
        // without a peer address nothing can be rate limited.
        let Some(ConnectInfo(peer)) = parts.extensions.get::<ConnectInfo<std::net::SocketAddr>>()
        else {
            tracing::error!("no peer address on the request; connect info is not wired up");
            return Err(ApiError::of(ErrorKind::InternalError));
        };

        let forwarded = parts
            .headers
            .get_all(FORWARDED_FOR)
            .iter()
            .filter_map(|value| value.to_str().ok());

        Ok(Self(resolve(peer.ip(), forwarded, &state.trusted_proxies)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn ip(raw: &str) -> IpAddr {
        raw.parse().expect("a valid address")
    }

    fn trusted(list: &str) -> TrustedProxies {
        let mut env = std::collections::HashMap::new();
        env.insert("SCREENWARD_TRUSTED_PROXIES".to_owned(), list.to_owned());
        Config::for_test(&env)
            .expect("the proxy list must be valid")
            .trusted_proxies
    }

    fn no_proxies() -> TrustedProxies {
        TrustedProxies::default()
    }

    /// With no proxies configured the header is ignored outright, which
    /// is the default posture.
    #[test]
    fn x_forwarded_for_is_ignored_when_no_proxy_is_trusted() {
        let peer = ip("192.0.2.10");
        assert_eq!(
            resolve(peer, ["198.51.100.1"].into_iter(), &no_proxies()),
            peer
        );
    }

    /// And ignored from a peer that is simply not on the list, which is
    /// the case that matters: anyone can send the header.
    #[test]
    fn x_forwarded_for_is_ignored_from_an_untrusted_peer() {
        let peer = ip("198.51.100.50");
        assert_eq!(
            resolve(peer, ["203.0.113.9"].into_iter(), &trusted("192.0.2.0/24")),
            peer,
            "a client must not be able to choose its own address"
        );
    }

    #[test]
    fn a_trusted_peer_may_report_the_client() {
        assert_eq!(
            resolve(
                ip("192.0.2.10"),
                ["198.51.100.1"].into_iter(),
                &trusted("192.0.2.0/24")
            ),
            ip("198.51.100.1")
        );
    }

    /// The core rule: entries are appended left to right, so the
    /// right-most untrusted entry is the furthest-left one our own
    /// infrastructure vouched for. A client that prepends its own
    /// entries must not be believed.
    #[test]
    fn the_right_most_untrusted_entry_wins_not_the_left_most() {
        let resolved = resolve(
            ip("192.0.2.10"),
            ["203.0.113.1, 198.51.100.7"].into_iter(),
            &trusted("192.0.2.0/24"),
        );
        assert_eq!(
            resolved,
            ip("198.51.100.7"),
            "the left-most entry is client-controlled and must be ignored"
        );
    }

    /// A client prepending a spoofed address gains nothing.
    #[test]
    fn a_spoofed_left_most_entry_does_not_help() {
        let honest = resolve(
            ip("192.0.2.10"),
            ["198.51.100.7"].into_iter(),
            &trusted("192.0.2.0/24"),
        );
        let with_spoof = resolve(
            ip("192.0.2.10"),
            ["10.0.0.1, 203.0.113.99, 198.51.100.7"].into_iter(),
            &trusted("192.0.2.0/24"),
        );
        assert_eq!(
            honest, with_spoof,
            "prepending entries must not change the answer"
        );
    }

    /// A chain of our own proxies resolves past them to the client.
    #[test]
    fn trusted_entries_are_skipped_while_walking_left() {
        let resolved = resolve(
            ip("192.0.2.1"),
            ["198.51.100.7, 192.0.2.8, 192.0.2.9"].into_iter(),
            &trusted("192.0.2.0/24"),
        );
        assert_eq!(resolved, ip("198.51.100.7"));
    }

    #[test]
    fn a_header_of_only_trusted_entries_falls_back_to_the_peer() {
        let peer = ip("192.0.2.1");
        assert_eq!(
            resolve(
                peer,
                ["192.0.2.8, 192.0.2.9"].into_iter(),
                &trusted("192.0.2.0/24")
            ),
            peer
        );
    }

    /// Stopping at an unparseable entry is deliberate: skipping it would
    /// let a client append garbage so the walk continues to an entry it
    /// controls.
    #[test]
    fn an_unparseable_entry_stops_the_walk() {
        let peer = ip("192.0.2.10");
        assert_eq!(
            resolve(
                peer,
                ["203.0.113.99, not-an-address"].into_iter(),
                &trusted("192.0.2.0/24")
            ),
            peer
        );
    }

    #[test]
    fn an_absent_or_empty_header_falls_back_to_the_peer() {
        let peer = ip("192.0.2.10");
        let proxies = trusted("192.0.2.0/24");
        assert_eq!(resolve(peer, std::iter::empty(), &proxies), peer);
        assert_eq!(resolve(peer, [""].into_iter(), &proxies), peer);
        assert_eq!(resolve(peer, [" , , "].into_iter(), &proxies), peer);
    }

    #[test]
    fn entries_split_across_several_headers_are_read_in_order() {
        let resolved = resolve(
            ip("192.0.2.1"),
            ["203.0.113.1", "198.51.100.7, 192.0.2.8"].into_iter(),
            &trusted("192.0.2.0/24"),
        );
        assert_eq!(resolved, ip("198.51.100.7"));
    }

    #[test]
    fn entries_may_carry_a_port() {
        let proxies = trusted("192.0.2.0/24");
        assert_eq!(
            resolve(ip("192.0.2.1"), ["198.51.100.7:4321"].into_iter(), &proxies),
            ip("198.51.100.7")
        );
        assert_eq!(
            resolve(
                ip("192.0.2.1"),
                ["[2001:db8::7]:4321"].into_iter(),
                &proxies
            ),
            ip("2001:db8::7")
        );
        assert_eq!(
            resolve(ip("192.0.2.1"), ["2001:db8::7"].into_iter(), &proxies),
            ip("2001:db8::7")
        );
    }

    /// A dual-stack listener hands over IPv4 peers as ::ffff:a.b.c.d.
    /// They must be recognized as the IPv4 proxy they are.
    #[test]
    fn an_ipv4_mapped_peer_is_matched_against_an_ipv4_range() {
        assert_eq!(
            resolve(
                ip("::ffff:192.0.2.10"),
                ["198.51.100.7"].into_iter(),
                &trusted("192.0.2.0/24")
            ),
            ip("198.51.100.7")
        );
    }

    // --- rate limit keys ---------------------------------------------

    #[test]
    fn ipv4_is_keyed_per_address() {
        assert_eq!(
            ClientKey::from_ip(ip("192.0.2.1")),
            ClientKey::from_ip(ip("192.0.2.1"))
        );
        assert_ne!(
            ClientKey::from_ip(ip("192.0.2.1")),
            ClientKey::from_ip(ip("192.0.2.2"))
        );
    }

    /// The bug this guards: ::ffff:0:0/64 contains every IPv4-mapped
    /// address, so truncating before unmapping would put every IPv4
    /// client into one shared bucket.
    #[test]
    fn ipv4_mapped_addresses_do_not_collapse_into_one_bucket() {
        let first = ClientKey::from_ip(ip("::ffff:192.0.2.1"));
        let second = ClientKey::from_ip(ip("::ffff:198.51.100.1"));
        assert_ne!(
            first, second,
            "every IPv4 client must not share a single bucket"
        );
        // And a mapped address keys the same as its plain form.
        assert_eq!(first, ClientKey::from_ip(ip("192.0.2.1")));
    }

    #[test]
    fn ipv6_is_keyed_per_64_prefix() {
        let a = ClientKey::from_ip(ip("2001:db8:1:2::1"));
        let b = ClientKey::from_ip(ip("2001:db8:1:2::ffff"));
        let c = ClientKey::from_ip(ip("2001:db8:1:2:ffff:ffff:ffff:ffff"));
        assert_eq!(a, b, "the same /64 must share a bucket");
        assert_eq!(a, c);

        // A different /64 is a different bucket.
        let other = ClientKey::from_ip(ip("2001:db8:1:3::1"));
        assert_ne!(a, other);
    }
}
