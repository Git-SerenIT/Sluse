// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The egress proxy (M9, D-035): the box's only way out.
//!
//! The box has no route off the host-only segment: the NAT is gone, and so is
//! its DNS. What leaves goes through here, by name, to a host on the config's
//! `egress.allow`, and nowhere else. It runs on the host, so it holds against
//! an agent that is root in the box.
//!
//! What it sees is a host and a port, never a method or a path: an HTTPS
//! connection is `CONNECT host:443` and then bytes it does not read. So a host
//! on the list is a way out for whatever the box sends it, which is why the
//! list says which of its hosts take uploads (`docs/config.md`).
//!
//! - **`CONNECT` to 443, and plain `GET http://…` to 80**, which Ubuntu's
//!   archive still uses. Any other port is refused, so `github.com` is not
//!   also `github.com:22`.
//! - **A name, never an address.** An address in a request is refused, and a
//!   name whose addresses include one that is not public (loopback, private,
//!   link-local, the host-only segment) is refused whole, so a name cannot be
//!   pointed at the host or the LAN. The proxy connects to the address it
//!   checked.
//! - **The box is told**, with a 403 that names the host and who can add it.
//!
//! What it records goes to its parent as claims (D-071): one per connection,
//! which the parent keeps as `logs\egress.jsonl` when the config turns that
//! on; and for the Event Log, the first refusal of each host while this proxy
//! runs, then the count for each host refused more than once when it stops
//! (jok, 2026-10-01). It runs inside Gate Front, without privilege, and stops
//! with it.
//!
//! ponytail: no upstream proxy. A host that itself reaches the internet only
//! through a company proxy cannot serve a box; add a `CONNECT` upstream when a
//! pilot needs one.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use sluse_proto::EgressConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A request head longer than this is not one a client of ours sends.
const MAX_HEAD: usize = 16 * 1024;
/// How long a client has to send its request head.
const HEAD_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a name may take to resolve, and an upstream to accept.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);
/// How long one address has before the next is tried beside it (RFC 8305's
/// connection attempt delay).
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);
/// The longest a DNS name can be, and the most of a host a record carries.
pub const MAX_HOST: usize = 253;

/// Connections at once. A box opens tens; past this it is refused, not queued.
const MAX_OPEN: usize = 512;

/// The first of the checked addresses to accept: RFC 8305's race, cut down
/// (D-045 point 8). The families alternate, starting with the resolver's
/// first; each attempt has `ATTEMPT_DELAY` before the next starts beside it,
/// and a failure starts the next at once; `UPSTREAM_TIMEOUT` for them all.
/// Only these addresses, never a new lookup: they are the ones `is_public`
/// passed (D-035). One at a time, 15 s each, a network with broken IPv6 made
/// every connection wait.
async fn connect_first(addrs: &[SocketAddr]) -> Option<TcpStream> {
    let first_v6 = addrs.first().is_some_and(SocketAddr::is_ipv6);
    let (same, mut other) = {
        let (a, b): (Vec<SocketAddr>, Vec<SocketAddr>) = addrs.iter().partition(|a| a.is_ipv6() == first_v6);
        (a.into_iter(), b.into_iter())
    };
    let mut order = Vec::with_capacity(addrs.len());
    for a in same {
        order.push(a);
        order.extend(other.next());
    }
    order.extend(other);

    let race = async {
        let mut tries = tokio::task::JoinSet::new();
        let mut pending = order.into_iter().peekable();
        loop {
            if let Some(a) = pending.next() {
                tries.spawn(TcpStream::connect(a));
            }
            let done = if pending.peek().is_some() {
                match tokio::time::timeout(ATTEMPT_DELAY, tries.join_next()).await {
                    Ok(done) => done,
                    Err(_) => continue,
                }
            } else {
                tries.join_next().await
            };
            match done {
                Some(Ok(Ok(s))) => return Some(s),
                Some(_) => {}
                None => return None,
            }
        }
    };
    tokio::time::timeout(UPSTREAM_TIMEOUT, race).await.ok().flatten()
}

/// Why a connection was refused. A code, as the audit records' reasons are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The host is not on `egress.allow`, or the request named an address.
    NotAllowed,
    /// The name resolves to an address that is not public.
    NotPublic,
    /// Not 443 for `CONNECT`, not 80 for plain HTTP.
    Port,
    /// A host on `egress.window` while no sign-in window is open (D-075).
    WindowClosed,
}

impl Refusal {
    pub fn code(self) -> &'static str {
        match self {
            Refusal::NotAllowed => "NOT_ALLOWED",
            Refusal::NotPublic => "NOT_PUBLIC",
            Refusal::Port => "PORT",
            Refusal::WindowClosed => "WINDOW_CLOSED",
        }
    }
}

/// Where the proxy's records go. Two, because they are kept differently: every
/// connection to a file, refusals to the Event Log.
pub struct Records {
    /// One line per connection.
    pub connection: Box<dyn Fn(&Value) + Send + Sync>,
    /// Every refusal. The parent records the first for each host and the
    /// counts when it stops (`sluse_gate_core::front::Refusals`): it outlives
    /// Front, so the counts are not lost with it.
    pub refusal: Box<dyn Fn(&Value) + Send + Sync>,
}

/// Asks the parent whether a sign-in window lets the box reach a host now
/// (D-075). Front may refuse; only its parent may allow.
pub type WindowAsk = Box<dyn Fn(String) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send>> + Send + Sync>;

pub struct Proxy {
    allow: EgressConfig,
    /// None: no window is ever open, as for a base build's proxy.
    pub window: Option<WindowAsk>,
    /// What every record carries: the box, the config, who opened it.
    about: Value,
    records: Records,
    open: AtomicUsize,
    /// The production rules. A test turns them off, because its servers are
    /// on loopback and on ports of the OS's choosing.
    pub public_only: bool,
    pub https_port: u16,
    pub http_port: u16,
}

/// One request head, as far as the proxy reads it.
#[derive(Debug, PartialEq, Eq)]
struct Request {
    connect: bool,
    host: String,
    port: u16,
    /// For plain HTTP: the head to send upstream, in origin form.
    forward: Option<String>,
}

impl Proxy {
    pub fn new(allow: EgressConfig, about: Value, records: Records) -> Self {
        Proxy {
            allow,
            window: None,
            about,
            records,
            open: AtomicUsize::new(0),
            public_only: true,
            https_port: 443,
            http_port: 80,
        }
    }

    /// Serve until the listener fails.
    pub async fn serve(self: Arc<Self>, listener: TcpListener) -> std::io::Result<()> {
        loop {
            let (client, _) = listener.accept().await?;
            if self.open.fetch_add(1, Ordering::SeqCst) >= MAX_OPEN {
                self.open.fetch_sub(1, Ordering::SeqCst);
                drop(client);
                continue;
            }
            let me = self.clone();
            tokio::spawn(async move {
                me.handle(client).await;
                me.open.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }

    async fn handle(&self, mut client: TcpStream) {
        let (head, rest) = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
            Ok(Ok(Some(h))) => h,
            // Nothing sent (a port check, the service's own) or nothing whole.
            Ok(Ok(None)) | Err(_) => return,
            Ok(Err(_)) => {
                let _ = reply(&mut client, 400, "Sluse's proxy could not read that request.").await;
                return;
            }
        };
        let req = match parse(&head) {
            Some(r) => r,
            None => {
                let _ = reply(&mut client, 400, "Sluse's proxy takes CONNECT host:443 and GET http://host/.").await;
                return;
            }
        };
        let wanted = if req.connect { self.https_port } else { self.http_port };
        if req.port != wanted {
            return self.refuse(&mut client, &req, Refusal::Port).await;
        }
        if req.host.parse::<IpAddr>().is_ok() {
            return self.refuse(&mut client, &req, Refusal::NotAllowed).await;
        }
        if !self.allow.allows(&req.host) {
            // A window host goes through only while the person's window is
            // open, which the parent decides each time (D-075).
            if !self.allow.in_window(&req.host) {
                return self.refuse(&mut client, &req, Refusal::NotAllowed).await;
            }
            let open = match &self.window {
                Some(ask) => ask(req.host.clone()).await,
                None => false,
            };
            if !open {
                return self.refuse(&mut client, &req, Refusal::WindowClosed).await;
            }
        }
        let addrs: Vec<SocketAddr> =
            match tokio::time::timeout(UPSTREAM_TIMEOUT, tokio::net::lookup_host((req.host.as_str(), req.port))).await {
                Ok(Ok(a)) => a.collect(),
                _ => Vec::new(),
            };
        if self.public_only && addrs.iter().any(|a| !is_public(a.ip())) {
            return self.refuse(&mut client, &req, Refusal::NotPublic).await;
        }
        let Some(mut upstream) = connect_first(&addrs).await else {
            self.connection(&req, true, 0, 0, Some("UNREACHABLE"));
            let _ = reply(&mut client, 502, &format!("Sluse's proxy could not reach {}.", req.host)).await;
            return;
        };
        let sent = async {
            match &req.forward {
                None => client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?,
                Some(head) => upstream.write_all(head.as_bytes()).await?,
            }
            upstream.write_all(&rest).await
        };
        if sent.await.is_err() {
            return;
        }
        let first = req.forward.as_ref().map_or(0, |h| h.len()) + rest.len();
        let (up, down) = tokio::io::copy_bidirectional(&mut client, &mut upstream).await.unwrap_or((0, 0));
        self.connection(&req, true, first as u64 + up, down, None);
    }

    async fn refuse(&self, client: &mut TcpStream, req: &Request, why: Refusal) {
        self.connection(req, false, 0, 0, Some(why.code()));
        // A host is a DNS name's length at most (review R-28); the parent
        // bounds how many it records one by one.
        let host: String = req.host.chars().take(MAX_HOST).collect();
        let named = Request { connect: req.connect, host, port: req.port, forward: None };
        (self.records.refusal)(&self.record(&named, why, 1));
        let text = match why {
            Refusal::Port => format!("Sluse lets this box reach port {} of a host only.", if req.connect { self.https_port } else { self.http_port }),
            _ => format!(
                "Sluse does not let this box connect to {}. Your IT department can add it to the box's list of allowed hosts.",
                req.host
            ),
        };
        let _ = reply(client, 403, &text).await;
    }

    fn record(&self, req: &Request, why: Refusal, count: u64) -> Value {
        let mut r = json!({
            "ts": chrono::Utc::now(), "op": "egress", "outcome": "refused",
            "host": req.host, "port": req.port, "reason": why.code(), "count": count,
        });
        merge(&mut r, &self.about);
        r
    }

    fn connection(&self, req: &Request, allowed: bool, up: u64, down: u64, reason: Option<&str>) {
        let mut r = json!({
            "ts": chrono::Utc::now(), "host": req.host, "port": req.port, "allowed": allowed,
            "up": up, "down": down,
        });
        if let Some(reason) = reason {
            r["reason"] = reason.into();
        }
        merge(&mut r, &self.about);
        (self.records.connection)(&r);
    }
}

fn merge(into: &mut Value, about: &Value) {
    if let (Some(o), Some(a)) = (into.as_object_mut(), about.as_object()) {
        for (k, v) in a {
            o.insert(k.clone(), v.clone());
        }
    }
}

/// Read up to the blank line. `None` when the client sent nothing or closed
/// first; the bytes after the head come back with it.
async fn read_head(client: &mut TcpStream) -> std::io::Result<Option<(String, Vec<u8>)>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 2048];
    loop {
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            let head = String::from_utf8(buf).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            return Ok(Some((head, rest)));
        }
        if buf.len() > MAX_HEAD {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "the request head is too long"));
        }
    }
}

/// `CONNECT host:port HTTP/1.1`, or `GET http://host[:port]/path HTTP/1.1`
/// rewritten to origin form for the host itself.
fn parse(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let (method, target, version) = (first.next()?, first.next()?, first.next()?);
    if first.next().is_some() || !version.starts_with("HTTP/1.") {
        return None;
    }
    if method == "CONNECT" {
        let (host, port) = authority(target, None)?;
        return Some(Request { connect: true, host, port, forward: None });
    }
    // Plain HTTP only: an https:// URL is a client that should have sent CONNECT.
    let rest = target.strip_prefix("http://")?;
    let (auth, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = authority(auth, Some(80))?;
    // The Host header is ours, from the URL: a different one would ask the
    // server on this address for some other name.
    let mut forward = format!("{method} {path} {version}\r\nHost: {auth}\r\n");
    for line in lines.filter(|l| !l.is_empty()) {
        let name = line.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
        if !matches!(name.as_str(), "host" | "connection" | "proxy-connection" | "proxy-authorization" | "keep-alive") {
            forward.push_str(line);
            forward.push_str("\r\n");
        }
    }
    // One request per connection, so a second one on it cannot name another host.
    forward.push_str("Connection: close\r\n\r\n");
    Some(Request { connect: false, host, port, forward: Some(forward) })
}

/// `host:port`, lowercased, with no user part. A bracketed IPv6 address comes
/// back as its address, which the caller refuses.
fn authority(a: &str, default: Option<u16>) -> Option<(String, u16)> {
    if a.contains('@') || a.is_empty() {
        return None;
    }
    let (host, port) = if let Some(v6) = a.strip_prefix('[') {
        let (h, p) = v6.split_once(']')?;
        (h, p.strip_prefix(':'))
    } else {
        match a.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (a, None),
        }
    };
    let port = match port {
        Some(p) => p.parse().ok()?,
        None => default?,
    };
    Some((host.trim_end_matches('.').to_ascii_lowercase(), port))
}

/// Whether an address is on the public internet: not this host, not a private
/// network, not link-local, not reserved.
fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => public_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => public_v4(v4),
            None => public_v6(v6),
        },
    }
}

fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..128).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19))
        || a >= 240)
}

fn public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    !(ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] & 0xfe00) == 0xfc00
        || (s[0] & 0xffc0) == 0xfe80
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        // NAT64 carries an IPv4 address the check above never sees.
        || (s[0] == 0x0064 && s[1] == 0xff9b))
}

async fn reply(client: &mut TcpStream, status: u16, text: &str) -> std::io::Result<()> {
    let reason = match status {
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Bad Gateway",
    };
    let body = format!("{text}\n");
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    client.write_all(head.as_bytes()).await?;
    client.write_all(body.as_bytes()).await?;
    client.shutdown().await
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A dead address first does not hold up a live one behind it, and
    /// nothing that accepts is nothing.
    #[tokio::test]
    async fn the_race_takes_the_first_address_to_accept() {
        let live = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let live = live.local_addr().map(|a| (a, live)).unwrap();
        let closed = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
        // Unroutable: it hangs or fails at once, depending on the network.
        let dead: SocketAddr = "10.255.255.1:9".parse().unwrap();
        let t = std::time::Instant::now();
        let s = connect_first(&[dead, closed, live.0]).await.expect("the live one");
        assert_eq!(s.peer_addr().unwrap(), live.0);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        assert!(connect_first(&[closed]).await.is_none());
        assert!(connect_first(&[]).await.is_none());
    }

    #[test]
    fn a_request_is_connect_or_plain_http_and_nothing_else() {
        let c = parse("CONNECT PyPI.org.:443 HTTP/1.1\r\nHost: pypi.org:443\r\n\r\n").unwrap();
        assert_eq!((c.connect, c.host.as_str(), c.port), (true, "pypi.org", 443));
        let g = parse("GET http://archive.ubuntu.com/ubuntu/dists HTTP/1.1\r\nHost: evil.example\r\nProxy-Authorization: x\r\nConnection: keep-alive\r\nAccept: */*\r\n\r\n").unwrap();
        assert_eq!((g.connect, g.host.as_str(), g.port), (false, "archive.ubuntu.com", 80));
        assert_eq!(
            g.forward.unwrap(),
            "GET /ubuntu/dists HTTP/1.1\r\nHost: archive.ubuntu.com\r\nAccept: */*\r\nConnection: close\r\n\r\n",
            "origin form, the URL's host, no proxy headers, one request"
        );
        assert_eq!(parse("CONNECT [::1]:443 HTTP/1.1\r\n\r\n").unwrap().host, "::1");
        for bad in [
            "GET https://pypi.org/ HTTP/1.1\r\n\r\n",
            "GET /simple HTTP/1.1\r\n\r\n",
            "CONNECT user@pypi.org:443 HTTP/1.1\r\n\r\n",
            "CONNECT pypi.org HTTP/1.1\r\n\r\n",
            "CONNECT pypi.org:443 SSH-2.0\r\n\r\n",
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn only_public_addresses_are_public() {
        for ip in ["8.8.8.8", "140.82.112.3", "2606:4700::1111", "::ffff:8.8.8.8"] {
            assert!(is_public(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.77.1", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "255.255.255.255", "224.0.0.1", "::1", "fe80::1", "fd00::1", "::ffff:192.168.1.1",
            "64:ff9b::a00:1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip}");
        }
    }

    type Seen = Arc<Mutex<Vec<Value>>>;

    async fn start(allow: &[&str], port: u16) -> (SocketAddr, Arc<Proxy>, Seen, Seen) {
        start_with(allow, port, false).await
    }

    async fn start_with(allow: &[&str], port: u16, public_only: bool) -> (SocketAddr, Arc<Proxy>, Seen, Seen) {
        let (conns, refusals): (Seen, Seen) = Default::default();
        let (c, r) = (conns.clone(), refusals.clone());
        let records = Records {
            connection: Box::new(move |v| c.lock().unwrap().push(v.clone())),
            refusal: Box::new(move |v| r.lock().unwrap().push(v.clone())),
        };
        let allow = EgressConfig {
            allow: allow.iter().map(|s| s.to_string()).collect(),
            window: vec!["window.localhost".into()],
            ..Default::default()
        };
        let mut p = Proxy::new(allow, json!({ "boxId": "box-test" }), records);
        p.public_only = public_only;
        (p.https_port, p.http_port) = (port, port);
        let p = Arc::new(p);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(p.clone().serve(l));
        (addr, p, conns, refusals)
    }

    /// An upstream that answers with what it was sent, once.
    async fn echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let _ = s.write_all(&buf[..n]).await;
                });
            }
        });
        port
    }

    async fn ask(proxy: SocketAddr, send: &str) -> String {
        let mut s = TcpStream::connect(proxy).await.unwrap();
        s.write_all(send.as_bytes()).await.unwrap();
        let mut out = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut out)).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn an_allowed_host_is_tunnelled_and_recorded_with_its_bytes() {
        let port = echo().await;
        let (proxy, _, conns, refusals) = start(&["localhost"], port).await;
        let got = ask(proxy, &format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\nhello")).await;
        assert_eq!(got, "HTTP/1.1 200 Connection established\r\n\r\nhello", "bytes sent with the head go too");
        // The line is written once both sides have closed.
        for _ in 0..50 {
            if !conns.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let c = conns.lock().unwrap()[0].clone();
        assert_eq!((c["host"].as_str(), c["allowed"].as_bool(), c["up"].as_u64(), c["down"].as_u64()), (Some("localhost"), Some(true), Some(5), Some(5)));
        assert_eq!(c["boxId"], "box-test");
        assert!(refusals.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_window_host_goes_through_only_while_the_parent_says_its_window_is_open() {
        let port = echo().await;
        let (proxy, p, _, refusals) = start(&["localhost"], port).await;
        // No parent answer at all, as for a base build: closed.
        let got = ask(proxy, &format!("CONNECT window.localhost:{port} HTTP/1.1\r\n\r\n")).await;
        assert!(got.starts_with("HTTP/1.1 403"), "{got}");
        assert!(got.contains("does not let this box connect"), "the box is told no more than for any host: {got}");
        assert_eq!(refusals.lock().unwrap()[0]["reason"], "WINDOW_CLOSED");
        // The parent's answer decides.
        let open = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let asked = Arc::new(Mutex::new(Vec::<String>::new()));
        let (o, a) = (open.clone(), asked.clone());
        drop(p);
        // `localhost` on the window alone: Windows does not resolve names under it.
        let window_only = EgressConfig { window: vec!["localhost".into()], ..Default::default() };
        let mut q = Proxy::new(window_only, json!({}), Records { connection: Box::new(|_| {}), refusal: Box::new(|_| {}) });
        q.window = Some(Box::new(move |h| {
            a.lock().unwrap().push(h);
            let o = o.load(std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move { o })
        }));
        (q.https_port, q.http_port, q.public_only) = (port, port, false);
        let q = Arc::new(q);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap();
        tokio::spawn(q.serve(l));
        let got = ask(addr, &format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\nhi")).await;
        assert!(got.starts_with("HTTP/1.1 200"), "open: {got}");
        open.store(false, std::sync::atomic::Ordering::SeqCst);
        assert!(ask(addr, &format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n")).await.starts_with("HTTP/1.1 403"));
        // A host on neither list is never asked about.
        assert!(ask(addr, &format!("CONNECT evil.example:{port} HTTP/1.1\r\n\r\n")).await.starts_with("HTTP/1.1 403"));
        assert_eq!(*asked.lock().unwrap(), ["localhost", "localhost"]);
    }

    #[tokio::test]
    async fn plain_http_goes_to_the_urls_host_in_origin_form() {
        let port = echo().await;
        let (proxy, ..) = start(&["localhost"], port).await;
        let got = ask(proxy, &format!("GET http://localhost:{port}/x HTTP/1.1\r\nHost: other.example\r\n\r\n")).await;
        assert_eq!(got, format!("GET /x HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: close\r\n\r\n"));
    }

    #[tokio::test]
    async fn a_host_not_on_the_list_is_refused_told_and_reported_every_time() {
        let port = echo().await;
        let (proxy, _, conns, refusals) = start(&["localhost"], port).await;
        for _ in 0..3 {
            let got = ask(proxy, &format!("CONNECT evil.example:{port} HTTP/1.1\r\n\r\n")).await;
            assert!(got.starts_with("HTTP/1.1 403"), "{got}");
            assert!(got.contains("does not let this box connect to evil.example"), "{got}");
        }
        let got = ask(proxy, &format!("CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n")).await;
        assert!(got.starts_with("HTTP/1.1 403"), "an address is never on the list: {got}");
        let got = ask(proxy, "CONNECT localhost:22 HTTP/1.1\r\n\r\n").await;
        assert!(got.starts_with("HTTP/1.1 403"), "nor another port: {got}");
        assert_eq!(conns.lock().unwrap().len(), 5, "every refusal is a connection line");
        let r = refusals.lock().unwrap();
        assert_eq!(r.len(), 5, "every refusal goes to the parent, which counts them: {r:?}");
        assert_eq!((r[0]["host"].as_str(), r[0]["reason"].as_str(), r[0]["count"].as_u64()), (Some("evil.example"), Some("NOT_ALLOWED"), Some(1)));
        assert_eq!(r[4]["reason"], "PORT");
    }

    #[tokio::test]
    async fn a_name_that_resolves_to_a_private_address_is_refused() {
        let port = echo().await;
        // The production rule, here, where localhost is the only name there is.
        let (proxy, _, _, refusals) = start_with(&["localhost"], port, true).await;
        let got = ask(proxy, &format!("CONNECT localhost:{port} HTTP/1.1\r\n\r\n")).await;
        assert!(got.starts_with("HTTP/1.1 403"), "{got}");
        assert_eq!(refusals.lock().unwrap()[0]["reason"], "NOT_PUBLIC");
    }
}
