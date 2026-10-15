//! UDP and RTSP relay for one proxy node.
//!
//! Python keeps pairing, TLS, and the decision of which pod a client belongs
//! to. This process owns the Sunshine UDP sockets and the RTSP TCP port.
//! Semantics match the old Python loops:
//!
//! * A datagram from an unmapped address is dropped.
//! * A datagram from a mapped client is sent to that pod, same port, and the
//!   return path for (pod, local port) becomes this client address.
//! * A datagram whose source is that pod is sent back to the client.
//! * RTSP is a raw TCP splice. The accept waits until the client address is
//!   mapped (the TLS session may still be finishing), then dials the pod.
//!
//! Control is one Unix stream. Python connects and reads `ready`. It then
//! writes `map <client-ipv4> <pod-ipv4> <user>` and waits for `ok`, so a
//! datagram sent after that call cannot race the insert. This process writes
//! `touch <user>` when forwarded bytes should count against the idle timer,
//! and at most once every few seconds per user.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::Path;
use std::process;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOCK_CLOEXEC: i32 = 0x80000;
const SOL_SOCKET: i32 = 1;
const SO_REUSEADDR: i32 = 2;
const TOUCH_EVERY: Duration = Duration::from_secs(5);

extern "C" {
    fn socket(domain: i32, typ: i32, protocol: i32) -> i32;
    fn bind(sockfd: i32, addr: *const SockAddrIn, len: u32) -> i32;
    fn listen(sockfd: i32, backlog: i32) -> i32;
    fn setsockopt(sockfd: i32, level: i32, optname: i32, optval: *const i32, optlen: u32) -> i32;
    fn close(fd: i32) -> i32;
}

#[repr(C)]
struct SockAddrIn {
    sin_family: u16,
    sin_port: u16,
    sin_addr: [u8; 4],
    sin_zero: [u8; 8],
}

#[derive(Clone)]
struct MapEntry {
    pod: Ipv4Addr,
    user: String,
}

#[derive(Clone)]
struct Flow {
    pod: Ipv4Addr,
    client: SocketAddr,
    user: String,
}

struct State {
    by_ip: HashMap<Ipv4Addr, MapEntry>,
    by_flow: HashMap<(Ipv4Addr, u16), Flow>,
}

struct Forward {
    dest: SocketAddr,
    user: String,
}

struct Touch {
    tx: mpsc::Sender<String>,
    recent: Mutex<HashMap<String, Instant>>,
}

impl Touch {
    fn note(&self, user: &str) {
        let mut recent = match self.recent.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        let now = Instant::now();
        if let Some(prev) = recent.get(user) {
            if now.duration_since(*prev) < TOUCH_EVERY {
                return;
            }
        }
        recent.insert(user.to_string(), now);
        drop(recent);
        let _ = self.tx.send(user.to_string());
    }
}

struct Config {
    control: String,
    bind: Ipv4Addr,
    udp: Vec<u16>,
    rtsp: u16,
    rtsp_wait: Duration,
}

fn main() {
    let cfg = parse_args();
    let state = Arc::new(Mutex::new(State {
        by_ip: HashMap::new(),
        by_flow: HashMap::new(),
    }));
    let (tx, rx) = mpsc::channel();
    let touch = Arc::new(Touch {
        tx,
        recent: Mutex::new(HashMap::new()),
    });

    for port in &cfg.udp {
        let sock = match bind_udp(cfg.bind, *port) {
            Ok(sock) => sock,
            Err(err) => die(&format!("fatal: bind udp {}: {err}", port)),
        };
        let state = state.clone();
        let touch = touch.clone();
        let port = *port;
        thread::spawn(move || udp_loop(sock, port, state, touch));
    }
    let rtsp = match bind_tcp(cfg.bind, cfg.rtsp) {
        Ok(sock) => sock,
        Err(err) => die(&format!("fatal: bind rtsp {}: {err}", cfg.rtsp)),
    };
    {
        let state = state.clone();
        let touch = touch.clone();
        let port = cfg.rtsp;
        let wait = cfg.rtsp_wait;
        thread::spawn(move || rtsp_loop(rtsp, port, state, wait, touch));
    }

    let listener = match prepare_socket(Path::new(&cfg.control)) {
        Ok(listener) => listener,
        Err(err) => die(&format!("fatal: control socket: {err}")),
    };
    let udp_list = cfg
        .udp
        .iter()
        .map(|port| port.to_string())
        .collect::<Vec<_>>()
        .join(",");
    log(&format!(
        "listening udp {udp_list} rtsp {} bind {}",
        cfg.rtsp, cfg.bind
    ));

    let (stream, _) = match listener.accept() {
        Ok(pair) => pair,
        Err(err) => die(&format!("fatal: control accept: {err}")),
    };
    {
        let mut hello = stream;
        if writeln!(hello, "ready").is_err() || hello.flush().is_err() {
            die("fatal: control ready");
        }
        let reader = match hello.try_clone() {
            Ok(reader) => reader,
            Err(err) => die(&format!("fatal: control clone: {err}")),
        };
        // One writer. Two fds writing the same stream can interleave bytes.
        let outbound = Arc::new(Mutex::new(hello));
        {
            let outbound = outbound.clone();
            thread::spawn(move || touch_writer(outbound, rx));
        }
        let state = state.clone();
        thread::spawn(move || control_loop(reader, outbound, state));
    }

    // The workers run until the control connection drops, which exits.
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}

fn parse_args() -> Config {
    let mut args = env::args().skip(1);
    let mut control = None;
    let mut udp = None;
    let mut rtsp = None;
    let mut wait = 30u64;
    let mut bind = Ipv4Addr::UNSPECIFIED;
    while let Some(flag) = args.next() {
        let value = match args.next() {
            Some(value) => value,
            None => die(&format!("missing value for {flag}")),
        };
        match flag.as_str() {
            "--control" => control = Some(value),
            "--udp" => udp = Some(value),
            "--rtsp" => rtsp = Some(value),
            "--rtsp-wait" => {
                wait = match value.parse() {
                    Ok(wait) if wait > 0 => wait,
                    _ => die("bad --rtsp-wait"),
                }
            }
            "--bind" => {
                bind = match value.parse() {
                    Ok(ip) => ip,
                    Err(_) => die("bad --bind"),
                }
            }
            other => die(&format!("unknown argument {other}")),
        }
    }
    let control = match control {
        Some(path) if !path.is_empty() => path,
        _ => die("missing --control"),
    };
    let udp = match udp {
        Some(list) => parse_ports(&list),
        None => die("missing --udp"),
    };
    if udp.is_empty() {
        die("missing --udp");
    }
    let rtsp = match rtsp.and_then(|text| text.parse::<u16>().ok()) {
        Some(port) if port > 0 => port,
        _ => die("bad --rtsp"),
    };
    Config {
        control,
        bind,
        udp,
        rtsp,
        rtsp_wait: Duration::from_secs(wait),
    }
}

fn parse_ports(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in text.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.parse::<u16>() {
            Ok(port) if port > 0 && !ports.contains(&port) => ports.push(port),
            _ => die(&format!("bad udp port {part}")),
        }
    }
    ports
}

fn udp_loop(sock: UdpSocket, port: u16, state: Arc<Mutex<State>>, touch: Arc<Touch>) {
    let mut buf = [0u8; 65535];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(got) => got,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                log(&format!("udp {port}: {err}"));
                thread::sleep(Duration::from_millis(20));
                continue;
            }
        };
        let forward = {
            let mut guard = match state.lock() {
                Ok(guard) => guard,
                Err(_) => return,
            };
            steer(&mut guard, port, src)
        };
        let Some(forward) = forward else {
            continue;
        };
        if let Err(err) = sock.send_to(&buf[..n], forward.dest) {
            log(&format!("udp {port}: {err}"));
            continue;
        }
        touch.note(&forward.user);
    }
}

/// Same branch order as the Python `_udp` method.
fn steer(state: &mut State, local_port: u16, src: SocketAddr) -> Option<Forward> {
    let src_ip = match src.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return None,
    };
    if let Some(flow) = state.by_flow.get(&(src_ip, local_port)) {
        if src_ip == flow.pod {
            return Some(Forward {
                dest: flow.client,
                user: flow.user.clone(),
            });
        }
    }
    let mapped = state.by_ip.get(&src_ip)?.clone();
    state.by_flow.insert(
        (mapped.pod, local_port),
        Flow {
            pod: mapped.pod,
            client: src,
            user: mapped.user.clone(),
        },
    );
    Some(Forward {
        dest: SocketAddr::new(IpAddr::V4(mapped.pod), local_port),
        user: mapped.user,
    })
}

fn rtsp_loop(
    listener: TcpListener,
    port: u16,
    state: Arc<Mutex<State>>,
    wait: Duration,
    touch: Arc<Touch>,
) {
    loop {
        match listener.accept() {
            Ok((sock, addr)) => {
                let state = state.clone();
                let touch = touch.clone();
                thread::spawn(move || handle_rtsp(sock, addr, state, port, wait, touch));
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                log(&format!("tcp {port}: {err}"));
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn handle_rtsp(
    client: TcpStream,
    peer: SocketAddr,
    state: Arc<Mutex<State>>,
    port: u16,
    wait: Duration,
    touch: Arc<Touch>,
) {
    let ip = match peer.ip() {
        IpAddr::V4(ip) => ip,
        IpAddr::V6(_) => return,
    };
    let deadline = Instant::now() + wait;
    let mapped = loop {
        let found = state
            .lock()
            .ok()
            .and_then(|guard| guard.by_ip.get(&ip).cloned());
        if let Some(found) = found {
            break found;
        }
        if Instant::now() >= deadline {
            return;
        }
        thread::sleep(Duration::from_millis(200));
    };
    let dest = SocketAddr::new(IpAddr::V4(mapped.pod), port);
    let back = match TcpStream::connect_timeout(&dest, Duration::from_secs(10)) {
        Ok(sock) => sock,
        Err(err) => {
            log(&format!("tcp {port}: {peer} -> {dest}: {err}"));
            return;
        }
    };
    touch.note(&mapped.user);
    splice(client, back, touch, mapped.user);
}

fn splice(left: TcpStream, right: TcpStream, touch: Arc<Touch>, user: String) {
    let (right_copy, left_copy) = match (right.try_clone(), left.try_clone()) {
        (Ok(right_copy), Ok(left_copy)) => (right_copy, left_copy),
        _ => return,
    };
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_b = stop.clone();
    let touch_b = touch.clone();
    let user_b = user.clone();
    let a = thread::spawn(move || pump(left, right, stop, touch, user));
    let b = thread::spawn(move || pump(right_copy, left_copy, stop_b, touch_b, user_b));
    let _ = a.join();
    let _ = b.join();
}

fn pump(
    mut src: TcpStream,
    mut dst: TcpStream,
    stop: Arc<std::sync::atomic::AtomicBool>,
    touch: Arc<Touch>,
    user: String,
) {
    let mut buf = [0u8; 65536];
    loop {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                touch.note(&user);
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = src.shutdown(std::net::Shutdown::Read);
    let _ = dst.shutdown(std::net::Shutdown::Write);
}

fn control_loop(
    stream: std::os::unix::net::UnixStream,
    outbound: Arc<Mutex<std::os::unix::net::UnixStream>>,
    state: Arc<Mutex<State>>,
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                log("control closed");
                process::exit(1);
            }
            Ok(_) => {
                if line.len() > 512 {
                    log("control line too long");
                    continue;
                }
                if !apply_line(line.trim(), &state) {
                    continue;
                }
                let mut guard = match outbound.lock() {
                    Ok(guard) => guard,
                    Err(_) => process::exit(1),
                };
                if writeln!(guard, "ok").is_err() || guard.flush().is_err() {
                    log("control ack failed");
                    process::exit(1);
                }
            }
            Err(err) => {
                log(&format!("control: {err}"));
                process::exit(1);
            }
        }
    }
}

fn apply_line(line: &str, state: &Mutex<State>) -> bool {
    if line.is_empty() {
        return false;
    }
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    if cmd != "map" {
        log(&format!("unknown control {cmd}"));
        return false;
    }
    let client = parts.next().unwrap_or("");
    let pod = parts.next().unwrap_or("");
    let user = parts.next().unwrap_or("");
    if parts.next().is_some() {
        log("bad map");
        return false;
    }
    let (Ok(client), Ok(pod), Some(user)) = (
        client.parse::<Ipv4Addr>(),
        pod.parse::<Ipv4Addr>(),
        check_user(user),
    ) else {
        log("bad map");
        return false;
    };
    if let Ok(mut guard) = state.lock() {
        guard.by_ip.insert(client, MapEntry { pod, user });
        return true;
    }
    false
}

fn check_user(user: &str) -> Option<String> {
    if user.is_empty() || user.len() > 64 {
        return None;
    }
    if user.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return None;
    }
    Some(user.to_string())
}

fn touch_writer(outbound: Arc<Mutex<std::os::unix::net::UnixStream>>, rx: mpsc::Receiver<String>) {
    while let Ok(user) = rx.recv() {
        if check_user(&user).is_none() {
            continue;
        }
        let mut guard = match outbound.lock() {
            Ok(guard) => guard,
            Err(_) => return,
        };
        if writeln!(guard, "touch {user}").is_err() || guard.flush().is_err() {
            break;
        }
    }
}

fn prepare_socket(path: &Path) -> io::Result<std::os::unix::net::UnixListener> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            fs::create_dir_all(parent)?;
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let _ = fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(listener)
}

fn bind_udp(ip: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    let fd = raw_socket(SOCK_DGRAM)?;
    if let Err(err) = bind_fd(fd, ip, port) {
        unsafe { close(fd) };
        return Err(err);
    }
    Ok(unsafe { UdpSocket::from_raw_fd(fd) })
}

fn bind_tcp(ip: Ipv4Addr, port: u16) -> io::Result<TcpListener> {
    let fd = raw_socket(SOCK_STREAM)?;
    if let Err(err) = bind_fd(fd, ip, port) {
        unsafe { close(fd) };
        return Err(err);
    }
    let rc = unsafe { listen(fd, 64) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe { close(fd) };
        return Err(err);
    }
    Ok(unsafe { TcpListener::from_raw_fd(fd) })
}

fn raw_socket(kind: i32) -> io::Result<RawFd> {
    let fd = unsafe { socket(AF_INET, kind | SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let one: i32 = 1;
    let rc = unsafe { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, 4) };
    if rc != 0 {
        let err = io::Error::last_os_error();
        unsafe { close(fd) };
        return Err(err);
    }
    Ok(fd)
}

fn bind_fd(fd: RawFd, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let addr = SockAddrIn {
        sin_family: AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: ip.octets(),
        sin_zero: [0; 8],
    };
    let rc = unsafe { bind(fd, &addr, std::mem::size_of::<SockAddrIn>() as u32) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn log(msg: &str) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{} gs-relay {msg}", utc_stamp());
    let _ = out.flush();
}

fn die(msg: &str) -> ! {
    log(msg);
    process::exit(1);
}

fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|dur| dur.as_secs() as i64)
        .unwrap_or(0);
    let days = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400) as u32;
    let (year, month, day) = civil_from_days(days);
    let hour = tod / 3600;
    let min = (tod % 3600) / 60;
    let sec = tod % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// Howard Hinnant's civil_from_days. `days` is the Unix day count.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    (year, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_epoch_and_a_known_day() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-10-15 is unix day 20741.
        assert_eq!(civil_from_days(20741), (2026, 10, 15));
    }

    fn empty() -> State {
        State {
            by_ip: HashMap::new(),
            by_flow: HashMap::new(),
        }
    }

    #[test]
    fn steer_matches_the_python_rules() {
        let mut state = empty();
        let port = 47998u16;
        let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)), 40000);
        assert!(steer(&mut state, port, client).is_none());
        state.by_ip.insert(
            Ipv4Addr::new(5, 5, 5, 5),
            MapEntry {
                pod: Ipv4Addr::new(10, 8, 0, 4),
                user: "gsuser0".into(),
            },
        );
        let forward = steer(&mut state, port, client).unwrap();
        assert_eq!(
            forward.dest,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 4)), port)
        );
        assert_eq!(forward.user, "gsuser0");
        let pod = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 4)), 50000);
        let back = steer(&mut state, port, pod).unwrap();
        assert_eq!(back.dest, client);
        let other = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 40001);
        state.by_ip.insert(
            Ipv4Addr::new(9, 9, 9, 9),
            MapEntry {
                pod: Ipv4Addr::new(10, 8, 0, 4),
                user: "gsuser1".into(),
            },
        );
        steer(&mut state, port, other).unwrap();
        let back = steer(&mut state, port, pod).unwrap();
        assert_eq!(back.dest, other);
        assert_eq!(back.user, "gsuser1");
    }

    #[test]
    fn udp_socket_binds() {
        let sock = bind_udp(Ipv4Addr::LOCALHOST, 0).unwrap();
        assert!(sock.local_addr().unwrap().port() > 0);
    }

    #[test]
    fn udp_roundtrip_across_loopback() {
        let sock = bind_udp(Ipv4Addr::new(127, 0, 0, 4), 0).unwrap();
        let port = sock.local_addr().unwrap().port();
        let other = UdpSocket::bind("127.0.0.3:0").unwrap();
        other
            .send_to(
                b"hi",
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 4)), port),
            )
            .unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut buf = [0u8; 8];
        let (n, src) = sock.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hi");
        assert_eq!(src.ip(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 3)));
    }
}
