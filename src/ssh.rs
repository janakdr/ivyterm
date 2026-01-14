use std::{
    io::{self, BufRead, BufReader},
    net::{SocketAddr, ToSocketAddrs},
    process::Command,
    time::Duration,
};

use log::debug;
use mio::{net::TcpStream, Events, Interest, Poll, Token};
use ssh2::{DisconnectCode, Session};

pub enum SSHData {
    Native(String, Session, Poll, Events),
    Binary(String),
}

pub const SSH_TOKEN: Token = Token(0);
const TCP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Default)]
pub struct SystemSshConfig {
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub user: Option<String>,
    pub proxy_command: Option<String>,
    // Fields for ssh2 configuration
    pub compression: Option<bool>,
    pub tcp_keep_alive: Option<bool>,
    pub server_alive_interval: Option<Duration>,
    pub kex_algorithms: Option<Vec<String>>,
    pub host_key_algorithms: Option<Vec<String>>,
    pub ciphers: Option<Vec<String>>,
    pub mac: Option<Vec<String>>,
}

pub fn query_system_ssh_config(host: &str) -> io::Result<SystemSshConfig> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg(host)
        .output()?;

    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("ssh -G failed: {}", String::from_utf8_lossy(&output.stderr)),
        ));
    }

    let mut config = SystemSshConfig::default();
    let reader = BufReader::new(io::Cursor::new(output.stdout));

    for line in reader.lines() {
        let line = line?;
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        if parts.len() < 2 {
            continue;
        }
        let key = parts[0].to_lowercase();
        let value = parts[1].trim();

        match key.as_str() {
            "hostname" => config.hostname = Some(value.to_string()),
            "port" => config.port = value.parse().ok(),
            "user" => config.user = Some(value.to_string()),
            "proxycommand" => {
                if value != "none" {
                    config.proxy_command = Some(value.to_string())
                }
            }
            "compression" => config.compression = Some(value == "yes"),
            "tcpkeepalive" => config.tcp_keep_alive = Some(value == "yes"),
            "serveraliveinterval" => {
                if let Ok(secs) = value.parse::<u64>() {
                    if secs > 0 {
                        config.server_alive_interval = Some(Duration::from_secs(secs));
                    }
                }
            }
             "kexalgorithms" => {
                 config.kex_algorithms = Some(value.split(',').map(|s| s.to_string()).collect())
             }
             "hostkeyalgorithms" => {
                 config.host_key_algorithms = Some(value.split(',').map(|s| s.to_string()).collect())
             }
             "ciphers" => {
                 config.ciphers = Some(value.split(',').map(|s| s.to_string()).collect())
             }
             "macs" => {
                 config.mac = Some(value.split(',').map(|s| s.to_string()).collect())
             }
            _ => {}
        }
    }

    Ok(config)
}


#[inline]
fn check_connected(tcp: &mut TcpStream) -> Result<(), ()> {
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(1024);
    poll.registry()
        .register(tcp, SSH_TOKEN, Interest::WRITABLE | Interest::READABLE)
        .unwrap();

    //  3. Wait for a (writable) event.
    loop {
        if let Err(_) = poll.poll(&mut events, Some(TCP_TIMEOUT)) {
            return Err(());
        }

        for event in events.iter() {
            if event.is_error() || event.is_write_closed() || event.is_read_closed() {
                return Err(());
            }

            match event.token() {
                SSH_TOKEN => {
                    //  4. Check `TcpStream::take_error`. If it returns an error, then
                    //     something went wrong. If it returns `Ok(None)`, then proceed to
                    //     step 5.
                    if let Err(err) = tcp.take_error() {
                        debug!("Something went wrong {}", err);
                        poll.registry().deregister(tcp).unwrap();
                        return Err(());
                    }
                    //  5. Check `TcpStream::peer_addr`. If it returns `libc::EINPROGRESS` or
                    //     `ErrorKind::NotConnected` it means the stream is not yet connected,
                    //     go back to step 3. If it returns an address it means the stream is
                    //     connected, go to step 6. If another error is returned something
                    //     went wrong.
                    if let Err(err) = tcp.peer_addr() {
                        if err.kind() == std::io::ErrorKind::NotConnected {
                            continue;
                        }
                        if err.raw_os_error() == Some(115) {
                            debug!("libc::EINPROGRESS");
                            continue;
                        }
                        poll.registry().deregister(tcp).unwrap();
                        return Err(());
                    }

                    poll.registry().deregister(tcp).unwrap();
                    return Ok(());
                }
                _ => unreachable!(),
            }
        }
    }
}

///  1. Call `TcpStream::connect`
///  2. Register the returned stream with at least [write interest].
///  3. Wait for a (writable) event.
///  4. Check `TcpStream::take_error`. If it returns an error, then
///     something went wrong. If it returns `Ok(None)`, then proceed to
///     step 5.
///  5. Check `TcpStream::peer_addr`. If it returns `libc::EINPROGRESS` or
///     `ErrorKind::NotConnected` it means the stream is not yet connected,
///     go back to step 3. If it returns an address it means the stream is
///     connected, go to step 6. If another error is returned something
///     went wrong.
///  6. Now the stream can be used.
fn connect_tcp(host: &str) -> Option<(TcpStream, Poll, Events)> {
    debug!("Connecting to host {}...", host);
    let socket_addresses: Vec<SocketAddr> = match host.to_socket_addrs() {
        Ok(s) => s.collect(),
        Err(err) => {
            eprintln!("Could not parse host: {}", err);
            return None;
        }
    };

    for socket_addr in socket_addresses.into_iter() {
        let mut tcp = match TcpStream::connect(socket_addr) {
            Ok(stream) => stream,
            Err(_) => {
                debug!("Continuing with next TCP stream");
                continue;
            }
        };

        if let Ok(_) = check_connected(&mut tcp) {
            let poll = Poll::new().unwrap();
            let events = Events::with_capacity(1024);
            poll.registry()
                .register(&mut tcp, SSH_TOKEN, Interest::WRITABLE | Interest::READABLE)
                .unwrap();

            return Some((tcp, poll, events));
        }
    }

    return None;
}

pub fn new_session(host: &str, password: &str) -> Result<SSHData, ()> {
    let original_host = host.to_string();
    let params = match query_system_ssh_config(host) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to query system ssh config: {}", e);
            return Err(());
        }
    };

    // Parse SSH host (resolved from ssh -G)
    // ssh -G returns the final hostname and port.
    // If the original host string had user@, ssh -G handles it.
    // But wait, if I pass `user@host` to `ssh -G`, it returns `user` and `hostname`.

    let host_addr = params.hostname.as_deref().unwrap_or(host);
    let port = params.port.unwrap_or(22);
    let full_host_addr = format!("{}:{}", host_addr, port);

    // Parse username
    let username = match params.user.as_ref() {
        Some(u) => u.clone(),
        None => {
             // Fallback if ssh -G didn't give user (unlikely)
             if host.contains("@") {
                 host.split("@").next().unwrap().to_string()
             } else {
                eprintln!("No username provided for SSH");
                return Err(());
             }
        }
    };
    debug!("SSH username: {}, host: {}", username, full_host_addr);

    if params.proxy_command.is_some() {
        // If ProxyCommand is present, we use the binary SSH client directly
        // because libssh2 often lacks support for modern crypto algorithms
        // required by servers that use ProxyCommand.
        eprintln!("ProxyCommand detected, using system ssh binary for {}", original_host);
        return Ok(SSHData::Binary(original_host));
    }

    // Connect to host
    let (tcp, poll, events) = match connect_tcp(&full_host_addr) {
        Some(ret) => ret,
        None => {
            return Err(());
        }
    };

    // Create SSH session
    let mut session = Session::new().map_err(|e| {
        eprintln!("Failed to create SSH session: {}", e);
    })?;
    configure_session(&mut session, &params);
    session.set_tcp_stream(tcp);
    if let Err(e) = session.handshake() {
        eprintln!("SSH handshake failed: {}", e);
        return Err(());
    }

    // Authenticate
    let code = match session.userauth_agent(&username) {
        Ok(_) => {
            return Ok(SSHData::Native(original_host, session, poll, events));
        }
        Err(err) => err.code(),
    };

    match code {
        ssh2::ErrorCode::Session(-18) => {
            debug!("Error authenticating with user agent, trying password")
        }
        _ => {
            let _ = session.disconnect(Some(DisconnectCode::AuthCancelledByUser), "", None);
            return Err(());
        }
    }

    if let Err(err) = session.userauth_password(&username, password) {
        eprintln!(
            "Both public key and password authentication failed: {}!",
            err
        );
        {
            let _ = session.disconnect(Some(DisconnectCode::AuthCancelledByUser), "", None);
            return Err(());
        };
    }

    if !session.authenticated() {
        eprintln!("Authentication failed without reason!");
        {
            let _ = session.disconnect(Some(DisconnectCode::AuthCancelledByUser), "", None);
            return Err(());
        };
    }

    println!("Established connection with {}", full_host_addr);
    return Ok(SSHData::Native(original_host, session, poll, events));
}

fn configure_session(session: &mut Session, params: &SystemSshConfig) {
    if let Some(compress) = params.compression {
        debug!("compression: {}", compress);
        session.set_compress(compress);
    }
    if params.tcp_keep_alive.unwrap_or(false) && params.server_alive_interval.is_some() {
        let interval = params.server_alive_interval.unwrap().as_secs() as u32;
        debug!("keepalive interval: {} seconds", interval);
        session.set_keepalive(true, interval);
    }
    // crypto algos
    // We intentionally do NOT apply crypto preferences (kex, ciphers, macs) from ssh -G.
    // ssh -G returns the configuration of the system `ssh` client (OpenSSH), which often
    // includes modern algorithms that `libssh2` does not support.
    // Enforcing these preferences can cause `libssh2` to fail handshake if it cannot
    // match the preferred algorithms with the server, or if the intersection is empty/invalid.
    // We let `libssh2` use its default supported algorithms, which gives the best chance
    // of connecting.

    /*
    if let Some(algos) = params.kex_algorithms.as_deref() {
        if let Err(err) = session.method_pref(MethodType::Kex, algos.join(",").as_str()) {
            debug!("Could not set KEX algorithms: {}", err);
        }
    }
    if let Some(algos) = params.host_key_algorithms.as_deref() {
        if let Err(err) = session.method_pref(MethodType::HostKey, algos.join(",").as_str()) {
            debug!("Could not set host key algorithms: {}", err);
        }
    }
    if let Some(algos) = params.ciphers.as_deref() {
        if let Err(err) = session.method_pref(MethodType::CryptCs, algos.join(",").as_str()) {
            debug!("Could not set crypt algorithms (client-server): {}", err);
        }
        if let Err(err) = session.method_pref(MethodType::CryptSc, algos.join(",").as_str()) {
            debug!("Could not set crypt algorithms (server-client): {}", err);
        }
    }
    if let Some(algos) = params.mac.as_deref() {
        if let Err(err) = session.method_pref(MethodType::MacCs, algos.join(",").as_str()) {
            debug!("Could not set MAC algorithms (client-server): {}", err);
        }
        if let Err(err) = session.method_pref(MethodType::MacSc, algos.join(",").as_str()) {
            debug!("Could not set MAC algorithms (server-client): {}", err);
        }
    }
    */
}
