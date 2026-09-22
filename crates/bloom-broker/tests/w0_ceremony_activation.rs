//! Linux ceremony-listener acquisition.
//!
//! The Linux unit set publishes two `ListenStream=` entries under different
//! `FileDescriptorName=` values (one per loopback family) and passes both
//! descriptors to the Broker through `Sockets=`/`LISTEN_FDS`. The Broker
//! must therefore consume those two descriptors and never bind the
//! configured addresses itself — a second bind can only ever fail with
//! `EADDRINUSE`, and the bind helpers have deliberately no fallback port,
//! so the service would exit.
//!
//! The inherited-listener cases run the real acquisition in a child process
//! with genuine descriptors while the parent still holds both addresses. If
//! the Broker attempted its own bind, the children could not succeed: the
//! parent's listeners prove the ports are already taken.
//!
//! Ordinary socket tests never claim 18734: each run selects an ephemeral
//! IPv4 port, holds it, binds IPv6 on the same port (retrying on collision),
//! and passes the resulting endpoint to activation children alongside their
//! inherited descriptors.

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use bloom_broker::ceremony::{CeremonyBroker, CeremonyEndpoint};

const CHILD_MODE: &str = "BLOOM_CEREMONY_ACTIVATION_CHILD";
const CHILD_PORT: &str = "BLOOM_CEREMONY_TEST_PORT";
const ACTIVATION_NAME_V4: &str = "broker-ceremony-ipv4";
const ACTIVATION_NAME_V6: &str = "broker-ceremony-ipv6";
const EXIT_REFUSED: i32 = 72;
/// The single test the child re-exec must run so it reaches `run_child`.
const CHILD_TEST: &str = "linux_ceremony_listeners_are_inherited_and_never_rebound";

/// Bind IPv4 on port 0, hold it, bind IPv6 on the same port, and return the
/// held pair plus its explicit nonzero endpoint. Retries if the IPv6 bind
/// collides. Test setup only, not a product port allocator.
fn ephemeral_endpoint_pair() -> (TcpListener, TcpListener, CeremonyEndpoint) {
    loop {
        let v4 = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
            .expect("bind ephemeral IPv4 loopback");
        let port = v4.local_addr().expect("ephemeral v4 address").port();
        assert_ne!(port, 0, "ephemeral bind must select a nonzero port");
        assert_ne!(
            port, 18_734,
            "ephemeral test pair must not claim the installed ceremony port"
        );
        let endpoint = CeremonyEndpoint::new(port).expect("ephemeral port is valid");
        match TcpListener::bind(endpoint.addr_v6()) {
            Ok(v6) => return (v4, v6, endpoint),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("bind ephemeral IPv6 loopback: {error}"),
        }
    }
}

fn child_endpoint() -> CeremonyEndpoint {
    let port: u16 = std::env::var(CHILD_PORT)
        .expect("activation child requires a test port")
        .parse()
        .expect("activation child port is numeric");
    CeremonyEndpoint::new(port).expect("activation child port is valid")
}

/// `dup` the listener so the child can move the copy to descriptor 3.
fn duplicate(raw: i32) -> OwnedFd {
    let duplicated = unsafe { libc::dup(raw) };
    assert!(
        duplicated >= 0,
        "dup failed: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

/// Re-exec this test binary as a child that receives `v4` and `v6` as
/// descriptors 3 and 4, exactly as systemd hands a `.socket` unit's
/// descriptors to its service.
fn spawn_child(
    mode: &str,
    v4: &TcpListener,
    v6: &TcpListener,
    names: &str,
    count: &str,
    port: u16,
) -> std::process::Output {
    let v4_copy = duplicate(v4.as_raw_fd());
    let v6_copy = duplicate(v6.as_raw_fd());
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env(CHILD_PORT, port.to_string())
        .env("LISTEN_FDS", count)
        .env("LISTEN_FDNAMES", names)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let v4_raw = v4_copy.into_raw_fd();
    let v6_raw = v6_copy.into_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(v4_raw, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::dup2(v6_raw, 4) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            for fd in [3, 4] {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().expect("spawn activation child");
    let output = child.wait_with_output().expect("activation child output");
    unsafe {
        libc::close(v4_raw);
        libc::close(v6_raw);
    }
    output
}

/// The child half: run the real acquisition and report what happened.
fn run_child(mode: &str) -> ! {
    unsafe { std::env::set_var("LISTEN_PID", std::process::id().to_string()) };
    let endpoint = child_endpoint();
    let result = CeremonyBroker::acquire_canonical_loopback_listeners(
        ACTIVATION_NAME_V4,
        ACTIVATION_NAME_V6,
        endpoint,
    );
    match (mode, result) {
        ("inherit", Ok((v4, v6))) => {
            let v4_addr = v4.local_addr().expect("inherited v4 listener address");
            let v6_addr = v6.local_addr().expect("inherited v6 listener address");
            println!("INHERITED {v4_addr} {v6_addr}");
            std::io::stdout().flush().unwrap();
            std::process::exit(0);
        }
        ("inherit", Err(error)) => {
            eprintln!("UNEXPECTED_ERROR {}", error.message);
            std::process::exit(70);
        }
        (_, Ok(_)) => {
            eprintln!("UNEXPECTED_SUCCESS");
            std::process::exit(71);
        }
        (_, Err(error)) => {
            eprintln!("REFUSED {}", error.message);
            std::process::exit(EXIT_REFUSED);
        }
    }
}

#[test]
fn linux_ceremony_listeners_are_inherited_and_never_rebound() {
    if let Ok(mode) = std::env::var(CHILD_MODE) {
        run_child(&mode);
    }

    // Hold both configured addresses for the whole test. Every child below
    // runs while they are held, so any attempt to bind either would fail.
    let (held_v4, held_v6, endpoint) = ephemeral_endpoint_pair();
    let expected_v4 = endpoint.addr_v4();
    let expected_v6 = endpoint.addr_v6();

    // The verifier accepts a listener that really is on the configured IPv4
    // address.
    let checked = CeremonyBroker::require_canonical_loopback_listener(
        duplicate(held_v4.as_raw_fd()).into(),
        expected_v4,
    )
    .expect("the configured IPv4 address must be accepted");
    assert_eq!(checked.local_addr().unwrap(), expected_v4);
    drop(checked);

    // A descriptor on any other address is refused, and the refusal names
    // the observed and expected addresses.
    let wrong = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind an ephemeral listener");
    let observed = wrong.local_addr().unwrap();
    assert_ne!(observed, expected_v4);
    assert_ne!(observed, expected_v6);
    let refused = CeremonyBroker::require_canonical_loopback_listener(wrong, expected_v4)
        .expect_err("a listener on another address must never be served");
    assert!(
        refused.message.contains(&observed.to_string()),
        "the refusal must name the observed address: {}",
        refused.message
    );
    assert!(
        refused.message.contains(&expected_v4.to_string()),
        "the refusal must name the expected address: {}",
        refused.message
    );

    // Swapped families are refused even though both addresses are loopback.
    let swapped = CeremonyBroker::require_canonical_loopback_listener(
        duplicate(held_v6.as_raw_fd()).into(),
        expected_v4,
    )
    .expect_err("swapped loopback families must never be served");
    assert!(
        swapped.message.contains(&expected_v4.to_string()),
        "the refusal must name the expected address: {}",
        swapped.message
    );

    // Wildcards are refused.
    let wildcard = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        endpoint.port(),
    )));
    if let Ok(wildcard) = wildcard {
        let observed = wildcard.local_addr().unwrap();
        let refused = CeremonyBroker::require_canonical_loopback_listener(wildcard, expected_v4)
            .expect_err("a wildcard listener must never be served");
        assert!(
            refused.message.contains(&observed.to_string()),
            "the refusal must name the observed address: {}",
            refused.message
        );
    }

    // The load-bearing case: the child acquires BOTH configured listeners
    // while the parent still holds them. Success is only possible by
    // consuming both inherited descriptors, because binding would return
    // EADDRINUSE.
    let output = spawn_child(
        "inherit",
        &held_v4,
        &held_v6,
        &format!("{ACTIVATION_NAME_V4}:{ACTIVATION_NAME_V6}"),
        "2",
        endpoint.port(),
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the Broker must consume both inherited listeners while the addresses are held.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains(&format!("INHERITED {expected_v4} {expected_v6}")),
        "the child must report both configured addresses.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Fail-closed cases. None of these may fall back to binding, which the
    // held addresses would prevent anyway — they must refuse explicitly.
    for (mode, names, count, why) in [
        (
            "misnamed",
            "some-other-name",
            "2",
            "a descriptor under another name",
        ),
        (
            "duplicated",
            &format!("{ACTIVATION_NAME_V4}:{ACTIVATION_NAME_V4}"),
            "2",
            "a duplicated descriptor name",
        ),
        (
            "count-mismatch",
            &format!("{ACTIVATION_NAME_V4}:{ACTIVATION_NAME_V6}"),
            "1",
            "a name/count disagreement",
        ),
    ] {
        let output = spawn_child(mode, &held_v4, &held_v6, names, count, endpoint.port());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(EXIT_REFUSED),
            "{why} must be refused.\nstderr: {stderr}"
        );
        assert!(stderr.contains("REFUSED"), "{why}: {stderr}");
    }

    drop(held_v4);
    drop(held_v6);
}

#[test]
fn a_service_with_no_inherited_descriptors_refuses_rather_than_binding() {
    if std::env::var(CHILD_MODE).is_ok() {
        return;
    }
    // No LISTEN_FDS at all: the configured addresses are free here, so a
    // Broker that fell back to binding would succeed. It must not.
    let (_held_v4, _held_v6, endpoint) = ephemeral_endpoint_pair();
    // Hold the pair while the child runs so the port cannot be recycled; the
    // child has no descriptors and must refuse without binding.
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, "no-activation")
        .env(CHILD_PORT, endpoint.port().to_string())
        .env_remove("LISTEN_FDS")
        .env_remove("LISTEN_FDNAMES")
        .env_remove("LISTEN_PID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .spawn()
        .expect("spawn activation child")
        .wait_with_output()
        .expect("activation child output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(EXIT_REFUSED),
        "a Broker with no inherited descriptor must refuse, never bind.\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("socket-activated") || stderr.contains("LISTEN_FDS"),
        "the refusal must explain that the service is socket-activated: {stderr}"
    );
}
