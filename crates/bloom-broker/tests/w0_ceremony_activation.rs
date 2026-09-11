//! Linux ceremony-listener acquisition.
//!
//! The Linux unit set publishes two `ListenStream=` entries under different
//! `FileDescriptorName=` values (one per loopback family) and passes both
//! descriptors to the Broker through `Sockets=`/`LISTEN_FDS`. The Broker
//! must therefore consume those two descriptors and never bind the
//! canonical addresses itself — a second bind can only ever fail with
//! `EADDRINUSE`, and the canonical bind helpers have deliberately no
//! fallback port, so the service would exit.
//!
//! The inherited-listener cases run the real acquisition in a child process
//! with genuine descriptors while the parent still holds both addresses. If
//! the Broker attempted its own bind, the children could not succeed: the
//! parent's listeners prove the ports are already taken.
//!
//! Every test that needs the canonical addresses holds them for the
//! duration of the children, so the addresses are held once and released
//! once rather than raced between tests.

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use bloom_broker::ceremony::{
    CEREMONY_ADDR_V4, CEREMONY_ADDR_V6, CEREMONY_LOOPBACK_ADDRS, CeremonyBroker,
};

const CHILD_MODE: &str = "BLOOM_CEREMONY_ACTIVATION_CHILD";
const ACTIVATION_NAME_V4: &str = "broker-ceremony-ipv4";
const ACTIVATION_NAME_V6: &str = "broker-ceremony-ipv6";
const EXIT_REFUSED: i32 = 72;
/// The single test the child re-exec must run so it reaches `run_child`.
const CHILD_TEST: &str = "linux_ceremony_listeners_are_inherited_and_never_rebound";

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
) -> std::process::Output {
    let v4_copy = duplicate(v4.as_raw_fd());
    let v6_copy = duplicate(v6.as_raw_fd());
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
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
    let result = CeremonyBroker::acquire_canonical_loopback_listeners(
        ACTIVATION_NAME_V4,
        ACTIVATION_NAME_V6,
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

    // Hold both canonical addresses for the whole test. Every child below
    // runs while they are held, so any attempt to bind either would fail.
    let held_v4 = TcpListener::bind(CEREMONY_ADDR_V4)
        .expect("the test must own the canonical IPv4 address before the children run");
    let held_v6 = TcpListener::bind(CEREMONY_ADDR_V6)
        .expect("the test must own the canonical IPv6 address before the children run");

    // The verifier accepts a listener that really is on the canonical IPv4
    // address.
    let checked = CeremonyBroker::require_canonical_loopback_listener(
        duplicate(held_v4.as_raw_fd()).into(),
        CEREMONY_ADDR_V4,
    )
    .expect("the canonical IPv4 address must be accepted");
    assert_eq!(checked.local_addr().unwrap(), CEREMONY_ADDR_V4);
    drop(checked);

    // A descriptor on any other address is refused, and the refusal names
    // every canonical loopback address so the operator can see what would
    // have been accepted.
    let wrong = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind an ephemeral listener");
    let observed = wrong.local_addr().unwrap();
    assert!(!CEREMONY_LOOPBACK_ADDRS.contains(&observed));
    let refused = CeremonyBroker::require_canonical_loopback_listener(wrong, CEREMONY_ADDR_V4)
        .expect_err("a listener on another address must never be served");
    assert!(
        refused.message.contains(&observed.to_string()),
        "the refusal must name the observed address: {}",
        refused.message
    );
    assert!(
        refused.message.contains(&CEREMONY_ADDR_V6.to_string())
            || refused.message.contains("[::1]:18734"),
        "the refusal must list a canonical loopback address: {}",
        refused.message
    );

    // The load-bearing case: the child acquires BOTH canonical listeners
    // while the parent still holds them. Success is only possible by
    // consuming both inherited descriptors, because binding would return
    // EADDRINUSE.
    let output = spawn_child(
        "inherit",
        &held_v4,
        &held_v6,
        &format!("{ACTIVATION_NAME_V4}:{ACTIVATION_NAME_V6}"),
        "2",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the Broker must consume both inherited listeners while the addresses are held.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains(&format!("INHERITED {CEREMONY_ADDR_V4} {CEREMONY_ADDR_V6}")),
        "the child must report both canonical addresses.\nstdout: {stdout}\nstderr: {stderr}"
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
        let output = spawn_child(mode, &held_v4, &held_v6, names, count);
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
    // No LISTEN_FDS at all: the canonical addresses are free here, so a
    // Broker that fell back to binding would succeed. It must not.
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, "no-activation")
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
