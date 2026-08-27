//! Linux ceremony-listener acquisition.
//!
//! The Linux unit set binds 127.0.0.1:18734 in a `.socket` unit and passes the
//! descriptor to the Broker through `Sockets=`/`LISTEN_FDS`. The Broker must
//! therefore consume that descriptor and never bind the address itself — a
//! second bind can only ever fail with `EADDRINUSE`, and `bind_canonical` has
//! deliberately no fallback port, so the service would exit.
//!
//! The inherited-listener cases run the real acquisition in a child process
//! with a genuine descriptor while the parent still holds the address. If the
//! Broker attempted its own bind, the child could not succeed: the parent's
//! listener proves the port is already taken.
//!
//! Everything that needs the canonical address lives in a single test, so the
//! address is held once and released once rather than raced between tests.

#![cfg(target_os = "linux")]

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::os::fd::{AsRawFd as _, FromRawFd as _, IntoRawFd as _, OwnedFd};
use std::os::unix::process::CommandExt as _;
use std::process::{Command, Stdio};

use bloom_broker::ceremony::{CEREMONY_ADDR, CeremonyBroker};

const CHILD_MODE: &str = "BLOOM_CEREMONY_ACTIVATION_CHILD";
const ACTIVATION_NAME: &str = "broker-ceremony";
const EXIT_REFUSED: i32 = 72;
/// The single test the child re-exec must run so it reaches `run_child`.
const CHILD_TEST: &str = "linux_ceremony_listener_is_inherited_and_never_rebound";

/// `dup` the listener so the child can move the copy to descriptor 3.
fn duplicate(raw: i32) -> OwnedFd {
    // SAFETY: `raw` is an open descriptor owned by the caller's listener, and
    // the duplicate is adopted into an OwnedFd that closes exactly once.
    let duplicated = unsafe { libc::dup(raw) };
    assert!(
        duplicated >= 0,
        "dup failed: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: `duplicated` is a fresh, open, owned descriptor.
    unsafe { OwnedFd::from_raw_fd(duplicated) }
}

/// Re-exec this test binary as a child that receives `listener` as descriptor
/// 3, exactly as systemd hands a socket unit's descriptor to its service.
fn spawn_child(
    mode: &str,
    listener: &TcpListener,
    names: &str,
    count: &str,
) -> std::process::Output {
    let copy = duplicate(listener.as_raw_fd());
    let mut command = Command::new(std::env::current_exe().unwrap());
    // Re-execing this binary re-enters the test harness, so name the single
    // test to run. Without this the child can execute a different test, exit
    // cleanly, and never reach the acquisition under test.
    command
        .arg(CHILD_TEST)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_MODE, mode)
        .env("LISTEN_FDS", count)
        .env("LISTEN_FDNAMES", names)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let raw = copy.into_raw_fd();
    // SAFETY: the closure runs between fork and exec in the child and calls
    // only async-signal-safe dup2/fcntl.
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(raw, 3) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // systemd passes descriptors without CLOEXEC so they survive exec.
            let flags = libc::fcntl(3, libc::F_GETFD);
            if flags == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::fcntl(3, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    // LISTEN_PID cannot be written here: the child's pid is unknown until
    // after spawn. The child sets it to its own pid, which is exactly the
    // value systemd would have written.
    let child = command.spawn().expect("spawn activation child");
    let output = child.wait_with_output().expect("activation child output");
    // SAFETY: `raw` was duplicated for the child and is unused in the parent
    // after spawn; closing it once here releases the parent's copy.
    unsafe { libc::close(raw) };
    output
}

/// The child half: run the real acquisition and report what happened.
fn run_child(mode: &str) -> ! {
    // SAFETY: single-threaded at this point in the child, before any
    // acquisition reads the environment.
    unsafe { std::env::set_var("LISTEN_PID", std::process::id().to_string()) };
    let result = CeremonyBroker::acquire_canonical_listener(ACTIVATION_NAME);
    match (mode, result) {
        ("inherit", Ok(listener)) => {
            let address = listener.local_addr().expect("inherited listener address");
            println!("INHERITED {address}");
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
fn linux_ceremony_listener_is_inherited_and_never_rebound() {
    if let Ok(mode) = std::env::var(CHILD_MODE) {
        run_child(&mode);
    }

    // Hold the canonical address for the whole test. Every child below runs
    // while it is held, so any attempt to bind it would fail.
    // A developer running the triad harness locally already owns this address,
    // and the failure would otherwise look like a product defect rather than a
    // busy port.
    let held = TcpListener::bind(CEREMONY_ADDR).unwrap_or_else(|error| {
        panic!(
            "this test needs the canonical ceremony address {CEREMONY_ADDR} to be free, but \
             binding it failed: {error}. A running Broker or triad harness holds it; stop that \
             first."
        )
    });

    // The verifier accepts a listener that really is on the canonical address.
    let checked = CeremonyBroker::require_canonical_listener(duplicate(held.as_raw_fd()).into())
        .expect("the canonical address must be accepted");
    assert_eq!(checked.local_addr().unwrap(), CEREMONY_ADDR);
    drop(checked);

    // A descriptor on any other address is refused, and the refusal names the
    // address actually observed.
    let wrong = TcpListener::bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)))
        .expect("bind an ephemeral listener");
    let observed = wrong.local_addr().unwrap();
    assert_ne!(observed, CEREMONY_ADDR);
    let refused = CeremonyBroker::require_canonical_listener(wrong)
        .expect_err("a listener on another address must never be served");
    assert!(
        refused.message.contains("not the canonical"),
        "{}",
        refused.message
    );
    assert!(
        refused.message.contains(&observed.to_string()),
        "the refusal must name the observed address: {}",
        refused.message
    );

    // The load-bearing case: the child acquires the listener while the parent
    // still holds the address. Success is only possible by consuming the
    // inherited descriptor, because binding would return EADDRINUSE.
    let output = spawn_child("inherit", &held, ACTIVATION_NAME, "1");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the Broker must consume the inherited listener while the address is \
         held.\nstdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains(&format!("INHERITED {CEREMONY_ADDR}")),
        "the child must report the canonical address.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // Fail-closed cases. None of these may fall back to binding, which the
    // held address would prevent anyway — they must refuse explicitly.
    for (mode, names, count, why) in [
        (
            "misnamed",
            "some-other-name",
            "1",
            "a descriptor under another name",
        ),
        (
            "duplicated",
            "broker-ceremony:broker-ceremony",
            "2",
            "a duplicated descriptor name",
        ),
        (
            "count-mismatch",
            ACTIVATION_NAME,
            "2",
            "a name/count disagreement",
        ),
    ] {
        let output = spawn_child(mode, &held, names, count);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(EXIT_REFUSED),
            "{why} must be refused.\nstderr: {stderr}"
        );
        assert!(stderr.contains("REFUSED"), "{why}: {stderr}");
    }

    drop(held);
}

#[test]
fn a_service_with_no_inherited_descriptors_refuses_rather_than_binding() {
    if std::env::var(CHILD_MODE).is_ok() {
        return;
    }
    // No LISTEN_FDS at all: the canonical address is free here, so a Broker
    // that fell back to binding would succeed. It must not.
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
