#[cfg(target_os = "linux")]
mod linux {
    use bloom_broker::ceremony::{CeremonyBroker, CeremonyEndpoint};
    use std::{
        io::{BufRead as _, Read as _, Write as _},
        net::TcpListener,
        os::unix::process::CommandExt as _,
        process::{Command, Stdio},
    };

    const CHILD_MODE: &str = "BLOOM_W0_LISTENER_CHILD";
    const PORT_ENV: &str = "BLOOM_W0_LISTENER_PORT";
    const FIRST_UID: u32 = 61_001;
    const SECOND_UID: u32 = 61_002;

    /// Endpoint under test, communicated from the root parent to both
    /// cross-UID children. The port is an ephemeral alternate selected by
    /// the parent: this test must never claim the fixed custody listener,
    /// while still proving both-address exclusivity between two principals.
    fn alternate_endpoint() -> CeremonyEndpoint {
        let port = std::env::var(PORT_ENV)
            .expect("alternate listener port")
            .parse::<u16>()
            .expect("parse alternate listener port");
        CeremonyEndpoint::new(port).expect("alternate listener endpoint")
    }

    #[test]
    fn two_cross_uid_brokers_fail_closed_on_an_alternate_listener() {
        match std::env::var(CHILD_MODE).as_deref() {
            Ok("hold") => {
                let _listeners = CeremonyBroker::bind_canonical_loopback_for(alternate_endpoint())
                    .expect("first Broker must acquire both alternate listeners");
                println!("BLOOM_W0_READY");
                std::io::stdout().flush().unwrap();
                let mut release = [0_u8; 1];
                let _ = std::io::stdin().read(&mut release);
                return;
            }
            Ok("conflict") => {
                // Probe each family independently: the Broker binds IPv4
                // first, so its pair acquisition alone cannot prove that
                // another principal is also excluded from IPv6.
                let endpoint = alternate_endpoint();
                for address in endpoint.addrs() {
                    let error = TcpListener::bind(address)
                        .expect_err("second principal must not share either alternate listener");
                    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{address}");
                    eprintln!("EXCLUSIVE {address}");
                }
                let error = CeremonyBroker::bind_canonical_loopback_for(endpoint)
                    .expect_err("second Broker must not share the alternate listener");
                eprintln!("{error}");
                assert!(
                    error
                        .message
                        .contains("cannot bind canonical ceremony listener")
                );
                assert!(error.message.contains("no fallback"));
                std::process::exit(73);
            }
            Ok(mode) => panic!("unknown W0 child mode {mode}"),
            Err(_) => {}
        }

        let effective_uid = Command::new("id")
            .arg("-u")
            .output()
            .expect("run id")
            .stdout;
        if effective_uid != b"0\n" {
            eprintln!(
                "cross-UID listener test requires the dedicated privileged CI lane; ordinary workspace test remains non-mutating"
            );
            return;
        }

        let port = select_alternate_port();
        let endpoint = CeremonyEndpoint::new(port).expect("alternate listener endpoint");
        let executable = std::env::current_exe().expect("locate integration-test executable");
        let test_name = "linux::two_cross_uid_brokers_fail_closed_on_an_alternate_listener";
        let mut first = Command::new(&executable);
        first
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_MODE, "hold")
            .env(PORT_ENV, port.to_string())
            .uid(FIRST_UID)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut first = first.spawn().expect("start first Broker principal");
        let first_stdout = first.stdout.take().expect("capture first Broker stdout");
        let mut first_stdout = std::io::BufReader::new(first_stdout);
        let mut ready = String::new();
        loop {
            let mut line = String::new();
            let count = first_stdout
                .read_line(&mut line)
                .expect("read first Broker readiness");
            ready.push_str(&line);
            if line.contains("BLOOM_W0_READY") || count == 0 {
                break;
            }
        }
        assert!(
            ready.contains("BLOOM_W0_READY"),
            "first Broker did not acquire the alternate listener: {ready:?}"
        );

        let second = Command::new(&executable)
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_MODE, "conflict")
            .env(PORT_ENV, port.to_string())
            .uid(SECOND_UID)
            .output()
            .expect("start second Broker principal");
        assert_eq!(
            second.status.code(),
            Some(73),
            "second Broker did not exit through the fatal conflict path:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&second.stdout),
            String::from_utf8_lossy(&second.stderr)
        );
        let second_stderr = String::from_utf8_lossy(&second.stderr);
        for address in endpoint.addrs() {
            assert!(
                second_stderr.contains(&format!("EXCLUSIVE {address}")),
                "second principal did not verify exclusivity for {address}: {second_stderr}"
            );
        }
        assert!(second_stderr.contains("cannot bind canonical ceremony listener"));
        assert!(second_stderr.contains("no fallback port"));

        drop(first.stdin.take());
        let first_status = first.wait().expect("wait for first Broker");
        assert!(
            first_status.success(),
            "first Broker failed: {first_status}"
        );
    }

    /// Select an available alternate port without claiming the fixed custody
    /// listener. Binds IPv4 port zero, keeps the assigned port, and drops
    /// the probe; the hold child then exclusively acquires both families.
    fn select_alternate_port() -> u16 {
        let probe =
            TcpListener::bind("127.0.0.1:0").expect("select an available alternate listener port");
        probe
            .local_addr()
            .expect("read alternate listener port")
            .port()
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn cross_uid_listener_ownership_is_exercised_in_the_linux_privileged_lane() {
    // macOS exercises the equivalent behavior with two installer-provisioned
    // Unix service principals in the guarded disposable two-login W0 lane.
}
