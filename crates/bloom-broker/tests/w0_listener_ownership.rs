#[cfg(target_os = "linux")]
mod linux {
    use bloom_broker::ceremony::CeremonyBroker;
    use std::{
        io::{BufRead as _, Read as _, Write as _},
        os::unix::process::CommandExt as _,
        process::{Command, Stdio},
    };

    const CHILD_MODE: &str = "BLOOM_W0_LISTENER_CHILD";
    const FIRST_UID: u32 = 61_001;
    const SECOND_UID: u32 = 61_002;

    #[test]
    fn two_cross_uid_brokers_fail_closed_on_the_canonical_listener() {
        match std::env::var(CHILD_MODE).as_deref() {
            Ok("hold") => {
                let _listener = CeremonyBroker::bind_canonical()
                    .expect("first Broker must acquire the canonical listener");
                println!("BLOOM_W0_READY");
                std::io::stdout().flush().unwrap();
                let mut release = [0_u8; 1];
                let _ = std::io::stdin().read(&mut release);
                return;
            }
            Ok("conflict") => {
                let error = CeremonyBroker::bind_canonical()
                    .expect_err("second Broker must not share the canonical listener");
                eprintln!("{error}");
                assert!(error.message.contains("fatal canonical ceremony listener"));
                assert!(error.message.contains("no fallback port"));
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

        let executable = std::env::current_exe().expect("locate integration-test executable");
        let test_name = "linux::two_cross_uid_brokers_fail_closed_on_the_canonical_listener";
        let mut first = Command::new(&executable);
        first
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_MODE, "hold")
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
            "first Broker did not acquire the canonical listener: {ready:?}"
        );

        let second = Command::new(&executable)
            .args(["--exact", test_name, "--nocapture"])
            .env(CHILD_MODE, "conflict")
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
        assert!(second_stderr.contains("fatal canonical ceremony listener"));
        assert!(second_stderr.contains("no fallback port"));

        drop(first.stdin.take());
        let first_status = first.wait().expect("wait for first Broker");
        assert!(
            first_status.success(),
            "first Broker failed: {first_status}"
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn cross_uid_listener_ownership_is_exercised_in_the_linux_privileged_lane() {
    // macOS exercises the equivalent behavior through the rendered,
    // code-signed LaunchAgent because changing effective UIDs is not the
    // selected macOS sandbox construction.
}
