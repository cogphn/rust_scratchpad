//! CLI-level behaviour: config validation and bind failures.
//!
//! These run the real binary (`CARGO_BIN_EXE_*`) because the behaviour being
//! tested is what an operator sees: exit codes and stderr, not HTTP.

use std::process::Command;

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_winrm_honeypot")
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("binary must run")
}

#[test]
fn check_config_reports_the_identity_and_exits_zero() {
    let out = run(&["--config", "config.example.toml", "--check-config"]);
    assert!(out.status.success(), "exit status: {:?}", out.status);

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("config OK: 2 credentials"), "{stdout}");
    assert!(stdout.contains("0.0.0.0:5985"), "{stdout}");
}

#[test]
fn check_config_does_not_create_the_log_or_bind() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("should-not-exist.log");
    let out = run(&[
        "--config",
        "config.example.toml",
        "--check-config",
        "--log-file",
        log_path.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(
        !log_path.exists(),
        "--check-config must not touch the log file"
    );
}

#[test]
fn missing_config_file_fails_with_its_path_in_the_message() {
    let out = run(&["--config", "definitely-not-here.toml", "--check-config"]);
    assert!(!out.status.success());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("definitely-not-here.toml"),
        "stderr was: {stderr}"
    );
}

#[test]
fn invalid_config_fails_and_names_the_field() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("bad.toml");
    std::fs::write(&cfg, "[server]\nlisten = \"not-an-address\"\n").unwrap();

    let out = run(&["--config", cfg.to_str().unwrap(), "--check-config"]);
    assert!(!out.status.success());

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("listen"), "stderr was: {stderr}");
}

#[test]
fn bind_conflict_says_what_is_wrong() {
    // Hold the port, then ask the honeypot to bind it.
    let held = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = held.local_addr().unwrap();

    let out = run(&[
        "--config",
        "config.example.toml",
        "--listen",
        &addr.to_string(),
        "--log-file",
        "-",
    ]);
    assert!(!out.status.success(), "must not pretend to have started");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("already taken"), "stderr was: {stderr}");
}
