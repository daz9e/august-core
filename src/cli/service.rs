//! Runs August as a background service that starts at login and is restarted when it
//! crashes (not when it stops cleanly: `august stop`, `restart`): a launchd agent on macOS,
//! a systemd user unit on Linux, a scheduled task running `august supervise` on Windows. Or,
//! without the service, on its own in the background.

use crate::config;
use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::process::Command;

const LABEL: &str = "dev.august.agent";

/// `""` for the default home (`~/.august`), else a suffix naming this `AUGUST_HOME`, so each
/// home gets a service of its own.
fn suffix() -> String {
    if config::home() == home_dir().join(".august") {
        return String::new();
    }
    // FNV-1a: stable across builds, unlike std's hasher.
    let hash = config::home().to_string_lossy().bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
    format!("-{:08x}", hash as u32)
}

/// launchd label.
fn label() -> String {
    format!("{LABEL}{}", suffix())
}

/// systemd unit.
fn unit() -> String {
    format!("august{}.service", suffix())
}

/// Whether `august serve` installed the background service for this `AUGUST_HOME` (one
/// installed for another home is not this August's to stop or restart).
pub fn installed() -> bool {
    if cfg!(windows) {
        return Command::new("schtasks").args(["/Query", "/TN", &task()]).output().is_ok_and(|o| o.status.success());
    }
    let file = if cfg!(target_os = "macos") { plist_path() } else { unit_path() };
    let home = config::home().display().to_string();
    std::fs::read_to_string(file).is_ok_and(|f| f.contains(&format!("AUGUST_HOME</key><string>{}<", xml(&home))) || f.contains(&format!("AUGUST_HOME={home}\"")))
}

pub fn log_path() -> PathBuf {
    config::home().join("logs").join("august.log")
}

fn run(cmd: &mut Command) -> Result<()> {
    let out = cmd.output().with_context(|| format!("failed to run {:?}", cmd.get_program()))?;
    if !out.status.success() {
        bail!(
            "{:?} failed: {}",
            cmd.get_program(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn home_dir() -> PathBuf {
    std::env::home_dir().unwrap_or_else(|| ".".into())
}

fn plist_path() -> PathBuf {
    home_dir().join("Library/LaunchAgents").join(format!("{}.plist", label()))
}

fn unit_path() -> PathBuf {
    home_dir().join(".config/systemd/user").join(unit())
}

/// The Windows task, one per `AUGUST_HOME`.
fn task() -> String {
    let home: String = config::home().to_string_lossy().chars().map(|c| if matches!(c, '\\' | '/' | ':') { '_' } else { c }).collect();
    format!("{LABEL} {home}")
}

fn xml(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Installs the service for the current binary and working directory (where `.env` is
/// read) and starts it.
pub fn start() -> Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let dir = std::env::current_dir()?;
    let log = log_path();
    std::fs::create_dir_all(log.parent().unwrap())?;
    let path = std::env::var("PATH").unwrap_or_default();

    if cfg!(windows) {
        // `conhost --headless`: a task's console program would get a window.
        let user = format!("{}\\{}", std::env::var("USERDOMAIN").unwrap_or_default(), std::env::var("USERNAME").unwrap_or_default());
        let definition = format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>August agent</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled><UserId>{user}</UserId></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>%SystemRoot%\System32\conhost.exe</Command>
      <Arguments>--headless "{exe}" supervise "{home}"</Arguments>
      <WorkingDirectory>{dir}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"#,
            user = xml(&user),
            exe = xml(&exe.to_string_lossy()),
            home = xml(&config::home().to_string_lossy()),
            dir = xml(&dir.to_string_lossy()),
        );
        // schtasks reads the file as UTF-16.
        let file = config::home().join("august-task.xml");
        let bytes: Vec<u8> = [0xFF, 0xFE].into_iter().chain(definition.encode_utf16().flat_map(u16::to_le_bytes)).collect();
        std::fs::write(&file, bytes)?;
        let made = run(Command::new("schtasks").args(["/Create", "/F", "/TN", &task()]).arg("/XML").arg(&file));
        std::fs::remove_file(&file).ok();
        made?;
        run(Command::new("schtasks").args(["/Run", "/TN", &task()]))?;
    } else if cfg!(target_os = "macos") {
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key><array><string>{exe}</string><string>gateway</string></array>
  <key>WorkingDirectory</key><string>{dir}</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{path}</string><key>AUGUST_HOME</key><string>{home}</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key><integer>5</integer>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
            label = xml(&label()),
            exe = xml(&exe.to_string_lossy()),
            dir = xml(&dir.to_string_lossy()),
            path = xml(&path),
            log = xml(&log.to_string_lossy()),
            home = xml(&config::home().to_string_lossy()),
        );
        let file = plist_path();
        std::fs::create_dir_all(file.parent().unwrap())?;
        std::fs::write(&file, plist)?;
        let domain = format!("gui/{}", uid()?);
        // Reload if it is already installed. `bootout` returns before the old job is
        // gone, and `bootstrap` fails with "5: Input/output error" until it is.
        let target = format!("{domain}/{}", label());
        Command::new("launchctl").args(["bootout", &target]).output().ok();
        for _ in 0..50 {
            let loaded = Command::new("launchctl").args(["print", &target]).output().is_ok_and(|o| o.status.success());
            if !loaded {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        run(Command::new("launchctl").args(["bootstrap", &domain]).arg(&file))?;
        run(Command::new("launchctl").args(["kickstart", &target]))?;
    } else {
        // Without linger the user's systemd stops at logout, and on a server it may not be
        // running at all. Most systems allow it without sudo.
        let linger = Command::new("loginctl").arg("enable-linger").output().is_ok_and(|o| o.status.success());
        if !user_systemd() {
            // WSL without systemd, a container, ...: no service, so on its own.
            spawn()?;
            println!("august is running in the background (no systemd here: it won't start at login or restart on crash)");
            if !linger {
                println!("on a server, `sudo loginctl enable-linger $USER` may start it; then run `august serve` again");
            }
            println!("logs: {}   (august logs)\nstop: august stop", log.display());
            return Ok(());
        }
        let definition = format!(
            "[Unit]\nDescription=August agent\nAfter=network-online.target\nWants=network-online.target\n\n\
             [Service]\nExecStart=\"{exe}\" gateway\nWorkingDirectory={dir}\nEnvironment=\"PATH={path}\"\nEnvironment=\"AUGUST_HOME={home}\"\n\
             Restart=on-failure\nRestartSec=5\nStandardOutput=append:{log}\nStandardError=append:{log}\n\n\
             [Install]\nWantedBy=default.target\n",
            exe = exe.display(),
            dir = dir.display(),
            log = log.display(),
            home = config::home().display(),
        );
        let file = unit_path();
        std::fs::create_dir_all(file.parent().unwrap())?;
        std::fs::write(&file, definition)?;
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
        run(Command::new("systemctl").args(["--user", "enable", "--now", &unit()]))?;
        run(Command::new("systemctl").args(["--user", "restart", &unit()]))?;
        if !linger {
            println!("to keep it running after logout: sudo loginctl enable-linger $USER");
        }
    }
    println!("august is running in the background (starts at login, restarts on crash)");
    println!("logs: {}   (august logs)\nstop: august stop", log.display());
    Ok(())
}

/// Whether `systemctl --user` reaches a running systemd. Waits a little: one that linger
/// has just started may not be up yet.
fn user_systemd() -> bool {
    for _ in 0..15 {
        let Ok(out) = Command::new("systemctl").args(["--user", "is-system-running"]).output() else {
            return false;
        };
        if matches!(String::from_utf8_lossy(&out.stdout).trim(), "running" | "degraded" | "starting" | "initializing") {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    false
}

/// Starts the installed service again.
pub fn kick() -> Result<()> {
    if cfg!(windows) {
        // Queued until the last run has ended.
        run(Command::new("schtasks").args(["/Run", "/TN", &task()]))
    } else if cfg!(target_os = "macos") {
        run(Command::new("launchctl").args(["kickstart", &format!("gui/{}/{}", uid()?, label())]))
    } else {
        run(Command::new("systemctl").args(["--user", "restart", &unit()]))
    }
}

/// Starts August on its own in the background (`august serve` keeps it running at login).
pub fn spawn() -> Result<()> {
    gateway()?.spawn().context("could not start August")?;
    Ok(())
}

/// What the Windows task runs: August, started again 5 s after it crashes (not when it
/// stops cleanly), like launchd and systemd do elsewhere.
pub fn supervise() -> Result<()> {
    loop {
        if gateway()?.status().context("could not start August")?.success() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

/// `august gateway` in the background, its output in the log.
fn gateway() -> Result<Command> {
    let log = log_path();
    std::fs::create_dir_all(log.parent().unwrap_or(&log))?;
    let out = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.arg("gateway").stdin(std::process::Stdio::null()).stdout(out.try_clone()?).stderr(out);
    // Its own process group, so closing this terminal doesn't stop it.
    #[cfg(unix)]
    std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
    // And no window: a hidden console of its own, which its extensions share.
    #[cfg(windows)]
    std::os::windows::process::CommandExt::creation_flags(&mut cmd, 0x200 | 0x0800_0000); // CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    Ok(cmd)
}

/// Stops the service (if still running) and removes it from autostart.
pub fn uninstall() -> Result<()> {
    if cfg!(windows) {
        if !installed() {
            bail!("service is not installed");
        }
        run(Command::new("schtasks").args(["/Delete", "/F", "/TN", &task()]))?;
    } else if cfg!(target_os = "macos") {
        let file = plist_path();
        if !file.exists() {
            bail!("service is not installed");
        }
        // Already stopped (`august stop` shut it down first) is fine.
        Command::new("launchctl").args(["bootout", &format!("gui/{}/{}", uid()?, label())]).output().ok();
        std::fs::remove_file(file)?;
    } else {
        let file = unit_path();
        if !file.exists() {
            bail!("service is not installed");
        }
        run(Command::new("systemctl").args(["--user", "disable", "--now", &unit()]))?;
        std::fs::remove_file(file)?;
        run(Command::new("systemctl").args(["--user", "daemon-reload"]))?;
    }
    Ok(())
}

/// Follows the service log.
pub fn logs() -> Result<()> {
    let log = log_path();
    if !log.exists() {
        bail!("no log yet: {}", log.display());
    }
    if cfg!(windows) {
        Command::new("powershell").args(["-NoProfile", "-Command", "Get-Content -Tail 100 -Wait -LiteralPath $args[0]"]).arg(log).status()?;
    } else {
        Command::new("tail").args(["-n", "100", "-f"]).arg(log).status()?;
    }
    Ok(())
}

fn uid() -> Result<String> {
    let out = Command::new("id").arg("-u").output()?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}
