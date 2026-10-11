//! The control socket (`AUGUST_HOME/control.sock`, on Windows a named pipe; this user only): how the `august` program
//! reaches the running core. One JSON object per line each way, `{"result"}` or `{"error"}`
//! for each request:
//! - `{"op": "cli"}`: the commands extensions add to `august` (`[{name, description, owner}]`);
//! - `{"op": "cli_open", "name"}`: what to run for one (`{exec, owner, token}`); the token
//!   lets that program call the core as the extension that owns the command;
//! - `{"op": "shutdown", "reason"}`: stop the extensions (`shutdown {reason}`) and August;
//! - `{"token", "call": op, "params"}`: run operation `op` as the token's extension.

use super::Gateway;
use anyhow::{Result, anyhow, bail};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener as Listener, UnixStream};

/// Where the core at `home` listens.
#[cfg(unix)]
pub fn socket_in(home: &Path) -> PathBuf {
    home.join("control.sock")
}

/// Where the core at `home` listens: a pipe named after `home`.
#[cfg(windows)]
pub fn socket_in(home: &Path) -> PathBuf {
    let home: String = home.to_string_lossy().chars().map(|c| if matches!(c, '\\' | '/' | ':') { '_' } else { c }).collect();
    PathBuf::from(format!(r"\\.\pipe\august-{home}"))
}

/// Starts listening, unless another August already does.
#[cfg(unix)]
pub(super) async fn bind(home: &Path) -> Result<Listener> {
    use anyhow::Context;
    let path = socket_in(home);
    if UnixStream::connect(&path).await.is_ok() {
        bail!("another August is already running ({})", path.display());
    }
    std::fs::remove_file(&path).ok();
    std::fs::create_dir_all(home)?;
    let listener = Listener::bind(&path).with_context(|| format!("listen on {}", path.display()))?;
    // Only this user may control the agent.
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))?;
    Ok(listener)
}

/// A named pipe takes one client per instance: the next one waits for the next client.
#[cfg(windows)]
pub(super) struct Listener {
    name: PathBuf,
    next: tokio::net::windows::named_pipe::NamedPipeServer,
}

/// Starts listening, unless another August already does.
#[cfg(windows)]
pub(super) async fn bind(home: &Path) -> Result<Listener> {
    let name = socket_in(home);
    std::fs::create_dir_all(home)?;
    // Only the first instance of a name may be made with `first`: another August has it.
    let next = pipe(&name, true).map_err(|_| anyhow!("another August is already running ({})", name.display()))?;
    Ok(Listener { name, next })
}

/// An instance of pipe `name` only this user may open.
#[cfg(windows)]
fn pipe(name: &Path, first: bool) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    // Full access for the owner (the user August runs as), none for anyone else.
    let sddl: Vec<u16> = "D:P(A;;GA;;;OW)".encode_utf16().chain([0]).collect();
    let mut sd = std::ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; `sd` is freed below, after the pipe is made.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, std::ptr::null_mut()) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut attrs = SECURITY_ATTRIBUTES { nLength: size_of::<SECURITY_ATTRIBUTES>() as u32, lpSecurityDescriptor: sd, bInheritHandle: 0 };
    // SAFETY: `attrs` points to a valid security descriptor for the duration of the call.
    let made = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .create_with_security_attributes_raw(name, (&raw mut attrs).cast())
    };
    // SAFETY: allocated by the conversion above.
    unsafe { LocalFree(sd) };
    made
}

impl Gateway {
    #[cfg(unix)]
    pub(super) async fn serve_control(self: Arc<Self>, listener: Listener) {
        while let Ok((stream, _)) = listener.accept().await {
            let me = self.clone();
            tokio::spawn(async move { me.control_client(stream).await });
        }
    }

    #[cfg(windows)]
    pub(super) async fn serve_control(self: Arc<Self>, mut listener: Listener) {
        loop {
            // A client that failed to connect costs only its own instance.
            let connected = listener.next.connect().await;
            let Ok(next) = pipe(&listener.name, false) else { return };
            let stream = std::mem::replace(&mut listener.next, next);
            if connected.is_ok() {
                let me = self.clone();
                tokio::spawn(async move { me.control_client(stream).await });
            }
        }
    }

    async fn control_client(self: Arc<Self>, stream: impl AsyncRead + AsyncWrite + Send + 'static) {
        let (read, mut write) = tokio::io::split(stream);
        let mut lines = BufReader::new(read).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let reply = match serde_json::from_str::<Value>(&line) {
                Ok(req) => self.control(&req).await,
                Err(e) => Err(anyhow!("bad request: {e}")),
            };
            let reply = match reply {
                Ok(result) => json!({"result": result}),
                Err(e) => json!({"error": format!("{e:#}")}),
            };
            if write.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                return;
            }
        }
    }

    async fn control(self: &Arc<Self>, req: &Value) -> Result<Value> {
        if let Some(op) = req["call"].as_str() {
            let token = req["token"].as_str().unwrap_or_default();
            let ext = self.tokens.lock().unwrap().get(token).cloned().ok_or_else(|| anyhow!("unknown token"))?;
            let params = if req["params"].is_object() { req["params"].clone() } else { json!({}) };
            self.ext.allows(&ext, op, &params)?;
            return self.op(&ext, op, &params).await;
        }
        match req["op"].as_str().unwrap_or_default() {
            "cli" => Ok(Value::Array(
                self.ext.cli().into_iter().map(|(owner, c)| json!({"name": c.name, "description": c.description, "owner": owner})).collect(),
            )),
            "cli_open" => {
                let name = req["name"].as_str().unwrap_or_default();
                let (owner, c) = self.ext.cli().into_iter().find(|(_, c)| c.name == name).ok_or_else(|| anyhow!("no extension offers `{name}`"))?;
                // ponytail: tokens live until August stops; expire them if programs should lose access sooner.
                let token = crate::util::new_uuid();
                self.tokens.lock().unwrap().insert(token.clone(), owner.clone());
                Ok(json!({"exec": c.exec, "owner": owner, "token": token}))
            }
            "shutdown" => {
                self.shutdown(req["reason"].as_str().unwrap_or("stop")).await;
                Ok(Value::Null)
            }
            other => bail!("unknown request `{other}`"),
        }
    }
}
