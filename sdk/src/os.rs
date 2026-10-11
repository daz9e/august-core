//! What differs between Unix and Windows: the core's control socket (a Unix socket, a named
//! pipe on Windows) and the process groups extensions and their commands run in (Job
//! Objects on Windows).

/// A connection to the core's control socket.
#[cfg(unix)]
pub type Stream = tokio::net::UnixStream;
#[cfg(windows)]
pub type Stream = tokio::net::windows::named_pipe::NamedPipeClient;

/// Connects to the control socket at `path` (on Windows, a pipe name `\\.\pipe\...`).
pub async fn connect(path: &std::path::Path) -> std::io::Result<Stream> {
    #[cfg(unix)]
    return tokio::net::UnixStream::connect(path).await;
    #[cfg(windows)]
    {
        const ERROR_PIPE_BUSY: i32 = 231;
        // Every instance is taken until the core makes the next one: try again shortly.
        for _ in 0..50 {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) => tokio::time::sleep(std::time::Duration::from_millis(20)).await,
                r => return r,
            }
        }
        tokio::net::windows::named_pipe::ClientOptions::new().open(path)
    }
}

/// Runs what `cmd` starts in a process group of its own (see `Group`).
pub fn own_group(cmd: &mut tokio::process::Command) -> &mut tokio::process::Command {
    #[cfg(unix)]
    return cmd.process_group(0);
    #[cfg(windows)]
    {
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x200;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP)
    }
}

/// The process group a child started with `own_group` leads (on Windows, a Job Object it
/// was put in right after it started): `kill` ends the child and all it started.
pub struct Group {
    #[cfg(unix)]
    pid: i32,
    #[cfg(windows)]
    job: usize,
}

impl Group {
    /// `child`'s group; none once it has ended.
    pub fn of(child: &tokio::process::Child) -> Option<Group> {
        #[cfg(unix)]
        return child.id().map(|pid| Group { pid: pid as i32 });
        #[cfg(windows)]
        {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW};
            let process = child.raw_handle()?;
            // ponytail: what the child starts before it is put in the job escapes it; start it suspended if that ever matters.
            // SAFETY: plain calls on a fresh job and the child's live handle.
            unsafe {
                let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
                if job.is_null() {
                    return None;
                }
                if AssignProcessToJobObject(job, process) == 0 {
                    CloseHandle(job);
                    return None;
                }
                Some(Group { job: job as usize })
            }
        }
    }

    /// Kills the child and all it started; they may already be gone.
    pub fn kill(&self) {
        #[cfg(unix)]
        // SAFETY: plain syscall on the child's own group.
        unsafe {
            libc::killpg(self.pid, libc::SIGKILL)
        };
        #[cfg(windows)]
        // SAFETY: the job is open until `drop`.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job as _, 1)
        };
    }
}

/// Closing the job leaves what is in it running, like a process group nobody kills.
#[cfg(windows)]
impl Drop for Group {
    fn drop(&mut self) {
        // SAFETY: opened in `of`, closed only here.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.job as _) };
    }
}
