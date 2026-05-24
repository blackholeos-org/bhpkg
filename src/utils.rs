use crate::error::{AppError, Result};
use crate::types::AppContext;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "linux")]
const FICLONE: libc::c_ulong = 0x40049409;

pub fn gen_tmp_path(prefix: &str, ctx: &AppContext) -> PathBuf {
    let pid = std::process::id();
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);
    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    ctx.root_path(&format!(
        "var/lib/bhpkg/tmp/{}-{}-{}-{:x}",
        prefix, pid, c, time
    ))
}

pub fn zero_copy_file(src: &Path, dst: &Path, mode: u32) -> Result<()> {
    let _ = fs::remove_file(dst);

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);

    let out_file = options.open(dst)?;
    let mut in_file = fs::File::open(src)?;

    out_file.set_permissions(fs::Permissions::from_mode(mode))?;

    use std::os::unix::io::AsRawFd;
    let fd_in = in_file.as_raw_fd();
    let fd_out = out_file.as_raw_fd();

    unsafe {
        libc::posix_fadvise(fd_in, 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        libc::posix_fadvise(fd_in, 0, 0, libc::POSIX_FADV_WILLNEED);
    }

    #[cfg(target_os = "linux")]
    {
        if unsafe { libc::ioctl(fd_out, FICLONE as _, fd_in) } == 0 {
            return Ok(());
        }
    }

    #[cfg(target_os = "linux")]
    {
        let mut offset_in: libc::off64_t = 0;
        let mut offset_out: libc::off64_t = 0;
        let file_size = in_file.metadata()?.len();
        let mut remaining = file_size as libc::size_t;

        while remaining > 0 {
            let ret = unsafe {
                libc::copy_file_range(fd_in, &mut offset_in, fd_out, &mut offset_out, remaining, 0)
            };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                let raw = err.raw_os_error();
                if raw == Some(libc::EXDEV)
                    || raw == Some(libc::ENOSYS)
                    || raw == Some(libc::EOPNOTSUPP)
                {
                    break;
                } else {
                    return Err(AppError::Io(err));
                }
            } else if ret == 0 {
                break;
            }
            remaining -= ret as libc::size_t;
        }
        if remaining == 0 {
            return Ok(());
        }
    }

    use std::io::{Seek, SeekFrom};
    in_file.seek(SeekFrom::Start(0))?;
    let mut out_write = out_file;
    std::io::copy(&mut in_file, &mut out_write)?;

    Ok(())
}

pub fn rename_or_copy(src: &Path, dst: &Path, mode: u32) -> Result<()> {
    let _ = fs::remove_file(dst);
    if fs::rename(src, dst).is_err() {
        zero_copy_file(src, dst, mode)?;
        let _ = fs::remove_file(src);
    } else {
        fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}

pub fn secure_copy(src: &Path, dst: &Path, mode: u32) -> Result<()> {
    zero_copy_file(src, dst, mode)
}

pub fn chown_recursive(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let mut walk = vec![path.to_path_buf()];
    while let Some(dir) = walk.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.filter_map(std::result::Result::ok) {
                let p = entry.path();
                let meta = fs::symlink_metadata(&p)?;
                if meta.is_dir() {
                    walk.push(p.clone());
                } else if meta.is_file() {
                    let mode = meta.permissions().mode();
                    if mode & 0o6000 != 0 {
                        let _ = fs::set_permissions(&p, fs::Permissions::from_mode(mode & !0o6000));
                    }
                }
                let _ = std::os::unix::fs::lchown(&p, Some(uid), Some(gid));
            }
        }
    }
    let _ = std::os::unix::fs::lchown(path, Some(uid), Some(gid));
    Ok(())
}
