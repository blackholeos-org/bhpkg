use crate::error::{AppError, Result};
use crate::types::AppContext;
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::unistd::chdir;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{exit, Command, Stdio};

fn apply_seccomp_whitelist() -> Result<()> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, TargetArch};
    use std::collections::BTreeMap;
    use syscalls::Sysno;

    let mut rules = BTreeMap::new();
    let allowed = [
        Sysno::read,
        Sysno::write,
        Sysno::openat,
        Sysno::close,
        Sysno::fstat,
        Sysno::newfstatat,
        Sysno::lseek,
        Sysno::mmap,
        Sysno::mprotect,
        Sysno::munmap,
        Sysno::brk,
        Sysno::rt_sigaction,
        Sysno::rt_sigprocmask,
        Sysno::rt_sigreturn,
        Sysno::ioctl,
        Sysno::pread64,
        Sysno::pwrite64,
        Sysno::readv,
        Sysno::writev,
        Sysno::faccessat,
        Sysno::pipe2,
        Sysno::epoll_wait,
        Sysno::epoll_ctl,
        Sysno::clone,
        Sysno::execve,
        Sysno::exit,
        Sysno::wait4,
        Sysno::kill,
        Sysno::uname,
        Sysno::fcntl,
        Sysno::flock,
        Sysno::fsync,
        Sysno::fdatasync,
        Sysno::truncate,
        Sysno::ftruncate,
        Sysno::getdents64,
        Sysno::getcwd,
        Sysno::chdir,
        Sysno::fchdir,
        Sysno::renameat,
        Sysno::mkdirat,
        Sysno::unlinkat,
        Sysno::symlinkat,
        Sysno::readlinkat,
        Sysno::fchmodat,
        Sysno::fchownat,
        Sysno::umask,
        Sysno::gettimeofday,
        Sysno::getrlimit,
        Sysno::getrusage,
        Sysno::sysinfo,
        Sysno::times,
        Sysno::getuid,
        Sysno::syslog,
        Sysno::getgid,
        Sysno::setuid,
        Sysno::setgid,
        Sysno::geteuid,
        Sysno::getegid,
        Sysno::setpgid,
        Sysno::getppid,
        Sysno::getpgrp,
        Sysno::setsid,
        Sysno::setreuid,
        Sysno::setregid,
        Sysno::getgroups,
        Sysno::setgroups,
        Sysno::setresuid,
        Sysno::getresuid,
        Sysno::setresgid,
        Sysno::getresgid,
        Sysno::getpgid,
        Sysno::setfsuid,
        Sysno::setfsgid,
        Sysno::getsid,
        Sysno::capget,
        Sysno::capset,
        Sysno::rt_sigpending,
        Sysno::rt_sigtimedwait,
        Sysno::rt_sigqueueinfo,
        Sysno::rt_sigsuspend,
        Sysno::sigaltstack,
        Sysno::utimensat,
        Sysno::mknodat,
        Sysno::statfs,
        Sysno::fstatfs,
        Sysno::sysfs,
        Sysno::getpriority,
        Sysno::setpriority,
        Sysno::sched_setparam,
        Sysno::sched_getparam,
        Sysno::sched_setscheduler,
        Sysno::sched_getscheduler,
        Sysno::sched_get_priority_max,
        Sysno::sched_get_priority_min,
        Sysno::sched_rr_get_interval,
        Sysno::prctl,
        Sysno::setrlimit,
        Sysno::sync,
        Sysno::gettid,
        Sysno::readahead,
        Sysno::setxattr,
        Sysno::lsetxattr,
        Sysno::fsetxattr,
        Sysno::getxattr,
        Sysno::lgetxattr,
        Sysno::fgetxattr,
        Sysno::listxattr,
        Sysno::llistxattr,
        Sysno::flistxattr,
        Sysno::removexattr,
        Sysno::lremovexattr,
        Sysno::fremovexattr,
        Sysno::tkill,
        Sysno::futex,
        Sysno::sched_setaffinity,
        Sysno::sched_getaffinity,
        Sysno::exit_group,
        Sysno::tgkill,
        Sysno::mbind,
        Sysno::set_mempolicy,
        Sysno::get_mempolicy,
        Sysno::madvise,
        Sysno::socket,
        Sysno::connect,
        Sysno::getsockname,
        Sysno::getpeername,
        Sysno::sendto,
        Sysno::recvfrom,
        Sysno::setsockopt,
        Sysno::getsockopt,
        Sysno::bind,
        Sysno::listen,
        Sysno::accept4,
        Sysno::sendmsg,
        Sysno::recvmsg,
        Sysno::shutdown,
        Sysno::mremap,
        Sysno::mincore,
        Sysno::shmget,
        Sysno::shmat,
        Sysno::shmctl,
        Sysno::dup,
        Sysno::dup2,
        Sysno::dup3,
        Sysno::nanosleep,
        Sysno::getrandom,
        Sysno::getcpu,
        Sysno::arch_prctl,
        Sysno::set_tid_address,
        Sysno::set_robust_list,
        Sysno::rseq,
        Sysno::stat,
        Sysno::lstat,
        Sysno::open,
        Sysno::mkdir,
        Sysno::rmdir,
        Sysno::unlink,
        Sysno::symlink,
        Sysno::readlink,
        Sysno::chmod,
        Sysno::chown,
        Sysno::lchown,
        Sysno::rename,
        Sysno::utime,
        Sysno::utimes,
        Sysno::access,
        Sysno::vfork,
        Sysno::clock_gettime,
        Sysno::poll,
        Sysno::ppoll,
        Sysno::select,
        Sysno::pselect6,
        Sysno::pipe,
        Sysno::getpid,
        Sysno::fork,
        Sysno::creat,
        Sysno::link,
        Sysno::fchmod,
        Sysno::fchown,
        Sysno::time,
        Sysno::waitid,
        Sysno::epoll_create,
        Sysno::epoll_create1,
        Sysno::epoll_pwait,
        Sysno::clock_getres,
        Sysno::clock_nanosleep,
        Sysno::mknod,
        Sysno::sendfile,
        Sysno::fallocate,
        Sysno::timerfd_create,
        Sysno::timerfd_settime,
        Sysno::timerfd_gettime,
        Sysno::socketpair,
        Sysno::getitimer,
        Sysno::setitimer,
        Sysno::alarm,
        Sysno::prlimit64,
        Sysno::statx,
        Sysno::execveat,
        Sysno::clone3,
        Sysno::faccessat2,
        Sysno::renameat2,
        Sysno::copy_file_range,
        Sysno::getdents,
        Sysno::splice,
        Sysno::tee,
        Sysno::vmsplice,
        Sysno::memfd_create,
        Sysno::sched_yield,
        Sysno::fadvise64,
        Sysno::openat2,
    ];

    for &syscall in &allowed {
        rules.insert(syscall.id() as i64, vec![]);
    }

    let arch: TargetArch = std::env::consts::ARCH
        .try_into()
        .map_err(|_| AppError::Security("Unsupported architecture for seccomp".into()))?;

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| AppError::Security(format!("Failed to build seccomp filter: {:?}", e)))?;

    let bpf_prog: BpfProgram = filter
        .try_into()
        .map_err(|e| AppError::Security(format!("Failed to compile BPF program: {:?}", e)))?;

    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| AppError::Security(format!("Failed to apply seccomp filter: {:?}", e)))?;

    Ok(())
}

pub fn execute_internal_sandbox() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        exit(1);
    }

    let builddir = &args[2];
    let fakeroot = &args[3];
    let net_access = args[4] == "true";

    let sandbox_root = format!("/var/lib/bhpkg/tmp/sandbox-{}", std::process::id());
    let _ = fs::create_dir_all(&sandbox_root);
    let _ = std::os::unix::fs::chown(&sandbox_root, Some(65534), Some(65534));

    let mut current = Path::new(builddir).parent();
    while let Some(p) = current {
        if p.as_os_str().is_empty() || p.to_string_lossy() == "/" {
            break;
        }
        let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o755));
        current = p.parent();
    }

    let mut flags = CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWIPC
        | CloneFlags::CLONE_NEWUTS
        | CloneFlags::CLONE_NEWPID;

    if !net_access {
        flags |= CloneFlags::CLONE_NEWNET;
    }

    if unshare(flags).is_err() {
        return Err(AppError::Security("Namespacing failed".into()));
    }

    match unsafe { libc::fork() } {
        -1 => return Err(AppError::Security("Fork failed".into())),
        0 => {}
        pid => {
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let exit_code = if (status & 0x7F) == 0 {
                (status >> 8) & 0xFF
            } else {
                1
            };
            std::process::exit(exit_code);
        }
    }

    let _ = nix::unistd::setsid();

    let _ = mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    );

    let _ = fs::create_dir_all(&sandbox_root);

    // Root tmpfs
    mount(
        Some("none"),
        sandbox_root.as_str(),
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=6G,mode=755"),
    )
    .map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to mount tmpfs on {}: {}", sandbox_root, e),
        ))
    })?;

    for d in &[
        "bin",
        "sbin",
        "usr",
        "lib",
        "lib64",
        "lib32",
        "etc",
        "dev",
        "proc",
        "sys",
        "build",
        "dest",
        "tmp",
        "old_root",
        "libexec",
        "x86_64-linux-musl",
        "x86_64-linux-gnu",
        "include",
        "share",
    ] {
        let _ = fs::create_dir_all(format!("{}/{}", sandbox_root, d));
    }

    for d in &[
        "bin",
        "sbin",
        "usr",
        "lib",
        "lib64",
        "lib32",
        "dev",
        "libexec",
        "x86_64-linux-musl",
        "x86_64-linux-gnu",
        "include",
        "share",
    ] {
        let src_path = PathBuf::from(format!("/{}", d));
        if !src_path.exists() {
            continue;
        }

        let resolved_src = fs::canonicalize(&src_path).unwrap_or_else(|_| src_path.clone());
        let resolved_str = resolved_src.to_string_lossy();

        if resolved_str != "/" && !resolved_str.is_empty() {
            let dst_dir = format!("{}{}", sandbox_root, resolved_str);

            let _ = fs::create_dir_all(&dst_dir);

            mount(
                Some(resolved_src.as_path()),
                dst_dir.as_str(),
                None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC,
                None::<&str>,
            )
            .map_err(|e| {
                AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "Failed to bind mount {} to {}: {}",
                        resolved_src.display(),
                        dst_dir,
                        e
                    ),
                ))
            })?;
        }

        if src_path.is_symlink() && src_path != resolved_src {
            if let Ok(link_target) = fs::read_link(&src_path) {
                let sym_path = format!("{}/{}", sandbox_root, d);
                let _ = fs::remove_dir_all(&sym_path);
                let _ = std::os::unix::fs::symlink(link_target, &sym_path);
            }
        }
    }

    for d in &["sys", "dev"] {
        let target = format!("{}/{}", sandbox_root, d);
        if Path::new(&target).exists() {
            let _ = mount(
                Some("none"),
                target.as_str(),
                None::<&str>,
                MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
                None::<&str>,
            );
        }
    }

    for entry in &[
        "ld.so.cache",
        "ld.so.conf",
        "ld.so.conf.d",
        "ld-musl-x86_64.path",
        "passwd",
        "group",
    ] {
        let host_path = format!("/etc/{}", entry);
        if Path::new(&host_path).exists() {
            let sand_path = format!("{}/etc/{}", sandbox_root, entry);
            if Path::new(&host_path).is_dir() {
                let _ = fs::create_dir_all(&sand_path);
                let _ = mount(
                    Some(host_path.as_str()),
                    sand_path.as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REC,
                    None::<&str>,
                );
            } else {
                if let Some(parent) = Path::new(&sand_path).parent() {
                    let _ = fs::create_dir_all(parent);
                }
                let _ = fs::File::create(&sand_path);
                let _ = mount(
                    Some(host_path.as_str()),
                    sand_path.as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND,
                    None::<&str>,
                );
            }
        }
    }

    if net_access {
        let _ = fs::create_dir_all(format!("{}/etc/ssl", sandbox_root));
        let ssl_path = PathBuf::from("/etc/ssl");
        if ssl_path.exists() {
            let canon_ssl = fs::canonicalize(&ssl_path).unwrap_or_else(|_| ssl_path.clone());
            let ssl_str = canon_ssl.to_string_lossy();

            if ssl_str != "/" && !ssl_str.is_empty() {
                mount(
                    Some(canon_ssl.as_path()),
                    format!("{}/etc/ssl", sandbox_root).as_str(),
                    None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
                    None::<&str>,
                )
                .map_err(|e| {
                    AppError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!("Failed to bind mount /etc/ssl: {}", e),
                    ))
                })?;
            }
        }
        let _ = fs::write(
            format!("{}/etc/resolv.conf", sandbox_root),
            "nameserver 1.1.1.1\nnameserver 8.8.8.8\n",
        );
    }

    let tmp_path = format!("{}/tmp", sandbox_root);
    mount(
        Some("none"),
        tmp_path.as_str(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("size=1G,mode=1777"),
    )
    .map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to mount tmpfs on {}: {}", tmp_path, e),
        ))
    })?;

    fs::create_dir_all(format!("{}/host_build", sandbox_root)).map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create {}/host_build: {}", sandbox_root, e),
        ))
    })?;

    let _ = fs::create_dir_all(builddir);

    mount(
        Some(builddir.as_str()),
        format!("{}/host_build", sandbox_root).as_str(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to bind mount builddir {} to {}/host_build: {}",
                builddir, sandbox_root, e
            ),
        ))
    })?;

    let build_path = format!("{}/build", sandbox_root);
    fs::create_dir_all(&build_path).map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create {}: {}", build_path, e),
        ))
    })?;
    let _ = std::os::unix::fs::chown(&build_path, Some(65534), Some(65534));

    fs::create_dir_all(format!("{}/dest", sandbox_root)).map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create {}/dest: {}", sandbox_root, e),
        ))
    })?;

    let _ = fs::create_dir_all(fakeroot);

    mount(
        Some(fakeroot.as_str()),
        format!("{}/dest", sandbox_root).as_str(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to bind mount fakeroot {} to {}/dest: {}",
                fakeroot, sandbox_root, e
            ),
        ))
    })?;

    fs::create_dir_all(format!("{}/proc", sandbox_root)).map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create {}/proc: {}", sandbox_root, e),
        ))
    })?;

    mount(
        Some("proc"),
        format!("{}/proc", sandbox_root).as_str(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to mount proc on {}/proc: {}", sandbox_root, e),
        ))
    })?;

    fs::create_dir_all(format!("{}/sys", sandbox_root)).map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to create {}/sys: {}", sandbox_root, e),
        ))
    })?;

    mount(
        Some("/sys"),
        format!("{}/sys", sandbox_root).as_str(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to bind mount /sys to {}/sys: {}", sandbox_root, e),
        ))
    })?;

    mount(
        Some(sandbox_root.as_str()),
        sandbox_root.as_str(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to self-bind mount {}: {}", sandbox_root, e),
        ))
    })?;

    chdir(sandbox_root.as_str()).map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to chdir to {}: {}", sandbox_root, e),
        ))
    })?;

    unsafe {
        if libc::syscall(
            libc::SYS_pivot_root,
            b".\0".as_ptr(),
            b"old_root\0".as_ptr(),
        ) != 0
        {
            exit(1);
        }
    }

    let _ = umount2("/old_root", MntFlags::MNT_DETACH);
    chdir("/").map_err(|e| {
        AppError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Failed to chdir to /: {}", e),
        ))
    })?;

    unsafe {
        libc::setgroups(0, std::ptr::null());
        libc::setresgid(65534, 65534, 65534);
        libc::setresuid(65534, 65534, 65534);
        libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0);
    }

    if unshare(CloneFlags::CLONE_NEWUSER).is_err() {
        return Err(AppError::Security(
            "User namespaces required for secure execution.".into(),
        ));
    }

    let _ = fs::write("/proc/self/uid_map", "0 65534 1\n");
    let _ = fs::write("/proc/self/setgroups", "deny\n");
    let _ = fs::write("/proc/self/gid_map", "0 65534 1\n");

    unsafe {
        libc::setresgid(0, 0, 0);
        libc::setresuid(0, 0, 0);
        libc::umask(0o022);
    }

    apply_seccomp_whitelist()?;

    let c_shell = CString::new("/bin/sh").unwrap();
    let c_arg = CString::new("/host_build/bh-build.sh").unwrap();

    let envs = [
        CString::new("PATH=/bin:/usr/bin:/sbin:/usr/sbin").unwrap(),
        CString::new("DESTDIR=/dest").unwrap(),
        CString::new("PREFIX=/usr").unwrap(),
        CString::new("HOME=/build").unwrap(),
        CString::new("USER=root").unwrap(),
    ];
    let mut envp: Vec<*const libc::c_char> = envs.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());

    unsafe {
        libc::execve(
            c_shell.as_ptr(),
            [c_shell.as_ptr(), c_arg.as_ptr(), std::ptr::null()].as_ptr(),
            envp.as_ptr(),
        );
    }
    exit(127);
}

pub fn run_build_sandboxed(builddir: &str, fakeroot: &str, net_access: bool) -> Result<()> {
    let exe = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/bin/bhpkg"));
    let child = Command::new(exe)
        .arg("--internal-sandbox")
        .arg(builddir)
        .arg(fakeroot)
        .arg(if net_access { "true" } else { "false" })
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let pid = child.id();
    let output = child.wait_with_output()?;

    let sandbox_root = format!("/var/lib/bhpkg/tmp/sandbox-{}", pid);
    let _ = fs::remove_dir_all(&sandbox_root);

    if output.status.success() {
        Ok(())
    } else {
        Err(AppError::General(format!(
            "Sandbox build failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

pub fn run_hook_privileged(script_body: &str, hook_name: &str, ctx: &AppContext) -> Result<()> {
    if script_body.trim().is_empty() {
        return Ok(());
    }
    ctx.print_msg(&format!("Executing privileged {} script...", hook_name));

    let builddir = crate::utils::gen_tmp_path("hookdir", ctx);
    fs::create_dir_all(&builddir)?;
    let hook_path = builddir.join("hook.sh");
    fs::write(
        &hook_path,
        format!(
            "#!/bin/sh\nexport PATH=\"/bin:/usr/bin:/sbin:/usr/sbin\"\n{}",
            script_body
        ),
    )?;

    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o700))?;

    let status = Command::new(&hook_path)
        .env_clear()
        .env("PATH", "/bin:/usr/bin:/sbin:/usr/sbin")
        .stdin(Stdio::null())
        .status()?;

    let _ = fs::remove_dir_all(&builddir);
    if status.success() {
        Ok(())
    } else {
        Err(AppError::General(format!(
            "Privileged hook {} failed",
            hook_name
        )))
    }
}

fn is_safe_hook(path: &Path) -> bool {
    if let Ok(meta) = fs::symlink_metadata(path) {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        return meta.uid() == 0 && (mode & 0o022 == 0);
    }
    false
}

pub fn hook_execute_all(operation: &str, ctx: &AppContext) {
    let hooks_path = ctx.root_path("etc/bhpkg/hooks");
    if let Ok(entries) = fs::read_dir(&hooks_path) {
        for entry in entries.filter_map(std::result::Result::ok) {
            if entry.path().extension().map_or(false, |ext| ext == "hook") {
                if !is_safe_hook(&entry.path()) {
                    ctx.print_warn(&format!(
                        "Skipping unsafe hook (bad permissions/owner): {}",
                        entry.path().display()
                    ));
                    continue;
                }
                let content = fs::read_to_string(entry.path()).unwrap_or_default();
                let mut matches_op = false;
                let mut exec_cmd = String::new();
                let mut desc = String::new();

                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.starts_with('[') {
                        continue;
                    }
                    if let Some((k, v)) = line.split_once('=') {
                        match k.trim() {
                            "Operation" => {
                                if v.trim() == operation {
                                    matches_op = true
                                }
                            }
                            "Exec" => exec_cmd = v.trim().to_string(),
                            "Description" => desc = v.trim().to_string(),
                            _ => {}
                        }
                    }
                }
                if matches_op && !exec_cmd.is_empty() {
                    if !desc.is_empty() {
                        ctx.print_msg(&format!("Hook: {}", desc));
                    }
                    let _ = Command::new("/bin/sh")
                        .env_clear()
                        .env("PATH", "/bin:/usr/bin:/sbin:/usr/sbin")
                        .arg("-c")
                        .arg(&exec_cmd)
                        .stdin(Stdio::null())
                        .status();
                }
            }
        }
    }
}

pub fn hook_evaluate_triggers(touched_files: &[PathBuf], ctx: &AppContext) {
    let hooks_path = ctx.root_path("etc/bhpkg/hooks");
    if let Ok(entries) = fs::read_dir(&hooks_path) {
        for entry in entries.filter_map(std::result::Result::ok) {
            if entry.path().extension().map_or(false, |ext| ext == "hook") {
                if !is_safe_hook(&entry.path()) {
                    ctx.print_warn(&format!(
                        "Skipping unsafe trigger hook: {}",
                        entry.path().display()
                    ));
                    continue;
                }
                let content = fs::read_to_string(entry.path()).unwrap_or_default();
                let mut target_pattern = String::new();
                let mut exec_cmd = String::new();

                for line in content.lines() {
                    let line = line.trim();
                    if line.starts_with('#') || line.starts_with('[') {
                        continue;
                    }
                    if let Some((k, v)) = line.split_once('=') {
                        match k.trim() {
                            "TriggerOn" => target_pattern = v.trim().to_string(),
                            "Exec" => exec_cmd = v.trim().to_string(),
                            _ => {}
                        }
                    }
                }

                if !target_pattern.is_empty() && !exec_cmd.is_empty() {
                    let mut check_str = target_pattern.clone();
                    let is_wildcard = check_str.ends_with('*');
                    if is_wildcard {
                        check_str.pop();
                    }

                    let found = touched_files.iter().any(|p| {
                        let s = p.to_string_lossy();
                        if is_wildcard {
                            s.starts_with(&check_str)
                        } else {
                            s == check_str
                        }
                    });

                    if found {
                        ctx.print_msg(&format!("Triggering hook: {}", entry.path().display()));
                        let _ = Command::new("/bin/sh")
                            .env_clear()
                            .env("PATH", "/bin:/usr/bin:/sbin:/usr/sbin")
                            .arg("-c")
                            .arg(&exec_cmd)
                            .stdin(Stdio::null())
                            .status();
                    }
                }
            }
        }
    }
}
