use crate::error::{AppError, Result};
use crate::solver::PackageDatabase;
use crate::types::{AppContext, Package, PackageRef};
use crate::{archive, crypto, delta, net, sandbox, utils};
use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::sync::{mpsc, Arc, Condvar, Mutex};

fn hex_encode_path(p: &Path) -> String {
    p.as_os_str()
        .as_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn hex_decode_path(s: &str) -> Option<PathBuf> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}

fn write_metadata_file(pkg: &Package, dest: &Path) -> Result<()> {
    let path = dest.join(".PKGINFO");
    let mut f = File::create(&path)?;
    writeln!(f, "name = \"{}\"", pkg.name)?;
    writeln!(f, "version = \"{}\"", pkg.version)?;
    writeln!(f, "architecture = \"{}\"", pkg.architecture)?;
    if !pkg.pre_install.is_empty() {
        writeln!(f, "pre_install = \"{}\"", pkg.pre_install)?;
    }
    if !pkg.post_install.is_empty() {
        writeln!(f, "post_install = \"{}\"", pkg.post_install)?;
    }
    Ok(())
}

fn check_symlink_escape(host_target: &Path, root_dir: &Path) -> Result<()> {
    let mut resolved = root_dir.to_path_buf();
    let rel_target = host_target.strip_prefix(root_dir).unwrap_or(host_target);

    for comp in rel_target.components() {
        match comp {
            Component::ParentDir => {
                if resolved == root_dir {
                    return Err(AppError::Security(format!(
                        "CRITICAL: Traversal escape detected (attempted to traverse above root {})",
                        root_dir.display()
                    )));
                }
                resolved.pop();
            }
            Component::RootDir => {
                resolved = root_dir.to_path_buf();
            }
            Component::Normal(c) => {
                resolved.push(c);
                if let Ok(meta) = fs::symlink_metadata(&resolved) {
                    if meta.is_symlink() {
                        let link = fs::read_link(&resolved)?;
                        if link.is_absolute() {
                            let mut new_resolved = root_dir.to_path_buf();
                            for l_comp in link.components() {
                                if let Component::Normal(lc) = l_comp {
                                    new_resolved.push(lc);
                                }
                            }
                            resolved = new_resolved;
                        } else {
                            resolved.pop();
                            for l_comp in link.components() {
                                match l_comp {
                                    Component::ParentDir => {
                                        if resolved == root_dir {
                                            return Err(AppError::Security(format!(
                                                "CRITICAL: Symlink traversal escape in {}",
                                                host_target.display()
                                            )));
                                        }
                                        resolved.pop();
                                    }
                                    Component::Normal(lc) => {
                                        resolved.push(lc);
                                    }
                                    Component::RootDir => {
                                        resolved = root_dir.to_path_buf();
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn match_pattern(pattern: &str, path: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return path.is_empty();
    }
    if !path.starts_with(parts[0]) {
        return false;
    }
    let mut current_idx = parts[0].len();
    for part in &parts[1..] {
        if part.is_empty() {
            continue;
        }
        if let Some(idx) = path[current_idx..].find(part) {
            current_idx += idx + part.len();
        } else {
            return false;
        }
    }
    pattern.ends_with('*') || current_idx == path.len()
}

fn split_subpackages_dynamic(pkg: &Package, fakeroot: &Path, ctx: &AppContext) -> Result<()> {
    for rule in &pkg.subpackages {
        let sub_root = fakeroot.with_file_name(format!("pkg-{}", rule.name));
        fs::create_dir_all(&sub_root)?;
    }
    let mut walk = vec![fakeroot.to_path_buf()];
    while let Some(dir) = walk.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.filter_map(std::result::Result::ok) {
                let path = entry.path();
                let meta = fs::symlink_metadata(&path)?;
                if meta.is_dir() {
                    walk.push(path);
                } else if meta.is_file() || meta.is_symlink() {
                    let rel_path = path
                        .strip_prefix(fakeroot)
                        .map_err(|e| AppError::General(e.to_string()))?;
                    let rel_str = rel_path.to_string_lossy();
                    for rule in &pkg.subpackages {
                        for pattern in &rule.patterns {
                            if match_pattern(pattern, &rel_str) {
                                let sub_root =
                                    fakeroot.with_file_name(format!("pkg-{}", rule.name));
                                let target = sub_root.join(rel_path);
                                if let Some(parent) = target.parent() {
                                    fs::create_dir_all(parent)?;
                                }
                                fs::rename(&path, &target)?;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    for rule in &pkg.subpackages {
        let sub_root = fakeroot.with_file_name(format!("pkg-{}", rule.name));
        let sub_pkg_name = format!("{}-{}", pkg.name, rule.name);
        let arc_path = ctx.root_path(&format!(
            "var/cache/bhpkg/{}-{}.tar.zst",
            sub_pkg_name, pkg.version
        ));
        let mut has_content = false;
        if sub_root.exists() {
            if let Ok(mut entries) = fs::read_dir(&sub_root) {
                if entries.next().is_some() {
                    has_content = true;
                }
            }
        }
        if has_content {
            let mut sub_pkg = pkg.clone();
            sub_pkg.name = sub_pkg_name.clone();
            write_metadata_file(&sub_pkg, &sub_root)?;
            archive::compress(&sub_root, &arc_path)?;
            ctx.print_msg(&format!("Created dynamic subpackage {}", sub_pkg_name));
        }
    }
    Ok(())
}

fn build_package(pkg: &mut Package, ctx: &AppContext) -> Result<()> {
    let builddir = utils::gen_tmp_path(&format!("build-{}", pkg.name), ctx);
    let fakeroot = utils::gen_tmp_path(&format!("pkg-{}", pkg.name), ctx);

    fs::create_dir_all(&builddir)?;
    fs::create_dir_all(&fakeroot)?;

    let _ = nix::mount::mount(
        Some("tmpfs"),
        &builddir,
        Some("tmpfs"),
        nix::mount::MsFlags::empty(),
        Some("mode=0755"),
    );

    struct CleanupGuard {
        builddir: PathBuf,
        fakeroot: PathBuf,
    }

    impl Drop for CleanupGuard {
        fn drop(&mut self) {
            let _ = nix::mount::umount2(&self.builddir, nix::mount::MntFlags::MNT_DETACH);
            let _ = fs::remove_dir_all(&self.builddir);
            let _ = fs::remove_dir_all(&self.fakeroot);
        }
    }

    let _guard = CleanupGuard {
        builddir: builddir.clone(),
        fakeroot: fakeroot.clone(),
    };

    fs::set_permissions(&builddir, fs::Permissions::from_mode(0o755))?;
    fs::set_permissions(&fakeroot, fs::Permissions::from_mode(0o755))?;

    utils::chown_recursive(&builddir, 65534, 65534)?;
    utils::chown_recursive(&fakeroot, 65534, 65534)?;

    for i in 0..pkg.sources.len() {
        let host_src = ctx.root_path(&format!(
            "var/lib/bhpkg/tmp/{}-{}-{}.src",
            pkg.name, pkg.version, i
        ));
        let staged = builddir.join(format!("{}-{}-{}.src", pkg.name, pkg.version, i));
        let orig = pkg.sources[i]
            .split('|')
            .next()
            .unwrap_or(&pkg.sources[i])
            .trim()
            .trim_end_matches('/')
            .to_lowercase();

        if orig.ends_with(".tar")
            || orig.ends_with(".tgz")
            || orig.ends_with(".tar.gz")
            || orig.ends_with(".tar.xz")
            || orig.ends_with(".tar.bz2")
            || orig.ends_with(".tar.zst")
        {
            let dest = if pkg.pkg_type == "binary" {
                &fakeroot
            } else {
                &builddir
            };

            if orig.ends_with(".tar.zst") {
                archive::extract(&host_src, dest, 1, ctx)?;
            } else {
                let file = File::open(&host_src)?;
                let status = std::process::Command::new("/bin/busybox")
                    .arg("tar")
                    .arg("xf")
                    .arg("-")
                    .arg("--strip-components=1")
                    .current_dir(dest)
                    .uid(65534)
                    .gid(65534)
                    .stdin(file)
                    .status()?;

                if !status.success() {
                    return Err(AppError::General(format!(
                        "tar extraction failed for: {}",
                        pkg.name
                    )));
                }
            }
        } else {
            utils::secure_copy(&host_src, &staged, 0o644)?;
        }
    }

    utils::chown_recursive(&builddir, 65534, 65534)?;
    utils::chown_recursive(&fakeroot, 65534, 65534)?;

    let script_path = builddir.join("bh-build.sh");
    let mut f = File::create(&script_path)?;
    f.set_permissions(fs::Permissions::from_mode(0o755))?;

    writeln!(
        f,
        "#!/bin/sh\nset -ex\nexport PATH=\"/bin:/usr/bin:/sbin:/usr/sbin\"\nexport DESTDIR=\"/dest\"\nexport PREFIX=\"/usr\""
    )?;

    let cflags_suffix = if pkg.name == "musl" || pkg.name == "glibc" {
        ""
    } else {
        " -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
    };

    let lto_flag = if ctx.config.is_use_flag_enabled("lto") {
        " -flto"
    } else {
        ""
    };

    writeln!(
        f,
        "export CFLAGS=\"-O3{} -pipe -fstack-protector-strong{}\"\nexport CXXFLAGS=\"$CFLAGS\"\nexport CPPFLAGS=\"{}\"\nexport MAKEFLAGS=\"-j$(nproc 2>/dev/null || echo 4)\"",
        lto_flag,
        cflags_suffix,
        cflags_suffix.trim()
    )?;

    for flag in &ctx.config.use_flags {
        let clean = flag.trim_start_matches('-');
        let val = if flag.starts_with('-') { 0 } else { 1 };
        writeln!(f, "export USE_{}={}", clean.to_uppercase(), val)?;
    }

    writeln!(f, "\ncp -a /host_build/. /build/ || exit 1")?;
    writeln!(f, "\ncd \"/build\" || exit 1\n{}", pkg.build_script)?;

    f.sync_all()?;
    drop(f);

    ctx.print_msg(&format!(
        "Building {} in sandboxed environment...",
        pkg.name
    ));

    let b_str = builddir
        .to_str()
        .ok_or_else(|| AppError::General("Non-UTF8 sandbox dir".into()))?;
    let f_str = fakeroot
        .to_str()
        .ok_or_else(|| AppError::General("Non-UTF8 sandbox fakeroot".into()))?;

    if let Err(e) = sandbox::run_build_sandboxed(b_str, f_str, pkg.net_access) {
        return Err(e);
    }

    utils::chown_recursive(&builddir, 0, 0)?;
    utils::chown_recursive(&fakeroot, 0, 0)?;

    split_subpackages_dynamic(pkg, &fakeroot, ctx)?;
    write_metadata_file(pkg, &fakeroot)?;

    let arc_path = ctx.root_path(&format!(
        "var/cache/bhpkg/{}-{}.tar.zst",
        pkg.name, pkg.version
    ));
    archive::compress(&fakeroot, &arc_path)?;

    Ok(())
}

fn apply_delta_rm_manifest(staging_dir: &Path) -> Result<()> {
    let manifest = staging_dir.join(".bhpkg-rm");
    if !manifest.exists() {
        return Ok(());
    }
    let file = File::open(&manifest)?;
    let reader = BufReader::new(file);

    for line in reader.lines().filter_map(std::result::Result::ok) {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let path_comp = Path::new(line);
        let is_safe = path_comp
            .components()
            .all(|comp| matches!(comp, Component::Normal(_)));

        if !is_safe {
            return Err(AppError::Security(format!(
                "CRITICAL: Path traversal detected in delta rm manifest: {}",
                line
            )));
        }

        let target = staging_dir.join(line);

        if let Some(parent) = target.parent() {
            let canon_parent = fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
            let canon_staging = fs::canonicalize(staging_dir)?;
            if !canon_parent.starts_with(&canon_staging) {
                return Err(AppError::Security(format!(
                    "CRITICAL: Symlink traversal escape in delta rm manifest: {}",
                    line
                )));
            }
        }

        let meta = match fs::symlink_metadata(&target) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if line.ends_with(".delta-patch") {
            if !meta.is_file() || meta.is_symlink() {
                return Err(AppError::Security(
                    "Attempted to patch a non-regular file".into(),
                ));
            }

            let orig_file_str = target.to_string_lossy();
            let orig_file = Path::new(&orig_file_str[..orig_file_str.len() - ".delta-patch".len()]);

            let orig_meta = match fs::symlink_metadata(orig_file) {
                Ok(m) => m,
                Err(_) => {
                    return Err(AppError::Security(
                        "Original file for patch is missing".into(),
                    ));
                }
            };

            if !orig_meta.is_file() || orig_meta.is_symlink() {
                return Err(AppError::Security(
                    "Target of patch is not a regular file".into(),
                ));
            }

            let tmp_patch_file = target.with_extension("tmp-patch");

            delta::apply_binary_delta(orig_file, &target, &tmp_patch_file)?;
            fs::rename(&tmp_patch_file, orig_file)?;
            let _ = fs::remove_file(&target);
        } else {
            if meta.is_dir() {
                let _ = fs::remove_dir(&target);
            } else {
                let _ = fs::remove_file(&target);
            }
        }
    }
    let _ = fs::remove_file(&manifest);
    Ok(())
}

fn stage_artifact(pkg: &mut Package, db: &dyn PackageDatabase, ctx: &AppContext) -> Result<()> {
    let arc_path = ctx.root_path(&format!(
        "var/cache/bhpkg/{}-{}.tar.zst",
        pkg.name, pkg.version
    ));
    pkg.staging_dir = utils::gen_tmp_path(&format!("staging-{}", pkg.name), ctx);
    fs::create_dir_all(&pkg.staging_dir)?;

    if pkg.is_delta {
        ctx.print_msg("Applying binary Delta patch to staging layer...");
        db.reconstruct_to_staging(&pkg.name, &pkg.staging_dir)?;
    }
    archive::extract(&arc_path, &pkg.staging_dir, 0, ctx)?;

    if pkg.is_delta {
        apply_delta_rm_manifest(&pkg.staging_dir)?;
    }

    if !pkg.staging_dir.join(".PKGINFO").exists() {
        return Err(AppError::General(format!(
            "Artifact {} is missing metadata.",
            pkg.name
        )));
    }
    Ok(())
}

pub fn commit_artifact(
    pkg: &Package,
    db: &dyn PackageDatabase,
    ctx: &AppContext,
    all_touched_files: &mut Vec<PathBuf>,
) -> Result<()> {
    let staging_dir = &pkg.staging_dir;
    let journal_path = ctx.root_path("var/lib/bhpkg/txn.journal");

    sandbox::run_hook_privileged(&pkg.pre_install, "pre_install", ctx)?;

    let mut journal = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&journal_path)?;
    let mut walk = vec![staging_dir.to_path_buf()];
    let mut dirs_to_create = Vec::new();
    let mut files_to_move = Vec::new();

    while let Some(dir) = walk.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.filter_map(std::result::Result::ok) {
                let path = entry.path();
                let rel = path
                    .strip_prefix(staging_dir)
                    .map_err(|e| AppError::General(e.to_string()))?;

                let is_safe = rel
                    .components()
                    .all(|comp| matches!(comp, Component::Normal(_)));
                if !is_safe {
                    return Err(AppError::Security(format!(
                        "CRITICAL: Path traversal escape detected in payload: {}",
                        rel.display()
                    )));
                }

                let target = ctx.root_path(&rel.to_string_lossy());
                if target.to_string_lossy().ends_with("/.PKGINFO") {
                    continue;
                }

                check_symlink_escape(&target, &ctx.config.root_dir)?;

                let meta = fs::symlink_metadata(&path)?;
                if meta.is_dir() {
                    let mode = meta.permissions().mode();
                    let uid = meta.uid();
                    let gid = meta.gid();
                    dirs_to_create.push((target, mode, uid, gid));
                    walk.push(path);
                } else {
                    files_to_move.push((path, target));
                }
            }
        }
    }

    let mut actual_moves = Vec::new();

    for (src, target) in files_to_move {
        let target_str = target.to_string_lossy().to_string();

        if target_str != "/usr/share/info/dir" {
            if let Some(owner) = db.check_conflict(&target_str, &pkg.name)? {
                return Err(AppError::General(format!(
                    "Conflict! '{}' is owned by '{}'.",
                    target_str, owner
                )));
            }
        }

        let is_config = target_str.contains("/etc/");
        let mut final_target = target.clone();

        if target.exists() {
            if is_config {
                let disk_hash = crypto::hash_file(&target).unwrap_or_default();
                let staged_hash = crypto::hash_file(&src).unwrap_or_default();
                let db_hash = db.get_file_hash(&target_str)?.unwrap_or_default();

                if !db_hash.is_empty() && disk_hash != db_hash && disk_hash != staged_hash {
                    final_target = PathBuf::from(format!("{}.bhpkg-new", target_str));
                    ctx.print_warn(&format!(
                        "Config modified. Installing new as {}",
                        final_target.display()
                    ));
                } else if db_hash.is_empty() {
                    final_target = PathBuf::from(format!("{}.bhpkg-new", target_str));
                }
            }

            if !final_target.to_string_lossy().ends_with(".bhpkg-new") {
                writeln!(
                    journal,
                    "B {} {}",
                    hex_encode_path(&target),
                    hex_encode_path(&PathBuf::from(format!("{}.bhpkg-backup", target.display())))
                )?;
            }
        }
        writeln!(
            journal,
            "I {} {}",
            hex_encode_path(&src),
            hex_encode_path(&final_target)
        )?;
        all_touched_files.push(final_target.clone());
        actual_moves.push((src, final_target, target.exists()));
    }

    for (target, _, _, _) in dirs_to_create.iter().rev() {
        writeln!(journal, "D {} -", hex_encode_path(target))?;
    }
    journal.sync_all()?;

    for (target, mode, uid, gid) in dirs_to_create {
        let _ = fs::create_dir_all(&target);
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode));
        let _ = nix::unistd::chown(
            &target,
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        );
    }

    for (src, target, target_existed) in actual_moves {
        if target_existed && !target.to_string_lossy().ends_with(".bhpkg-new") {
            let backup = format!("{}.bhpkg-backup", target.display());
            let _ = fs::rename(&target, &backup);
        }

        if fs::symlink_metadata(&src)?.is_symlink() {
            let link = fs::read_link(&src)?;
            let _ = fs::remove_file(&target);
            std::os::unix::fs::symlink(link, &target)?;
            let _ = fs::remove_file(&src);
        } else {
            let mode = fs::metadata(&src)?.permissions().mode();
            utils::rename_or_copy(&src, &target, mode)?;
        }
    }

    fs::remove_file(journal_path)?;
    sandbox::run_hook_privileged(&pkg.post_install, "post_install", ctx)?;
    Ok(())
}

pub fn rollback_journal(ctx: &AppContext) -> Result<()> {
    let journal_path = ctx.root_path("var/lib/bhpkg/txn.journal");
    if !journal_path.exists() {
        return Ok(());
    }

    ctx.print_warn("Incomplete transaction detected. Rolling back...");
    let file = File::open(&journal_path)?;
    let reader = BufReader::new(file);
    let mut actions = Vec::new();

    for line in reader.lines().filter_map(std::result::Result::ok) {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() == 3 {
            let op = parts[0].chars().next().unwrap();
            let p1 = hex_decode_path(parts[1]);

            if op == 'D' && parts[2] == "-" {
                if let Some(path1) = p1 {
                    actions.push((op, path1, PathBuf::new()));
                }
            } else {
                let p2 = hex_decode_path(parts[2]);
                if let (Some(path1), Some(path2)) = (p1, p2) {
                    actions.push((op, path1, path2));
                }
            }
        }
    }

    for (op, p1, p2) in actions.into_iter().rev() {
        match op {
            'D' => {
                let _ = fs::remove_dir(p1);
            }
            'B' => {
                let _ = fs::rename(p2, p1);
            }
            'I' => {
                let _ = fs::remove_file(p2);
            }
            _ => {}
        }
    }
    fs::remove_file(journal_path)?;
    ctx.print_msg("Filesystem rollback complete.");
    Ok(())
}

#[derive(Clone, PartialEq)]
enum TaskState {
    Pending,
    Building,
    Committed,
}

struct BuildGraph {
    in_degree: Vec<usize>,
    adj: Vec<Vec<usize>>,
    state: Vec<TaskState>,
    ready_queue: VecDeque<usize>,
    failed: bool,
    completed_count: usize,
    building_count: usize,
    total_tasks: usize,
}

enum Msg {
    BuildComplete(usize, Package),
    BuildFailed(usize, String),
}

pub fn process_build_queue(
    order: Vec<PackageRef>,
    db: &mut dyn PackageDatabase,
    ctx: &AppContext,
) -> Result<()> {
    ctx.print_msg(&format!("Preparing to commit {} packages...", order.len()));
    let mut to_download = Vec::new();

    let packages: Vec<Package> = order
        .into_iter()
        .map(|p| Arc::try_unwrap(p).unwrap_or_else(|arc| (*arc).clone()))
        .collect();

    for pkg in &packages {
        let cache_path = ctx.root_path(&format!(
            "var/cache/bhpkg/{}-{}.tar.zst",
            pkg.name, pkg.version
        ));
        if !pkg.is_installed && !cache_path.exists() {
            to_download.push(pkg.clone());
        }
    }

    net::download_all(&to_download, ctx)?;

    let n = packages.len();
    let mut name_to_idx = std::collections::HashMap::new();
    for (i, pkg) in packages.iter().enumerate() {
        name_to_idx.insert(pkg.name.clone(), i);
        for prov in &pkg.provides {
            name_to_idx.insert(prov.clone(), i);
        }
    }

    let mut adj = vec![Vec::new(); n];
    let mut in_degree = vec![0; n];

    for i in 0..n {
        let pkg = &packages[i];
        let deps = if !pkg.is_installed && pkg.pkg_type == "source" {
            pkg.dep_names
                .iter()
                .chain(pkg.makedep_names.iter())
                .collect::<Vec<_>>()
        } else {
            pkg.dep_names.iter().collect::<Vec<_>>()
        };

        let mut unique_deps = std::collections::HashSet::new();
        for dep in deps {
            if let Some(&dep_idx) = name_to_idx.get(dep) {
                if dep_idx != i {
                    unique_deps.insert(dep_idx);
                }
            }
        }

        for &dep_idx in &unique_deps {
            if dep_idx < i {
                adj[dep_idx].push(i);
                in_degree[i] += 1;
            } else if ctx.config.verbosity >= 2 {
                ctx.print_warn(&format!(
                    "Breaking circular loop edge: {} -> {}",
                    pkg.name, packages[dep_idx].name
                ));
            }
        }
    }

    let mut initial_ready_queue = VecDeque::new();
    for i in 0..n {
        if in_degree[i] == 0 {
            initial_ready_queue.push_back(i);
        }
    }

    let graph = Arc::new((
        Mutex::new(BuildGraph {
            in_degree,
            adj,
            state: vec![TaskState::Pending; n],
            ready_queue: initial_ready_queue,
            failed: false,
            completed_count: 0,
            building_count: 0,
            total_tasks: n,
        }),
        Condvar::new(),
    ));

    let (tx, rx) = mpsc::channel();
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let packages_arc = Arc::new(packages);

    let mut workers = Vec::new();

    for _ in 0..num_workers {
        let graph_clone = Arc::clone(&graph);
        let tx_clone = tx.clone();
        let ctx_clone = ctx.clone();
        let pkgs = Arc::clone(&packages_arc);

        workers.push(std::thread::spawn(move || loop {
            let task_idx = {
                let (lock, cvar) = &*graph_clone;
                let mut g = lock.lock().unwrap();
                loop {
                    if g.failed || ctx_clone.is_interrupted() {
                        return;
                    }
                    if g.completed_count == g.total_tasks {
                        return;
                    }

                    if let Some(idx) = g.ready_queue.pop_front() {
                        g.state[idx] = TaskState::Building;
                        g.building_count += 1;
                        break idx;
                    }

                    if g.building_count == 0 {
                        g.failed = true;
                        let _ = tx_clone.send(Msg::BuildFailed(
                            0,
                            "Deadlock detected in execution graph".into(),
                        ));
                        return;
                    }
                    g = cvar.wait(g).unwrap();
                }
            };

            let mut pkg = pkgs[task_idx].clone();
            let mut success = true;

            if !pkg.is_installed {
                pkg.is_cached = ctx_clone
                    .root_path(&format!(
                        "var/cache/bhpkg/{}-{}.tar.zst",
                        pkg.name, pkg.version
                    ))
                    .exists();

                if !pkg.is_cached {
                    if let Err(e) = build_package(&mut pkg, &ctx_clone) {
                        let _ = tx_clone.send(Msg::BuildFailed(
                            task_idx,
                            format!("Build failed for {}: {}", pkg.name, e),
                        ));
                        success = false;
                    }
                }
            }

            if success {
                let _ = tx_clone.send(Msg::BuildComplete(task_idx, pkg));
            }
        }));
    }

    drop(tx);

    let mut all_touched_files = Vec::new();
    let mut overall_success = true;

    for msg in rx {
        match msg {
            Msg::BuildComplete(idx, mut pkg) => {
                if !pkg.is_installed {
                    if let Err(e) = stage_artifact(&mut pkg, db, ctx) {
                        ctx.print_err(&format!("Stage failed for {}: {}", pkg.name, e));
                        overall_success = false;
                        break;
                    }
                    if let Err(e) = commit_artifact(&pkg, db, ctx, &mut all_touched_files) {
                        ctx.print_err(&format!("Commit failed for {}: {}", pkg.name, e));
                        overall_success = false;
                        break;
                    }
                    if let Err(e) = db.register_package(&pkg, &pkg.staging_dir, ctx) {
                        ctx.print_err(&format!("DB register failed for {}: {}", pkg.name, e));
                        overall_success = false;
                        break;
                    }
                    ctx.print_msg(&format!("Successfully installed: {}", pkg.name));
                    let _ = fs::remove_dir_all(&pkg.staging_dir);
                }

                let (lock, cvar) = &*graph;
                let mut g = lock.lock().unwrap();

                let state = &mut *g;
                state.state[idx] = TaskState::Committed;
                state.completed_count += 1;
                state.building_count -= 1;

                for &dep_idx in &state.adj[idx] {
                    state.in_degree[dep_idx] -= 1;
                    if state.in_degree[dep_idx] == 0 {
                        state.ready_queue.push_back(dep_idx);
                    }
                }
                cvar.notify_all();
            }
            Msg::BuildFailed(_idx, err) => {
                ctx.print_err(&err);
                overall_success = false;
                break;
            }
        }
    }

    if !overall_success || ctx.is_interrupted() {
        ctx.print_err("Transaction interrupted or failed. Safe state preserved.");
        let (lock, cvar) = &*graph;
        let mut g = lock.lock().unwrap();
        g.failed = true;
        cvar.notify_all();
    } else {
        unsafe {
            libc::sync();
        }
        sandbox::hook_execute_all("Install", ctx);
        sandbox::hook_evaluate_triggers(&all_touched_files, ctx);
        ctx.print_msg("Transaction completed successfully.");
    }

    for worker in workers {
        let _ = worker.join();
    }

    Ok(())
}

pub fn cache_prune(ctx: &AppContext) -> Result<()> {
    ctx.print_msg("Cleaning cache directory...");
    let cache_dir = ctx.root_path("var/cache/bhpkg");
    let _ = fs::remove_dir_all(&cache_dir);
    fs::create_dir_all(&cache_dir)?;
    ctx.print_msg("Cache pruned successfully.");
    Ok(())
}
