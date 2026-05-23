use crate::error::Result;
use crate::solver::{self, PackageDatabase};
use crate::types::{AppContext, Config, Package, PackageRef, SubpackageRule};
use crate::{crypto, net, sandbox};
use rusqlite::{Connection, OpenFlags, Row, params};
use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn new(ctx: &AppContext) -> Result<Self> {
        let db_path = ctx.root_path("var/lib/bhpkg/local.db");
        if let Some(parent) = db_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;

        conn.create_collation("BHPKG_VERCMP", |s1: &str, s2: &str| {
            solver::bhpkg_vercmp(s1, s2)
        })?;

        conn.busy_timeout(std::time::Duration::from_secs(60))?;
        conn.execute_batch("
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=NORMAL;
            PRAGMA foreign_keys=ON;
            CREATE TABLE IF NOT EXISTS local_packages (name TEXT PRIMARY KEY, version TEXT, reason INTEGER);
            CREATE TABLE IF NOT EXISTS files (package TEXT, filepath TEXT, hash TEXT, is_config INTEGER, UNIQUE(filepath));
        ")?;
        Ok(Database { conn })
    }

    pub fn attach_repos(&self, ctx: &AppContext) -> Result<()> {
        let mut view_sql = String::from("CREATE TEMP VIEW IF NOT EXISTS sync_packages AS ");
        let mut attached = 0;

        for repo in &ctx.config.repos {
            if !repo
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                ctx.print_warn(&format!(
                    "Skipping invalid repo name to prevent SQLi: {}",
                    repo.name
                ));
                continue;
            }

            let db_path = ctx.root_path(&format!("var/lib/bhpkg/repo_{}.db", repo.name));
            let db_path_str = db_path.to_string_lossy().replace('\'', "''");

            if db_path.exists()
                && self
                    .conn
                    .execute(
                        &format!("ATTACH DATABASE '{}' AS repo_{}", db_path_str, repo.name),
                        [],
                    )
                    .is_ok()
            {
                if attached > 0 {
                    view_sql.push_str(" UNION ALL ");
                }
                view_sql.push_str(&format!(
                    "SELECT '{}' AS origin_repo, {} AS priority, * FROM repo_{}.packages",
                    repo.name, repo.priority, repo.name
                ));
                attached += 1;
            }
        }

        if attached > 0 {
            self.conn.execute(&view_sql, [])?;
        }
        Ok(())
    }

    pub fn sync_repos(&self, ctx: &AppContext) -> Result<()> {
        let mut packages = Vec::new();
        for repo in &ctx.config.repos {
            packages.push(Package {
                name: format!("repo_{}.db", repo.name),
                version: "tmp".to_string(),
                sources: vec![repo.url.clone()],
                ..Default::default()
            });
            packages.push(Package {
                name: format!("repo_{}.db.sig", repo.name),
                version: "tmp".to_string(),
                sources: vec![repo.sig_url.clone()],
                ..Default::default()
            });
        }
        net::download_all(&packages, ctx)?;

        for repo in &ctx.config.repos {
            if !repo
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                continue;
            }
            let src_db = ctx.root_path(&format!(
                "var/lib/bhpkg/tmp/repo_{}.db-tmp-0.src",
                repo.name
            ));
            let src_sig = ctx.root_path(&format!(
                "var/lib/bhpkg/tmp/repo_{}.db.sig-tmp-0.src",
                repo.name
            ));
            if !src_db.exists() || !src_sig.exists() {
                continue;
            }

            match crypto::verify_signature(&src_db, &src_sig, &repo.pubkey_path, ctx) {
                Ok(true) => {
                    let remote_conn = Connection::open(&src_db)?;
                    let mut remote_ts: i64 = remote_conn
                        .query_row("PRAGMA user_version", [], |r| r.get(0))
                        .unwrap_or(0);
                    if remote_ts == 0 {
                        remote_ts = remote_conn
                            .query_row("SELECT updated_at FROM repo_meta WHERE id = 1", [], |r| {
                                r.get(0)
                            })
                            .unwrap_or(0);
                    }

                    let local_db = ctx.root_path(&format!("var/lib/bhpkg/repo_{}.db", repo.name));
                    if local_db.exists() {
                        if let Ok(local_conn) = Connection::open(&local_db) {
                            let mut local_ts: i64 = local_conn
                                .query_row("PRAGMA user_version", [], |r| r.get(0))
                                .unwrap_or(0);

                            if local_ts == 0 {
                                local_ts = local_conn
                                    .query_row(
                                        "SELECT updated_at FROM repo_meta WHERE id = 1",
                                        [],
                                        |r| r.get(0),
                                    )
                                    .unwrap_or(0);
                            }

                            if remote_ts > 0 && remote_ts < local_ts {
                                ctx.print_err(&format!("CRITICAL: Replay attack detected on repo '{}'. Downgrade rejected.", repo.name));
                                let _ = fs::remove_file(&src_sig);
                                let _ = fs::remove_file(&src_db);
                                continue;
                            }
                        }
                    }

                    fs::rename(&src_db, &local_db)?;
                    ctx.print_msg(&format!("Successfully synced: {}", repo.name));
                }
                _ => ctx.print_err(&format!(
                    "Signature verification failed for repo {}!",
                    repo.name
                )),
            }
            let _ = fs::remove_file(&src_sig);
            let _ = fs::remove_file(&src_db);
        }
        Ok(())
    }

    fn map_row_to_package(row: &Row, ctx: &AppContext) -> rusqlite::Result<Package> {
        let parse_list = |s: Option<String>| -> Vec<String> {
            s.unwrap_or_default()
                .split(',')
                .filter(|x| !x.is_empty())
                .map(|x| x.trim().to_string())
                .collect()
        };
        let parse_cond = |s: Option<String>, config: &Config| -> (Vec<String>, Vec<String>) {
            let mut n = Vec::new();
            let mut c = Vec::new();
            for tok in s.unwrap_or_default().split(',').filter(|x| !x.is_empty()) {
                let clean = tok.trim();
                let actual_dep = if let Some((flag, dep)) = clean.split_once('?') {
                    if !config.is_use_flag_enabled(flag.trim()) {
                        continue;
                    }
                    dep.trim()
                } else {
                    clean
                };
                if let Some(idx) = actual_dep.find(|c: char| c == '<' || c == '>' || c == '=') {
                    n.push(actual_dep[..idx].to_string());
                    c.push(actual_dep[idx..].to_string());
                } else {
                    n.push(actual_dep.to_string());
                    c.push(String::new());
                }
            }
            (n, c)
        };

        let (dep_names, dep_constraints) = parse_cond(row.get(5).ok(), &ctx.config);
        let (makedep_names, makedep_constraints) = parse_cond(row.get(6).ok(), &ctx.config);
        let mut subpackages = Vec::new();
        if let Ok(sub_str) = row.get::<_, String>(16) {
            for sub in sub_str.split('|').filter(|s| !s.is_empty()) {
                if let Some((name, patterns)) = sub.split_once(':') {
                    subpackages.push(SubpackageRule {
                        name: name.to_string(),
                        patterns: patterns.split(',').map(|s| s.to_string()).collect(),
                    });
                }
            }
        }

        Ok(Package {
            repo_origin: row.get(0).unwrap_or_default(),
            pkg_type: row.get(1).unwrap_or_else(|_| "source".to_string()),
            license: row.get(2).unwrap_or_else(|_| "Unknown".to_string()),
            sources: parse_list(row.get(3).ok()),
            hashes: parse_list(row.get(4).ok()),
            dep_names,
            dep_constraints,
            makedep_names,
            makedep_constraints,
            build_script: row.get(7).unwrap_or_default(),
            pre_install: row.get(8).unwrap_or_default(),
            post_install: row.get(9).unwrap_or_default(),
            pre_remove: row.get(10).unwrap_or_default(),
            post_remove: row.get(11).unwrap_or_default(),
            architecture: row.get(12).unwrap_or_else(|_| "any".to_string()),
            provides: parse_list(row.get(13).ok()),
            conflicts: parse_list(row.get(14).ok()),
            obsoletes: parse_list(row.get(15).ok()),
            subpackages,
            ..Default::default()
        })
    }

    pub fn fetch_manifest(
        &self,
        name: &str,
        version: Option<&str>,
        ctx: &AppContext,
    ) -> Result<Option<PackageRef>> {
        let query = if version.is_some() {
            "SELECT origin_repo, type, license, sources, hashes, depends, makedepends, build_script, pre_install, post_install, pre_remove, post_remove, architecture, provides, conflicts, obsoletes, subpackages, version FROM sync_packages WHERE name = ?1 AND version = ?2 LIMIT 1"
        } else {
            "SELECT origin_repo, type, license, sources, hashes, depends, makedepends, build_script, pre_install, post_install, pre_remove, post_remove, architecture, provides, conflicts, obsoletes, subpackages, version FROM sync_packages WHERE name = ?1 ORDER BY priority ASC, version COLLATE BHPKG_VERCMP DESC LIMIT 1"
        };

        let mut stmt = self.conn.prepare_cached(query)?;
        let mut rows = if let Some(v) = version {
            stmt.query(params![name, v])?
        } else {
            stmt.query(params![name])?
        };

        if let Some(row) = rows.next()? {
            let mut pkg = Self::map_row_to_package(row, ctx)?;
            pkg.name = name.to_string();
            pkg.version = row.get(17)?;
            pkg.is_installed = self
                .conn
                .query_row(
                    "SELECT 1 FROM local_packages WHERE name = ?1",
                    params![name],
                    |_| Ok(()),
                )
                .is_ok();
            return Ok(Some(Arc::new(pkg)));
        }
        Ok(None)
    }

    pub fn get_updates(&self, ctx: &AppContext) -> Result<Vec<PackageRef>> {
        let mut updates = Vec::new();
        let mut stmt = self.conn.prepare_cached("SELECT l.name, l.version, s.version FROM local_packages l JOIN sync_packages s ON l.name = s.name ORDER BY s.priority ASC")?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for res in rows.filter_map(|r| r.ok()) {
            if solver::bhpkg_vercmp(&res.2, &res.1) == Ordering::Greater {
                if let Some(p) = self.fetch_manifest(&res.0, None, ctx)? {
                    let mut p_mut = Arc::try_unwrap(p).unwrap_or_else(|arc| (*arc).clone());
                    p_mut.install_reason = 0;
                    updates.push(Arc::new(p_mut));
                }
            }
        }
        Ok(updates)
    }

    pub fn is_required_by_others(&self, pkg_name: &str) -> Result<bool> {
        let mut is_required = false;
        let mut stmt = self.conn.prepare_cached("SELECT r.depends, r.makedepends FROM local_packages l JOIN sync_packages r ON l.name = r.name WHERE l.name != ?1")?;
        let _ = stmt.query_map(params![pkg_name], |row| {
            for dep_list in [
                row.get::<_, String>(0).unwrap_or_default(),
                row.get::<_, String>(1).unwrap_or_default(),
            ] {
                for tok in dep_list.split(',').map(|s| s.trim()) {
                    let actual_dep =
                        if let Some(idx) = tok.find(|c: char| c == '<' || c == '>' || c == '=') {
                            &tok[..idx]
                        } else {
                            tok
                        };
                    if actual_dep == pkg_name {
                        is_required = true;
                    }
                }
            }
            Ok(())
        })?;
        Ok(is_required)
    }

    pub fn remove_orphans(&mut self, ctx: &AppContext) -> Result<()> {
        ctx.print_msg("Checking for orphan dependencies...");
        loop {
            let mut installed = std::collections::HashMap::new();

            {
                let mut stmt = self.conn.prepare_cached("SELECT l.name, l.reason, s.depends, s.makedepends FROM local_packages l JOIN sync_packages s ON l.name = s.name")?;
                for row in stmt
                    .query_map([], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i32>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, String>(3)?,
                        ))
                    })?
                    .filter_map(|r| r.ok())
                {
                    installed.insert(row.0, (row.1, row.2, row.3));
                }
            }

            let mut required = std::collections::HashSet::new();
            for (_, (_, deps, makedeps)) in &installed {
                for dep_list in [deps, makedeps] {
                    for tok in dep_list.split(',').filter(|s| !s.is_empty()) {
                        let dep = tok.trim();
                        let actual_dep = if let Some(idx) =
                            dep.find(|c: char| c == '<' || c == '>' || c == '=')
                        {
                            &dep[..idx]
                        } else {
                            dep
                        };
                        required.insert(actual_dep.to_string());
                    }
                }
            }

            let mut orphans = Vec::new();
            for (name, (reason, _, _)) in &installed {
                if *reason == 1 && !required.contains(name) {
                    orphans.push(name.clone());
                }
            }

            if orphans.is_empty() {
                break;
            }

            for orphan in orphans {
                ctx.print_msg(&format!("Removing orphan: {}", orphan));
                self.remove_package(&orphan, ctx)?;
            }
        }
        Ok(())
    }

    pub fn list_installed(&self) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT name, version FROM local_packages ORDER BY name")?;
        println!("\n\x1b[1m==> Installed Packages:\x1b[0m");
        let mut count = 0;
        for res in stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
            .filter_map(|r| r.ok())
        {
            println!("  \x1b[1;32m{}\x1b[0m {}", res.0, res.1);
            count += 1;
        }
        println!("\n  Total: {} packages.\n", count);
        Ok(())
    }

    pub fn search(&self, query: &str) -> Result<()> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT name, version, type, license FROM sync_packages WHERE name LIKE ?1",
        )?;
        println!("\n\x1b[1m==> Search results for '{}':\x1b[0m", query);
        let mut count = 0;
        for res in stmt
            .query_map(params![format!("%{}%", query)], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?
            .filter_map(|r| r.ok())
        {
            println!(
                "  \x1b[1;36m{}\x1b[0m {} ({}) [{}]",
                res.0, res.1, res.2, res.3
            );
            count += 1;
        }
        if count == 0 {
            println!("  No packages found.");
        }
        println!();
        Ok(())
    }

    fn is_protected_file(path: &str) -> bool {
        let protected = [
            "/bin/sh",
            "/bin/busybox",
            "/bin/bhpkg",
            "/lib/libc.so",
            "/lib/ld-musl-x86_64.so.1",
            "/etc/passwd",
            "/etc/shadow",
        ];
        let resolved = fs::canonicalize(path).unwrap_or_else(|_| PathBuf::from(path));
        protected.iter().any(|&p| resolved.to_string_lossy() == p)
    }
}

impl PackageDatabase for Database {
    fn fetch_all_versions(&self, name: &str, ctx: &AppContext) -> Result<Vec<PackageRef>> {
        let mut versions = Vec::new();
        let mut stmt = self.conn.prepare_cached(
            "SELECT version FROM sync_packages WHERE name = ?1 ORDER BY version COLLATE BHPKG_VERCMP DESC",
        )?;
        for ver in stmt
            .query_map(params![name], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
        {
            if let Some(pkg) = self.fetch_manifest(name, Some(&ver), ctx)? {
                versions.push(pkg);
            }
        }
        Ok(versions)
    }

    fn fetch_providers(&self, provides_name: &str, ctx: &AppContext) -> Result<Vec<PackageRef>> {
        let mut providers = Vec::new();
        let mut stmt = self
            .conn
            .prepare_cached("SELECT name, version FROM sync_packages WHERE provides LIKE ?1")?;
        for (name, ver) in stmt
            .query_map(params![format!("%{}%", provides_name)], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .filter_map(|r| r.ok())
        {
            if let Some(pkg) = self.fetch_manifest(&name, Some(&ver), ctx)? {
                if pkg.provides.contains(&provides_name.to_string()) {
                    providers.push(pkg);
                }
            }
        }
        Ok(providers)
    }

    fn check_conflict(&self, filepath: &str, pkg_name: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT package FROM files WHERE filepath = ?1 AND package != ?2")?;
        Ok(stmt
            .query_row(params![filepath, pkg_name], |r| r.get::<_, String>(0))
            .ok())
    }

    fn get_file_hash(&self, filepath: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT hash FROM files WHERE filepath = ?1")?;
        Ok(stmt
            .query_row(params![filepath], |r| r.get::<_, String>(0))
            .ok())
    }

    fn reconstruct_to_staging(&self, pkg_name: &str, staging_dir: &Path) -> Result<()> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT filepath FROM files WHERE package = ?1")?;

        for file in stmt
            .query_map(params![pkg_name], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok())
        {
            let host_path = Path::new(&file);
            let target = staging_dir.join(file.trim_start_matches('/'));
            if let Some(parent) = target.parent() {
                let _ = fs::create_dir_all(parent);
            }

            if let Ok(meta) = fs::symlink_metadata(host_path) {
                use std::os::unix::fs::PermissionsExt;
                if meta.is_symlink() {
                    if let Ok(link) = fs::read_link(host_path) {
                        let _ = std::os::unix::fs::symlink(link, &target);
                    }
                } else if meta.is_dir() {
                    let _ = fs::create_dir_all(&target);
                } else {
                    let _ =
                        crate::utils::secure_copy(host_path, &target, meta.permissions().mode());
                }
            }
        }
        Ok(())
    }

    fn remove_package(&mut self, name: &str, ctx: &AppContext) -> Result<bool> {
        if self.is_required_by_others(name)? {
            ctx.print_err(&format!(
                "Cannot remove '{}': required by other packages.",
                name
            ));
            return Ok(false);
        }
        ctx.print_msg(&format!("Removing {}...", name));
        let pkg = self.fetch_manifest(name, None, ctx)?;
        if let Some(ref p) = pkg {
            sandbox::run_hook_privileged(&p.pre_remove, "pre_remove", ctx)?;
        }
        sandbox::hook_execute_all("Remove", ctx);

        let mut files_to_delete = Vec::new();

        {
            let mut stmt = self.conn.prepare_cached(
                "SELECT filepath, hash, is_config FROM files WHERE package = ?1 ORDER BY filepath DESC",
            )?;
            for row in stmt
                .query_map(params![name], |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Option<String>>(1)?,
                        r.get::<_, i32>(2)? == 1,
                    ))
                })?
                .filter_map(|r| r.ok())
            {
                files_to_delete.push(row);
            }
        }

        for (file, db_hash, is_config) in files_to_delete {
            if Self::is_protected_file(&file) {
                ctx.print_warn(&format!(
                    "Refusing to delete critical system file: {}",
                    file
                ));
                continue;
            }
            let p = Path::new(&file);
            if is_config && db_hash.is_some() && p.exists() {
                if let Ok(disk_hash) = crypto::hash_file(p) {
                    if disk_hash != db_hash.unwrap() {
                        let save = format!("{}.bhpkg-save", file);
                        let _ = fs::rename(&file, &save);
                        ctx.print_warn(&format!("Saved modified config as {}", save));
                        continue;
                    }
                }
            }

            if fs::remove_file(&file).is_ok() {
                let mut dir = p.parent();
                while let Some(d) = dir {
                    if d.as_os_str().is_empty()
                        || d.to_string_lossy() == "/"
                        || fs::remove_dir(d).is_err()
                    {
                        break;
                    }
                    dir = d.parent();
                }
            }
        }

        self.conn.execute("BEGIN EXCLUSIVE TRANSACTION", [])?;
        self.conn
            .execute("DELETE FROM files WHERE package = ?1", params![name])?;
        self.conn
            .execute("DELETE FROM local_packages WHERE name = ?1", params![name])?;
        self.conn.execute("COMMIT", [])?;

        if let Some(ref p) = pkg {
            sandbox::run_hook_privileged(&p.post_remove, "post_remove", ctx)?;
        }
        Ok(true)
    }

    fn register_package(
        &mut self,
        pkg: &Package,
        staging_dir: &Path,
        _ctx: &AppContext,
    ) -> Result<()> {
        self.conn.execute("BEGIN EXCLUSIVE TRANSACTION", [])?;
        self.conn.execute(
            "INSERT OR REPLACE INTO local_packages (name, version, reason) VALUES (?1, ?2, ?3)",
            params![pkg.name, pkg.version, pkg.install_reason],
        )?;
        self.conn
            .execute("DELETE FROM files WHERE package = ?1", params![pkg.name])?;

        let mut walk = vec![staging_dir.to_path_buf()];
        while let Some(dir) = walk.pop() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.filter_map(std::result::Result::ok) {
                    let path = entry.path();
                    let meta = fs::symlink_metadata(&path).unwrap();
                    if meta.is_dir() {
                        walk.push(path);
                    } else if meta.is_file() || meta.is_symlink() {
                        if let Ok(rel) = path.strip_prefix(staging_dir) {
                            let target = format!("/{}", rel.to_string_lossy());

                            if target.ends_with("/.PKGINFO") {
                                continue;
                            }

                            let is_config = target.starts_with("/etc/");
                            let hash = crypto::hash_file(&path).ok();

                            self.conn.execute("INSERT OR REPLACE INTO files (package, filepath, hash, is_config) VALUES (?1, ?2, ?3, ?4)", params![pkg.name, target, hash, is_config])?;
                        }
                    }
                }
            }
        }
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }
}
