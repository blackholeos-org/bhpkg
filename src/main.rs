mod archive;
mod config;
mod core_ops;
mod crypto;
mod db;
mod delta;
mod error;
mod net;
mod sandbox;
mod solver;
mod types;
mod utils;

use crate::error::Result;
use crate::solver::PackageDatabase;
use crate::types::{AppContext, Config};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

pub static SIGNAL_INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[derive(Parser, Debug)]
#[command(
    name = "bhpkg",
    version = "2.0",
    author = "Blackhole OS",
    about = "Blazing fast, transactional package manager"
)]
struct Cli {
    #[arg(short = 'S', long, help = "Sync repository databases")]
    sync: bool,
    #[arg(short = 'i', long, help = "Install a package explicitly")]
    install: bool,
    #[arg(short = 'u', long, help = "Update system")]
    update: bool,
    #[arg(short = 'R', long, help = "Remove a package")]
    remove: bool,
    #[arg(
        short = 's',
        long,
        help = "Search repositories or remove orphans (if combined with -R)"
    )]
    search_or_orphans: bool,
    #[arg(short = 'Y', long, help = "Remove all orphans globally")]
    orphans_global: bool,
    #[arg(short = 'Q', long, help = "List installed packages")]
    list: bool,
    #[arg(short = 'c', long, help = "Clean cache directory")]
    clean: bool,
    #[arg(short = 'q', long, help = "Silent mode")]
    quiet: bool,
    #[arg(short = 'v', action = clap::ArgAction::Count, help = "Increase verbosity up to 3 times")]
    verbose: u8,
    #[arg(
        long,
        value_name = "DIR",
        help = "Operate on an alternative root filesystem"
    )]
    root: Option<PathBuf>,
    #[arg(long, hide = true)]
    internal_sandbox: bool,

    #[arg(help = "Target package names or search queries")]
    targets: Vec<String>,
}

fn bootstrap_filesystem(ctx: &AppContext) -> Result<()> {
    let dirs = [
        "var/lib/bhpkg",
        "var/lib/bhpkg/tmp",
        "var/cache/bhpkg",
        "etc/bhpkg",
        "etc/bhpkg/hooks",
        "etc/bhpkg/keys",
    ];
    for dir in dirs {
        let _ = fs::create_dir_all(ctx.root_path(dir));
    }
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(
        ctx.root_path("var/lib/bhpkg/tmp"),
        fs::Permissions::from_mode(0o711),
    )?;
    Ok(())
}

fn run_app() -> Result<()> {
    let cli = Cli::parse();

    if cli.internal_sandbox {
        sandbox::execute_internal_sandbox()?;
        return Ok(());
    }

    if nix::unistd::geteuid().as_raw() != 0 {
        eprintln!("\x1b[1;31m==> ERROR:\x1b[0m \x1b[1mbhpkg must be run as root.\x1b[0m");
        std::process::exit(1);
    }

    ctrlc::set_handler(move || {
        SIGNAL_INTERRUPTED.store(true, Ordering::SeqCst);
    })
    .expect("Error setting signal handler");

    let target_root = cli.root.unwrap_or_else(|| PathBuf::from("/"));
    let mut cfg = Config::load(&target_root);

    if cli.quiet {
        cfg.verbosity = 0;
    } else if cli.verbose > 0 {
        cfg.verbosity = (cfg.verbosity + cli.verbose).min(3);
    }

    let ctx = AppContext { config: cfg };

    bootstrap_filesystem(&ctx)?;
    core_ops::rollback_journal(&ctx)?;

    let mut db = db::Database::new(&ctx)?;
    if let Err(e) = db.attach_repos(&ctx) {
        ctx.print_warn(&format!("Failed to attach remote repos: {}", e));
    }

    if cli.clean {
        core_ops::cache_prune(&ctx)?;
    }
    if cli.orphans_global && !cli.remove {
        db.remove_orphans(&ctx)?;
    }
    if cli.sync {
        db.sync_repos(&ctx)?;
    }
    if cli.search_or_orphans && !cli.remove {
        for target in &cli.targets {
            db.search(target)?;
        }
    }
    if cli.list {
        db.list_installed()?;
    }
    if cli.remove {
        for target in &cli.targets {
            if db.remove_package(target, &ctx)? && cli.search_or_orphans {
                db.remove_orphans(&ctx)?;
            }
        }
    }

    if cli.update {
        let updates = if !cli.targets.is_empty() {
            let mut specific_updates = Vec::new();
            for target in &cli.targets {
                if let Some(p) = db.fetch_manifest(target, None, &ctx)? {
                    let mut p_mut =
                        std::sync::Arc::try_unwrap(p).unwrap_or_else(|arc| (*arc).clone());
                    p_mut.install_reason = 0;
                    specific_updates.push(std::sync::Arc::new(p_mut));
                } else {
                    ctx.print_err(&format!("Package '{}' not found.", target));
                }
            }
            specific_updates
        } else {
            db.get_updates(&ctx)?
        };

        if updates.is_empty() && cli.targets.is_empty() {
            ctx.print_msg("System is fully up-to-date.");
        } else {
            for pkg in updates {
                if ctx.is_interrupted() {
                    break;
                }
                match solver::resolve_dependencies(&pkg, &mut db, &ctx) {
                    Ok(order) => {
                        if let Err(e) = core_ops::process_build_queue(order, &mut db, &ctx) {
                            ctx.print_err(&format!("Upgrade failed: {}", e));
                        }
                    }
                    Err(e) => ctx.print_err(&format!("Dependency resolution failed: {}", e)),
                }
            }
        }
    }

    if cli.install {
        for target in &cli.targets {
            if let Some(pkg_ref) = db.fetch_manifest(target, None, &ctx)? {
                let mut pkg =
                    std::sync::Arc::try_unwrap(pkg_ref).unwrap_or_else(|arc| (*arc).clone());
                pkg.install_reason = 0;
                match solver::resolve_dependencies(&std::sync::Arc::new(pkg), &mut db, &ctx) {
                    Ok(order) => {
                        if let Err(e) = core_ops::process_build_queue(order, &mut db, &ctx) {
                            ctx.print_err(&format!("Installation failed: {}", e));
                        }
                    }
                    Err(e) => ctx.print_err(&format!("Dependency resolution failed: {}", e)),
                }
            } else {
                ctx.print_err(&format!("Package '{}' not found in sync database!", target));
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run_app() {
        eprintln!("\x1b[1;31m==> FATAL ERROR:\x1b[0m \x1b[1m{:#}\x1b[0m", e);
        std::process::exit(1);
    }

    unsafe {
        libc::_exit(0);
    }
}
