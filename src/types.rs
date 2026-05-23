#![allow(dead_code)]

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct SubpackageRule {
    pub name: String,
    pub patterns: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub pkg_type: String,
    pub license: String,
    pub repo_origin: String,

    pub sources: Vec<String>,
    pub hashes: Vec<String>,
    pub dep_names: Vec<String>,
    pub dep_constraints: Vec<String>,
    pub makedep_names: Vec<String>,
    pub makedep_constraints: Vec<String>,

    pub provides: Vec<String>,
    pub conflicts: Vec<String>,
    pub obsoletes: Vec<String>,
    pub subpackages: Vec<SubpackageRule>,

    pub build_script: String,
    pub pre_install: String,
    pub post_install: String,
    pub pre_remove: String,
    pub post_remove: String,

    pub install_reason: i32,
    pub is_installed: bool,
    pub is_cached: bool,
    pub net_access: bool,
    pub is_delta: bool,
    pub staging_dir: PathBuf,
}

pub type PackageRef = Arc<Package>;

#[derive(Debug, Clone)]
pub struct RepoConfig {
    pub name: String,
    pub url: String,
    pub sig_url: String,
    pub pubkey_path: String,
    pub priority: i32,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub verbosity: u8,
    pub pacman_mode: bool,
    pub root_dir: PathBuf,
    pub use_flags: HashSet<String>,
    pub repos: Vec<RepoConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            verbosity: 1,
            pacman_mode: false,
            root_dir: PathBuf::from("/"),
            use_flags: HashSet::new(),
            repos: Vec::new(),
        }
    }
}

impl Config {
    pub fn is_use_flag_enabled(&self, flag: &str) -> bool {
        if flag.starts_with('-') {
            return false;
        }
        self.use_flags.contains(flag) || !self.use_flags.contains(&format!("-{}", flag))
    }
}

#[derive(Clone)]
pub struct AppContext {
    pub config: Config,
}

impl AppContext {
    pub fn is_interrupted(&self) -> bool {
        crate::SIGNAL_INTERRUPTED.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn root_path(&self, path: &str) -> PathBuf {
        let stripped = path.strip_prefix('/').unwrap_or(path);
        self.config.root_dir.join(stripped)
    }

    pub fn print_msg(&self, msg: &str) {
        if self.config.verbosity >= 1 {
            println!("\x1b[1;36m==>\x1b[0m \x1b[1m{}\x1b[0m", msg);
        }
    }

    pub fn print_warn(&self, msg: &str) {
        if self.config.verbosity >= 1 {
            println!("\x1b[1;33m==> WARNING:\x1b[0m \x1b[1m{}\x1b[0m", msg);
        }
    }

    pub fn print_err(&self, msg: &str) {
        eprintln!("\x1b[1;31m==> ERROR:\x1b[0m \x1b[1m{}\x1b[0m", msg);
    }
}
