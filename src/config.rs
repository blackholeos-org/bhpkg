use crate::types::{Config, RepoConfig};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Deserialize, Default)]
struct TomlConfig {
    #[serde(default)]
    options: OptionsConfig,
    #[serde(default)]
    repos: Vec<TomlRepoConfig>,
}

#[derive(Deserialize, Default)]
struct OptionsConfig {
    verbosity: Option<u8>,
    pacman_mode: Option<bool>,
    use_flags: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct TomlRepoConfig {
    name: String,
    url: String,
    sig_url: String,
    pubkey_path: String,
    priority: Option<i32>,
}

impl Config {
    pub fn load(root_dir: &Path) -> Self {
        let mut cfg = Config {
            verbosity: 1,
            pacman_mode: false,
            root_dir: root_dir.to_path_buf(),
            use_flags: HashSet::new(),
            repos: Vec::new(),
        };

        let conf_path = root_dir.join("etc/bhpkg/bhpkg.toml");
        if let Ok(content) = fs::read_to_string(&conf_path) {
            if let Ok(toml_cfg) = toml::from_str::<TomlConfig>(&content) {
                if let Some(v) = toml_cfg.options.verbosity {
                    cfg.verbosity = v;
                }
                if let Some(p) = toml_cfg.options.pacman_mode {
                    cfg.pacman_mode = p;
                }
                if let Some(flags) = toml_cfg.options.use_flags {
                    cfg.use_flags = flags.into_iter().collect();
                }
                for repo in toml_cfg.repos {
                    cfg.repos.push(RepoConfig {
                        name: repo.name,
                        url: repo.url,
                        sig_url: repo.sig_url,
                        pubkey_path: repo.pubkey_path,
                        priority: repo.priority.unwrap_or(99),
                    });
                }
            }
        }
        cfg
    }
}
