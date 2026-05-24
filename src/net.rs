use crate::crypto;
use crate::error::{AppError, Result};
use crate::types::{AppContext, Package};
use curl::easy::Easy;
use curl::multi::Multi;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

struct DownloadTask {
    name: String,
    dest: PathBuf,
    mirrors: Vec<String>,
    current_mirror: usize,
    expected_hash: Option<String>,
    progress_idx: usize,
}

struct ActiveHandle {
    handle: curl::multi::EasyHandle,
    task: DownloadTask,
}

fn create_easy(
    task: &DownloadTask,
    progress_state: Arc<Vec<(AtomicU64, AtomicU64)>>,
    interrupted: Arc<AtomicBool>,
) -> Result<Easy> {
    let mut easy = Easy::new();

    let target_url = &task.mirrors[task.current_mirror];
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Err(AppError::Net(format!(
            "Insecure or unsupported protocol rejected: {}",
            target_url
        )));
    }
    easy.url(target_url)
        .map_err(|e| AppError::Net(e.to_string()))?;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW);

    let mut file = match options.open(&task.dest) {
        Ok(f) => f,
        Err(_) => {
            let _ = std::fs::remove_file(&task.dest);
            options.open(&task.dest)?
        }
    };

    let interrupt_arc_write = Arc::clone(&interrupted);
    easy.write_function(move |data| {
        if interrupt_arc_write.load(Ordering::SeqCst) {
            return Ok(0);
        }
        if file.write_all(data).is_err() {
            return Ok(0);
        }
        Ok(data.len())
    })
    .map_err(|e| AppError::Net(e.to_string()))?;

    let interrupt_arc_hdr = Arc::clone(&interrupted);
    easy.header_function(move |header| {
        if let Ok(hdr_str) = std::str::from_utf8(header) {
            let hdr_lower = hdr_str.to_ascii_lowercase();
            if hdr_lower.starts_with("location:") {
                let loc = hdr_lower[9..].trim();
                if let Some(idx) = loc.find("://") {
                    let proto = &loc[..idx];
                    if proto != "http" && proto != "https" {
                        interrupt_arc_hdr.store(true, Ordering::SeqCst);
                        return false;
                    }
                }
            }
        }
        true
    })
    .map_err(|e| AppError::Net(e.to_string()))?;

    let state_arc = Arc::clone(&progress_state);
    let interrupt_arc_prog = Arc::clone(&interrupted);
    let idx = task.progress_idx;

    easy.progress_function(move |dltotal, dlnow, _, _| {
        if interrupt_arc_prog.load(Ordering::SeqCst) {
            return false;
        }
        state_arc[idx].1.store(dltotal.to_bits(), Ordering::Relaxed);
        state_arc[idx].0.store(dlnow.to_bits(), Ordering::Relaxed);
        true
    })
    .map_err(|e| AppError::Net(e.to_string()))?;

    easy.progress(true)
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.follow_location(true)
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.max_redirections(10)
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.max_filesize(4_000_000_000)
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.fail_on_error(true)
        .map_err(|e| AppError::Net(e.to_string()))?;

    easy.ssl_verify_peer(true)
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.ssl_verify_host(true)
        .map_err(|e| AppError::Net(e.to_string()))?;

    let ca_path = std::path::Path::new("/etc/ssl/certs/ca-certificates.crt");
    if ca_path.exists() {
        easy.cainfo(ca_path)
            .map_err(|e| AppError::Net(e.to_string()))?;
    }

    easy.useragent("bhpkg/2.0 (Blackhole OS)")
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.buffer_size(102400)
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.connect_timeout(Duration::from_secs(15))
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.low_speed_limit(100)
        .map_err(|e| AppError::Net(e.to_string()))?;
    easy.low_speed_time(Duration::from_secs(15))
        .map_err(|e| AppError::Net(e.to_string()))?;

    Ok(easy)
}

pub fn download_all(packages: &[Package], ctx: &AppContext) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }

    let mut tasks_vec = Vec::new();
    let mut idx = 0;
    for pkg in packages {
        for (i, source) in pkg.sources.iter().enumerate() {
            let mirrors: Vec<String> = source.split('|').map(|s| s.trim().to_string()).collect();
            let dest = ctx.root_path(&format!(
                "var/lib/bhpkg/tmp/{}-{}-{}.src",
                pkg.name, pkg.version, i
            ));
            tasks_vec.push(DownloadTask {
                name: pkg.name.clone(),
                dest,
                mirrors,
                current_mirror: 0,
                expected_hash: pkg.hashes.get(i).cloned(),
                progress_idx: idx,
            });
            idx += 1;
        }
    }

    let total_tasks = tasks_vec.len();
    if total_tasks == 0 {
        return Ok(());
    }

    let progress_state = Arc::new(
        (0..total_tasks)
            .map(|_| (AtomicU64::new(0), AtomicU64::new(0)))
            .collect::<Vec<_>>(),
    );
    let is_done = Arc::new(AtomicBool::new(false));
    let interrupted = Arc::new(AtomicBool::new(false));

    let monitor_state = Arc::clone(&progress_state);
    let monitor_done = Arc::clone(&is_done);
    let monitor_ctx = ctx.clone();
    let pacman_mode = ctx.config.pacman_mode;

    let monitor_handle = std::thread::spawn(move || {
        let mut last_percent = -1;
        let bar_width = 30;

        if monitor_ctx.config.verbosity >= 1 {
            print!("\x1b[?25l");
        }

        while !monitor_done.load(Ordering::Relaxed) && !monitor_ctx.is_interrupted() {
            if monitor_ctx.config.verbosity >= 1 {
                let mut total_now = 0f64;
                let mut total_expected = 0f64;

                for state in monitor_state.iter() {
                    let now = f64::from_bits(state.0.load(Ordering::Relaxed));
                    let total = f64::from_bits(state.1.load(Ordering::Relaxed));
                    total_now += now;
                    if total > 0.0 {
                        total_expected += total;
                    } else {
                        total_expected += now + 1.0;
                    }
                }

                let mut percent = if total_expected > 0.0 {
                    (total_now / total_expected) * 100.0
                } else {
                    0.0
                };
                if percent > 100.0 {
                    percent = 100.0;
                }
                let current_percent = percent as i32;

                if current_percent != last_percent {
                    let pos = (current_percent * bar_width) / 100;
                    print!(
                        "\r\x1b[1;36m==>\x1b[0m Fetching {} sources... [",
                        total_tasks
                    );

                    if pacman_mode {
                        for j in 0..bar_width {
                            if j < pos {
                                print!("-");
                            } else if j == pos {
                                print!("{}", if current_percent % 2 == 0 { 'C' } else { 'c' });
                            } else if j % 2 == 0 {
                                print!("o");
                            } else {
                                print!(" ");
                            }
                        }
                    } else {
                        for j in 0..bar_width {
                            if j < pos {
                                print!("#");
                            } else {
                                print!("-");
                            }
                        }
                    }
                    print!("] {:3.0}%\x1b[K", percent);
                    std::io::stdout().flush().unwrap();
                    last_percent = current_percent;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        if monitor_ctx.config.verbosity >= 1 {
            print!(
                "\r\x1b[1;36m==>\x1b[0m Fetching {} sources... [",
                total_tasks
            );
            for _ in 0..bar_width {
                print!("{}", if pacman_mode { "-" } else { "#" });
            }
            println!("] 100%\x1b[K\x1b[?25h");
        }
    });

    let mut multi = Multi::new();
    multi.pipelining(true, true).ok();

    let mut active_transfers: HashMap<usize, ActiveHandle> = HashMap::new();
    let mut pending_tasks = tasks_vec.into_iter();
    let mut overall_success = true;
    let max_concurrent = 16;

    let fill_queue = |multi: &mut Multi,
                      active: &mut HashMap<usize, ActiveHandle>,
                      pending: &mut std::vec::IntoIter<DownloadTask>,
                      success_flag: &mut bool| {
        while active.len() < max_concurrent {
            if let Some(task) = pending.next() {
                match create_easy(&task, Arc::clone(&progress_state), Arc::clone(&interrupted)) {
                    Ok(easy) => {
                        let token = task.progress_idx;
                        if let Ok(mut handle) = multi.add(easy) {
                            handle.set_token(token).unwrap();
                            active.insert(token, ActiveHandle { handle, task });
                        }
                    }
                    Err(e) => {
                        ctx.print_err(&format!("Failed to init download for {}: {}", task.name, e));
                        *success_flag = false;
                    }
                }
            } else {
                break;
            }
        }
    };

    fill_queue(
        &mut multi,
        &mut active_transfers,
        &mut pending_tasks,
        &mut overall_success,
    );

    while !active_transfers.is_empty() && !crate::SIGNAL_INTERRUPTED.load(Ordering::SeqCst) {
        multi.perform().map_err(|e| AppError::Net(e.to_string()))?;

        let mut done_tokens = Vec::new();
        multi.messages(|msg| {
            if let Some(result) = msg.result() {
                if let Ok(token) = msg.token() {
                    done_tokens.push((token, result));
                }
            }
        });

        for (token, result) in done_tokens {
            if let Some(mut active) = active_transfers.remove(&token) {
                let mut easy = multi.remove(active.handle).unwrap();

                let mut hash_ok = false;
                let mut err_msg = String::new();
                let mut http_code = 0;

                let success = match result {
                    Ok(_) => {
                        http_code = easy.response_code().unwrap_or(0);
                        http_code / 100 == 2
                    }
                    Err(e) => {
                        err_msg = format!("TLS/Network Error: {}", e);
                        false
                    }
                };

                drop(easy);

                if success {
                    if let Some(ref hash) = active.task.expected_hash {
                        if !hash.is_empty() {
                            hash_ok = crypto::verify_sha256(&active.task.dest, hash);
                            if !hash_ok {
                                err_msg = "SHA256 mismatch".into();
                            }
                        } else {
                            err_msg = "Expected hash is empty".into();
                        }
                    } else {
                        let file_name = active.task.dest.to_string_lossy();
                        if file_name.contains("repo_")
                            && (file_name.contains(".db-tmp-")
                                || file_name.contains(".db.sig-tmp-"))
                        {
                            hash_ok = true;
                        } else {
                            err_msg = "No hash provided for package".into();
                        }
                    }
                } else if err_msg.is_empty() {
                    err_msg = format!("HTTP {}", http_code);
                }

                if success && hash_ok {
                    if ctx.config.verbosity >= 1 && active.task.expected_hash.is_some() {
                        println!("\r\x1b[K  \x1b[1;32m[PASS]\x1b[0m {}", active.task.name);
                    }
                } else {
                    active.task.current_mirror += 1;
                    let _ = std::fs::remove_file(&active.task.dest);

                    if active.task.current_mirror < active.task.mirrors.len() {
                        ctx.print_warn(&format!(
                            "[{}] {} - Falling back to: {}",
                            active.task.name,
                            err_msg,
                            active.task.mirrors[active.task.current_mirror]
                        ));

                        interrupted.store(false, Ordering::SeqCst);
                        match create_easy(
                            &active.task,
                            Arc::clone(&progress_state),
                            Arc::clone(&interrupted),
                        ) {
                            Ok(new_easy) => {
                                let mut new_handle = multi.add(new_easy).unwrap();
                                new_handle.set_token(token).unwrap();
                                active_transfers.insert(
                                    token,
                                    ActiveHandle {
                                        handle: new_handle,
                                        task: active.task,
                                    },
                                );
                            }
                            Err(_) => {
                                overall_success = false;
                            }
                        }
                    } else {
                        ctx.print_err(&format!(
                            "All mirrors exhausted for '{}' (Last error: {})",
                            active.task.name, err_msg
                        ));
                        overall_success = false;
                    }
                }
            }
        }

        fill_queue(
            &mut multi,
            &mut active_transfers,
            &mut pending_tasks,
            &mut overall_success,
        );
        multi
            .wait(&mut [], Duration::from_millis(100))
            .map_err(|e| AppError::Net(e.to_string()))?;
    }

    if !overall_success || crate::SIGNAL_INTERRUPTED.load(Ordering::SeqCst) {
        interrupted.store(true, Ordering::SeqCst);
        for (_, active) in active_transfers {
            let _ = multi.remove(active.handle);
            let _ = std::fs::remove_file(&active.task.dest);
        }
        is_done.store(true, Ordering::Relaxed);
        let _ = monitor_handle.join();
        return Err(AppError::Net("Downloads failed or interrupted".into()));
    }

    is_done.store(true, Ordering::Relaxed);
    let _ = monitor_handle.join();

    Ok(())
}
