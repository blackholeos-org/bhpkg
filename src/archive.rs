use crate::error::{AppError, Result};
use crate::types::AppContext;
use std::fs::{self, File};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::{Archive, Builder};
use zstd::stream::{Decoder, Encoder};

pub fn extract(
    filename: &Path,
    dest_dir: &Path,
    strip_components: usize,
    ctx: &AppContext,
) -> Result<()> {
    let file = File::open(filename)?;
    let decoder = Decoder::new(file)?;
    let mut archive = Archive::new(decoder);

    archive.set_preserve_permissions(true);
    archive.set_unpack_xattrs(true);

    if strip_components == 0 {
        if !dest_dir.exists() {
            fs::create_dir_all(dest_dir)?;
        }
        archive.unpack(dest_dir)?;
        return Ok(());
    }

    let tmp_sandbox = crate::utils::gen_tmp_path("extract_sandbox", ctx);
    fs::create_dir_all(&tmp_sandbox)?;
    fs::set_permissions(&tmp_sandbox, fs::Permissions::from_mode(0o700))?;

    archive.unpack(&tmp_sandbox)?;

    let mut current_dir = tmp_sandbox.clone();
    for _ in 0..strip_components {
        let mut entries = fs::read_dir(&current_dir)?;
        if let Some(Ok(entry)) = entries.next() {
            if entries.next().is_some() {
                let _ = fs::remove_dir_all(&tmp_sandbox);
                return Err(AppError::Security(
                    "Ambiguous top-level directories detected during strip_components".into(),
                ));
            }
            if !entry.file_type()?.is_dir() {
                let _ = fs::remove_dir_all(&tmp_sandbox);
                return Err(AppError::Security(
                    "Cannot strip component: Target is not a directory".into(),
                ));
            }
            current_dir = entry.path();
        } else {
            let _ = fs::remove_dir_all(&tmp_sandbox);
            return Err(AppError::Security(
                "Not enough components to strip in archive".into(),
            ));
        }
    }

    if !dest_dir.exists() {
        fs::create_dir_all(dest_dir)?;
    }

    for entry in fs::read_dir(&current_dir)? {
        let entry = entry?;
        let file_name = entry.file_name();
        let dest_path = dest_dir.join(&file_name);
        fs::rename(entry.path(), dest_path)?;
    }

    let _ = fs::remove_dir_all(&tmp_sandbox);
    Ok(())
}

pub fn compress(src_dir: &Path, dest_archive: &Path) -> Result<()> {
    let file = File::create(dest_archive)?;
    let mut encoder = Encoder::new(file, 3)?;
    encoder.multithread(0)?;

    let mut builder = Builder::new(encoder);

    builder.follow_symlinks(false);

    // Note: tar crate's append_dir_all apparently has a bug where it throws ELOOP on symlink loops
    // even if follow_symlinks(false) is set. We have to manually walk the tree to get around it.
    builder.append_dir(".", src_dir)?;

    let mut walk = vec![(src_dir.to_path_buf(), PathBuf::from("."))];
    while let Some((dir, rel)) = walk.pop() {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.filter_map(std::result::Result::ok) {
                let path = entry.path();
                let file_name = entry.file_name();
                let rel_path = rel.join(&file_name);

                if let Ok(meta) = fs::symlink_metadata(&path) {
                    if meta.is_dir() {
                        builder.append_dir(&rel_path, &path)?;
                        walk.push((path, rel_path));
                    } else {
                        builder.append_path_with_name(&path, &rel_path)?;
                    }
                }
            }
        }
    }

    let encoder = builder.into_inner()?;
    encoder.finish()?;
    Ok(())
}
