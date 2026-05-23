use crate::error::{AppError, Result};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

#[inline(always)]
fn offin(buf: &[u8]) -> Result<i64> {
    let mut y = (buf[7] & 0x7F) as i64;
    for i in (0..=6).rev() {
        y = y
            .checked_shl(8)
            .ok_or_else(|| AppError::Security("Shift overflow".into()))?
            | (buf[i] as i64);
    }
    if buf[7] & 0x80 != 0 {
        y.checked_neg()
            .ok_or_else(|| AppError::Security("Negation overflow".into()))
    } else {
        Ok(y)
    }
}

pub fn apply_binary_delta(old_file: &Path, patch_file: &Path, new_file: &Path) -> Result<()> {
    let mut f_patch = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(patch_file)?;

    let mut header = [0u8; 32];
    f_patch.read_exact(&mut header)?;

    if &header[0..8] != b"BSDIFF40" {
        return Err(AppError::General("Invalid BSDIFF40 header".into()));
    }

    let ctrl_len_raw = offin(&header[8..16])?;
    let diff_len_raw = offin(&header[16..24])?;
    let new_size_raw = offin(&header[24..32])?;

    let ctrl_len =
        u64::try_from(ctrl_len_raw).map_err(|_| AppError::Security("Negative ctrl_len".into()))?;
    let diff_len =
        u64::try_from(diff_len_raw).map_err(|_| AppError::Security("Negative diff_len".into()))?;
    let new_size =
        u64::try_from(new_size_raw).map_err(|_| AppError::Security("Negative new_size".into()))?;

    let total_patch_size = f_patch.metadata()?.len();

    let min_req_size = 32u64
        .checked_add(ctrl_len)
        .and_then(|x| x.checked_add(diff_len))
        .ok_or_else(|| AppError::Security("Delta lengths overflow".into()))?;

    if min_req_size > total_patch_size {
        return Err(AppError::Security(
            "Corrupt patch metadata (Lengths exceed file size)".into(),
        ));
    }

    let mut ctrl_reader = BufReader::with_capacity(131_072, std::fs::File::open(patch_file)?);
    ctrl_reader.seek(SeekFrom::Start(32))?;

    let mut diff_reader = BufReader::with_capacity(524_288, std::fs::File::open(patch_file)?);
    diff_reader.seek(SeekFrom::Start(32 + ctrl_len))?;

    let mut extra_reader = BufReader::with_capacity(524_288, std::fs::File::open(patch_file)?);
    extra_reader.seek(SeekFrom::Start(32 + ctrl_len + diff_len))?;

    let mut f_old = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(old_file)?;
    let old_len = f_old.metadata()?.len();

    let f_new_inner = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(new_file)?;
    let mut f_new = BufWriter::with_capacity(1024 * 1024, f_new_inner);

    let mut old_pos: i64 = 0;
    let mut new_pos: u64 = 0;
    let mut ctrl_buf = [0u8; 24];
    const CHUNK_SIZE: usize = 2 * 1024 * 1024;
    let mut diff_buf = vec![0u8; CHUNK_SIZE];
    let mut old_buf = vec![0u8; CHUNK_SIZE];

    while new_pos < new_size {
        ctrl_reader.read_exact(&mut ctrl_buf)?;
        let ctrl_add_raw = offin(&ctrl_buf[0..8])?;
        let ctrl_copy_raw = offin(&ctrl_buf[8..16])?;
        let ctrl_seek = offin(&ctrl_buf[16..24])?;

        let ctrl_add = u64::try_from(ctrl_add_raw)
            .map_err(|_| AppError::Security("Negative add len".into()))?;
        let ctrl_copy = u64::try_from(ctrl_copy_raw)
            .map_err(|_| AppError::Security("Negative copy len".into()))?;

        if new_pos
            .checked_add(ctrl_add)
            .ok_or_else(|| AppError::Security("Delta Overflow".into()))?
            > new_size
        {
            return Err(AppError::Security(
                "Corrupt patch metadata (Add exceeds new size)".into(),
            ));
        }

        let mut remaining_add = ctrl_add as usize;
        while remaining_add > 0 {
            let chunk = std::cmp::min(remaining_add, CHUNK_SIZE);
            diff_reader.read_exact(&mut diff_buf[..chunk])?;

            if old_pos >= 0 && (old_pos as u64) < old_len {
                f_old.seek(SeekFrom::Start(old_pos as u64))?;
                let available = (old_len - old_pos as u64) as usize;
                let to_read = std::cmp::min(chunk, available);

                f_old.read_exact(&mut old_buf[..to_read])?;
                if to_read < chunk {
                    old_buf[to_read..chunk].fill(0);
                }
            } else {
                old_buf[..chunk].fill(0);
            }

            for i in 0..chunk {
                diff_buf[i] = diff_buf[i].wrapping_add(old_buf[i]);
            }

            f_new.write_all(&diff_buf[..chunk])?;
            remaining_add -= chunk;

            old_pos = old_pos
                .checked_add(chunk as i64)
                .ok_or_else(|| AppError::Security("Overflow".into()))?;
            new_pos += chunk as u64;
        }

        if new_pos
            .checked_add(ctrl_copy)
            .ok_or_else(|| AppError::Security("Delta Overflow".into()))?
            > new_size
        {
            return Err(AppError::Security(
                "Corrupt patch metadata (Copy exceeds new size)".into(),
            ));
        }

        let mut remaining_copy = ctrl_copy as usize;
        while remaining_copy > 0 {
            let chunk = std::cmp::min(remaining_copy, CHUNK_SIZE);
            extra_reader.read_exact(&mut diff_buf[..chunk])?;
            f_new.write_all(&diff_buf[..chunk])?;
            remaining_copy -= chunk;
            new_pos += chunk as u64;
        }

        old_pos = old_pos
            .checked_add(ctrl_seek)
            .ok_or_else(|| AppError::Security("Seek Overflow".into()))?;
    }

    f_new.flush()?;
    Ok(())
}
