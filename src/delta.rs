use crate::error::{AppError, Result};
use memmap2::Mmap;
use std::fs::File;
use std::io::{BufWriter, Write};
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
    let f_old = File::open(old_file)?;
    let f_patch = File::open(patch_file)?;

    let old_len = f_old.metadata()?.len() as usize;
    let m_old = if old_len > 0 {
        Some(unsafe { Mmap::map(&f_old)? })
    } else {
        None
    };
    let m_patch = unsafe { Mmap::map(&f_patch)? };

    if m_patch.len() < 32 || &m_patch[0..8] != b"BSDIFF40" {
        return Err(AppError::General("Invalid BSDIFF40 header".into()));
    }

    let ctrl_len = offin(&m_patch[8..16])? as usize;
    let diff_len = offin(&m_patch[16..24])? as usize;
    let new_size = offin(&m_patch[24..32])? as usize;

    let min_req_size = 32usize
        .checked_add(ctrl_len)
        .and_then(|x| x.checked_add(diff_len))
        .ok_or_else(|| AppError::Security("Delta lengths overflow".into()))?;

    if min_req_size > m_patch.len() {
        return Err(AppError::Security(
            "Corrupt patch metadata (Lengths exceed file size)".into(),
        ));
    }

    let f_new_inner = File::create(new_file)?;
    f_new_inner.set_len(new_size as u64)?;
    let mut f_new = BufWriter::with_capacity(2 * 1024 * 1024, f_new_inner);

    let mut old_pos: i64 = 0;
    let mut new_pos: usize = 0;

    let mut ctrl_ptr = 32;
    let mut diff_ptr = 32 + ctrl_len;
    let mut extra_ptr = diff_ptr + diff_len;

    while new_pos < new_size {
        let add_len = offin(&m_patch[ctrl_ptr..ctrl_ptr + 8])? as usize;
        let copy_len = offin(&m_patch[ctrl_ptr + 8..ctrl_ptr + 16])? as usize;
        let seek_val = offin(&m_patch[ctrl_ptr + 16..ctrl_ptr + 24])?;
        ctrl_ptr += 24;

        if new_pos
            .checked_add(add_len)
            .ok_or_else(|| AppError::Security("Delta Overflow".into()))?
            > new_size
        {
            return Err(AppError::Security(
                "Corrupt patch metadata (Add exceeds new size)".into(),
            ));
        }

        if add_len > 0 {
            let mut buffer = vec![0u8; add_len];
            if let Some(ref m_old_data) = m_old {
                for i in 0..add_len {
                    let old_idx = (old_pos + i as i64) as usize;
                    let old_byte = if old_idx < old_len {
                        m_old_data[old_idx]
                    } else {
                        0
                    };
                    buffer[i] = m_patch[diff_ptr + i].wrapping_add(old_byte);
                }
            } else {
                for i in 0..add_len {
                    buffer[i] = m_patch[diff_ptr + i];
                }
            }
            f_new.write_all(&buffer)?;
            diff_ptr += add_len;
            new_pos += add_len;
            old_pos += add_len as i64;
        }

        if new_pos
            .checked_add(copy_len)
            .ok_or_else(|| AppError::Security("Delta Overflow".into()))?
            > new_size
        {
            return Err(AppError::Security(
                "Corrupt patch metadata (Copy exceeds new size)".into(),
            ));
        }

        if copy_len > 0 {
            f_new.write_all(&m_patch[extra_ptr..extra_ptr + copy_len])?;
            extra_ptr += copy_len;
            new_pos += copy_len;
        }

        old_pos = old_pos
            .checked_add(seek_val)
            .ok_or_else(|| AppError::Security("Seek Overflow".into()))?;
    }

    f_new.flush()?;
    Ok(())
}
