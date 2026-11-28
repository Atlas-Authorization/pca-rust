//! Windows arm of the durable replace: `MoveFileExW(.., MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` does not return
//! until the move is on disk.

use std::path::Path;

pub(crate) fn replace_file(src: &Path, dst: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    // MOVEFILE_REPLACE_EXISTING (0x1) | MOVEFILE_WRITE_THROUGH (0x8), written as one value: the two bits are disjoint, so an
    // operator between them (| vs ^ vs +) could not change the call
    const FLAGS: u32 = 0x9;
    let wide = |p: &Path| p.as_os_str().encode_wide().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let (s, d) = (wide(src), wide(dst));
    // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the call.
    let ok = unsafe { MoveFileExW(s.as_ptr(), d.as_ptr(), FLAGS) };
    if ok == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}
