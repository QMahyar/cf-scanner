//! Runtime file locations (refreshed ranges, xray binary). Tests and
//! embedding flows redirect the whole data dir via `CF_SCANNER_DATA_DIR`.

use std::path::PathBuf;

use anyhow::{Result, anyhow};

pub fn data_dir() -> Result<PathBuf> {
    // Redirects the whole data directory (tests, embedding flows); the
    // refresh-ranges path, the xray binary path and the trial dirs all
    // resolve through this one function. warpgen's identity path honors the
    // same variable (its own entry point), so a test or embedder setting it
    // redirects the entire product data footprint.
    if let Ok(dir) = std::env::var("CF_SCANNER_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let dirs = directories::ProjectDirs::from("com", "qmahyar", "cf-scanner")
        .ok_or_else(|| anyhow!("could not resolve a data directory"))?;
    Ok(dirs.data_dir().to_path_buf())
}

pub fn refreshed_ranges_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("cf-ranges.txt"))
}

/// Data-dir copy of the refreshed IPv6 list (`ranges refresh --ipv6`).
pub fn refreshed_ranges_v6_path() -> Result<PathBuf> {
    Ok(data_dir()?.join("cf-ranges-v6.txt"))
}

/// Data-dir location of the xray binary (dev/downloaded fallback; release
/// archives bundle the binary next to the executable instead).
pub fn xray_binary_path() -> Result<PathBuf> {
    let name = if cfg!(windows) { "xray.exe" } else { "xray" };
    // Test-only seam, scoped to THIS path: lets the xray test module isolate
    // its binary/cache without mutating the process-wide env var. It must
    // not live in `data_dir()` — ranges' refresh tests resolve the shared
    // data dir at arbitrary moments, and a seam there would redirect (and
    // drop) their files mid-test. `xray_binary_path` is read only by xray's
    // own resolution/download code, so the seam is visible nowhere else.
    #[cfg(test)]
    if let Some(dir) = test_env::SEAM_DATA_DIR.lock().unwrap().clone() {
        return Ok(dir.join(name));
    }
    Ok(data_dir()?.join(name))
}

/// Restricts a secret-bearing file (identity keys, profiles, trial configs)
/// to the current user: a protected DACL with one grant replaces whatever
/// inherited ACEs the parent directory contributed. Unix callers don't need
/// this — secrets are written 0o600 at open time; this closes the Windows
/// half of the same boundary. Owner-only suffices because nothing on this
/// machine legitimately needs SYSTEM/Admins read access to these files.
#[cfg(windows)]
pub fn lock_down_to_owner(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
    use windows::Win32::Foundation::{CloseHandle, GENERIC_ALL, HANDLE, NO_ERROR, WIN32_ERROR};
    use windows::Win32::Security::Authorization::{
        EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW,
        TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
    };
    use windows::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, GetTokenInformation, NO_INHERITANCE,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows::core::{PCWSTR, PWSTR};

    fn win_err(err: WIN32_ERROR) -> std::io::Error {
        std::io::Error::from_raw_os_error(err.0 as i32)
    }

    fn hresult_err(err: windows::core::Error) -> std::io::Error {
        std::io::Error::from_raw_os_error(err.code().0)
    }

    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(hresult_err)?;
    let mut len = 0u32;
    // Sized query: the first call must fail with ERROR_INSUFFICIENT_BUFFER and
    // fill `len` with the TOKEN_USER size; any other outcome means `len` is
    // meaningless and the sized buffer below would be empty.
    let sized = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut len) };
    let expected = sized
        .err()
        .map(|e| e.code() == windows::core::HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0))
        .unwrap_or(false);
    if !expected || len == 0 {
        unsafe {
            let _ = CloseHandle(token);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "token user size query failed",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }
    .map_err(|e| {
        unsafe {
            let _ = CloseHandle(token);
        }
        hresult_err(e)
    })?;
    let sid: PSID = unsafe { (*(buf.as_ptr() as *const TOKEN_USER)).User.Sid };

    let ea = [EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL.0,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: Default::default(),
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: PWSTR(sid.0.cast()),
        },
    }];
    let mut new_acl: *mut ACL = std::ptr::null_mut();
    let err = unsafe { SetEntriesInAclW(Some(&ea), None, &mut new_acl) };
    if err != NO_ERROR {
        return Err(win_err(err));
    }
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl),
            None,
        )
    };
    if err != NO_ERROR {
        return Err(win_err(err));
    }
    Ok(())
}

#[cfg(not(windows))]
pub fn lock_down_to_owner(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_env {
    //! Isolated-data-dir harness for the paths and xray test modules.
    //!
    //! The xray tests redirect via [`SEAM_DATA_DIR`] (a test-only override
    //! consulted by `xray_binary_path` alone) so they never race the ranges
    //! refresh tests, which resolve the shared data dir mid-body. The paths
    //! tests exercise the real cross-module contract — the
    //! `CF_SCANNER_DATA_DIR` env var — using warpgen's exact pattern
    //! (warpgen.rs `isolated_identity_dir`): set the var to a fixed temp
    //! dir, never restore it. The variable only ever holds one of a handful
    //! of stable absolute paths, so any other test resolving the data dir
    //! sees a consistent value between two calls.

    use std::path::{Path, PathBuf};

    /// Serializes every test that mutates `CF_SCANNER_DATA_DIR` or the
    /// seam. A tokio mutex so async tests may hold the guard across awaits
    /// without deadlocking the runtime.
    pub(crate) static DATA_DIR_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
        std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

    /// Test-only data dir consulted by `xray_binary_path()`; set instead of
    /// the env var so the xray tests never race the ranges refresh tests'
    /// env reads (or warpgen's own flips of the variable).
    pub(crate) static SEAM_DATA_DIR: std::sync::Mutex<Option<PathBuf>> =
        std::sync::Mutex::new(None);

    /// Points `CF_SCANNER_DATA_DIR` at a fresh temp dir; the variable stays
    /// set for the rest of the process (warpgen's pattern), so path fns
    /// resolve consistently from any test's point of view.
    pub(crate) struct IsolatedDataDir {
        dir: PathBuf,
    }

    impl IsolatedDataDir {
        pub(crate) fn new() -> Self {
            let dir = std::env::temp_dir().join("cf-scanner-paths-tests");
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            // Unsafe: process-global env mutation, sound because callers
            // serialize on DATA_DIR_LOCK and the value is a stable absolute
            // path any reader can safely use.
            unsafe { std::env::set_var("CF_SCANNER_DATA_DIR", &dir) };
            Self { dir }
        }

        pub(crate) fn path(&self) -> &Path {
            &self.dir
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::test_env::{DATA_DIR_LOCK, IsolatedDataDir};

    #[cfg(windows)]
    #[test]
    fn lock_down_to_owner_keeps_the_file_usable_by_the_owner() {
        let dir = std::env::temp_dir().join(format!("cf-scanner-acl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("secret.json");
        std::fs::write(&file, b"{}").unwrap();
        lock_down_to_owner(&file).expect("DACL lockdown must succeed for the owner");
        // The owner must still be able to rewrite the file afterwards.
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&file)
            .expect("owner retains write access");
        assert_eq!(std::fs::read(&file).unwrap(), b"");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn data_dir_honors_cf_scanner_data_dir_override() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let isolated = IsolatedDataDir::new();
        let dir = isolated.path();
        assert_eq!(data_dir().unwrap(), dir);
        assert_eq!(refreshed_ranges_path().unwrap(), dir.join("cf-ranges.txt"));
        assert_eq!(
            refreshed_ranges_v6_path().unwrap(),
            dir.join("cf-ranges-v6.txt")
        );
        assert_eq!(xray_binary_path().unwrap().parent().unwrap(), dir);
    }

    #[test]
    fn xray_binary_path_uses_platform_exe_name() {
        let _guard = DATA_DIR_LOCK.blocking_lock();
        let _isolated = IsolatedDataDir::new();
        let expected = if cfg!(windows) { "xray.exe" } else { "xray" };
        assert_eq!(
            xray_binary_path()
                .unwrap()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap(),
            expected
        );
    }

    #[test]
    fn default_data_dir_is_absolute() {
        // Without the override, the directories fallback must still resolve
        // to something usable (exact path is platform/user dependent). The
        // env var is deliberately NOT touched: any test-set value is an
        // absolute temp dir, so the assertion holds regardless.
        let _guard = DATA_DIR_LOCK.blocking_lock();
        assert!(data_dir().unwrap().is_absolute());
    }
}
