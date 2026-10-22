//! Resolution and loading of the packaged Unicorn shared library.

use std::path::{Path, PathBuf};

use libloading::Library;

use crate::client::AppleClient;
use crate::error::ClientError;

/// The packaged or system Unicorn library to load.
#[derive(Debug, Clone)]
pub struct Paths {
    pub library: PathBuf,
}

/// Resolves Unicorn from the package that installed iDescriptor. Development
/// and distro packages use the system loader; self-contained packages place
/// the library beside the executable or in their private library directory.
pub async fn ensure(_client: &AppleClient, _cache_dir: &Path) -> Result<Paths, ClientError> {
    if let Some(path) = std::env::var_os("IDESCRIPTOR_UNICORN_PATH") {
        return Ok(Paths {
            library: PathBuf::from(path),
        });
    }

    let executable = std::env::current_exe().ok();

    #[cfg(target_os = "windows")]
    let candidates = executable
        .as_deref()
        .and_then(Path::parent)
        .map(|directory| vec![directory.join("libunicorn.dll")])
        .unwrap_or_default();

    #[cfg(target_os = "macos")]
    let candidates = executable
        .as_deref()
        .and_then(Path::parent)
        .map(|directory| vec![directory.join("../Frameworks/libunicorn.2.dylib")])
        .unwrap_or_default();

    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates = executable
        .as_deref()
        .and_then(Path::parent)
        .map(|directory| {
            vec![
                directory.join("../lib/libunicorn.so.2"),
                PathBuf::from("/app/lib/libunicorn.so.2"),
            ]
        })
        .unwrap_or_else(|| vec![PathBuf::from("/app/lib/libunicorn.so.2")]);

    if let Some(library) = candidates.into_iter().find(|path| path.is_file()) {
        return Ok(Paths { library });
    }

    #[cfg(target_os = "windows")]
    let library = PathBuf::from("libunicorn.dll");
    #[cfg(target_os = "macos")]
    let library = PathBuf::from("libunicorn.2.dylib");
    #[cfg(all(unix, not(target_os = "macos")))]
    let library = PathBuf::from("libunicorn.so.2");

    Ok(Paths { library })
}

/// Opens Unicorn; its native dependencies are resolved by the system loader.
///
/// # Safety
///
/// Loading a shared library runs its initializers. The paths must come from a
/// trusted system package or an iDescriptor package.
pub unsafe fn open(paths: &Paths) -> Result<Library, ClientError> {
    unsafe { open_unicorn(&paths.library) }
}

#[cfg(not(target_os = "windows"))]
unsafe fn open_unicorn(path: &Path) -> Result<Library, ClientError> {
    unsafe { open_one(path) }
}

/// Loads Unicorn and rewrites the imports it cannot be called through as
/// shipped. See [`super::windows`].
#[cfg(target_os = "windows")]
unsafe fn open_unicorn(path: &Path) -> Result<Library, ClientError> {
    use libloading::os::windows::Library as WindowsLibrary;

    let loaded = unsafe { WindowsLibrary::new(path) }
        .map_err(|e| ClientError::Sap(format!("load {}: {e}", path.display())))?;

    let handle = loaded.into_raw();

    // Reconstructed before preparing, so a failure below still unloads the DLL
    // rather than leaking the handle taken out of `loaded`.
    //
    // SAFETY: `handle` came from a successful `LoadLibraryExW` just above and
    // has not been used since.
    let library = Library::from(unsafe { WindowsLibrary::from_raw(handle) });

    // SAFETY: the module stays loaded for as long as `library` is alive, and it
    // is returned to the caller on success.
    unsafe { super::windows::prepare(handle as *const u8) }?;

    Ok(library)
}

unsafe fn open_one(path: &Path) -> Result<Library, ClientError> {
    unsafe { Library::new(path) }
        .map_err(|e| ClientError::Sap(format!("load {}: {e}", path.display())))
}
