//! Thin binding to the Unicorn CPU emulator.
//!
//! Only the entry points the SAP runtime needs are bound, loaded
//! from the system or application package at runtime rather than linked at
//! build time.

mod arm64;
pub mod library;
pub mod patch;
#[cfg(target_os = "windows")]
pub mod windows;

use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::time::Duration;

use libloading::Library;

use crate::client::AppleClient;
use crate::error::ClientError;

const ARCH_X86: c_int = 4;
const MODE_64: c_int = 8;
const ARCH_ARM64: c_int = 2;
const HOOK_INSN_INVALID: c_int = 1 << 14;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    X86_64,
    Arm64,
}
/// `UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC`.
const PROT_ALL: u32 = 7;
/// `UC_HOOK_CODE`.
const HOOK_CODE: c_int = 1 << 2;

/// x86-64 register identifiers, as numbered by Unicorn.
pub mod reg {
    pub const RAX: i32 = 35;
    pub const RCX: i32 = 38;
    pub const RDI: i32 = 39;
    pub const RDX: i32 = 40;
    pub const RIP: i32 = 41;
    pub const RSI: i32 = 43;
    pub const RSP: i32 = 44;
    pub const R8: i32 = 106;
    pub const R9: i32 = 107;
}

/// ARM64 register numbers from Unicorn 2.1, independent of the host CPU.
pub mod arm64_reg {
    pub const X29: i32 = 1;
    pub const LR: i32 = 2;
    pub const SP: i32 = 4;
    pub const X0: i32 = 199;
    pub const V0: i32 = 228;
    pub const PC: i32 = 260;

    pub fn general(index: u32) -> Option<i32> {
        match index {
            0..=28 => Some(X0 + index as i32),
            29 => Some(X29),
            30 => Some(LR),
            _ => None,
        }
    }
}

type Handle = *mut c_void;
type HookHandle = usize;

/// Entry points bound from the loaded library.
///
/// Held at a stable address so hook callbacks can reach it through a raw
/// pointer carried in Unicorn's `user_data`.
struct Api {
    version: unsafe extern "C" fn(*mut u32, *mut u32) -> u32,
    open: unsafe extern "C" fn(c_int, c_int, *mut Handle) -> c_int,
    close: unsafe extern "C" fn(Handle) -> c_int,
    ctl: unsafe extern "C" fn(Handle, u32, ...) -> c_int,
    query: unsafe extern "C" fn(Handle, c_int, *mut usize) -> c_int,
    strerror: unsafe extern "C" fn(c_int) -> *const c_char,
    mem_map: unsafe extern "C" fn(Handle, u64, usize, u32) -> c_int,
    mem_unmap: unsafe extern "C" fn(Handle, u64, usize) -> c_int,
    mem_read: unsafe extern "C" fn(Handle, u64, *mut c_void, usize) -> c_int,
    mem_write: unsafe extern "C" fn(Handle, u64, *const c_void, usize) -> c_int,
    reg_read: unsafe extern "C" fn(Handle, c_int, *mut c_void) -> c_int,
    reg_write: unsafe extern "C" fn(Handle, c_int, *const c_void) -> c_int,
    emu_start: unsafe extern "C" fn(Handle, u64, u64, u64, usize) -> c_int,
    emu_stop: unsafe extern "C" fn(Handle) -> c_int,
    hook_add: unsafe extern "C" fn(
        Handle,
        *mut HookHandle,
        c_int,
        *mut c_void,
        *mut c_void,
        u64,
        u64,
    ) -> c_int,
    hook_del: unsafe extern "C" fn(Handle, HookHandle) -> c_int,
}

/// Access to emulator state, usable both from outside and from within a hook.
///
/// Hook callbacks re-enter the emulator to read and write guest registers and
/// memory. Handing them a `Guest` rather than the owning [`Engine`] keeps that
/// re-entry from aliasing the engine itself.
#[derive(Clone, Copy)]
pub struct Guest<'a> {
    api: &'a Api,
    handle: Handle,
}

impl Guest<'_> {
    pub fn mem_map(&self, address: u64, size: u64) -> Result<(), ClientError> {
        // SAFETY: `handle` is a live engine created by `uc_open`.
        self.check(unsafe { (self.api.mem_map)(self.handle, address, size as usize, PROT_ALL) })
    }

    pub fn mem_unmap(&self, address: u64, size: u64) -> Result<(), ClientError> {
        // SAFETY: as above.
        self.check(unsafe { (self.api.mem_unmap)(self.handle, address, size as usize) })
    }

    pub fn mem_write(&self, address: u64, data: &[u8]) -> Result<(), ClientError> {
        if data.is_empty() {
            return Ok(());
        }

        // SAFETY: `data` is valid for `data.len()` bytes; Unicorn only reads it.
        self.check(unsafe {
            (self.api.mem_write)(self.handle, address, data.as_ptr().cast(), data.len())
        })
    }

    pub fn mem_read(&self, address: u64, size: usize) -> Result<Vec<u8>, ClientError> {
        let mut data = vec![0u8; size];
        self.mem_read_into(address, &mut data)?;

        Ok(data)
    }

    pub fn mem_read_into(&self, address: u64, data: &mut [u8]) -> Result<(), ClientError> {
        if data.is_empty() {
            return Ok(());
        }

        // SAFETY: `data` is valid for `data.len()` bytes and uniquely borrowed.
        self.check(unsafe {
            (self.api.mem_read)(self.handle, address, data.as_mut_ptr().cast(), data.len())
        })
    }

    pub fn reg_read(&self, register: i32) -> Result<u64, ClientError> {
        let mut value = 0u64;

        // SAFETY: a 64-bit register is written into a 64-bit slot.
        self.check(unsafe { (self.api.reg_read)(self.handle, register, (&raw mut value).cast()) })?;

        Ok(value)
    }

    pub fn reg_write(&self, register: i32, value: u64) -> Result<(), ClientError> {
        // SAFETY: as above; Unicorn only reads the slot.
        self.check(unsafe {
            (self.api.reg_write)(self.handle, register, (&raw const value).cast())
        })
    }

    pub fn reg_read128(&self, register: i32) -> Result<[u8; 16], ClientError> {
        let mut value = [0_u8; 16];
        // SAFETY: the caller selects a vector register; the output slot holds
        // the entire 128-bit value, unlike the scalar register accessor.
        self.check(unsafe {
            (self.api.reg_read)(self.handle, register, value.as_mut_ptr().cast())
        })?;
        Ok(value)
    }

    pub fn reg_write128(&self, register: i32, value: &[u8; 16]) -> Result<(), ClientError> {
        // SAFETY: the input buffer contains a complete 128-bit register.
        self.check(unsafe { (self.api.reg_write)(self.handle, register, value.as_ptr().cast()) })
    }

    /// Requests that a running `emu_start` return.
    pub fn stop(&self) -> Result<(), ClientError> {
        // SAFETY: `handle` is a live engine.
        self.check(unsafe { (self.api.emu_stop)(self.handle) })
    }

    fn check(&self, code: c_int) -> Result<(), ClientError> {
        if code == 0 {
            return Ok(());
        }

        // SAFETY: uc_strerror returns a static NUL-terminated string.
        let message = unsafe { CStr::from_ptr((self.api.strerror)(code)) }
            .to_string_lossy()
            .into_owned();

        Err(ClientError::Sap(format!("unicorn error {code}: {message}")))
    }
}

/// Callback invoked before each instruction covered by a code hook.
type CodeHook = Box<dyn FnMut(Guest<'_>, u64, u32) -> Result<(), ClientError>>;
type InvalidInstructionHook = Box<dyn FnMut(Guest<'_>) -> Result<bool, ClientError>>;

enum Callback {
    Code(CodeHook),
    InvalidInstruction(InvalidInstructionHook),
}

/// A registered code hook: the boxed callback plus the state the C trampoline
/// needs to reach it.
struct HookData {
    callback: Callback,
    api: *const Api,
    handle: Handle,
    fault: Option<ClientError>,
}

struct HookSlot {
    data: Box<HookData>,
    handle: HookHandle,
}

pub struct Engine {
    /// Boxed for a stable address; `HookData` holds a pointer to it.
    api: Box<Api>,
    handle: Handle,
    hooks: Vec<HookSlot>,

    // Declared last so the library outlives the entry points and hooks above.
    _library: Library,
}

impl Engine {
    /// Opens the packaged Unicorn library with the existing x86-64 SAP guest.
    pub async fn open(client: &AppleClient, cache_dir: &Path) -> Result<Self, ClientError> {
        Self::open_for_architecture(client, cache_dir, Architecture::X86_64).await
    }

    pub async fn open_for_architecture(
        client: &AppleClient,
        cache_dir: &Path,
        architecture: Architecture,
    ) -> Result<Self, ClientError> {
        let paths = library::ensure(client, cache_dir).await?;

        // SAFETY: the path is resolved from the application/system package,
        // or an explicit developer override.
        let library = unsafe { library::open(&paths) }?;

        // SAFETY: every signature below is the one from unicorn.h for the
        // pinned version, and the pointers live no longer than `library`.
        let api = unsafe {
            Box::new(Api {
                version: symbol(&library, b"uc_version\0")?,
                open: symbol(&library, b"uc_open\0")?,
                close: symbol(&library, b"uc_close\0")?,
                ctl: symbol(&library, b"uc_ctl\0")?,
                query: symbol(&library, b"uc_query\0")?,
                strerror: symbol(&library, b"uc_strerror\0")?,
                mem_map: symbol(&library, b"uc_mem_map\0")?,
                mem_unmap: symbol(&library, b"uc_mem_unmap\0")?,
                mem_read: symbol(&library, b"uc_mem_read\0")?,
                mem_write: symbol(&library, b"uc_mem_write\0")?,
                reg_read: symbol(&library, b"uc_reg_read\0")?,
                reg_write: symbol(&library, b"uc_reg_write\0")?,
                emu_start: symbol(&library, b"uc_emu_start\0")?,
                emu_stop: symbol(&library, b"uc_emu_stop\0")?,
                hook_add: symbol(&library, b"uc_hook_add\0")?,
                hook_del: symbol(&library, b"uc_hook_del\0")?,
            })
        };

        let mut major = 0u32;
        let mut minor = 0u32;

        // SAFETY: both pointers are valid for the call.
        unsafe { (api.version)(&raw mut major, &raw mut minor) };

        // The register numbering and hook ABI below are those of 2.1.
        if (major, minor) != (2, 1) {
            return Err(ClientError::Sap(format!(
                "unsupported Unicorn API version {major}.{minor}"
            )));
        }

        let mut handle: Handle = std::ptr::null_mut();

        // SAFETY: `handle` is a valid out-parameter.
        let (arch, mode) = match architecture {
            Architecture::X86_64 => (ARCH_X86, MODE_64),
            Architecture::Arm64 => (ARCH_ARM64, 0),
        };
        let code = unsafe { (api.open)(arch, mode, &raw mut handle) };
        if code != 0 || handle.is_null() {
            return Err(ClientError::Sap(format!(
                "create {architecture:?} emulator: unicorn error {code}"
            )));
        }

        let mut engine = Self {
            api,
            handle,
            hooks: Vec::new(),
            _library: library,
        };
        if architecture == Architecture::Arm64 {
            // UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), UC_CPU_ARM64_MAX.
            engine.guest().check(unsafe {
                (engine.api.ctl)(engine.handle, 7_u32 | 1 << 26 | 1 << 30, 3_u32)
            })?;
            engine.add_invalid_instruction_hook(arm64::emulate_invalid_instruction)?;
        }
        Ok(engine)
    }

    pub fn guest(&self) -> Guest<'_> {
        Guest {
            api: &self.api,
            handle: self.handle,
        }
    }

    /// Registers `callback` for instructions starting in `[begin, end]`.
    ///
    /// If the callback returns an error the emulator is stopped and the error
    /// surfaces from the [`Engine::start`] call that was running.
    pub fn add_code_hook(
        &mut self,
        begin: u64,
        end: u64,
        callback: impl FnMut(Guest<'_>, u64, u32) -> Result<(), ClientError> + 'static,
    ) -> Result<(), ClientError> {
        let mut data = Box::new(HookData {
            callback: Callback::Code(Box::new(callback)),
            api: &raw const *self.api,
            handle: self.handle,
            fault: None,
        });

        let mut hook_handle: HookHandle = 0;
        let user_data: *mut c_void = (&raw mut *data).cast();

        // SAFETY: the trampoline matches uc_cb_hookcode_t, and `data` is kept
        // alive in `self.hooks` for as long as the hook is registered.
        let code = unsafe {
            (self.api.hook_add)(
                self.handle,
                &raw mut hook_handle,
                HOOK_CODE,
                code_hook_trampoline as *mut c_void,
                user_data,
                begin,
                end,
            )
        };

        self.guest().check(code)?;

        self.hooks.push(HookSlot {
            data,
            handle: hook_handle,
        });

        Ok(())
    }

    fn add_invalid_instruction_hook(
        &mut self,
        callback: impl FnMut(Guest<'_>) -> Result<bool, ClientError> + 'static,
    ) -> Result<(), ClientError> {
        let mut data = Box::new(HookData {
            callback: Callback::InvalidInstruction(Box::new(callback)),
            api: &raw const *self.api,
            handle: self.handle,
            fault: None,
        });
        let mut handle = 0;
        // SAFETY: this trampoline matches uc_cb_hookinsn_invalid_t. The boxed
        // callback remains alive in hooks until the native hook is removed.
        self.guest().check(unsafe {
            (self.api.hook_add)(
                self.handle,
                &raw mut handle,
                HOOK_INSN_INVALID,
                invalid_instruction_trampoline as *mut c_void,
                (&raw mut *data).cast(),
                1,
                0,
            )
        })?;
        self.hooks.push(HookSlot { data, handle });
        Ok(())
    }

    /// Runs from `begin` until `end` is reached, the limits are hit, or a hook
    /// stops execution.
    pub fn start(
        &mut self,
        begin: u64,
        end: u64,
        timeout: Duration,
        instruction_limit: usize,
    ) -> Result<(), ClientError> {
        // A zero timeout means "no limit" to Unicorn, which is not what a
        // caller passing a duration intends.
        let microseconds = u64::try_from(timeout.as_micros())
            .unwrap_or(u64::MAX)
            .max(1);

        self.clear_faults();

        // SAFETY: `handle` is a live engine; hook callbacks re-enter through
        // the trampoline while this runs.
        let code = unsafe {
            (self.api.emu_start)(self.handle, begin, end, microseconds, instruction_limit)
        };

        // A fault raised inside a hook is the real cause; report it in
        // preference to the "stopped early" status Unicorn returns.
        if let Some(fault) = self.take_fault() {
            return Err(fault);
        }

        self.guest().check(code)?;
        let mut timed_out = 0_usize;
        // UC_QUERY_TIMEOUT distinguishes a timeout from a normal stop: both
        // can otherwise return UC_ERR_OK.
        self.guest()
            .check(unsafe { (self.api.query)(self.handle, 4, &raw mut timed_out) })?;
        if timed_out != 0 {
            return Err(ClientError::Sap("Unicorn emulation timed out".into()));
        }
        Ok(())
    }

    fn clear_faults(&mut self) {
        for slot in &mut self.hooks {
            slot.data.fault = None;
        }
    }

    fn take_fault(&mut self) -> Option<ClientError> {
        self.hooks
            .iter_mut()
            .find_map(|slot| slot.data.fault.take())
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        for slot in &self.hooks {
            // SAFETY: `handle` is still live; failures here cannot be reported.
            unsafe { (self.api.hook_del)(self.handle, slot.handle) };
        }

        // SAFETY: the engine is closed exactly once, here.
        unsafe { (self.api.close)(self.handle) };
    }
}

/// `uc_cb_hookcode_t`: called by Unicorn before each instruction in range.
///
/// Unwinding into C is undefined, so panics are caught and turned into faults.
unsafe extern "C" fn code_hook_trampoline(
    _engine: Handle,
    address: u64,
    size: u32,
    user_data: *mut c_void,
) {
    let data = user_data.cast::<HookData>();

    // SAFETY: `user_data` is the pointer registered in `add_code_hook`, and the
    // `HookData` it names outlives the hook registration.
    let data = unsafe { &mut *data };

    if data.fault.is_some() {
        return;
    }

    let guest = Guest {
        // SAFETY: the `Api` is boxed by the engine and outlives the hook.
        api: unsafe { &*data.api },
        handle: data.handle,
    };

    let Callback::Code(callback) = &mut data.callback else {
        return;
    };
    let result = catch_unwind(AssertUnwindSafe(|| callback(guest, address, size)));

    let fault = match result {
        Ok(Ok(())) => return,
        Ok(Err(e)) => e,
        Err(_) => ClientError::Sap(format!("guest hook panicked at {address:#x}")),
    };

    data.fault = Some(fault);
    let _ = guest.stop();
}

unsafe extern "C" fn invalid_instruction_trampoline(
    _engine: Handle,
    user_data: *mut c_void,
) -> bool {
    // SAFETY: registered as a stable boxed HookData, retained by Engine.
    let data = unsafe { &mut *user_data.cast::<HookData>() };
    if data.fault.is_some() {
        return false;
    }
    let guest = Guest {
        api: unsafe { &*data.api },
        handle: data.handle,
    };
    let Callback::InvalidInstruction(callback) = &mut data.callback else {
        return false;
    };
    let result = catch_unwind(AssertUnwindSafe(|| callback(guest)));
    let fault = match result {
        Ok(Ok(handled)) => return handled,
        Ok(Err(error)) => error,
        Err(_) => ClientError::Sap("ARM64 compatibility hook panicked".into()),
    };
    data.fault = Some(fault);
    let _ = guest.stop();
    false
}

/// # Safety
///
/// `T` must match the symbol's actual signature in the loaded library.
unsafe fn symbol<T: Copy>(library: &Library, name: &[u8]) -> Result<T, ClientError> {
    let symbol: libloading::Symbol<T> = unsafe { library.get(name) }.map_err(|e| {
        ClientError::Sap(format!(
            "Unicorn library is missing {}: {e}",
            String::from_utf8_lossy(&name[..name.len() - 1])
        ))
    })?;

    Ok(*symbol)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_client() -> AppleClient {
        crate::client::AppleClient::for_tests()
    }

    fn cache() -> std::path::PathBuf {
        std::env::temp_dir().join("ipatool-rs-unicorn-test")
    }

    async fn engine() -> Engine {
        Engine::open(&test_client(), &cache())
            .await
            .expect("open engine")
    }

    const CODE: u64 = 0x1000;
    const RETURN: u64 = 0x2000;

    #[tokio::test]
    #[ignore = "requires a packaged Unicorn shared library with ARM64 support"]
    async fn live_arm64_execution_and_compatibility_instructions() {
        let mut engine =
            Engine::open_for_architecture(&test_client(), &cache(), Architecture::Arm64)
                .await
                .unwrap();
        let guest = engine.guest();
        guest.mem_map(CODE, 0x1000).unwrap();
        guest.mem_map(RETURN, 0x1000).unwrap();
        // add x0, x0, x1
        guest.mem_write(CODE, &[0x00, 0x00, 0x01, 0x8b]).unwrap();
        guest.reg_write(arm64_reg::X0, 40).unwrap();
        guest.reg_write(arm64_reg::X0 + 1, 2).unwrap();
        engine
            .start(CODE, CODE + 4, Duration::from_secs(1), 100)
            .unwrap();
        assert_eq!(engine.guest().reg_read(arm64_reg::X0).unwrap(), 42);

        let guest = engine.guest();
        // Directly exercise the fallback even if this Unicorn CPU model
        // implements some of the instructions natively.
        guest.reg_write(arm64_reg::PC, CODE).unwrap();
        guest.reg_write(arm64_reg::X0, 7).unwrap();
        guest.reg_write(arm64_reg::X0 + 1, RETURN).unwrap();
        guest.reg_write(arm64_reg::X0 + 2, 11).unwrap();
        guest.mem_write(RETURN, &7_u64.to_le_bytes()).unwrap();
        let casal = 0xc8e0fc00_u32 | (1 << 5) | 2;
        guest.mem_write(CODE, &casal.to_le_bytes()).unwrap();
        assert!(arm64::emulate_invalid_instruction(guest).unwrap());
        assert_eq!(guest.mem_read(RETURN, 8).unwrap(), 11_u64.to_le_bytes());
        assert_eq!(guest.reg_read(arm64_reg::X0).unwrap(), 7);
        assert_eq!(guest.reg_read(arm64_reg::PC).unwrap(), CODE + 4);

        guest.reg_write(arm64_reg::PC, CODE).unwrap();
        guest.reg_write128(arm64_reg::V0 + 1, &[0x55; 16]).unwrap();
        guest.reg_write128(arm64_reg::V0 + 2, &[0xaa; 16]).unwrap();
        guest.reg_write128(arm64_reg::V0 + 3, &[0x0f; 16]).unwrap();
        let eor3 = 0xce000000_u32 | (1 << 5) | (2 << 16) | (3 << 10);
        guest.mem_write(CODE, &eor3.to_le_bytes()).unwrap();
        assert!(arm64::emulate_invalid_instruction(guest).unwrap());
        assert_eq!(guest.reg_read128(arm64_reg::V0).unwrap(), [0xf0; 16]);
    }

    #[tokio::test]
    #[ignore = "requires a packaged Unicorn shared library with ARM64 support"]
    async fn live_arm64_timeout_is_an_error() {
        let mut engine =
            Engine::open_for_architecture(&test_client(), &cache(), Architecture::Arm64)
                .await
                .unwrap();
        engine.guest().mem_map(CODE, 0x1000).unwrap();
        // b . loops forever; Unicorn may return UC_ERR_OK on timeout.
        engine
            .guest()
            .mem_write(CODE, &[0x00, 0x00, 0x00, 0x14])
            .unwrap();
        assert!(
            engine
                .start(CODE, CODE + 4, Duration::from_millis(1), 0)
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
    }

    /// Downloads ~12 MB from PyPI on a cold cache, so these are opt-in:
    /// `cargo test -- --ignored live_`.
    #[tokio::test]
    #[ignore = "requires a packaged Unicorn shared library"]
    async fn live_executes_x86_64_and_returns_the_result() {
        let mut engine = engine().await;
        let guest = engine.guest();

        guest.mem_map(CODE, 0x1000).unwrap();
        // mov rax, rdi; add rax, rsi; ret
        guest
            .mem_write(CODE, &[0x48, 0x89, 0xF8, 0x48, 0x01, 0xF0, 0xC3])
            .unwrap();

        guest.reg_write(reg::RDI, 40).unwrap();
        guest.reg_write(reg::RSI, 2).unwrap();

        engine
            .start(CODE, CODE + 6, Duration::from_secs(5), 1000)
            .unwrap();

        assert_eq!(engine.guest().reg_read(reg::RAX).unwrap(), 42);
    }

    /// The pattern the SAP shims rely on: a hook intercepts a call, supplies a
    /// result, and redirects control flow back to the caller.
    #[tokio::test]
    #[ignore = "requires a packaged Unicorn shared library"]
    async fn live_hook_can_service_a_guest_call() {
        let mut engine = engine().await;

        {
            let guest = engine.guest();

            guest.mem_map(CODE, 0x1000).unwrap();
            guest.mem_map(RETURN, 0x1000).unwrap();
            // The hook stands in for whatever would live at RETURN.
            guest.mem_write(RETURN, &[0xC3]).unwrap();

            // jmp to RETURN
            let offset = (RETURN as i64 - (CODE as i64 + 5)) as i32;
            guest.mem_write(CODE, &[0xE9]).unwrap();
            guest.mem_write(CODE + 1, &offset.to_le_bytes()).unwrap();
        }

        engine
            .add_code_hook(RETURN, RETURN, |guest, _, _| {
                guest.reg_write(reg::RAX, 0xD00D)?;
                guest.stop()
            })
            .unwrap();

        engine.start(CODE, 0, Duration::from_secs(5), 1000).unwrap();

        assert_eq!(engine.guest().reg_read(reg::RAX).unwrap(), 0xD00D);
    }

    /// An error out of a hook must surface from `start`, not be swallowed by
    /// the "stopped early" status Unicorn reports.
    #[tokio::test]
    #[ignore = "requires a packaged Unicorn shared library"]
    async fn live_hook_error_surfaces_from_start() {
        let mut engine = engine().await;
        let guest = engine.guest();

        guest.mem_map(CODE, 0x1000).unwrap();
        guest.mem_write(CODE, &[0x90, 0x90, 0xC3]).unwrap();

        engine
            .add_code_hook(CODE, CODE, |_, address, _| {
                Err(ClientError::Sap(format!("refused at {address:#x}")))
            })
            .unwrap();

        let error = engine
            .start(CODE, CODE + 2, Duration::from_secs(5), 1000)
            .unwrap_err()
            .to_string();

        assert!(error.contains("refused at 0x1000"), "{error}");
    }
}
