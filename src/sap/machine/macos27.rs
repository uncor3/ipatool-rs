//! macOS 27.0.1 (26A434) ARM64e SAP and StoreAgent runtime.
use super::*;
use crate::sap::unicorn::{Architecture, arm64_reg};

const FUNCTIONS: &[(u64, &str)] = &[
    (0x0000000180675ce8, "_malloc"),
    (0x00000001806766f0, "_free"),
    (0x00000001806cf570, "_dispatch_once"),
    (0x000000018071acc8, "_sysctlbyname"),
    (0x000000018071bec4, "_gettimeofday"),
    (0x0000000180721fb8, "_arc4random"),
    (0x00000001807238a4, "___memset_chk"),
    (0x00000001807903c4, "_abort"),
    (0x0000000180849604, "___error"),
    (0x0000000180889bc4, "_pthread_once"),
    (0x000000018088a6f8, "_pthread_rwlock_unlock"),
    (0x000000018088a7c0, "_pthread_rwlock_wrlock"),
    (0x000000018088b2d8, "_pthread_rwlock_init"),
    (0x0000000180894b40, "_strlen"),
    (0x00000001808cf540, "_CFStringCreateWithCString"),
    (0x00000001808d4200, "_CFStringGetLength"),
    (0x00000001808d44dc, "_CFStringGetCString"),
    (0x00000001808d7278, "_CFRelease"),
    (0x00000001808e89e8, "_CFDataGetLength"),
    (0x0000000184d6b4cc, "_IOServiceMatching"),
    (0x0000000184d6c168, "_IOServiceGetMatchingServices"),
    (0x0000000184d6c4fc, "_IOIteratorNext"),
    (0x0000000184d6cb50, "_IOObjectRelease"),
];
const SLOTS: &[(u64, &str)] = &[
    (0x00000001e02205c0, "___stack_chk_guard"),
    (0x00000001e800c958, "___chkstk_darwin"),
];

impl Machine {
    pub async fn open_macos27(
        client: &AppleClient,
        bundle: &crate::sap::assets::macos27::Bundle,
        include_commerce: bool,
    ) -> Result<Self, ClientError> {
        let mut core = Image::open_arm64("CoreFP", &bundle.core_fp)?;
        let mut ams = Image::open_arm64("AppleMediaServices", &bundle.apple_media_services)?;
        let mut commerce = if include_commerce {
            Some(Image::open_arm64("commerce", &bundle.commerce)?)
        } else {
            None
        };
        let mut exports: HashMap<String, u64> = HashMap::new();
        let mut core_exports = HashMap::new();
        for name in CORE_EXPORTS {
            let address = core.export(name, CORE_FP_BASE)?;
            exports.insert((*name).into(), address);
            core_exports.insert((*name).into(), address);
        }
        let entry = EntryPoints {
            initialize: ams.export("_cp2g1b9ro", ams.base())?,
            exchange: ams.export("_Mib5yocT", ams.base())?,
            sign: ams.export("_Fc3vhtJDvr", ams.base())?,
            teardown: ams.export("_IPaI1oem5iL", ams.base())?,
            dispose: ams.export("_jEHf8Xzsv8K", ams.base())?,
        };
        for (name, address) in [
            ("_cp2g1b9ro", entry.initialize),
            ("_Mib5yocT", entry.exchange),
            ("_Fc3vhtJDvr", entry.sign),
            ("_IPaI1oem5iL", entry.teardown),
            ("_jEHf8Xzsv8K", entry.dispose),
        ] {
            exports.insert(name.into(), address);
        }
        let mut engine =
            Engine::open_for_architecture(client, client.cache_dir(), Architecture::Arm64).await?;
        let guest = engine.guest();
        for (address, size) in [
            (RETURN_ADDRESS, PAGE_SIZE),
            (SCRATCH_BASE, SCRATCH_SIZE),
            (shims::HEAP_BASE, shims::HEAP_SIZE),
            (STACK_BASE, STACK_SIZE),
        ] {
            guest.mem_map(address, size)?;
        }
        guest.mem_write(RETURN_ADDRESS, &0xd4200000u32.to_le_bytes())?;
        let mut services = Shims::new(&guest, core_exports, bundle.core_fp_icxs.clone())?;
        services.add_aliases(
            &[
                "_pthread_rwlock_rdlock",
                "_pthread_rwlock_rdlock$UNIX2003",
                "_pthread_mutex_init",
                "_pthread_mutex_destroy",
                "_pthread_rwlock_destroy",
            ],
            shims::Shim::ReturnZero,
            &guest,
        )?;
        let mut resolve = |name: &str| match exports.get(name) {
            Some(address) => Ok(*address),
            None => services.resolve(name, &guest),
        };
        let mut pages = std::collections::HashSet::new();
        for &(address, _) in FUNCTIONS.iter().chain(SLOTS) {
            pages.insert(address & !0xfff);
            pages.insert((address + 15) & !0xfff);
        }
        for page in pages {
            guest.mem_map(page, PAGE_SIZE)?;
        }
        for &(address, name) in FUNCTIONS {
            let target = resolve(name)?;
            let mut code = Vec::from(0x58000050u32.to_le_bytes());
            code.extend_from_slice(&0xd61f0200u32.to_le_bytes());
            code.extend_from_slice(&target.to_le_bytes());
            guest.mem_write(address, &code)?;
        }
        for &(address, name) in SLOTS {
            guest.mem_write(address, &resolve(name)?.to_le_bytes())?;
        }
        core.relocate(CORE_FP_BASE, &mut resolve)?;
        ams.prepare_prelinked(FUNCTIONS, &mut resolve)?;
        core.load(&guest)?;
        ams.load(&guest)?;
        if let Some(image) = commerce.as_mut() {
            image.relocate(kbsync::STORE_AGENT_BASE, &mut resolve)?;
            image.load(&guest)?;
        }
        let services = Arc::new(Mutex::new(services));
        engine.add_code_hook(
            shims::SHIM_BASE,
            shims::SHIM_BASE + shims::SHIM_CODE_SIZE - 1,
            move |guest, address, _| {
                let mut services = services
                    .lock()
                    .map_err(|_| ClientError::Sap("ARM64 shim state poisoned".into()))?;
                shims::dispatch(&mut services, guest, address)
            },
        )?;
        Ok(Self {
            inner: Mutex::new(Inner {
                engine,
                entry,
                scratch_cursor: 0,
                deadline: None,
                architecture: Architecture::Arm64,
            }),
        })
    }
}

pub(super) fn prepare_call(guest: &Guest<'_>, arguments: &[u64]) -> Result<(), ClientError> {
    for index in 0..8 {
        guest.reg_write(
            arm64_reg::X0 + index as i32,
            arguments.get(index).copied().unwrap_or(0),
        )?;
    }
    let extra = arguments.len().saturating_sub(8);
    let stack = (STACK_END - (extra as u64) * 8) & !15;
    for (index, value) in arguments.iter().skip(8).enumerate() {
        shims::write_u64(guest, stack + index as u64 * 8, *value)?;
    }
    guest.reg_write(arm64_reg::SP, stack)?;
    guest.reg_write(arm64_reg::LR, RETURN_ADDRESS)
}
