//! Go's macOS 27.0.1 (26A434) StoreAgent kbsync profile.
use super::*;

pub(super) const STORE_AGENT_BASE: u64 = 0x0000_1000_c000_0000;

pub async fn generate(client: &AppleClient, dsid: u64) -> Result<Vec<u8>, ClientError> {
    generate_macos27(client, dsid).await
}

pub async fn generate_macos27(client: &AppleClient, dsid: u64) -> Result<Vec<u8>, ClientError> {
    if dsid == 0 || client.hardware_id().len() != 6 {
        return Err(ClientError::Sap(
            "invalid kbsync account/device identity".into(),
        ));
    }
    let bundle = crate::sap::assets::macos27::load().await?;
    let machine = Machine::open_macos27(client, &bundle, true).await?;
    let hardware = client.hardware_id().to_vec();
    tokio::task::spawn_blocking(move || {
        generate_profile(
            machine,
            &hardware,
            dsid,
            STORE_AGENT_BASE + 0x1312fc,
            STORE_AGENT_BASE + 0x19ae34,
            Some(STORE_AGENT_BASE + 0x130eb4),
        )
    })
    .await
    .map_err(|_| ClientError::Sap("macOS 27 kbsync worker failed".into()))?
}

fn generate_profile(
    machine: Machine,
    hardware: &[u8],
    dsid: u64,
    initialize: u64,
    kbsync: u64,
    close: Option<u64>,
) -> Result<Vec<u8>, ClientError> {
    let mut inner = machine.lock()?;
    inner.deadline = Some(Instant::now() + Duration::from_secs(90));
    inner.begin_call();
    let mut global = 0;
    let result = (|| {
        let block = hardware_block(hardware)?;
        let hardware = inner.scratch(Some(&block), block.len() as u64)?;
        let path = b"/Users/Shared/SC Info\0";
        let path = inner.scratch(Some(path), path.len() as u64)?;
        let context = inner.scratch(None, 4)?;
        let status = inner.invoke(initialize, &[0, hardware, path, context])?;
        if status as i32 != 0 {
            return Err(ClientError::Sap(format!(
                "StoreAgent global initialization returned {}",
                status as i32
            )));
        }
        let context = shims::read_u32(&inner.engine.guest(), context)?;
        if context == 0 {
            return Err(ClientError::Sap(
                "StoreAgent returned a null global context".into(),
            ));
        }
        global = context;
        inner.clear_scratch();
        inner.begin_call();
        let pointer = inner.scratch(None, 8)?;
        // StoreAgent writes a uint32 length; zero the upper half for consume_output.
        let length = inner.scratch(None, 8)?;
        let status = inner.invoke(kbsync, &[u64::from(context), dsid, 0, 1, pointer, length])?;
        let output = inner.consume_output(pointer, length);
        if status as i32 != 0 {
            return Err(ClientError::Sap(format!(
                "StoreAgent kbsync returned {}",
                status as i32
            )));
        }
        let output = output?;
        if output.is_empty() {
            return Err(ClientError::Sap(
                "StoreAgent kbsync returned an empty buffer".into(),
            ));
        }
        Ok(output)
    })();
    inner.clear_scratch();
    if global != 0
        && let Some(close) = close
    {
        let status = inner.invoke(close, &[u64::from(global)])?;
        if status as i32 != 0 && result.is_ok() {
            return Err(ClientError::Sap("StoreAgent global close failed".into()));
        }
    }
    // The dedicated emulator drops after the global context has been closed.
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires verified Go macOS 27 assets and packaged ARM64 Unicorn"]
    async fn live_macos27_kbsync_generates_fresh_blob() {
        let client = AppleClient::for_tests();
        let blob = generate_macos27(&client, 42)
            .await
            .expect("generate macOS 27 kbsync");
        assert!(!blob.is_empty());
    }

    /// Uses a synthetic account ID; never opens the user's keyring or cookie jar.
    #[tokio::test]
    #[ignore = "downloads verified Apple assets and runs packaged Unicorn"]
    async fn live_kbsync_generates_fresh_blob() {
        let cache = std::env::var_os("IPATOOL_KBSYNC_TEST_CACHE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join("ipatool-rs-test-cache"));
        let client = AppleClient::new(
            crate::guid::MachineIdentity {
                guid: "AABBCCDDEEFF".into(),
                hardware_id: vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            },
            None,
            cache,
        )
        .unwrap();
        let blob = generate(&client, 42).await.expect("generate fresh kbsync");
        assert!(!blob.is_empty());
    }
}
