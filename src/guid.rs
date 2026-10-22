use crate::error::IpaToolError;

/// The GUID sent to Apple and the hardware ID the SAP handshake binds its
/// session key to are two encodings of the same MAC address bytes. Deriving
/// them separately would let them drift apart, which Apple rejects, so they are
/// produced together and carried together.
#[derive(Debug, Clone)]
pub struct MachineIdentity {
    pub guid: String,
    pub hardware_id: Vec<u8>,
}

pub fn generate_machine_identity() -> Result<MachineIdentity, IpaToolError> {
    let mac = mac_address::get_mac_address()
        .map_err(|e| IpaToolError::Unexpected(format!("failed to get MAC address: {e}")))?
        .ok_or(IpaToolError::NoGuid)?;

    let hardware_id = mac.bytes().to_vec();

    // Apple's SAP setup call rejects anything outside this range.
    if hardware_id.is_empty() || hardware_id.len() > 20 {
        return Err(IpaToolError::Unexpected(format!(
            "hardware address must be 1-20 bytes, got {}",
            hardware_id.len()
        )));
    }

    let guid = hardware_id.iter().map(|b| format!("{b:02X}")).collect();
    // let guid = "244CFX070422".into();
    // println!("GUID:  {}", guid);

    Ok(MachineIdentity { guid, hardware_id })
}

pub fn generate_guid() -> Result<String, IpaToolError> {
    Ok(generate_machine_identity()?.guid)
}
