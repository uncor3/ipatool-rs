use super::*;

impl State {
    pub(super) fn account_message(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        class: &str,
        selector: &str,
        meta: bool,
    ) -> Result<bool, ClientError> {
        if meta {
            return Ok(false);
        }
        if class == "ACAccountStore" || class == "ACDAccountStore" {
            let value = match selector {
                "accountTypeWithAccountTypeIdentifier:"
                | "accountTypeWithAccountTypeIdentifier:error:" => {
                    let identifier = self.arg(guest, 2)?;
                    let object = self.new_object(guest, "ACAccountType", Value::Null)?;
                    self.objects
                        .get_mut(&object)
                        .unwrap()
                        .properties
                        .insert("identifier".into(), identifier);
                    if selector.ends_with("error:") && self.arg(guest, 3)? != 0 {
                        guest.mem_write(self.arg(guest, 3)?, &0u64.to_le_bytes())?;
                    }
                    object
                }
                "accounts"
                | "accountsWithAccountType:"
                | "accountsWithAccountType:options:error:"
                | "accountsWithAccountType:options:classification:error:" => {
                    if selector.ends_with("error:") {
                        let out = self.arg(
                            guest,
                            if selector.contains("classification:") {
                                5
                            } else {
                                4
                            },
                        )?;
                        if out != 0 {
                            guest.mem_write(out, &0u64.to_le_bytes())?;
                        }
                    }
                    self.new_object(guest, "NSArray", Value::Array(Vec::new()))?
                }
                "accountWithIdentifier:" => 0,
                _ => return Ok(false),
            };
            self.set(guest, value)?;
            return Ok(true);
        }
        if !self.kind_of(class, "ACAccount")
            && !["ACAccountType", "ACAccountCredential"].contains(&class)
        {
            return Ok(false);
        }
        match selector {
            "initWithIdentifier:description:" => {
                let identifier = self.arg(guest, 2)?;
                let description = self.arg(guest, 3)?;
                let properties = &mut self.objects.get_mut(&receiver).unwrap().properties;
                properties.insert("identifier".into(), identifier);
                properties.insert("accountTypeDescription".into(), description);
                self.set(guest, receiver)?;
            }
            "initWithAccountType:" => {
                let account_type = self.arg(guest, 2)?;
                let mut random = [0; 16];
                getrandom::fill(&mut random).map_err(|_| failure("Store UUID source failed"))?;
                random[6] = (random[6] & 15) | 64;
                random[8] = (random[8] & 63) | 128;
                let identifier = format!(
                    "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                    u32::from_be_bytes(random[..4].try_into().unwrap()),
                    u16::from_be_bytes(random[4..6].try_into().unwrap()),
                    u16::from_be_bytes(random[6..8].try_into().unwrap()),
                    u16::from_be_bytes(random[8..10].try_into().unwrap()),
                    u64::from_be_bytes([
                        0, 0, random[10], random[11], random[12], random[13], random[14],
                        random[15]
                    ])
                );
                let identifier = self.new_object(guest, "NSString", Value::String(identifier))?;
                let fields = self.new_object(
                    guest,
                    "NSMutableDictionary",
                    Value::Dictionary(HashMap::new()),
                )?;
                let properties = &mut self.objects.get_mut(&receiver).unwrap().properties;
                properties.insert("identifier".into(), identifier);
                properties.insert("accountType".into(), account_type);
                properties.insert("accountProperties".into(), fields);
                self.set(guest, receiver)?;
            }
            "initWithPassword:" => {
                let password = self.arg(guest, 2)?;
                self.objects
                    .get_mut(&receiver)
                    .unwrap()
                    .properties
                    .insert("password".into(), password);
                self.set(guest, receiver)?;
            }
            "accountPropertyForKey:" | "setAccountProperty:forKey:" => {
                let fields = self.objects[&receiver]
                    .properties
                    .get("accountProperties")
                    .copied()
                    .ok_or_else(|| failure("Store account has no properties"))?;
                let key =
                    self.string(self.arg(guest, if selector.starts_with("set") { 3 } else { 2 })?)?;
                let value = self.arg(guest, 2)?;
                let Value::Dictionary(values) = &mut self
                    .objects
                    .get_mut(&fields)
                    .ok_or_else(|| failure("Store account properties are absent"))?
                    .value
                else {
                    return Err(failure("invalid Store account properties"));
                };
                let result = if selector.starts_with("set") {
                    if value == 0 {
                        values.remove(&key);
                    } else {
                        values.insert(key, value);
                    }
                    0
                } else {
                    values.get(&key).copied().unwrap_or(0)
                };
                self.set(guest, result)?;
            }
            "accountType" | "identifier" | "username" | "credential" | "accountProperties"
            | "authenticated" | "active" | "owningBundleID" | "accountDescription"
            | "parentAccount" | "isDirty" => {
                self.set(
                    guest,
                    self.objects[&receiver]
                        .properties
                        .get(selector)
                        .copied()
                        .unwrap_or(0),
                )?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
