use super::*;

impl State {
    pub(super) fn symbol(&mut self, guest: Guest<'_>, name: &str) -> Result<(), ClientError> {
        if self.compression_symbol(guest, name)? {
            return Ok(());
        }
        if self.dispatch_symbol(guest, name)? {
            return Ok(());
        }
        if self.swift_symbol(guest, name)? {
            return Ok(());
        }
        if self.system_symbol(guest, name)? {
            return Ok(());
        }
        let arg = |i| self.arg(guest, i);
        match name {
            "objc_retain"
            | "objc_retainAutoreleasedReturnValue"
            | "objc_claimAutoreleasedReturnValue"
            | "objc_unsafeClaimAutoreleasedReturnValue"
            | "objc_autoreleaseReturnValue"
            | "objc_autorelease"
            | "objc_retainAutoreleaseReturnValue"
            | "objc_retainAutorelease"
            | "objc_opt_self" => Ok(()),
            "objc_release"
            | "objc_autoreleasePoolPop"
            | "free"
            | "dispatch_retain"
            | "dispatch_release"
            | "chkstk_darwin"
            | "Block_object_dispose"
            | "Block_release" => Ok(()),
            "objc_autoreleasePoolPush"
            | "CRIsAutoSubmitEnabled"
            | "os_signpost_enabled"
            | "os_log_type_enabled"
            | "os_variant_has_internal_content" => self.set(guest, 0),
            "os_log_create" => {
                let object = self.new_object(guest, "HostOSLog", Value::Null)?;
                self.set(guest, object)
            }
            "os_feature_enabled_impl" => {
                let key = format!(
                    "{}/{}",
                    self.cstring(guest, arg(0)?)?,
                    self.cstring(guest, arg(1)?)?
                );
                let enabled = self
                    .data
                    .metadata
                    .features
                    .get(&key)
                    .copied()
                    .ok_or_else(|| failure(format!("unprepared Store feature {key}")))?;
                self.set(guest, u64::from(enabled))
            }
            "getpid" => self.set(guest, 123),
            "CFBundleGetMainBundle" => {
                let bundle = self.bundle(guest)?;
                self.set(guest, bundle)
            }
            "CFBundleGetInfoDictionary" => {
                let info = self.bundle_info(guest)?;
                self.set(guest, info)
            }
            "CFBundleGetValueForInfoDictionaryKey" => {
                let key = self.string(arg(1)?)?;
                let info = self.bundle_info(guest)?;
                let Value::Dictionary(values) = &self.objects[&info].value else {
                    unreachable!()
                };
                self.set(guest, values.get(&key).copied().unwrap_or(0))
            }
            "CFBundleCopyExecutableURL" => {
                let object =
                    self.new_object(guest, "NSURL", Value::String("file:///ipatool".into()))?;
                self.set(guest, object)
            }
            "CFRelease" => self.set(guest, 0),
            "getuid" | "geteuid" => self.set(guest, 501),
            "getgid" | "getegid" => self.set(guest, 20),
            "getprogname" => {
                let pointer = self.alloc(8)?;
                guest.mem_write(pointer, b"ipatool\0")?;
                self.set(guest, pointer)
            }
            "NSUserName"
            | "NSFullUserName"
            | "NSTemporaryDirectory"
            | "CPSharedResourcesDirectory"
            | "NSHomeDirectory" => {
                let value = match name {
                    "NSTemporaryDirectory" => "/ipatool/tmp/",
                    "NSHomeDirectory" | "CPSharedResourcesDirectory" => "/ipatool",
                    _ => "ipatool",
                };
                let object = self.new_object(guest, "NSString", Value::String(value.into()))?;
                self.set(guest, object)
            }
            "time" => {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| failure("system clock precedes Unix epoch"))?
                    .as_secs();
                let out = arg(0)?;
                if out != 0 {
                    guest.mem_write(out, &now.to_le_bytes())?;
                }
                self.set(guest, now)
            }
            "objc_getProperty" => self.set(guest, read64(guest, arg(0)? + arg(2)?)?),
            "objc_getAssociatedObject" => self.set(
                guest,
                self.associations
                    .get(&(arg(0)?, arg(1)?))
                    .copied()
                    .unwrap_or(0),
            ),
            "objc_setAssociatedObject" => {
                let object = arg(0)?;
                let key = arg(1)?;
                let value = arg(2)?;
                let policy = arg(3)?;
                if policy & 255 == 3 {
                    self.copy_value(
                        guest,
                        value,
                        Box::new(move |state, guest, copied| {
                            state.associations.insert((object, key), copied);
                            state.set(guest, 0)
                        }),
                    )
                } else {
                    self.associations.insert((object, key), value);
                    self.set(guest, 0)
                }
            }
            "CFPreferencesCopyAppValue" | "CFPreferencesCopyValue" => {
                let key = (self.string(arg(1)?)?, self.string(arg(0)?)?);
                self.set(guest, self.preferences.get(&key).copied().unwrap_or(0))
            }
            "CFPreferencesSetAppValue" | "CFPreferencesSetValue" => {
                let key = (self.string(arg(2)?)?, self.string(arg(0)?)?);
                let value = arg(1)?;
                self.preferences.insert(key, value);
                self.set(guest, 0)
            }
            "CFPreferencesAppSynchronize" | "CFPreferencesSynchronize" => self.set(guest, 1),
            "CFPreferencesGetAppIntegerValue" | "CFPreferencesGetAppBooleanValue" => {
                let key = (self.string(arg(1)?)?, self.string(arg(0)?)?);
                let object = self.preferences.get(&key).and_then(|a| self.objects.get(a));
                let (value, valid) = match object.map(|o| &o.value) {
                    Some(Value::Integer(v)) => (*v as u64, true),
                    Some(Value::Boolean(v)) if name.ends_with("BooleanValue") => {
                        (u64::from(*v), true)
                    }
                    _ => (0, false),
                };
                let out = arg(2)?;
                if out != 0 {
                    guest.mem_write(out, &[u8::from(valid)])?;
                }
                self.set(
                    guest,
                    if name.ends_with("BooleanValue") {
                        u64::from(value != 0)
                    } else {
                        value
                    },
                )
            }
            "objc_setProperty_nonatomic" | "objc_setProperty_atomic" => {
                guest.mem_write(arg(0)? + arg(3)?, &arg(2)?.to_le_bytes())
            }
            "objc_setProperty_nonatomic_copy" | "objc_setProperty_atomic_copy" => {
                let destination = arg(0)? + arg(3)?;
                let value = arg(2)?;
                self.copy_value(
                    guest,
                    value,
                    Box::new(move |state, guest, copied| {
                        guest.mem_write(destination, &copied.to_le_bytes())?;
                        state.set(guest, 0)
                    }),
                )
            }
            "objc_storeStrong" | "objc_storeWeak" | "objc_initWeak" => {
                let value = arg(1)?;
                guest.mem_write(arg(0)?, &value.to_le_bytes())?;
                self.set(guest, value)
            }
            "objc_loadWeakRetained" | "objc_loadWeak" => self.set(guest, read64(guest, arg(0)?)?),
            "objc_destroyWeak" => guest.mem_write(arg(0)?, &0u64.to_le_bytes()),
            "objc_copyWeak" | "objc_moveWeak" => {
                let source = arg(1)?;
                guest.mem_write(arg(0)?, &read64(guest, source)?.to_le_bytes())?;
                if name == "objc_moveWeak" {
                    guest.mem_write(source, &0u64.to_le_bytes())?;
                }
                Ok(())
            }
            "objc_alloc" | "objc_allocWithZone" | "objc_alloc_init" | "objc_opt_new" => {
                let class = self
                    .class_names
                    .get(&arg(0)?)
                    .cloned()
                    .ok_or_else(|| failure("unknown allocated Store class"))?;
                let object = self.new_object(guest, &class, Value::Null)?;
                self.set(guest, object)?;
                if name == "objc_alloc_init" || name == "objc_opt_new" {
                    self.message(guest, object, "init", false)?;
                }
                Ok(())
            }
            "objc_msgSend" => {
                let receiver = arg(0)?;
                let selector = self.cstring(guest, arg(1)?)?;
                self.message(guest, receiver, &selector, false)
            }
            "objc_msgSendSuper2" => {
                let pointer = arg(0)?;
                let receiver = read64(guest, pointer)?;
                let selector = self.cstring(guest, arg(1)?)?;
                let class = self
                    .class_names
                    .get(&read64(guest, pointer + 8)?)
                    .cloned()
                    .ok_or_else(|| failure("unknown Store superclass"))?;
                let (_, meta) = self.receiver(receiver)?;
                if let Some(index) = self.classes.get(&class) {
                    let entry =
                        self.lookup(&self.class_definitions[*index].superclass, &selector, meta);
                    if entry != 0 {
                        return self.jump(guest, entry, receiver, &selector);
                    }
                }
                self.message(guest, receiver, &selector, true)
            }
            "objc_getClass" => {
                let name = self.cstring(guest, arg(0)?)?;
                self.set(
                    guest,
                    self.classes
                        .get(&name)
                        .map_or(0, |i| self.class_definitions[*i].address),
                )
            }
            "NSClassFromString" => {
                let name = self.string(arg(0)?)?;
                self.set(
                    guest,
                    self.classes
                        .get(&name)
                        .map_or(0, |i| self.class_definitions[*i].address),
                )
            }
            "NSSelectorFromString" => {
                let name = self.string(arg(0)?)?;
                let address = self.selector(guest, &name)?;
                self.set(guest, address)
            }
            "NSStringFromClass" => {
                let address = arg(0)?;
                if address == 0 {
                    return self.set(guest, 0);
                }
                let name = self
                    .class_names
                    .get(&address)
                    .cloned()
                    .ok_or_else(|| failure("unknown Store class"))?;
                let object = self.new_object(guest, "NSString", Value::String(name))?;
                self.set(guest, object)
            }
            "NSStringFromSelector" => {
                let name = self.cstring(guest, arg(0)?)?;
                let object = self.new_object(guest, "NSString", Value::String(name))?;
                self.set(guest, object)
            }
            "sel_getName" => Ok(()),
            "class_getMethodImplementation" => {
                let class = self
                    .class_names
                    .get(&arg(0)?)
                    .cloned()
                    .ok_or_else(|| failure("unknown Store class"))?;
                let selector = self.cstring(guest, arg(1)?)?;
                self.set(guest, self.lookup(&class, &selector, false))
            }
            "objc_opt_isKindOfClass" => {
                let object = arg(0)?;
                let target = self
                    .class_names
                    .get(&arg(1)?)
                    .cloned()
                    .ok_or_else(|| failure("unknown Store type"))?;
                let result = self
                    .objects
                    .get(&object)
                    .is_some_and(|o| self.kind_of(&o.class, &target));
                self.set(guest, u64::from(result))
            }
            "SecTaskCreateFromSelf" => {
                let object = self.new_object(guest, "HostSecurityTask", Value::Null)?;
                self.set(guest, object)
            }
            "SecTaskCopyValueForEntitlement" => {
                let out = arg(2)?;
                if out != 0 {
                    guest.mem_write(out, &0u64.to_le_bytes())?;
                }
                self.set(guest, 0)
            }
            "sel_registerName" | "sel_getUid" => {
                let name = self.cstring(guest, arg(0)?)?;
                let address = self.selector(guest, &name)?;
                self.set(guest, address)
            }
            "objc_opt_class" => {
                let receiver = arg(0)?;
                if receiver == 0 {
                    return self.set(guest, 0);
                }
                let (class, _) = self.receiver(receiver)?;
                self.set(
                    guest,
                    self.classes
                        .get(&class)
                        .map_or(0, |i| self.class_definitions[*i].address),
                )
            }
            "objc_opt_respondsToSelector" => {
                if !self.objects.contains_key(&arg(0)?) && !self.class_names.contains_key(&arg(0)?)
                {
                    return self.set(guest, 0);
                }
                let selector = self.cstring(guest, arg(1)?)?;
                self.set(guest, u64::from(self.responds(arg(0)?, &selector)))
            }
            "malloc" | "calloc" | "malloc_type_malloc" | "malloc_type_calloc" => {
                let mut size = arg(0)?;
                if name.contains("calloc") {
                    size = size
                        .checked_mul(arg(1)?)
                        .ok_or_else(|| failure("Store allocation overflow"))?;
                }
                let address = self.alloc(size)?;
                self.set(guest, address)
            }
            "malloc_size" => self.set(guest, self.allocations.get(&arg(0)?).copied().unwrap_or(0)),
            "memcpy" | "memmove" | "memcpy_chk" | "memmove_chk" | "platform_memcpy"
            | "platform_memmove" => {
                let destination = arg(0)?;
                let source = arg(1)?;
                let size = arg(2)?;
                if size == 0 {
                    return self.set(guest, destination);
                }
                if size > HEAP_SIZE || (name.ends_with("_chk") && size > arg(3)?) {
                    return Err(failure("Store memory copy exceeds limit"));
                }
                guest.mem_write(destination, &guest.mem_read(source, size as usize)?)?;
                self.set(guest, destination)
            }
            "memset" | "memset_chk" | "bzero" => {
                let destination = arg(0)?;
                let size = if name == "bzero" { arg(1)? } else { arg(2)? };
                if size == 0 {
                    return self.set(guest, destination);
                }
                if size > HEAP_SIZE || (name.ends_with("_chk") && size > arg(3)?) {
                    return Err(failure("Store memory fill exceeds limit"));
                }
                let value = if name == "bzero" { 0 } else { arg(1)? as u8 };
                guest.mem_write(destination, &vec![value; size as usize])?;
                self.set(guest, destination)
            }
            "strlen" => self.set(guest, self.cstring(guest, arg(0)?)?.len() as u64),
            "strcmp" => {
                let first = self.cstring(guest, arg(0)?)?;
                let second = self.cstring(guest, arg(1)?)?;
                self.set(
                    guest,
                    match first.cmp(&second) {
                        std::cmp::Ordering::Less => u64::MAX,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    },
                )
            }
            "arc4random_buf" => {
                let address = arg(0)?;
                let size = arg(1)?;
                if size > HEAP_SIZE {
                    return Err(failure("Store random request exceeds limit"));
                }
                let mut bytes = vec![0; size as usize];
                getrandom::fill(&mut bytes).map_err(|_| failure("Store random source failed"))?;
                guest.mem_write(address, &bytes)
            }
            "pthread_mutex_init"
            | "pthread_mutex_lock"
            | "pthread_mutex_unlock"
            | "pthread_mutex_destroy"
            | "pthread_rwlock_init"
            | "pthread_rwlock_rdlock"
            | "pthread_rwlock_wrlock"
            | "pthread_rwlock_unlock"
            | "pthread_rwlock_destroy"
            | "os_unfair_lock_lock"
            | "os_unfair_lock_unlock"
            | "os_unfair_lock_assert_not_owner"
            | "os_unfair_lock_assert_owner"
            | "os_unfair_lock_lock_with_options"
            | "os_unfair_recursive_lock_lock_with_options"
            | "os_unfair_recursive_lock_unlock"
            | "objc_sync_enter"
            | "objc_sync_exit" => self.set(guest, 0),
            "dispatch_once" | "dispatch_once_f" | "swift_once" => {
                let token = arg(0)?;
                if read64(guest, token)? != 0 {
                    return self.set(guest, 0);
                }
                guest.mem_write(token, &u64::MAX.to_le_bytes())?;
                let (entry, arguments) = if name == "dispatch_once" {
                    let block = arg(1)?;
                    (read64(guest, block + 16)?, vec![block])
                } else if name == "dispatch_once_f" {
                    (arg(2)?, vec![arg(1)?])
                } else {
                    (arg(1)?, vec![arg(2)?])
                };
                self.callback(guest, entry, &arguments, Some(0))
            }
            "Block_copy" | "objc_retainBlock" => {
                let block = arg(0)?;
                self.copy_block(
                    guest,
                    block,
                    Box::new(|state, guest, copied| state.set(guest, copied)),
                )
            }
            "Block_object_assign" => {
                let destination = arg(0)?;
                let value = arg(1)?;
                let flags = arg(2)?;
                let after: ValueCompletion = Box::new(move |_, guest, copied| {
                    guest.mem_write(destination, &copied.to_le_bytes())
                });
                if flags & 15 == 7 {
                    self.copy_block(guest, value, after)
                } else if flags & 8 != 0 {
                    self.copy_byref(guest, value, after)
                } else {
                    guest.mem_write(destination, &value.to_le_bytes())
                }
            }
            "abort" | "__stack_chk_fail" | "__assert_rtn" => {
                Err(failure("Store framework aborted execution"))
            }
            _ => Err(failure(format!("unimplemented Store host symbol {name}"))),
        }
    }

    fn callback(
        &mut self,
        guest: Guest<'_>,
        entry: u64,
        args: &[u64],
        result: Option<u64>,
    ) -> Result<(), ClientError> {
        self.callback_then(
            guest,
            entry,
            args,
            Box::new(move |state, guest| {
                if let Some(result) = result {
                    state.set(guest, result)?;
                }
                Ok(())
            }),
        )
    }

    pub(super) fn callback_then(
        &mut self,
        guest: Guest<'_>,
        entry: u64,
        args: &[u64],
        after: Completion,
    ) -> Result<(), ClientError> {
        if args.len() > 8 {
            return Err(failure("Store callback exceeds register argument limit"));
        }
        let link = guest.reg_read(reg::LR)?;
        let resume = self.alloc(16)?;
        guest.mem_write(resume, &0xd65f03c0u32.to_le_bytes())?;
        self.callbacks.insert(resume, Resume { link, after });
        for (index, value) in args.iter().enumerate() {
            guest.reg_write(reg::general(index as u32).unwrap(), *value)?;
        }
        guest.reg_write(reg::LR, resume)?;
        guest.reg_write(reg::PC, entry)
    }
}
