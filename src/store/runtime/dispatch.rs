use super::*;

impl State {
    pub(super) fn host_block(
        &mut self,
        guest: Guest<'_>,
        callback: HostCall,
    ) -> Result<u64, ClientError> {
        let function = self.alloc(16)?;
        guest.mem_write(function, &0xd65f03c0u32.to_le_bytes())?;
        self.host_calls.insert(function, callback);
        let descriptor = self.alloc(16)?;
        guest.mem_write(descriptor + 8, &32u64.to_le_bytes())?;
        let block = self.alloc(32)?;
        guest.mem_write(block + 8, &(1u64 << 28).to_le_bytes())?;
        guest.mem_write(block + 16, &function.to_le_bytes())?;
        guest.mem_write(block + 24, &descriptor.to_le_bytes())?;
        Ok(block)
    }
    fn next_pending(&mut self) -> Result<(u64, u64), ClientError> {
        let position = self
            .pending
            .iter()
            .position(|(_, queue)| {
                self.objects.get(queue).is_none_or(|object| {
                    object.properties.get("suspendCount").copied().unwrap_or(0) == 0
                })
            })
            .ok_or_else(|| failure("Store has no runnable callback"))?;
        Ok(self.pending.remove(position).unwrap())
    }
    pub(super) fn run_pending(
        &mut self,
        guest: Guest<'_>,
        after: Completion,
    ) -> Result<(), ClientError> {
        let (block, queue) = self.next_pending()?;
        let previous = self.current_queue;
        self.current_queue = queue;
        self.callback_then(
            guest,
            read64(guest, block + 16)?,
            &[block],
            Box::new(move |state, guest| {
                state.current_queue = previous;
                after(state, guest)
            }),
        )
    }

    pub(super) fn dispatch_symbol(
        &mut self,
        guest: Guest<'_>,
        name: &str,
    ) -> Result<bool, ClientError> {
        match name {
            "dispatch_time" => {
                let base = self.arg(guest, 0)?;
                let base = if base == 0 {
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| failure("invalid Store clock"))?
                        .as_nanos() as u64
                } else {
                    base
                };
                self.set(guest, base.wrapping_add(self.arg(guest, 1)?))?;
            }
            "dispatch_after" => {
                let deadline = self.arg(guest, 0)?;
                let block = self.arg(guest, 2)?;
                self.copy_block(
                    guest,
                    block,
                    Box::new(move |state, guest, copied| {
                        state.timers.push((deadline, copied));
                        state.set(guest, 0)
                    }),
                )?;
            }
            "dispatch_queue_attr_make_with_autorelease_frequency"
            | "dispatch_queue_attr_make_with_qos_class" => (),
            "dispatch_queue_create"
            | "dispatch_get_global_queue"
            | "dispatch_get_main_queue"
            | "dispatch_queue_create_with_target" => {
                let target = if name == "dispatch_queue_create_with_target" {
                    self.arg(guest, 2)?
                } else {
                    0
                };
                let queue = self.new_object(guest, "HostQueue", Value::Null)?;
                self.objects
                    .get_mut(&queue)
                    .unwrap()
                    .properties
                    .insert("targetQueue".into(), target);
                self.set(guest, queue)?;
            }
            "dispatch_set_target_queue" => {
                let queue = self.arg(guest, 0)?;
                let target = self.arg(guest, 1)?;
                self.objects
                    .get_mut(&queue)
                    .ok_or_else(|| failure("unknown Store dispatch queue"))?
                    .properties
                    .insert("targetQueue".into(), target);
            }
            "dispatch_suspend" | "dispatch_resume" => {
                let queue = self.arg(guest, 0)?;
                let count = self
                    .objects
                    .get_mut(&queue)
                    .ok_or_else(|| failure("unknown Store dispatch queue"))?
                    .properties
                    .entry("suspendCount".into())
                    .or_default();
                *count = if name == "dispatch_suspend" {
                    count
                        .checked_add(1)
                        .ok_or_else(|| failure("Store queue suspension overflow"))?
                } else {
                    count
                        .checked_sub(1)
                        .ok_or_else(|| failure("resuming active Store dispatch queue"))?
                };
            }
            "dispatch_async" => {
                let queue = self.arg(guest, 0)?;
                let block = self.arg(guest, 1)?;
                self.copy_block(
                    guest,
                    block,
                    Box::new(move |state, guest, copied| {
                        state.pending.push_back((copied, queue));
                        state.set(guest, 0)
                    }),
                )?;
            }
            "dispatch_sync" | "dispatch_sync_f" => {
                let queue = self.arg(guest, 0)?;
                let previous = self.current_queue;
                self.current_queue = queue;
                let (entry, argument) = if name == "dispatch_sync" {
                    let block = self.arg(guest, 1)?;
                    (read64(guest, block + 16)?, block)
                } else {
                    (self.arg(guest, 2)?, self.arg(guest, 1)?)
                };
                self.callback_then(
                    guest,
                    entry,
                    &[argument],
                    Box::new(move |state, guest| {
                        state.current_queue = previous;
                        state.set(guest, 0)
                    }),
                )?;
            }
            "dispatch_assert_queue" => {
                let target = self.arg(guest, 0)?;
                let mut queue = self.current_queue;
                let mut found = false;
                for _ in 0..32 {
                    if queue == target {
                        found = true;
                        break;
                    }
                    queue = self
                        .objects
                        .get(&queue)
                        .and_then(|o| o.properties.get("targetQueue"))
                        .copied()
                        .unwrap_or(0);
                    if queue == 0 {
                        break;
                    }
                }
                if !found {
                    return Err(failure("Store dispatch queue mismatch"));
                }
            }
            "dispatch_block_create" => {
                let block = self.arg(guest, 1)?;
                self.copy_block(
                    guest,
                    block,
                    Box::new(|state, guest, copied| state.set(guest, copied)),
                )?;
            }
            "dispatch_semaphore_create" => {
                let count = self.arg(guest, 0)? as i64;
                let semaphore = self.new_object(guest, "HostSemaphore", Value::Integer(count))?;
                self.set(guest, semaphore)?;
            }
            "dispatch_semaphore_signal" => {
                let semaphore = self.arg(guest, 0)?;
                let Value::Integer(count) = &mut self
                    .objects
                    .get_mut(&semaphore)
                    .ok_or_else(|| failure("unknown Store semaphore"))?
                    .value
                else {
                    return Err(failure("invalid Store semaphore"));
                };
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| failure("Store semaphore overflow"))?;
                self.set(guest, 0)?;
            }
            "dispatch_semaphore_wait" => {
                let semaphore = self.arg(guest, 0)?;
                let Value::Integer(count) = &mut self
                    .objects
                    .get_mut(&semaphore)
                    .ok_or_else(|| failure("unknown Store semaphore"))?
                    .value
                else {
                    return Err(failure("invalid Store semaphore"));
                };
                if *count > 0 {
                    *count -= 1;
                    self.set(guest, 0)?;
                } else {
                    self.run_pending(
                        guest,
                        Box::new(move |state, guest| {
                            let Value::Integer(count) = &mut state
                                .objects
                                .get_mut(&semaphore)
                                .ok_or_else(|| failure("unknown Store semaphore"))?
                                .value
                            else {
                                return Err(failure("invalid Store semaphore"));
                            };
                            if *count <= 0 {
                                return Err(failure("Store semaphore remains unsignaled"));
                            }
                            *count -= 1;
                            state.set(guest, 0)
                        }),
                    )?;
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
}
