//! Serial Swift task and continuation scheduler, matching the pinned Go runtime.
use super::*;

#[derive(Clone)]
pub(super) struct Task {
    context: u64,
    entry: u64,
    closure: u64,
    result: u64,
    continuation: u64,
    executor: [u64; 2],
    done: bool,
}
impl State {
    pub(super) fn task_symbol(
        &mut self,
        guest: Guest<'_>,
        name: &str,
    ) -> Result<bool, ClientError> {
        match name {
            "swift_task_localValueGet" => {
                let key = self.arg(guest, 0)?;
                let value = self
                    .task_locals
                    .get(&self.current_task)
                    .and_then(|v| v.iter().rev().find(|(k, _)| *k == key))
                    .map_or(0, |(_, v)| *v);
                self.set(guest, value)?;
            }
            "swift_task_localValuePush" => {
                let key = self.arg(guest, 0)?;
                let source = self.arg(guest, 1)?;
                let metadata = self.arg(guest, 2)?;
                let size = read64(guest, read64(guest, metadata - 8)? + 64)?;
                let value = self.alloc(size)?;
                guest.mem_write(value, &guest.mem_read(source, size as usize)?)?;
                self.task_locals
                    .entry(self.current_task)
                    .or_default()
                    .push((key, value));
                self.set(guest, 0)?;
            }
            "swift_task_localValuePop" => {
                if self
                    .task_locals
                    .get_mut(&self.current_task)
                    .and_then(Vec::pop)
                    .is_none()
                {
                    return Err(failure("empty Swift TaskLocal stack"));
                }
            }
            "swift_task_localsCopyTo" => {
                let target = self.arg(guest, 0)?;
                if !self.tasks.contains_key(&target) {
                    return Err(failure("unknown Swift task"));
                }
                let values = self
                    .task_locals
                    .get(&self.current_task)
                    .cloned()
                    .unwrap_or_default();
                self.task_locals.insert(target, values);
            }
            "swift_task_create" => {
                let flags = self.arg(guest, 0)?;
                let options = self.arg(guest, 1)?;
                let result_type = self.arg(guest, 2)?;
                let descriptor = self.arg(guest, 3)?;
                let closure = self.arg(guest, 4)?;
                if options != 0 || flags & !0x1cff != 0 {
                    return Err(failure("unsupported Swift task options"));
                }
                let bits = read64(guest, descriptor)?;
                let size = bits >> 32;
                if !(16..=1 << 20).contains(&size) {
                    return Err(failure("invalid Swift task context size"));
                }
                let handle = self.new_object(guest, "HostSwiftTask", Value::Null)?;
                let context = self.alloc(size + 32)? + 32;
                let entry = descriptor
                    .checked_add_signed(bits as i32 as i64)
                    .ok_or_else(|| failure("Swift task entry overflow"))?;
                let value_size = if result_type == 0 {
                    0
                } else {
                    read64(guest, read64(guest, result_type - 8)? + 64)?
                };
                let result = self.alloc(value_size)?;
                self.tasks.insert(
                    handle,
                    Task {
                        context,
                        entry,
                        closure,
                        result,
                        continuation: 0,
                        executor: [0; 2],
                        done: false,
                    },
                );
                if flags & (1 << 10) != 0 {
                    let values = self
                        .task_locals
                        .get(&self.current_task)
                        .cloned()
                        .unwrap_or_default();
                    self.task_locals.insert(handle, values);
                }
                let block = self.host_block(
                    guest,
                    Arc::new(move |state, guest| state.start_async(guest, handle)),
                )?;
                self.pending.push_back((block, 0));
                self.set(guest, handle)?;
                guest.reg_write(reg::X0 + 1, context)?;
            }
            "swift_task_alloc" => {
                let value = self.alloc(self.arg(guest, 0)?)?;
                self.set(guest, value)?;
            }
            "swift_task_dealloc" => (),
            "swift_task_getCurrent" => self.set(guest, self.current_task)?,
            "swift_task_isCancelled" => {
                self.set(guest, u64::from(self.cancellation.is_cancelled()))?
            }
            "swift_task_switch" => {
                let function = self.arg(guest, 0)?;
                let executor = [self.arg(guest, 1)?, self.arg(guest, 2)?];
                self.tasks
                    .get_mut(&self.current_task)
                    .ok_or_else(|| failure("Swift executor switch outside task"))?
                    .executor = executor;
                guest.reg_write(reg::PC, function)?;
            }
            "swift_task_getCurrentExecutor" | "swift_task_isCurrentExecutor" => {
                let executor = self
                    .tasks
                    .get(&self.current_task)
                    .map_or([0; 2], |t| t.executor);
                if name == "swift_task_isCurrentExecutor" {
                    self.set(
                        guest,
                        u64::from(executor == [self.arg(guest, 0)?, self.arg(guest, 1)?]),
                    )?;
                } else {
                    self.set(guest, executor[0])?;
                    guest.reg_write(reg::X0 + 1, executor[1])?;
                }
            }
            "swift_continuation_init" => {
                let context = self.arg(guest, 0)?;
                let flags = self.arg(guest, 1)?;
                if flags & 4 != 0 {
                    return Err(failure("preawaited Swift continuation is unsupported"));
                }
                self.tasks
                    .get_mut(&self.current_task)
                    .ok_or_else(|| failure("Swift continuation initialized outside task"))?
                    .continuation = context;
                for (offset, value) in [(16, (flags & 1) | ((flags & 8) >> 2)), (24, 0), (32, 0)] {
                    guest.mem_write(context + offset, &value.to_le_bytes())?;
                }
                if flags & 2 == 0 {
                    guest.mem_write(context + 48, &[0; 16])?;
                }
                self.set(guest, self.current_task)?;
            }
            "swift_continuation_resume"
            | "swift_continuation_throwingResume"
            | "swift_continuation_throwingResumeWithError" => {
                let task = self.arg(guest, 0)?;
                let context = self
                    .tasks
                    .get(&task)
                    .map(|t| t.continuation)
                    .filter(|c| *c != 0)
                    .ok_or_else(|| failure("unknown Swift continuation"))?;
                if read64(guest, context + 24)? == 2 {
                    return Err(failure("Swift continuation resumed twice"));
                }
                if name == "swift_continuation_throwingResumeWithError" {
                    guest.mem_write(context + 32, &self.arg(guest, 1)?.to_le_bytes())?;
                }
                guest.mem_write(context + 24, &2u64.to_le_bytes())?;
                self.set(guest, 0)?;
            }
            "swift_continuation_await" => {
                let context = self.arg(guest, 0)?;
                let task = self.current_task;
                if self
                    .tasks
                    .get(&task)
                    .is_none_or(|t| t.continuation != context)
                {
                    return Err(failure("awaiting unknown Swift continuation"));
                }
                self.await_continuation(guest, task, context)?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    fn await_continuation(
        &mut self,
        guest: Guest<'_>,
        task: u64,
        context: u64,
    ) -> Result<(), ClientError> {
        if read64(guest, context + 24)? == 2 {
            self.tasks
                .get_mut(&task)
                .ok_or_else(|| failure("unknown Swift task"))?
                .continuation = 0;
            self.current_task = task;
            guest.reg_write(reg::general(22).unwrap(), context)?;
            guest.reg_write(reg::PC, read64(guest, context + 8)?)
        } else {
            self.current_task = 0;
            self.run_pending(
                guest,
                Box::new(move |state, guest| {
                    state.current_task = task;
                    state.await_continuation(guest, task, context)
                }),
            )
        }
    }
    fn start_async(&mut self, guest: Guest<'_>, handle: u64) -> Result<(), ClientError> {
        let task = self
            .tasks
            .get(&handle)
            .filter(|t| !t.done)
            .cloned()
            .ok_or_else(|| failure("unknown or completed Swift task"))?;
        let mut saved = Vec::new();
        for register in [reg::SP, reg::LR, reg::general(29).unwrap()]
            .into_iter()
            .chain((19..=28).map(|i| reg::general(i).unwrap()))
        {
            saved.push((register, guest.reg_read(register)?));
        }
        let previous = self.current_task;
        self.current_task = handle;
        let completion = self.host_block(
            guest,
            Arc::new(move |state, guest| {
                let task = state
                    .tasks
                    .get_mut(&handle)
                    .filter(|t| !t.done)
                    .ok_or_else(|| failure("Swift task completed twice"))?;
                task.done = true;
                state.current_task = previous;
                for (register, value) in &saved {
                    guest.reg_write(*register, *value)?;
                }
                state.set(guest, 0)?;
                guest.reg_write(
                    reg::PC,
                    saved.iter().find(|(r, _)| *r == reg::LR).unwrap().1,
                )
            }),
        )?;
        let completion = read64(guest, completion + 16)?;
        for (offset, value) in [
            (task.context, 0),
            (task.context + 8, completion),
            (task.context - 32, task.result),
            (task.context - 24, task.entry),
            (task.context - 16, task.closure),
        ] {
            guest.mem_write(offset, &value.to_le_bytes())?;
        }
        self.set(guest, task.result)?;
        guest.reg_write(reg::general(20).unwrap(), task.closure)?;
        guest.reg_write(reg::general(21).unwrap(), 0)?;
        guest.reg_write(reg::general(22).unwrap(), task.context)?;
        guest.reg_write(reg::PC, task.entry)
    }
}
