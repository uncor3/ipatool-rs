//! Isolated ARM64 guest and Objective-C object bridge for the pinned Store image.
mod accounts;
mod bridge;
#[cfg(test)]
mod bridge_tests;
mod callbacks;
mod client;
mod compression;
mod delegates;
mod dictionaries;
mod dispatch;
mod foundation;
mod hashing;
mod memory;
mod network;
mod notifications;
mod swift;
mod symbols;
mod system;
mod tasks;
pub use client::{Request, Response, Transport};

use super::profile::{self, Data};
use crate::{
    client::AppleClient,
    error::ClientError,
    sap::{
        hex_digest,
        macho::{Image, Memory},
        unicorn::{Architecture, Engine, Guest, arm64_reg as reg},
    },
};
use memory::{Mapper, failure, group_pages};
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};

const HEAP_BASE: u64 = 0x400000000000;
const HEAP_SIZE: u64 = 64 << 20;
const STACK_BASE: u64 = 0x500000000000;
const STACK_SIZE: u64 = 8 << 20;
const RETURN_PC: u64 = 0x100000000;

#[derive(Clone, PartialEq)]
pub enum Value {
    Null,
    String(String),
    Bytes(Vec<u8>),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Dictionary(HashMap<String, u64>),
    Array(Vec<u64>),
    Date(f64),
}
#[derive(Clone)]
struct Object {
    class: String,
    value: Value,
    properties: HashMap<String, u64>,
}
type Completion = Box<dyn for<'a> FnOnce(&mut State, Guest<'a>) -> Result<(), ClientError> + Send>;
type HostCall = Arc<dyn for<'a> Fn(&mut State, Guest<'a>) -> Result<(), ClientError> + Send + Sync>;
type ValueCompletion =
    Box<dyn for<'a> FnOnce(&mut State, Guest<'a>, u64) -> Result<(), ClientError> + Send>;
struct Resume {
    link: u64,
    after: Completion,
}

struct State {
    cancellation: super::cancellation::Cancellation,
    data: Arc<Data>,
    class_definitions: Vec<profile::format::Class>,
    objects: HashMap<u64, Object>,
    classes: HashMap<String, usize>,
    class_names: HashMap<u64, String>,
    methods: HashMap<(String, String, bool), u64>,
    selectors: HashMap<u64, String>,
    selector_addresses: HashMap<String, u64>,
    calls: HashMap<u64, usize>,
    code: Vec<(u64, u64)>,
    cursor: u64,
    allocations: HashMap<u64, u64>,
    callbacks: HashMap<u64, Resume>,
    host_calls: HashMap<u64, HostCall>,
    pending: std::collections::VecDeque<(u64, u64)>,
    timers: Vec<(u64, u64)>,
    current_queue: u64,
    steps: u64,
    deadline: std::time::Instant,
    transport: Option<Transport>,
    last_response: Option<Response>,
    hardware_id: Vec<u8>,
    stream_response: bool,
    auth_request: bool,
    no_redirects: bool,
    preferences: HashMap<(String, String), u64>,
    associations: HashMap<(u64, u64), u64>,
    notification_center: u64,
    null_object: u64,
    observers: HashSet<u64>,
    tasks: HashMap<u64, tasks::Task>,
    current_task: u64,
    task_locals: HashMap<u64, Vec<(u64, u64)>>,
    response_headers: HashMap<u64, reqwest::header::HeaderMap>,
    inflaters: HashMap<u64, compression::Inflater>,
}

pub struct Runtime {
    engine: Engine,
    state: Arc<Mutex<State>>,
}
impl Runtime {
    pub async fn open(client: &AppleClient, image: &[u8]) -> Result<Self, ClientError> {
        Self::open_cancellable(client, image, super::cancellation::Cancellation::new()).await
    }
    pub(crate) async fn open_cancellable(
        client: &AppleClient,
        image: &[u8],
        cancellation: super::cancellation::Cancellation,
    ) -> Result<Self, ClientError> {
        cancellation.check()?;
        if hex_digest(image) != "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4" {
            return Err(failure("Store framework does not match pinned image"));
        }
        let data = tokio::task::spawn_blocking(profile::load)
            .await
            .map_err(|_| failure("Store profile worker failed"))?
            .map_err(|e| failure(e.to_string()))?;
        let mut engine =
            Engine::open_for_architecture(client, client.cache_dir(), Architecture::Arm64).await?;
        let mapper = Mapper {
            guest: engine.guest(),
            pages: Default::default(),
        };
        for (address, size) in [
            (HEAP_BASE, HEAP_SIZE),
            (STACK_BASE, STACK_SIZE),
            (RETURN_PC, 4096),
        ] {
            cancellation.check()?;
            mapper.map(address, size)?;
        }
        mapper.write(RETURN_PC, &0xd4200000u32.to_le_bytes())?;
        let mut code = Vec::new();
        for (name, bytes) in [
            ("AppleMediaServices", image),
            ("AMSAccountAuthenticationPlugin", data.plugin.as_slice()),
        ] {
            cancellation.check()?;
            let mut image = Image::open_arm64(name, bytes)?;
            image.prepare_prelinked(&[], |_| Err(failure("unexpected Store image relocation")))?;
            image.load(&mapper)?;
            code.extend(code_ranges(bytes)?);
        }
        let mut pages: Vec<u64> = data.metadata.pages.iter().map(|p| p.address).collect();
        pages.extend(data.metadata.calls.iter().map(|c| c.address & !4095));
        pages.push(0x1a2d0fb94 & !4095);
        pages.retain(|page| !mapper.pages.borrow().contains(page));
        for (address, size) in group_pages(pages)? {
            cancellation.check()?;
            mapper.map(address, size)?;
        }
        for page in &data.metadata.pages {
            cancellation.check()?;
            mapper.write(
                page.address,
                &data.pages[page.offset as usize..page.offset as usize + 4096],
            )?;
        }
        for call in &data.metadata.calls {
            mapper.write(call.address, &0xd65f03c0u32.to_le_bytes())?;
        }
        mapper.write(0x1a2d0fb94, &0xd65f03c0u32.to_le_bytes())?;
        for bytes in [image, data.plugin.as_slice()] {
            patch_ivars(bytes, &data.metadata, &mapper)?;
        }
        for patch in &data.metadata.metadata_patches {
            mapper.write(patch.address, &patch.data)?;
        }
        drop(mapper);
        cancellation.check()?;
        let state = Arc::new(Mutex::new(State::new(data, code, cancellation)?));
        let hook_state = Arc::clone(&state);
        engine.add_code_hook(1, 0, move |guest, address, _| {
            hook_state
                .lock()
                .map_err(|_| failure("Store state lock poisoned"))?
                .step(guest, address)
        })?;
        Ok(Self { engine, state })
    }

    pub fn class_address(&self, name: &str) -> Result<u64, ClientError> {
        let state = self
            .state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?;
        Ok(state
            .classes
            .get(name)
            .map_or(0, |i| state.class_definitions[*i].address))
    }

    pub fn new_object(&mut self, class: &str, value: Value) -> Result<u64, ClientError> {
        self.state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?
            .new_object(self.engine.guest(), class, value)
    }

    pub fn invoke(
        &mut self,
        receiver: u64,
        selector: &str,
        arguments: &[u64],
    ) -> Result<u64, ClientError> {
        let guest = self.engine.guest();
        let mut state = self
            .state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?;
        let (class, meta) = state.receiver(receiver).map_err(|_| {
            failure(format!(
                "unknown Store receiver {receiver:#x} for {selector}"
            ))
        })?;
        state.cancellation.check()?;
        let selector_address = state.selector(guest, selector)?;
        let mut entry = state.lookup(&class, selector, meta);
        if arguments.len() > 64 {
            return Err(failure("Store call exceeds argument limit"));
        }
        let args: Vec<u64> = [receiver, selector_address]
            .into_iter()
            .chain(arguments.iter().copied())
            .collect();
        for index in 0..8 {
            guest.reg_write(
                reg::general(index).unwrap(),
                args.get(index as usize).copied().unwrap_or(0),
            )?;
        }
        let stack = STACK_BASE + STACK_SIZE - 4096;
        for (index, arg) in args.iter().enumerate().skip(8) {
            guest.mem_write(stack + (index as u64 - 8) * 8, &arg.to_le_bytes())?;
        }
        guest.reg_write(reg::SP, stack)?;
        guest.reg_write(reg::LR, RETURN_PC)?;
        guest.reg_write(reg::PC, RETURN_PC)?;
        state.steps = 0;
        state.deadline = std::time::Instant::now() + Duration::from_secs(120);
        if entry == 0 {
            let selector = selector.to_owned();
            let block = state.host_block(
                guest,
                Arc::new(move |state, guest| state.message(guest, receiver, &selector, false)),
            )?;
            entry = read64(guest, block + 16)?;
        }
        drop(state);
        self.engine
            .start(entry, RETURN_PC, Duration::from_secs(120), 20_000_000)?;
        if self.engine.guest().reg_read(reg::PC)? != RETURN_PC {
            return Err(failure("Store instruction budget exhausted"));
        }
        self.engine.guest().reg_read(reg::X0)
    }

    pub fn export(&self, address: u64) -> Result<plist::Value, ClientError> {
        self.state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?
            .export(address, &mut HashSet::new(), 0)
    }

    pub fn import(&mut self, value: &plist::Value) -> Result<u64, ClientError> {
        self.state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?
            .import_value(self.engine.guest(), value, 0)
    }

    /// Builds an ephemeral guest account; never opens or writes a host account store.
    pub fn ephemeral_account(
        &mut self,
        saved: Option<(&str, &str, &str)>,
    ) -> Result<u64, ClientError> {
        let account = self.invoke(
            self.class_address("ACAccount")?,
            "ams_createEphemeralAccount",
            &[],
        )?;
        if let Some((dsid, token, storefront)) = saved {
            let dsid = dsid
                .parse::<i64>()
                .map_err(|_| failure("invalid Store account identifier"))?;
            let username = self.new_object("NSString", Value::String(String::new()))?;
            let dsid = self.new_object("NSNumber", Value::Integer(dsid))?;
            let token = self.new_object("NSString", Value::String(token.into()))?;
            let storefront = self.new_object("NSString", Value::String(storefront.into()))?;
            for (selector, value) in [
                ("setUsername:", username),
                ("ams_setDSID:", dsid),
                ("ams_setPassword:", token),
                ("ams_setStorefront:", storefront),
            ] {
                self.invoke(account, selector, &[value])?;
            }
        }
        Ok(account)
    }
}

impl State {
    fn new(
        data: Arc<Data>,
        code: Vec<(u64, u64)>,
        cancellation: super::cancellation::Cancellation,
    ) -> Result<Self, ClientError> {
        let mut state = Self {
            cancellation,
            class_definitions: data.metadata.classes.clone(),
            data,
            code,
            objects: HashMap::new(),
            classes: HashMap::new(),
            class_names: HashMap::new(),
            methods: HashMap::new(),
            selectors: HashMap::new(),
            selector_addresses: HashMap::new(),
            calls: HashMap::new(),
            cursor: 0,
            allocations: HashMap::new(),
            callbacks: HashMap::new(),
            host_calls: HashMap::new(),
            pending: Default::default(),
            timers: Vec::new(),
            current_queue: 0,
            steps: 0,
            deadline: std::time::Instant::now() + Duration::from_secs(120),
            transport: None,
            last_response: None,
            hardware_id: Vec::new(),
            stream_response: false,
            auth_request: false,
            no_redirects: false,
            preferences: HashMap::new(),
            associations: HashMap::new(),
            notification_center: 0,
            null_object: 0,
            observers: HashSet::new(),
            tasks: HashMap::new(),
            current_task: 0,
            task_locals: HashMap::new(),
            response_headers: HashMap::new(),
            inflaters: HashMap::new(),
        };
        for (index, class) in state.data.metadata.classes.iter().enumerate() {
            state.classes.insert(class.name.clone(), index);
            state.class_names.insert(class.address, class.name.clone());
            if class.meta_address != 0 {
                state
                    .class_names
                    .insert(class.meta_address, class.name.clone());
            }
            for method in &class.methods {
                state.methods.insert(
                    (
                        class.name.clone(),
                        method.selector.clone(),
                        method.class_method,
                    ),
                    method.address,
                );
            }
        }
        for (address, text) in &state.data.metadata.strings {
            state.objects.insert(
                address
                    .parse()
                    .map_err(|_| failure("invalid Store constant address"))?,
                Object {
                    class: "NSString".into(),
                    value: Value::String(text.clone()),
                    properties: HashMap::new(),
                },
            );
        }
        for (address, constant) in &state.data.metadata.constants {
            let value = match constant.kind.as_str() {
                "NSString" => Value::String(constant.text.clone()),
                "NSNumber" if constant.is_boolean => Value::Boolean(constant.boolean),
                "NSNumber" => Value::Integer(constant.number),
                "NSDictionary" => Value::Dictionary(constant.entries.clone()),
                "NSArray" | "NSSet" => Value::Array(constant.items.clone()),
                _ => Value::Null,
            };
            state.objects.insert(
                address
                    .parse()
                    .map_err(|_| failure("invalid Store constant address"))?,
                Object {
                    class: constant.kind.clone(),
                    value,
                    properties: HashMap::new(),
                },
            );
        }
        for (index, call) in state.data.metadata.calls.iter().enumerate() {
            state.calls.insert(call.address, index);
            if !call.selector.is_empty() {
                state
                    .selectors
                    .insert(call.selector_address, call.selector.clone());
                state
                    .selector_addresses
                    .insert(call.selector.clone(), call.selector_address);
            }
        }
        Ok(state)
    }
    fn alloc(&mut self, size: u64) -> Result<u64, ClientError> {
        let size = size
            .checked_add(15)
            .map(|s| s & !15)
            .filter(|s| *s <= HEAP_SIZE - self.cursor)
            .ok_or_else(|| failure("Store guest heap exhausted"))?
            .max(16);
        if size > HEAP_SIZE - self.cursor {
            return Err(failure("Store guest heap exhausted"));
        }
        let address = HEAP_BASE + self.cursor;
        self.cursor += size;
        self.allocations.insert(address, size);
        Ok(address)
    }
    fn new_object(
        &mut self,
        guest: Guest<'_>,
        class: &str,
        value: Value,
    ) -> Result<u64, ClientError> {
        let class_info = self.classes.get(class).map(|i| &self.class_definitions[*i]);
        let size = class_info.map_or(256, |c| c.size.max(16));
        let isa = class_info.map_or(0, |c| c.address);
        let address = self.alloc(size)?;
        guest.mem_write(address, &isa.to_le_bytes())?;
        self.objects.insert(
            address,
            Object {
                class: class.into(),
                value,
                properties: HashMap::new(),
            },
        );
        Ok(address)
    }
    fn receiver(&self, address: u64) -> Result<(String, bool), ClientError> {
        if let Some(class) = self.class_names.get(&address) {
            return Ok((class.clone(), true));
        }
        self.objects
            .get(&address)
            .map(|o| (o.class.clone(), false))
            .ok_or_else(|| failure(format!("unknown Store receiver {address:#x}")))
    }
    fn lookup(&self, class: &str, selector: &str, meta: bool) -> u64 {
        let mut class = class;
        for _ in 0..64 {
            if let Some(address) = self.methods.get(&(class.into(), selector.into(), meta)) {
                return *address;
            }
            let Some(index) = self.classes.get(class) else {
                break;
            };
            class = &self.class_definitions[*index].superclass;
            if class.is_empty() {
                break;
            }
        }
        0
    }
    fn kind_of<'a>(&'a self, mut class: &'a str, target: &str) -> bool {
        if target == "NSObject" {
            return true;
        }
        for _ in 0..64 {
            if class == target {
                return true;
            }
            let Some(index) = self.classes.get(class) else {
                return false;
            };
            class = &self.class_definitions[*index].superclass;
        }
        false
    }
    fn selector(&mut self, guest: Guest<'_>, text: &str) -> Result<u64, ClientError> {
        if let Some(address) = self.selector_addresses.get(text) {
            return Ok(*address);
        }
        if text.len() > 16384 {
            return Err(failure("Store selector exceeds limit"));
        }
        let address = self.alloc(text.len() as u64 + 1)?;
        let mut bytes = text.as_bytes().to_vec();
        bytes.push(0);
        guest.mem_write(address, &bytes)?;
        self.selector_addresses.insert(text.into(), address);
        self.selectors.insert(address, text.into());
        Ok(address)
    }
    fn string(&self, address: u64) -> Result<String, ClientError> {
        if address == 0 {
            return Ok(String::new());
        }
        match self.objects.get(&address).map(|o| &o.value) {
            Some(Value::String(text)) => Ok(text.clone()),
            _ => Err(failure(format!(
                "Store object {address:#x} ({}) is not a string",
                self.objects
                    .get(&address)
                    .map_or("unknown", |o| o.class.as_str())
            ))),
        }
    }
    fn cstring(&self, guest: Guest<'_>, address: u64) -> Result<String, ClientError> {
        if address == 0 {
            return Ok(String::new());
        }
        if let Some(selector) = self.selectors.get(&address) {
            return Ok(selector.clone());
        }
        let mut data = Vec::new();
        for offset in 0..16384 {
            let mut byte = [0];
            guest.mem_read_into(address + offset, &mut byte)?;
            if byte[0] == 0 {
                return String::from_utf8(data).map_err(|_| failure("invalid Store UTF-8 string"));
            }
            data.push(byte[0]);
        }
        Err(failure("unterminated Store C string"))
    }
    fn arg(&self, guest: Guest<'_>, index: u32) -> Result<u64, ClientError> {
        if index < 8 {
            guest.reg_read(reg::general(index).unwrap())
        } else {
            read64(guest, guest.reg_read(reg::SP)? + (index as u64 - 8) * 8)
        }
    }
    fn set(&self, guest: Guest<'_>, value: u64) -> Result<(), ClientError> {
        guest.reg_write(reg::X0, value)
    }
    fn jump(
        &mut self,
        guest: Guest<'_>,
        entry: u64,
        receiver: u64,
        selector: &str,
    ) -> Result<(), ClientError> {
        guest.reg_write(reg::X0, receiver)?;
        guest.reg_write(reg::X0 + 1, self.selector(guest, selector)?)?;
        guest.reg_write(reg::PC, entry)
    }
    fn step(&mut self, guest: Guest<'_>, address: u64) -> Result<(), ClientError> {
        self.cancellation.check()?;
        if let Some(resume) = self.callbacks.remove(&address) {
            guest.reg_write(reg::LR, resume.link)?;
            guest.reg_write(reg::PC, resume.link)?;
            return (resume.after)(self, guest);
        }
        if let Some(callback) = self.host_calls.get(&address).cloned() {
            return callback(self, guest);
        }
        if address == 0x1a2d0fb94 {
            return self.set(guest, 0);
        }
        if let Some(index) = self.calls.get(&address).copied() {
            let call = &self.data.metadata.calls[index];
            let selector = call.selector.clone();
            let symbol = call.symbol.trim_start_matches('_').to_owned();
            if !selector.is_empty() {
                return self.message(guest, self.arg(guest, 0)?, &selector, false);
            }
            return self.symbol(guest, &symbol);
        }
        if !self
            .code
            .iter()
            .any(|(start, end)| address >= *start && address < *end)
        {
            return Err(failure(format!(
                "execution outside pinned Store image at {address:#x}"
            )));
        }
        self.steps += 1;
        if self.steps.is_multiple_of(4096) && std::time::Instant::now() >= self.deadline {
            return Err(failure("Store request deadline exceeded"));
        }
        Ok(())
    }
    fn export(
        &self,
        address: u64,
        active: &mut HashSet<u64>,
        depth: usize,
    ) -> Result<plist::Value, ClientError> {
        if address == 0 {
            return Err(failure("null Store value cannot be exported as plist"));
        }
        if depth > 32 || !active.insert(address) {
            return Err(failure("cyclic or excessively nested Store value"));
        }
        let object = self
            .objects
            .get(&address)
            .ok_or_else(|| failure("unknown exported Store object"))?;
        let result = match &object.value {
            Value::String(v) => plist::Value::String(v.clone()),
            Value::Bytes(v) => plist::Value::Data(v.clone()),
            Value::Integer(v) => plist::Value::Integer((*v).into()),
            Value::Real(v) => plist::Value::Real(*v),
            Value::Boolean(v) => plist::Value::Boolean(*v),
            Value::Array(values) => plist::Value::Array(
                values
                    .iter()
                    .map(|v| self.export(*v, active, depth + 1))
                    .collect::<Result<_, _>>()?,
            ),
            Value::Dictionary(values) => plist::Value::Dictionary(
                values
                    .iter()
                    .collect::<std::collections::BTreeMap<_, _>>()
                    .into_iter()
                    .map(|(k, v)| Ok((k.clone(), self.export(*v, active, depth + 1)?)))
                    .collect::<Result<_, ClientError>>()?,
            ),
            Value::Null => return Err(failure("unsupported null Store plist value")),
            Value::Date(seconds) => {
                if !seconds.is_finite() {
                    return Err(failure("invalid Store date"));
                }
                let duration = Duration::try_from_secs_f64(seconds.abs())
                    .map_err(|_| failure("Store date exceeds supported range"))?;
                let time = if *seconds >= 0.0 {
                    std::time::UNIX_EPOCH.checked_add(duration)
                } else {
                    std::time::UNIX_EPOCH.checked_sub(duration)
                }
                .ok_or_else(|| failure("Store date exceeds supported range"))?;
                plist::Value::Date(time.into())
            }
        };
        active.remove(&address);
        Ok(result)
    }
}

fn read64(guest: Guest<'_>, address: u64) -> Result<u64, ClientError> {
    let mut bytes = [0; 8];
    guest.mem_read_into(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}
fn patch_ivars(
    bytes: &[u8],
    profile: &profile::format::Profile,
    memory: &impl Memory,
) -> Result<(), ClientError> {
    let u32at = |offset: usize| {
        bytes
            .get(offset..offset + 4)
            .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
            .ok_or_else(|| failure("truncated Store Mach-O"))
    };
    let mut offset = 32;
    for _ in 0..u32at(16)? {
        let size = u32at(offset + 4)? as usize;
        if size < 8 || offset + size > bytes.len() {
            return Err(failure("invalid Store Mach-O command"));
        }
        if u32at(offset)? == 2 {
            let symbols = u32at(offset + 8)? as usize;
            let count = u32at(offset + 12)? as usize;
            let strings = u32at(offset + 16)? as usize;
            for i in 0..count {
                let entry = bytes
                    .get(symbols + i * 16..symbols + i * 16 + 16)
                    .ok_or_else(|| failure("invalid Store symbol table"))?;
                let index = u32::from_le_bytes(entry[..4].try_into().unwrap()) as usize;
                let rest = bytes
                    .get(strings + index..)
                    .ok_or_else(|| failure("invalid Store symbol string"))?;
                let end = rest
                    .iter()
                    .position(|b| *b == 0)
                    .ok_or_else(|| failure("unterminated Store symbol"))?;
                let Ok(name) = std::str::from_utf8(&rest[..end]) else {
                    continue;
                };
                let Some((class, ivar)) = name
                    .strip_prefix("_OBJC_IVAR_$_")
                    .and_then(|s| s.split_once('.'))
                else {
                    continue;
                };
                if let Some(value) = profile
                    .classes
                    .iter()
                    .find(|c| c.name == class)
                    .and_then(|c| c.ivars.get(ivar))
                {
                    memory.write(
                        u64::from_le_bytes(entry[8..16].try_into().unwrap()),
                        &(*value as u32).to_le_bytes(),
                    )?;
                }
            }
        }
        offset += size;
    }
    Ok(())
}
fn code_ranges(bytes: &[u8]) -> Result<Vec<(u64, u64)>, ClientError> {
    let mut ranges = Vec::new();
    let mut offset = 32;
    let count = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    for _ in 0..count {
        let command = bytes
            .get(offset..offset + 8)
            .ok_or_else(|| failure("truncated Store Mach-O"))?;
        let size = u32::from_le_bytes(command[4..8].try_into().unwrap()) as usize;
        let command = bytes
            .get(offset..offset + size)
            .filter(|_| size >= 8)
            .ok_or_else(|| failure("invalid Store Mach-O command"))?;
        if u32::from_le_bytes(command[..4].try_into().unwrap()) == 0x19 {
            for section in command
                .get(72..)
                .ok_or_else(|| failure("truncated Store segment"))?
                .chunks_exact(80)
            {
                if u32::from_le_bytes(section[64..68].try_into().unwrap()) & 0x80000400 == 0 {
                    continue;
                }
                let address = u64::from_le_bytes(section[32..40].try_into().unwrap());
                let size = u64::from_le_bytes(section[40..48].try_into().unwrap());
                ranges.push((
                    address,
                    address
                        .checked_add(size)
                        .ok_or_else(|| failure("Store section overflow"))?,
                ));
            }
        }
        offset += size;
    }
    Ok(ranges)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires pinned assets and ARM64 Unicorn; no account or network requests"]
    async fn live_store_vm_cancellation_stops_guest_execution() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
            .await
            .unwrap();
        let mut state = runtime.state.lock().unwrap();
        let entry = state.alloc(16).unwrap();
        runtime
            .engine
            .guest()
            .mem_write(entry, &0x14000000u32.to_le_bytes())
            .unwrap();
        state.code.push((entry, entry + 4));
        let token = state.cancellation.clone();
        drop(state);
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            drop(token.guard());
        });
        let error = runtime
            .engine
            .start(entry, RETURN_PC, Duration::from_secs(2), 100_000_000)
            .unwrap_err();
        worker.join().unwrap();
        assert!(error.to_string().contains("Store request cancelled"));
    }
    #[tokio::test]
    #[ignore = "requires pinned Apple assets and ARM64 Unicorn; no account or network requests"]
    async fn live_store_vm_comparator_sort_is_stable_and_preserves_source() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
            .await
            .unwrap();
        let mut items = Vec::new();
        for text in ["b", "a", "b", "c"] {
            items.push(
                runtime
                    .new_object("NSString", Value::String(text.into()))
                    .unwrap(),
            );
        }
        let block = {
            let mut state = runtime.state.lock().unwrap();
            state
                .host_block(
                    runtime.engine.guest(),
                    Arc::new(|state, guest| {
                        let first = state.arg(guest, 1)?;
                        let second = state.arg(guest, 2)?;
                        guest.reg_write(reg::X0, first)?;
                        guest.reg_write(reg::X0 + 2, second)?;
                        state.message(guest, first, "compare:", false)
                    }),
                )
                .unwrap()
        };
        for (input, expected) in [
            (items.clone(), vec![items[1], items[0], items[2], items[3]]),
            (Vec::new(), Vec::new()),
            (vec![items[0]], vec![items[0]]),
            (
                vec![items[3], items[2], items[1]],
                vec![items[1], items[2], items[3]],
            ),
        ] {
            let array = runtime
                .new_object("NSArray", Value::Array(input.clone()))
                .unwrap();
            let result = runtime
                .invoke(array, "sortedArrayUsingComparator:", &[block])
                .unwrap();
            assert_ne!(array, result);
            let state = runtime.state.lock().unwrap();
            assert!(
                matches!(&state.objects[&result].value,Value::Array(values)if values==&expected)
            );
            assert!(matches!(&state.objects[&array].value,Value::Array(values)if values==&input));
        }
        let oversized = runtime
            .new_object("NSArray", Value::Array(vec![items[0]; 4097]))
            .unwrap();
        assert!(
            runtime
                .invoke(oversized, "sortedArrayUsingComparator:", &[block])
                .unwrap_err()
                .to_string()
                .contains("sort exceeds runtime budget")
        );
    }
    #[tokio::test]
    #[ignore = "requires local pinned Apple assets and ARM64 Unicorn; no account or network requests"]
    async fn live_store_vm_runs_apple_buy_parameters() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
            .await
            .unwrap();
        let object = runtime.new_object("AMSBuyParams", Value::Null).unwrap();
        let object = runtime.invoke(object, "init", &[]).unwrap();
        let value = runtime
            .new_object("NSString", Value::String("1234".into()))
            .unwrap();
        let key = runtime
            .new_object("NSString", Value::String("salableAdamId".into()))
            .unwrap();
        runtime
            .invoke(object, "setParameter:forKey:", &[value, key])
            .unwrap();
        let value = runtime.invoke(object, "parameterForKey:", &[key]).unwrap();
        assert_eq!(
            runtime.export(value).unwrap(),
            plist::Value::String("1234".into())
        );
    }

    #[tokio::test]
    #[ignore = "requires local pinned Apple assets and ARM64 Unicorn; synthetic account only"]
    async fn live_store_vm_creates_ephemeral_account() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
            .await
            .unwrap();
        let account = runtime
            .ephemeral_account(Some(("42", "fixture-token", "143441-1,29")))
            .unwrap();
        let dsid = runtime.invoke(account, "ams_DSID", &[]).unwrap();
        assert_eq!(
            runtime.export(dsid).unwrap(),
            plist::Value::Integer(42.into())
        );
    }

    #[tokio::test]
    #[ignore = "requires local pinned Apple assets and ARM64 Unicorn; no account or network requests"]
    async fn live_store_vm_dispatch_callback_restores_caller() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
            .await
            .unwrap();
        let guest = runtime.engine.guest();
        let mut state = runtime.state.lock().unwrap();
        let queue = state.new_object(guest, "HostQueue", Value::Null).unwrap();
        let block = state
            .host_block(
                guest,
                Arc::new(|state, guest| {
                    assert_ne!(state.current_queue, 0);
                    state.set(guest, 55)
                }),
            )
            .unwrap();
        state.pending.push_back((block, queue));
        guest.reg_write(reg::LR, RETURN_PC).unwrap();
        state
            .run_pending(
                guest,
                Box::new(|state, guest| {
                    assert_eq!(guest.reg_read(reg::X0)?, 55);
                    state.set(guest, 123)
                }),
            )
            .unwrap();
        let entry = guest.reg_read(reg::PC).unwrap();
        drop(state);
        runtime
            .engine
            .start(entry, RETURN_PC, Duration::from_secs(5), 1000)
            .unwrap();
        assert_eq!(runtime.engine.guest().reg_read(reg::X0).unwrap(), 123);
        assert_eq!(runtime.state.lock().unwrap().current_queue, 0);
    }

    #[tokio::test]
    #[ignore = "requires pinned assets and ARM64 Unicorn; HTTP response is synthetic"]
    async fn live_store_framework_get_runs_session_and_transport() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
            .await
            .unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let response = runtime
            .execute(Request {
                url: "https://buy.itunes.apple.com/request".parse().unwrap(),
                method: reqwest::Method::GET,
                operation: "lookup".into(),
                headers: Default::default(),
                parameters: None,
                body: vec![],
                bag: None,
                hardware_id: vec![0, 1, 2, 3, 4, 5],
                signer: None,
                format: "",
                stream: false,
                raw: true,
                no_redirects: false,
                transport: Arc::new(move |request| {
                    observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    assert_eq!(request.method(), reqwest::Method::GET);
                    Ok(Response {
                        status: reqwest::StatusCode::OK,
                        headers: Default::default(),
                        body: b"fixture-value".to_vec(),
                        stream: None,
                    })
                }),
            })
            .unwrap();
        assert_eq!(response.body, b"fixture-value");
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    #[ignore = "requires pinned assets and ARM64 Unicorn; HTTP response is synthetic"]
    async fn live_store_framework_encoded_post_and_decoding() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        for gzip in [false, true] {
            let mut runtime =
                Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
                    .await
                    .unwrap();
            let parameters =
                plist::Dictionary::from_iter([("fixture", plist::Value::String("value".into()))]);
            let response=runtime.execute(Request {
            url:"https://buy.itunes.apple.com/request".parse().unwrap(),method:reqwest::Method::POST,operation:"download".into(),
            headers:Default::default(),parameters:Some(parameters.clone()),body:vec![],bag:None,hardware_id:vec![0,1,2,3,4,5],signer:None,
            format:"",stream:false,raw:false,no_redirects:false,
            transport:Arc::new(move |request| {
                assert_eq!(request.method(),reqwest::Method::POST);
                let body=request.body().unwrap().as_bytes().unwrap();
                let value=plist::Value::from_reader(std::io::Cursor::new(body)).unwrap();
                assert_eq!(value.as_dictionary(),Some(&parameters));
                let mut headers=reqwest::header::HeaderMap::new();headers.insert(reqwest::header::CONTENT_TYPE,"application/x-apple-plist".parse().unwrap());
                let mut body=b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>success</key><true/></dict></plist>".to_vec();
                if gzip{use std::io::Write;let mut encoder=flate2::write::GzEncoder::new(Vec::new(),flate2::Compression::default());encoder.write_all(&body).unwrap();body=encoder.finish().unwrap();headers.insert(reqwest::header::CONTENT_ENCODING,"gzip".parse().unwrap());}
                Ok(Response {status:reqwest::StatusCode::OK,headers,body,stream:None})
            }),
        }).unwrap();
            let value = plist::Value::from_reader(std::io::Cursor::new(response.body)).unwrap();
            assert_eq!(
                value.as_dictionary().unwrap().get("success"),
                Some(&plist::Value::Boolean(true))
            );
        }
    }

    #[tokio::test]
    #[ignore = "requires pinned assets and ARM64 Unicorn; credentials and responses are synthetic"]
    async fn live_store_framework_purchase_and_authentication() {
        struct Signer;
        impl crate::sap::ActionSigner for Signer {
            fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, ClientError> {
                assert!(!bytes.is_empty());
                Ok(vec![1, 2, 3])
            }
        }
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        for (operation, finance, numeric) in [
            ("authenticate", false, false),
            ("purchase", false, false),
            ("authenticate", true, false),
            ("purchase", true, false),
            ("purchase", false, true),
        ] {
            let mut runtime =
                Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
                    .await
                    .unwrap();
            let mut parameters = plist::Dictionary::from_iter(
                [
                    ("salableAdamId", "1234"),
                    ("pricingParameters", "STDQ"),
                    ("price", "0"),
                    ("productType", "C"),
                    ("appleId", "test@example.com"),
                    ("password", "test"),
                ]
                .map(|(k, v)| (k, plist::Value::String(v.into()))),
            );
            if numeric {
                parameters.insert("price".into(), plist::Value::Integer(0.into()));
                parameters.insert("salableAdamId".into(), plist::Value::Integer(1234.into()));
            }
            let mut headers = reqwest::header::HeaderMap::new();
            for (k, v) in [
                ("X-Dsid", "123456"),
                ("X-Token", "test-token"),
                ("X-Apple-Store-Front", "143441-1,29"),
            ] {
                headers.insert(
                    k.parse::<reqwest::header::HeaderName>().unwrap(),
                    v.parse().unwrap(),
                );
            }
            let response=runtime.execute(Request{
                url:"https://buy.itunes.apple.com/request".parse().unwrap(),method:reqwest::Method::POST,operation:operation.into(),
                headers,parameters:Some(parameters),body:vec![],bag:Some(plist::Dictionary::from_iter([("buyProduct",plist::Value::String("https://buy.itunes.apple.com/request".into()))])),hardware_id:vec![0,1,2,3,4,5],signer:Some(Arc::new(Signer)),
                format:"",stream:false,raw:false,no_redirects:false,
                transport:Arc::new(move|request|{
                    assert_eq!(request.method(),reqwest::Method::POST);assert_eq!(request.headers()["X-Apple-ActionSignature"],"AQID");
                    let mut headers=reqwest::header::HeaderMap::new();headers.insert(reqwest::header::CONTENT_TYPE,"application/x-apple-plist".parse().unwrap());
                    let body=if finance{b"<plist version=\"1.0\"><dict><key>failureType</key><string>2034</string><key>customerMessage</key><string>fixture-value</string></dict></plist>".as_slice()}else{b"<plist version=\"1.0\"><dict><key>status</key><integer>0</integer></dict></plist>".as_slice()};
                    Ok(Response{status:reqwest::StatusCode::OK,headers,body:body.to_vec(),stream:None})
                }),
            }).unwrap_or_else(|e|panic!("{operation}: {e}"));
            assert_eq!(response.status, reqwest::StatusCode::OK);
            if finance {
                let value = plist::Value::from_reader(std::io::Cursor::new(response.body)).unwrap();
                assert_eq!(
                    value
                        .as_dictionary()
                        .unwrap()
                        .get("failureType")
                        .and_then(plist::Value::as_string),
                    Some("2034")
                );
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires pinned assets and ARM64 Unicorn; HTTP responses are synthetic"]
    async fn live_store_framework_json_and_redirects() {
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        let mut runtime = Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
            .await
            .unwrap();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let response = runtime
            .execute(Request {
                url: "https://buy.itunes.apple.com/start".parse().unwrap(),
                method: reqwest::Method::GET,
                operation: "lookup".into(),
                headers: Default::default(),
                parameters: None,
                body: vec![],
                bag: None,
                hardware_id: vec![0, 1, 2, 3, 4, 5],
                signer: None,
                format: "json",
                stream: false,
                raw: false,
                no_redirects: false,
                transport: Arc::new(move |request| {
                    let count = observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let mut headers = reqwest::header::HeaderMap::new();
                    if count == 0 {
                        headers.insert(reqwest::header::LOCATION, "/finish".parse().unwrap());
                        return Ok(Response {
                            status: reqwest::StatusCode::FOUND,
                            headers,
                            body: vec![],
                            stream: None,
                        });
                    }
                    assert_eq!(count, 1);
                    assert_eq!(request.url().path(), "/finish");
                    headers.insert(
                        reqwest::header::CONTENT_TYPE,
                        "application/json".parse().unwrap(),
                    );
                    Ok(Response {
                        status: reqwest::StatusCode::OK,
                        headers,
                        body: br#"{"results":[{"bundleId":"fixture-value"}],"extra":null}"#
                            .to_vec(),
                        stream: None,
                    })
                }),
            })
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(value["results"][0]["bundleId"], "fixture-value");
        assert!(value["extra"].is_null());
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    #[ignore = "requires pinned assets and ARM64 Unicorn; authentication and HTTP responses are synthetic"]
    async fn live_store_framework_authentication_redirect_keeps_signed_post() {
        struct Signer;
        impl crate::sap::ActionSigner for Signer {
            fn sign(&self, bytes: &[u8]) -> Result<Vec<u8>, ClientError> {
                use sha2::Digest;
                Ok(sha2::Sha256::digest(bytes).to_vec())
            }
        }
        let bundle = crate::sap::assets::macos27::load_verified(
            &crate::sap::assets::macos27::cache_directory().unwrap(),
        )
        .unwrap();
        for no_redirects in [false, true] {
            let mut runtime =
                Runtime::open(&AppleClient::for_tests(), &bundle.apple_media_services)
                    .await
                    .unwrap();
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let observed = calls.clone();
            let parameters = plist::Dictionary::from_iter([
                (
                    "appleId",
                    plist::Value::String("fixture@example.com".into()),
                ),
                ("password", plist::Value::String("fixture".into())),
                ("attempt", plist::Value::String("1".into())),
            ]);
            let response=runtime.execute(Request{url:"https://buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate".parse().unwrap(),method:reqwest::Method::POST,operation:"authenticate".into(),format:"plist",headers:Default::default(),parameters:Some(parameters),body:vec![],bag:None,hardware_id:vec![0,1,2,3,4,5],signer:Some(Arc::new(Signer)),stream:false,raw:false,no_redirects,
                transport:Arc::new(move|request|{use sha2::Digest;use base64::Engine;assert_eq!(request.method(),reqwest::Method::POST);let body=request.body().unwrap().as_bytes().unwrap();assert_eq!(request.headers()["X-Apple-ActionSignature"],base64::engine::general_purpose::STANDARD.encode(sha2::Sha256::digest(body)));let count=observed.fetch_add(1,std::sync::atomic::Ordering::SeqCst);let mut headers=reqwest::header::HeaderMap::new();
                    if count==0{headers.insert(reqwest::header::LOCATION,"https://p12-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate".parse().unwrap());Ok(Response{status:reqwest::StatusCode::TEMPORARY_REDIRECT,headers,body:vec![],stream:None})}else{assert_eq!(count,1);headers.insert(reqwest::header::CONTENT_TYPE,"application/x-apple-plist".parse().unwrap());Ok(Response{status:reqwest::StatusCode::OK,headers,body:b"<plist version=\"1.0\"><dict><key>status</key><integer>0</integer></dict></plist>".to_vec(),stream:None})}
                })}).unwrap();
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                if no_redirects { 1 } else { 2 }
            );
            assert_eq!(
                response.status,
                if no_redirects {
                    reqwest::StatusCode::TEMPORARY_REDIRECT
                } else {
                    reqwest::StatusCode::OK
                }
            );
        }
    }
}
