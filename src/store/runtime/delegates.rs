use super::*;

impl State {
    fn subclass(&mut self, guest: Guest<'_>, name: &str, base: &str) -> Result<(), ClientError> {
        if self.classes.contains_key(name) {
            return Ok(());
        }
        let index = *self
            .classes
            .get(base)
            .ok_or_else(|| failure("missing Store superclass"))?;
        let size = self.class_definitions[index].size;
        let address = self.alloc(16)?;
        guest.mem_write(address, &[0; 16])?;
        self.classes
            .insert(name.into(), self.class_definitions.len());
        self.class_names.insert(address, name.into());
        self.class_definitions.push(profile::format::Class {
            meta_address: 0,
            name: name.into(),
            address,
            superclass: base.into(),
            size,
            ivars: HashMap::new(),
            methods: Vec::new(),
        });
        Ok(())
    }
    fn host_method(
        &mut self,
        guest: Guest<'_>,
        class: &str,
        selector: &str,
        callback: HostCall,
    ) -> Result<(), ClientError> {
        let block = self.host_block(guest, callback)?;
        self.methods.insert(
            (class.into(), selector.into(), false),
            read64(guest, block + 16)?,
        );
        Ok(())
    }
}

impl Runtime {
    pub(super) fn interactive_delegate(&mut self) -> Result<u64, ClientError> {
        let guest = self.engine.guest();
        let mut state = self
            .state
            .lock()
            .map_err(|_| failure("Store state lock poisoned"))?;
        let name = "IPAToolStoreDelegate";
        state.subclass(guest, name, "NSObject")?;
        for (index, selector) in [
            "AMSURLSession:task:handleAuthenticateRequest:completion:",
            "AMSURLSession:task:handleDialogRequest:completion:",
        ]
        .into_iter()
        .enumerate()
        {
            state.host_method(
                guest,
                name,
                selector,
                Arc::new(move |state, guest| {
                    let completion = state.arg(guest, 5)?;
                    let domain = state.new_object(
                        guest,
                        "NSString",
                        Value::String("IPAToolStoreInteraction".into()),
                    )?;
                    let code =
                        state.new_object(guest, "NSNumber", Value::Integer(index as i64 + 1))?;
                    let info = state.new_object(
                        guest,
                        "NSDictionary",
                        Value::Dictionary(HashMap::new()),
                    )?;
                    let error = state.new_object(
                        guest,
                        "NSError",
                        Value::Dictionary(HashMap::from([
                            ("domain".into(), domain),
                            ("code".into(), code),
                            ("userInfo".into(), info),
                        ])),
                    )?;
                    state.callback_then(
                        guest,
                        read64(guest, completion + 16)?,
                        &[completion, 0, error],
                        Box::new(|state, guest| state.set(guest, 0)),
                    )
                }),
            )?;
        }
        state.new_object(guest, name, Value::Null)
    }

    pub(super) fn purchase_encoder(&mut self, info: u64, bag: u64) -> Result<u64, ClientError> {
        {
            let guest = self.engine.guest();
            let mut state = self
                .state
                .lock()
                .map_err(|_| failure("Store state lock poisoned"))?;
            let name = "IPAToolPurchaseRequestEncoder";
            state.subclass(guest, name, "AMSPurchaseRequestEncoder")?;
            let selector = "requestByEncodingRequestAndReturnSigningErrors:parameters:";
            let implementation = state.lookup("AMSURLRequestEncoder", selector, false);
            if implementation == 0 {
                return Err(failure("missing base Store purchase encoder"));
            }
            state.host_method(
                guest,
                name,
                selector,
                Arc::new(move |state, guest| {
                    let receiver = state.arg(guest, 0)?;
                    let request = state.arg(guest, 2)?;
                    let parameters = state.arg(guest, 3)?;
                    state.delegate_call(
                        guest,
                        receiver,
                        "setAnisetteType:",
                        vec![0],
                        Box::new(move |state, guest| {
                            state.delegate_call(
                                guest,
                                receiver,
                                "setMescalType:",
                                vec![0],
                                Box::new(move |state, guest| {
                                    state.delegate_call(
                                        guest,
                                        request,
                                        "properties",
                                        vec![],
                                        Box::new(move |state, guest| {
                                            let properties = state.arg(guest, 0)?;
                                            state.delegate_call(
                                                guest,
                                                properties,
                                                "setAnisetteType:",
                                                vec![0],
                                                Box::new(move |state, guest| {
                                                    state.delegate_call(
                                                        guest,
                                                        properties,
                                                        "setMescalType:",
                                                        vec![0],
                                                        Box::new(move |state, guest| {
                                                            state.delegate_call(
                                                                guest,
                                                                properties,
                                                                "setDisableLoadURLMetrics:",
                                                                vec![1],
                                                                Box::new(move |state, guest| {
                                                                    state.delegate_call(
                                                                        guest,
                                                                        receiver,
                                                                        "setDisableLoadURLMetrics:",
                                                                        vec![1],
                                                                        Box::new(
                                                                            move |state, guest| {
                                                                                let method = state
                                                                                    .selector(
                                                                                        guest,
                                                                                        selector,
                                                                                    )?;
                                                                                state.callback_then(
                                                                                    guest,
                                                                                    implementation,
                                                                                    &[
                                                                                        receiver,
                                                                                        method,
                                                                                        request,
                                                                                        parameters,
                                                                                    ],
                                                                                    Box::new(
                                                                                        |_, _| {
                                                                                            Ok(())
                                                                                        },
                                                                                    ),
                                                                                )
                                                                            },
                                                                        ),
                                                                    )
                                                                }),
                                                            )
                                                        }),
                                                    )
                                                }),
                                            )
                                        }),
                                    )
                                }),
                            )
                        }),
                    )
                }),
            )?;
        }
        let encoder = self.new_object("IPAToolPurchaseRequestEncoder", Value::Null)?;
        self.invoke(encoder, "initWithPurchaseInfo:bag:", &[info, bag])
    }
}
