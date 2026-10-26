use super::*;

impl State {
    pub(super) fn notification_message(
        &mut self,
        guest: Guest<'_>,
        receiver: u64,
        class: &str,
        selector: &str,
        meta: bool,
    ) -> Result<bool, ClientError> {
        if meta && class == "NSNotificationCenter" && selector == "defaultCenter" {
            if self.notification_center == 0 {
                self.notification_center = self.new_object(guest, class, Value::Null)?;
            }
            self.set(guest, self.notification_center)?;
            return Ok(true);
        }
        if class == "NSNotification" && ["name", "object", "userInfo"].contains(&selector) {
            self.set(
                guest,
                self.objects[&receiver]
                    .properties
                    .get(selector)
                    .copied()
                    .unwrap_or(0),
            )?;
            return Ok(true);
        }
        if meta || class != "NSNotificationCenter" {
            return Ok(false);
        }
        match selector {
            "addObserver:selector:name:object:" => {
                let properties = HashMap::from([
                    ("observer".into(), self.arg(guest, 2)?),
                    ("selector".into(), self.arg(guest, 3)?),
                    ("name".into(), self.arg(guest, 4)?),
                    ("object".into(), self.arg(guest, 5)?),
                ]);
                let observer = self.new_object(guest, "HostObserver", Value::Null)?;
                self.objects.get_mut(&observer).unwrap().properties = properties;
                self.observers.insert(observer);
            }
            "removeObserver:" | "removeObserver:name:object:" => {
                let target = self.arg(guest, 2)?;
                let remove: Vec<_> = self
                    .observers
                    .iter()
                    .copied()
                    .filter(|id| {
                        *id == target
                            || self.objects[id].properties.get("observer") == Some(&target)
                    })
                    .collect();
                for id in remove {
                    self.observers.remove(&id);
                }
            }
            "postNotificationName:object:" | "postNotificationName:object:userInfo:" => {
                let name = self.arg(guest, 2)?;
                let object = self.arg(guest, 3)?;
                let info = if selector.ends_with("userInfo:") {
                    self.arg(guest, 4)?
                } else {
                    0
                };
                let notification = self.new_object(guest, "NSNotification", Value::Null)?;
                self.objects
                    .get_mut(&notification)
                    .unwrap()
                    .properties
                    .extend([
                        ("name".into(), name),
                        ("object".into(), object),
                        ("userInfo".into(), info),
                    ]);
                let observers: Vec<_> = self
                    .observers
                    .iter()
                    .map(|id| self.objects[id].properties.clone())
                    .collect();
                for observer in observers {
                    let filter = observer.get("name").copied().unwrap_or(0);
                    if filter != 0 && self.string(filter)? != self.string(name)? {
                        continue;
                    }
                    let filter = observer.get("object").copied().unwrap_or(0);
                    if filter != 0 && filter != object {
                        continue;
                    }
                    let target = observer["observer"];
                    let selector = self.cstring(guest, observer["selector"])?;
                    let block = self.host_block(
                        guest,
                        Arc::new(move |state, guest| {
                            state.delegate_call(
                                guest,
                                target,
                                &selector,
                                vec![notification],
                                Box::new(|state, guest| state.set(guest, 0)),
                            )
                        }),
                    )?;
                    self.pending.push_back((block, 0));
                }
            }
            _ => return Ok(false),
        }
        self.set(guest, 0)?;
        Ok(true)
    }
}
