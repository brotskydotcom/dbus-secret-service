// Copyright 2016-2024 dbus-secret-service Contributors
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// Contains helpers for:
//   exec_prompt
//   interfaces
//   formatting secrets
//
//   Consider: What else should be in here? Should
//   formatting secrets be in crypto? Should interfaces
//   have their own module?

use std::fmt::Formatter;
use std::rc::Rc;

use dbus::{
    arg::messageitem::{MessageItem, Props},
    blocking::SyncConnection,
    strings::{BusName, Interface},
    Message,
    MessageType::Signal,
    Path,
};
use rand::{rngs::OsRng, Rng};
use MessageItem::{Array, Bool, Byte, ObjectPath, Str, Struct};

use crate::error::Error;
use crate::session::{encrypt, Session};
use crate::ss::{SS_DBUS_NAME, SS_INTERFACE_PROMPT};

#[derive(Clone)]
pub struct InterfaceWrapper<'a> {
    bus: Rc<SyncConnection>,
    name: BusName<'a>,
    path: Path<'a>,
    interface: Interface<'a>,
}

impl std::fmt::Debug for InterfaceWrapper {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceWrapper")
            .field("name", &self.name)
            .field("path", &self.path)
            .field("interface", &self.interface)
            .finish()
    }
}

impl InterfaceWrapper {
    pub fn new(bus: Rc<SyncConnection>, name: BusName, path: Path, interface: Interface) -> Self {
        InterfaceWrapper {
            bus,
            name,
            path,
            interface,
        }
    }

    pub fn method(
        &self,
        method_name: &str,
        args: Vec<MessageItem>,
    ) -> Result<Vec<MessageItem>, Error> {
        // Should never fail, so unwrap
        let mut m = Message::new_method_call(
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            method_name,
        )
        .unwrap();

        m.append_items(&args);

        // could use and_then?
        let r = self.bus.send_with_reply_and_block(m, 2000)?;

        Ok(r.get_items())
    }

    pub fn get_props(&self, prop_name: &str) -> Result<MessageItem, Error> {
        let p = Props::new(
            &self.bus,
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            2000,
        );

        Ok(p.get(prop_name)?)
    }

    pub fn set_props(&self, prop_name: &str, value: MessageItem) -> Result<(), Error> {
        let p = Props::new(
            &self.bus,
            self.name.clone(),
            self.path.clone(),
            self.interface.clone(),
            2000,
        );

        Ok(p.set(prop_name, value)?)
    }
}

pub fn format_secret(
    session: &Session,
    secret: &[u8],
    content_type: &str,
) -> Result<MessageItem, Error> {
    if session.is_encrypted() {
        let mut rng = OsRng {};
        let mut aes_iv = [0; 16];
        rng.fill(&mut aes_iv);

        let encrypted_secret = encrypt(secret, &session.get_shared_key(), &aes_iv)?;

        // Construct secret struct
        // (These are all straight conversions, can't fail.
        let object_path = ObjectPath(session.object_path.clone());
        let parameters = MessageItem::from(&aes_iv[..]);
        // Construct an array, even if it's empty
        let value_dbus = MessageItem::from(&encrypted_secret[..]);
        let content_type = Str(content_type.to_owned());

        Ok(Struct(vec![
            object_path,
            parameters,
            value_dbus,
            content_type,
        ]))
    } else {
        // just Plain for now
        let object_path = ObjectPath(session.object_path.clone());
        let parameters = Array(vec![], Byte(0u8).type_sig());
        let value_dbus = MessageItem::from(secret);
        let content_type = Str(content_type.to_owned());

        Ok(Struct(vec![
            object_path,
            parameters,
            value_dbus,
            content_type,
        ]))
    }
}

pub fn exec_prompt(bus: Rc<SyncConnection>, prompt: Path) -> Result<MessageItem, Error> {
    let prompt_interface = InterfaceWrapper::new(
        bus.clone(),
        BusName::new(SS_DBUS_NAME).unwrap(),
        prompt,
        Interface::new(SS_INTERFACE_PROMPT).unwrap(),
    );
    prompt_interface.method("Prompt", vec![Str("".to_owned())])?;

    // check to see if prompt is dismissed or accepted
    // TODO: Find a better way to do this.
    // Also, should I return the paths in the result?
    for event in bus.iter(5000) {
        if let Signal(message) = event {
            //println!("Incoming Signal {:?}", message);
            let items = message.get_items();
            if let Some(&Bool(dismissed)) = items.get(0) {
                //println!("Was prompt dismissed? {:?}", dismissed);
                if dismissed {
                    return Err(Error::Prompt);
                }
            }
            if let Some(&ref result) = items.get(1) {
                return Ok(result.clone());
            }
        }
    }
    Err(Error::Prompt)
}
