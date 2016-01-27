#![feature(box_patterns)]
#![allow(dead_code)]
// requires ldbus dev library
// on ubuntu, libdbus-1-dev

// TODO:
// crypto
// handle drop for delete methods?
// lib.rs especially needs to be rewritten
//
// factor out handling mapping paths to Item
// Remove all matches for option and result!
// properly return path for delete actions?
// Move similar methods to common interface: locking, attributes, del, label?
// Reorg imports, format function params to be consistent
// Then check that all functions return Collection or Item instead
// of Path or MessageItem
// Refactor Dict
// Refactor to make str and String function params consistent
// Redo tests now that full range of api is implemented
// Return using map when possible instead of matching
// Abstract prompts for creating items. Can I abstract other prompts?
// in all tests, make sure that check for structs
// Change all MessageItems initialization to use MessageItem::from()

extern crate crypto;
extern crate dbus;
extern crate rand;

pub mod collection;
pub mod error;
pub mod item;
mod util;
mod ss;
mod session;

use std::rc::Rc;

use collection::Collection;
use util::{Interface, exec_prompt};
use session::Session;
use ss::{
    SS_DBUS_NAME,
    SS_INTERFACE_SERVICE,
    SS_PATH,
};

use dbus::{
    BusName,
    BusType,
    Connection,
    Error,
    MessageItem,
    Path,
};
use dbus::Interface as InterfaceName;
use dbus::MessageItem::{
    Array,
    DictEntry,
    ObjectPath,
    Str,
    Variant,
};

// Secret Service Struct

#[derive(Debug)]
pub struct SecretService {
    bus: Rc<Connection>,
    session: Session,
    service_interface: Interface,
}

impl SecretService {
    pub fn new() -> Result<Self, dbus::Error> {
        let bus = Rc::new(try!(Connection::get_private(BusType::Session)));
        let session = try!(Session::new(&bus));
        let service_interface = Interface::new(
            bus.clone(),
            BusName::new(SS_DBUS_NAME).unwrap(),
            Path::new(SS_PATH).unwrap(),
            InterfaceName::new(SS_INTERFACE_SERVICE).unwrap()
        );

        Ok(SecretService {
            bus: bus.clone(),
            session: session,
            service_interface: service_interface,
        })
    }

    pub fn get_all_collections(&self) -> Result<Vec<Collection>, Error> {
        let mut collections = Vec::new();
        if let Array(ref items, _) = try!(self.service_interface.get_props("Collections")) {
            for item in items {
                if let ObjectPath(ref path) = *item {
                    collections.push(Collection::new(
                        self.bus.clone(),
                        &self.session,
                        path.clone()
                    ));
                }
            }
        }
        Ok(collections)
    }

    pub fn get_collection_by_alias(&self, alias: &str) -> Result<Collection, Error>{
        let name = Str(alias.to_owned());

        let res = try!(self.service_interface.method("ReadAlias", vec![name]));
        if let ObjectPath(ref path) = res[0] {
            Ok(Collection::new(
                self.bus.clone(),
                &self.session,
                path.clone()
            ))
        } else {
            Err(Error::new_custom("SSError", "Didn't return an object path"))
        }

    }

    pub fn get_default_collection(&self) -> Result<Collection, Error> {
        self.get_collection_by_alias("default")
    }

    pub fn get_any_collection(&self) -> Result<Collection, Error> {
        // default first, then session, then first

        self.get_default_collection()
            .or_else(|_| {
                self.get_collection_by_alias("session")
            }).or_else(|_| {
                match try!(self.get_all_collections()).get(0) {
                    Some(collection) => Ok(collection.clone()),
                    _ => Err(Error::new_custom("SSError", "No collections found")),
                }
            })
    }

    pub fn create_collection(&self, label: &str, alias: &str) -> Result<Collection, Error> {
        let label = DictEntry(
            Box::new(Str("org.freedesktop.Secret.Collection.Label".to_owned())),
            Box::new(Variant(Box::new(Str(label.to_owned()))))
        );
        let label_type_sig = label.type_sig();
        let properties = Array(vec![label], label_type_sig);
        let alias = Str(alias.to_owned());

        let res = try!(self.service_interface.method("CreateCollection", vec![properties, alias]));

        let collection_path: Path = {
            // Get path of created object
            let created_object_path = try!(res
                .get(0)
                .ok_or(Error::new_custom("SSError", "Could not create Collection"))
            );
            let created_path: &Path = created_object_path.inner().unwrap();

            // Check if that path is "/", if so should execute a prompt
            if &**created_path == "/" {
                let prompt_object_path = try!(res
                    .get(1)
                    .ok_or(Error::new_custom("SSError", "Could not create Collection"))
                );
                let prompt_path: &Path = prompt_object_path.inner().unwrap();

                // Exec prompt and parse result
                let var_obj_path = try!(exec_prompt(self.bus.clone(), prompt_path.clone()));
                let obj_path: &MessageItem = var_obj_path.inner().unwrap();
                let path: &Path = obj_path.inner().unwrap();
                path.clone()
            } else {
                // if not, just return created path
                created_path.clone()
            }
        };

        Ok(Collection::new(
            self.bus.clone(),
            &self.session,
            collection_path.clone()
        ))
    }

    pub fn search_items(&self, attributes: Vec<(String, String)>) -> Result<Vec<MessageItem>, Error> {
        let attr_dict_entries: Vec<_> = attributes.iter().map(|&(ref key, ref value)| {
            let dict_entry = (Str(key.to_owned()), Str(value.to_owned()));
            MessageItem::from(dict_entry)
        }).collect();
        let attr_type_sig = DictEntry(
            Box::new(Str("".to_owned())),
            Box::new(Str("".to_owned()))
        ).type_sig();
        let attr_dbus_dict = Array(
            attr_dict_entries,
            attr_type_sig
        );

        // Method call to SearchItem
        let res = try!(self.service_interface.method("SearchItems", vec![attr_dbus_dict]));
        let mut unlocked = match res.get(0) {
            Some(ref array) => {
                match **array {
                    Array(ref v, _) => v.clone(),
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
        };
        let locked = match res.get(1) {
            Some(ref array) => {
                match **array {
                    Array(ref v, _) => v.clone(),
                    _ => Vec::new(),
                }
            }
            _ => Vec::new(),
        };
        unlocked.extend(locked);
        Ok(unlocked)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dbus::Path;

    #[test]
    fn should_create_secret_service() {
        SecretService::new().unwrap();
    }

    #[test]
    fn should_get_all_collections() {
        // Assumes that there will always be a default
        // collection
        let ss = SecretService::new().unwrap();
        let collections = ss.get_all_collections().unwrap();
        assert!(collections.len() >= 1);
        println!("{:?}", collections);
        println!("# of collections {:?}", collections.len());
        //assert!(false);
    }

    #[test]
    fn should_get_collection_by_alias() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_collection_by_alias("session");
    }

    #[test]
    fn should_get_default_collection() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_default_collection();
    }

    #[test]
    fn should_get_any_collection() {
        let ss = SecretService::new().unwrap();
        let _ = ss.get_any_collection().unwrap();
    }

    #[test]
    #[ignore]
    fn should_create_and_delete_collection() {
        let ss = SecretService::new().unwrap();
        let test_collection = ss.create_collection("Test", "").unwrap();
        println!("{:?}", test_collection);
        assert_eq!(
            test_collection.collection_path,
            Path::new("/org/freedesktop/secrets/collection/Test").unwrap()
        );
        test_collection.delete().unwrap();
    }

    #[test]
    // TODO: add an item and search
    fn should_search_items() {
        let ss = SecretService::new().unwrap();
        let items = ss.search_items(Vec::new()).unwrap();
        println!("{:?}", items);
        let items = ss.search_items(vec![("test".into(), "test".into())]).unwrap();
        println!("{:?}", items);
        assert!(false);
    }
}
