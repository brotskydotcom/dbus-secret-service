# dbus-secret-service

This crate is a knock-off of the
[hwchen/secret-service](https://crates.io/crates/secret-service)
crate, which is currently at version 4
and uses
[zbus](https://crates.io/crates/zbus)
to access the secret service. The basic
collection, item and search APIs in this
crate are meant to work the same as the
blocking APIs in the zbus-based crate.

Why do a knock-off? So that folks who write
synchronous Rust apps that access the secret
service (typically through the
[hwchen/keyring](https://crates.io/crates/keyring)
crate) are not required to add an async
runtime. Because this knock-off uses lib-dbus,
it doesn't require an async runtime.

Why is this crate starting at version 4?
Since it's API is sync'd to a particular
version of the dbus-based crate, I figured
it would be clearest if it's version
number was sync'd as well.

### Basic Usage

Just in case it wasn't clear from the above,
in order to use this crate on a given machine,
you will need to have `libdbus` installed.
Most do, but if yours doesn't then
search your package manager for `dbus`.

In `Cargo.toml`:

```
[dependencies]
dbus-secret-service = "4"
```

In source code (below example is for --bin, not --lib)

```rust
use secret_service::SecretService;
use secret_service::EncryptionType;
use std::error::Error;

fn main() -> Result<(), Box<Error>> {

    // initialize secret service (dbus connection and encryption session)
    let ss = SecretService::new(EncryptionType::Dh)?;

    // get default collection
    let collection = ss.get_default_collection()?;

    //create new item
    collection.create_item(
        "test_label", // label
        vec![("test", "test_value")], // properties
        b"test_secret", //secret
        false, // replace item with same attributes
        "text/plain" // secret content type
    )?;

    // search items by properties
    let search_items = ss.search_items(
        vec![("test", "test_value")]
    )?;

    let item = search_items.get(0)?;

    // retrieve secret from item
    let secret = item.get_secret()?;
    assert_eq!(secret, b"test_secret");

    // delete item (deletes the dbus object, not the struct instance)
    item.delete()?;
}
```

### Functionality

- SecretService: initialize dbus, create plain/encrypted session.
- Collections: create, delete, search.
- Items: create, delete, search, get/set secret.

### Changelog

v4.0.0: first release, same API as secret-service v4.0.
Only functional difference is that we don't support
secret types other than `text/plain`.

## License

The copyright to all material in this repository belongs to
the collective of contributors who have checked material in to
this repository.

All material is this repository is licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise,
any contribution intentionally submitted
for inclusion in the work by you,
as defined in the Apache-2.0 license,
shall be dual licensed as above,
without any additional terms or conditions.
