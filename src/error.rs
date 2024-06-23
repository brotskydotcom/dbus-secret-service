// Copyright 2016-2024 dbus-secret-service Contributors
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

// implement custom errors
//
// Classes of errors:
// - Dbus (IO, validation)
// - crypto
// - parsing dbus output (dbus returns unrecognizable output). Sometimes it's
//     for if the index exists in the results vector, sometimes it's for whether
//     the value being parsed at that index is the right type. Along these lines
//     I'm currently using unwrap() for converting types, should these also return
//     Result?
//
//     Almost all custom errors are of this type. It's mostly an internal error,
//     unexpected behavior indicates something very wrong, so should it panic? Or
//     is it still better to bubble up?
// - locked (currently custom dbus error)
// - prompt dismissed (not an error?) (currently custom dbus error)

use std::error;
use std::fmt;

use dbus;

#[derive(Debug)]
pub enum Error {
    Crypto(String),
    Dbus(dbus::Error),
    Locked,
    NoResult,
    Parse,
    Prompt,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            // crypto error does not implement Display
            Error::Crypto(_) => write!(f, "Crypto error: Invalid Length or Padding"),
            Error::Dbus(ref err) => write!(f, "Dbus error: {}", err),
            Error::Locked => write!(f, "SS Error: object locked"),
            Error::NoResult => write!(f, "SS error: result not returned from SS API"),
            Error::Parse => write!(f, "SS error: could not parse Dbus output"),
            Error::Prompt => write!(f, "SS error: prompt dismissed"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Crypto(_) => "crypto: Invalid Length or Padding",
            Error::Dbus(ref err) => &err.to_string(),
            Error::Locked => "Object locked",
            Error::NoResult => "Result not returned from Secret Service API",
            Error::Parse => "Error parsing Dbus output",
            Error::Prompt => "Prompt Dismissed",
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match *self {
            Error::Dbus(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<dbus::Error> for Error {
    fn from(err: dbus::Error) -> Error {
        Error::Dbus(err)
    }
}
