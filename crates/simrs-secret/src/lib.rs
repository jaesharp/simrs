//! Zero-cost compile-time secret data protection.
//!
//! This crate provides [`Secret<T>`] and [`CtOption<T>`], wrappers that
//! enforce constant-time-only operations on secret data at compile time.
//!
//! # `Secret<T>`
//!
//! A zero-cost wrapper that restricts a value to constant-time operations.
//! `Secret<T>` deliberately omits `PartialEq`, `Display`, `Hash`, `Deref`,
//! and other traits that would allow non-CT operations on the inner value.
//! The only way to compare secrets is via [`CtEq::ct_eq`], and the only
//! way to extract the inner value is [`Secret::declassify`].
//!
//! ```
//! use simrs_secret::Secret;
//! use simrs_consttime::CtEq;
//!
//! let a = Secret::new([0xABu8; 16]);
//! let b = Secret::new([0xABu8; 16]);
//!
//! // CT comparison works:
//! assert!(a.ct_eq(&b).into_bool());
//!
//! // Extract when needed (explicit acknowledgement):
//! let raw: [u8; 16] = a.declassify();
//! ```
//!
//! # `CtOption<T>`
//!
//! A constant-time option type where the discriminant is a [`CtBool`], not
//! a Rust `bool`. The value is always present in memory, avoiding
//! cache-timing leaks from allocation/deallocation patterns.
//!
//! # `no_std`, `no_alloc`
//!
//! This crate uses no heap. All operations are performed on stack values.
#![no_std]
#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

mod ctoption;
mod secret;

pub use ctoption::CtOption;
pub use secret::Secret;
