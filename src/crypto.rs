// Copyright 2026 Grzegorz Blach
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Signature verification, backed by aws-lc-rs, graviola or RustCrypto depending on the enabled
//! feature.
//!
//! Several can be enabled at once, because rust-crypto is a default feature and Cargo merges the
//! features every dependent asks for. aws-lc-rs then wins over graviola, and both win over
//! rust-crypto, since asking for them is an explicit choice a dependent can make without turning
//! off the defaults.

#[cfg(not(any(feature = "aws-lc-rs", feature = "graviola", feature = "rust-crypto")))]
compile_error!(
    "passki needs a crypto backend: enable the `aws-lc-rs`, `graviola` or `rust-crypto` feature"
);

#[cfg(feature = "aws-lc-rs")]
mod aws_lc;
#[cfg(feature = "aws-lc-rs")]
pub(crate) use aws_lc::*;

#[cfg(all(feature = "graviola", not(feature = "aws-lc-rs")))]
mod graviola;
#[cfg(all(feature = "graviola", not(feature = "aws-lc-rs")))]
pub(crate) use graviola::*;

#[cfg(all(
    feature = "rust-crypto",
    not(any(feature = "aws-lc-rs", feature = "graviola"))
))]
mod rust_crypto;
#[cfg(all(
    feature = "rust-crypto",
    not(any(feature = "aws-lc-rs", feature = "graviola"))
))]
pub(crate) use rust_crypto::*;
