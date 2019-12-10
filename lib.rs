// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Enum variants in rust are customarily camel case, but bindgen will leave the original names
// intact.
#![allow(non_camel_case_types)]

// Generated with `bindgen --default-enum-style rust --whitelist-function '^minijail_.*' \
// --whitelist-var '^MINIJAIL_.*' --output libminijail.rs libminijail.h`.
mod libminijail;
pub use crate::libminijail::*;
