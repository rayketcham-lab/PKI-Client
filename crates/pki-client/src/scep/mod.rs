//! SCEP Client Implementation (RFC 8894)
//!
//! This module provides a client for Simple Certificate Enrollment Protocol (SCEP),
//! a legacy but widely-used protocol for certificate enrollment, particularly for
//! network devices and MDM systems.

mod client;
mod types;

pub use client::ScepClient;
