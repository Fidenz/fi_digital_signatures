#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

/// Algorithm and algorithm family constants
pub mod algorithms;
/// Signing and verifying for each algorithm
pub mod crypto;
/// Constant error values
pub mod errors;
/// JWT token management
pub mod jwt;
pub mod log;
/// Content signer
pub mod signer;
/// Signature verifier
pub mod verifier;
