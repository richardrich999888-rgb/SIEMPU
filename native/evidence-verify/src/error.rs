//! Verification error type.

use crate::canonical::CanonicalError;
use std::fmt;

/// A verification failure. Every failure is fatal: the verifier never returns a partial result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    /// Message written to the error report.
    pub message: String,
    /// True when `message` is byte-identical to the reference verifier's message for the same
    /// input. False for implementation-specific input errors (JSON syntax, file access, curve
    /// point decoding) whose wording legitimately differs between implementations.
    pub parity: bool,
}

impl VerifyError {
    /// A protocol-level rejection whose message is fixed by the specification.
    #[must_use]
    pub fn protocol(message: &str) -> Self {
        Self {
            message: message.to_owned(),
            parity: true,
        }
    }

    /// An implementation-specific input rejection.
    #[must_use]
    pub fn input(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            parity: false,
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VerifyError {}

impl From<CanonicalError> for VerifyError {
    fn from(error: CanonicalError) -> Self {
        Self::protocol(error.0)
    }
}
