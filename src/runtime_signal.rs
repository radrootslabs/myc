//! Binary-owned process-signal injection for the Myc daemon.

use core::{fmt, future::Future, pin::Pin};

/// One normalized process signal supplied by the Myc binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycProcessSignal {
    Interrupt,
    #[cfg(unix)]
    Terminate,
}

impl MycProcessSignal {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            #[cfg(unix)]
            Self::Terminate => "terminate",
        }
    }
}

impl fmt::Display for MycProcessSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Boxed wait returned by a binary-owned signal source.
pub type MycProcessSignalFuture<'a> =
    Pin<Box<dyn Future<Output = Option<MycProcessSignal>> + Send + 'a>>;

/// Process-signal source installed only by the executable boundary.
pub trait MycProcessSignalSource: Send {
    fn next_signal(&mut self) -> MycProcessSignalFuture<'_>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_signal_names_are_stable() {
        assert_eq!(MycProcessSignal::Interrupt.as_str(), "interrupt");
        assert_eq!(MycProcessSignal::Interrupt.to_string(), "interrupt");
        #[cfg(unix)]
        assert_eq!(MycProcessSignal::Terminate.as_str(), "terminate");
    }
}
