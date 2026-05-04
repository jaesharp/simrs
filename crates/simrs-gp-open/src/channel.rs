//! Logical channel management.
//!
//! Derived from GP 2.1.1 clause 9.5 (verified there); GP 2.3.1
//! retains the four-channel model in Chapter 6. Cross-references
//! ETSI TS 102 221 § 8.6 for MANAGE CHANNEL semantics.
//!
//! The GP card supports up to 4 logical channels (basic channel 0 + 3
//! supplementary channels 1-3). Each channel independently tracks which
//! applet is currently selected.

/// State of a single logical channel.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel is closed (not available for use).
    #[default]
    Closed,
    /// Channel is open. `selected_applet` is the registry index of the
    /// currently selected applet on this channel, or `None` if no applet
    /// is selected (ISD receives commands by default).
    Open {
        /// Index into the applet registry of the currently selected applet.
        selected_applet: Option<u8>,
    },
}

impl ChannelState {
    /// Create an open channel with no applet selected.
    pub const fn open_default() -> Self {
        Self::Open {
            selected_applet: None,
        }
    }

    /// Whether the channel is open.
    pub const fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    /// Get the selected applet index, if any.
    pub const fn selected_applet(&self) -> Option<u8> {
        match self {
            Self::Open {
                selected_applet: Some(idx),
            } => Some(*idx),
            _ => None,
        }
    }

    /// Set the selected applet on this channel. Only valid if open.
    /// Returns `true` if the channel was open and the selection was set.
    pub const fn select_applet(&mut self, registry_index: u8) -> bool {
        match self {
            Self::Open { selected_applet } => {
                *selected_applet = Some(registry_index);
                true
            }
            Self::Closed => false,
        }
    }

    /// Clear the selected applet (deselect). Returns `true` if the channel
    /// was open.
    pub const fn deselect(&mut self) -> bool {
        match self {
            Self::Open { selected_applet } => {
                *selected_applet = None;
                true
            }
            Self::Closed => false,
        }
    }
}

/// MANAGE CHANNEL P1 values per ETSI TS 102 221 clause 11.1.17.
pub const MANAGE_CHANNEL_OPEN: u8 = 0x00;
/// Close channel.
pub const MANAGE_CHANNEL_CLOSE: u8 = 0x80;

/// Process a MANAGE CHANNEL command.
///
/// - P1=0x00: Open supplementary channel. P2=0x00 means assign next available.
/// - P1=0x80: Close channel specified by P2.
///
/// Returns `Ok(channel_number)` on success for open, `Ok(0)` for close,
/// or `Err(sw)` on failure.
///
/// # Errors
///
/// Returns a [`StatusWord`](simrs_iso7816::StatusWord) error when:
/// - All supplementary channels are already open (69 85)
/// - The requested channel number is out of range (6A 86)
/// - Attempting to close the basic channel (69 85)
/// - Attempting to close an already-closed channel (69 85)
/// - P1 is an unrecognised value (6A 86)
pub fn manage_channel(
    channels: &mut [ChannelState; 4],
    p1: u8,
    p2: u8,
) -> Result<u8, simrs_iso7816::StatusWord> {
    use simrs_iso7816::StatusWord;

    match p1 {
        MANAGE_CHANNEL_OPEN => {
            if p2 == 0x00 {
                // Assign next available supplementary channel (1-3).
                for i in 1..4u8 {
                    if !channels[i as usize].is_open() {
                        channels[i as usize] = ChannelState::open_default();
                        return Ok(i);
                    }
                }
                // No channel available.
                Err(StatusWord::command_not_allowed(0x85))
            } else if (1..=3).contains(&p2) {
                // Open specific channel.
                if channels[p2 as usize].is_open() {
                    // Already open.
                    return Err(StatusWord::command_not_allowed(0x85));
                }
                channels[p2 as usize] = ChannelState::open_default();
                Ok(p2)
            } else {
                Err(StatusWord::wrong_params(0x86))
            }
        }
        MANAGE_CHANNEL_CLOSE => {
            if p2 == 0 {
                // Can't close the basic channel.
                return Err(StatusWord::command_not_allowed(0x85));
            }
            if !(1..=3).contains(&p2) {
                return Err(StatusWord::wrong_params(0x86));
            }
            if !channels[p2 as usize].is_open() {
                return Err(StatusWord::command_not_allowed(0x85));
            }
            channels[p2 as usize] = ChannelState::Closed;
            Ok(0)
        }
        _ => Err(StatusWord::wrong_params(0x86)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_channels() -> [ChannelState; 4] {
        [
            ChannelState::open_default(), // basic channel always open
            ChannelState::Closed,
            ChannelState::Closed,
            ChannelState::Closed,
        ]
    }

    #[test]
    fn basic_channel_always_open() {
        let channels = make_channels();
        assert!(channels[0].is_open());
    }

    #[test]
    fn open_supplementary_channel_auto_assign() {
        let mut channels = make_channels();
        let result = manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 0x00);
        assert_eq!(result, Ok(1));
        assert!(channels[1].is_open());
    }

    #[test]
    fn open_supplementary_channel_specific() {
        let mut channels = make_channels();
        let result = manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 2);
        assert_eq!(result, Ok(2));
        assert!(channels[2].is_open());
    }

    #[test]
    fn open_already_open_channel_fails() {
        let mut channels = make_channels();
        manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 1).unwrap();
        let result = manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 1);
        assert!(result.is_err());
    }

    #[test]
    fn close_supplementary_channel() {
        let mut channels = make_channels();
        manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 1).unwrap();
        assert!(channels[1].is_open());
        let result = manage_channel(&mut channels, MANAGE_CHANNEL_CLOSE, 1);
        assert_eq!(result, Ok(0));
        assert!(!channels[1].is_open());
    }

    #[test]
    fn close_basic_channel_fails() {
        let mut channels = make_channels();
        let result = manage_channel(&mut channels, MANAGE_CHANNEL_CLOSE, 0);
        assert!(result.is_err());
    }

    #[test]
    fn close_already_closed_channel_fails() {
        let mut channels = make_channels();
        let result = manage_channel(&mut channels, MANAGE_CHANNEL_CLOSE, 1);
        assert!(result.is_err());
    }

    #[test]
    fn open_out_of_range_channel_fails() {
        let mut channels = make_channels();
        let result = manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 4);
        assert!(result.is_err());
    }

    #[test]
    fn all_supplementary_channels_exhausted() {
        let mut channels = make_channels();
        assert_eq!(
            manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 0x00),
            Ok(1)
        );
        assert_eq!(
            manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 0x00),
            Ok(2)
        );
        assert_eq!(
            manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 0x00),
            Ok(3)
        );
        // No more channels.
        assert!(manage_channel(&mut channels, MANAGE_CHANNEL_OPEN, 0x00).is_err());
    }

    #[test]
    fn channel_select_and_deselect() {
        let mut ch = ChannelState::open_default();
        assert_eq!(ch.selected_applet(), None);
        assert!(ch.select_applet(5));
        assert_eq!(ch.selected_applet(), Some(5));
        assert!(ch.deselect());
        assert_eq!(ch.selected_applet(), None);
    }

    #[test]
    fn closed_channel_operations_fail() {
        let mut ch = ChannelState::Closed;
        assert!(!ch.select_applet(1));
        assert!(!ch.deselect());
        assert_eq!(ch.selected_applet(), None);
    }

    #[test]
    fn invalid_p1_fails() {
        let mut channels = make_channels();
        let result = manage_channel(&mut channels, 0x42, 0x00);
        assert!(result.is_err());
    }
}
