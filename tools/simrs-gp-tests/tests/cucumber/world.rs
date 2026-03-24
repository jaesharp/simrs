use cucumber::World;

/// Test world for GlobalPlatform BDD scenarios.
///
/// This will hold a GP card instance, response buffer, and SCP session
/// state once the GP crates are implemented. For now it's a scaffold.
#[derive(Debug, Default, World)]
pub struct GpWorld {
    /// Last APDU response (data + SW).
    pub last_response: Vec<u8>,
    /// Last SW1.
    pub sw1: u8,
    /// Last SW2.
    pub sw2: u8,
    /// Whether an SCP session is established.
    pub scp_authenticated: bool,
    /// Card lifecycle state (for verification).
    pub expected_card_lifecycle: u8,
}
