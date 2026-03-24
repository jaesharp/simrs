// Common step definitions for GP BDD tests.
// These will be implemented as the GP crates are built.
// For now, this file exists to make the cucumber harness compile.

use super::world::GpWorld;
use cucumber::given;

#[given("a GP card in OP_READY state")]
fn given_gp_card_op_ready(world: &mut GpWorld) {
    world.expected_card_lifecycle = simrs_gp_tests::card_lifecycle::OP_READY;
    // TODO: initialize GpCard once simrs-gp-card exists
}
