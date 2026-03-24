#![allow(
    missing_docs,
    dead_code,
    clippy::needless_pass_by_value,
    clippy::needless_pass_by_ref_mut,
    clippy::missing_const_for_fn,
    clippy::doc_markdown,
    clippy::missing_fields_in_debug,
    clippy::items_after_statements,
    clippy::cast_possible_truncation,
    clippy::no_effect_underscore_binding,
    clippy::trivial_regex
)]

use cucumber::World as _;

mod common;
mod world;

fn main() {
    // GP tests will use the cucumber runner once the GP card crates exist.
    // For now this is a scaffold -- feature files are @wip tagged.
    futures::executor::block_on(world::GpWorld::run("features/"));
}
