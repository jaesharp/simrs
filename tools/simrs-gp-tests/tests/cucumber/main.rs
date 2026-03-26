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
    clippy::trivial_regex,
    clippy::wildcard_imports,
    clippy::used_underscore_binding
)]

use cucumber::World as _;

mod common;
mod world;

fn main() {
    // By default, run only non-@wip scenarios (promoted, expected to pass).
    // Set SIMRS_GP_RUN_WIP=1 to include @wip scenarios for development.
    let run_wip = std::env::var("SIMRS_GP_RUN_WIP").is_ok();
    if run_wip {
        futures::executor::block_on(world::GpWorld::run("features/"));
    } else {
        futures::executor::block_on(
            world::GpWorld::cucumber()
                .filter_run("features/", |_, _, sc| {
                    !sc.tags.iter().any(|t| t == "wip")
                }),
        );
    }
}
