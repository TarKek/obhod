//! Application core: component state, health evaluation, profiles and history.
//!
//! The UI is a projection of this state. Screens emit [`Action`]s, the core
//! records [`Event`]s and produces statuses; no screen invents its own
//! notion of whether a component works.

pub mod background;
pub mod health;
pub mod history;
pub mod profiles;
pub mod state;

pub use profiles::ProfileStore;
pub use state::{Component, Phase};
