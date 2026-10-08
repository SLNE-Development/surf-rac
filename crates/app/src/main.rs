//! Entry point of the surf-rac client.

/// Starts the client.
fn main() {
    let dir = surf_rac_app::store::default_dir();
    let store = surf_rac_app::store::Store::open(dir);
    println!("state version {}", store.state().version);
}
