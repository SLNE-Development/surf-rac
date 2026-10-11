# Releasing the surf-rac client

Releases are built by GitHub Actions (`.github/workflows/ci.yml`) and published
as GitHub Releases. Running clients use the latest release as their update feed.

## Cut a release

1. Bump `version` in `crates/app/Cargo.toml` (`MAJOR.MINOR.PATCH`, digits only)
   and commit it on `master`.
2. Tag that commit and push the tag:
   ```sh
   git tag v0.2.0
   git push origin v0.2.0
   ```
3. CI runs the Docker test suite and the Windows build. When the tag does not
   match the crate version, or the `SURF_RAC_RELEASE_KEY` secret is missing,
   the run fails and nothing is published.
4. Once both pass, the `release` job creates the GitHub Release `v0.2.0` with
   two assets:
   - `surf-rac-0.2.0-windows-x86_64.exe`
   - `update.json`: version, asset name, SHA-256, size and the Ed25519
     signature made with the release key

Every other push uploads the same two files, signed with a throwaway key, as
the `surf-rac-windows` workflow artifact. Clients reject that signature, so
these builds are for testing only.

## How clients update

- The client reads
  `https://api.github.com/repos/SLNE-Development/surf-rac/releases/latest`.
  It checks 30 seconds after start, then every 6 hours, from
  *Settings > Updates > Check for updates*, and right away when the server
  answers `update_required`.
- It accepts `update.json` only if the signature verifies against the release
  public key compiled into the client, and the version is strictly newer than
  its own.
- It downloads the executable next to itself as `surf-rac.exe.new`, then
  checks the size and SHA-256.
- *Restart to update* renames the running `surf-rac.exe` to `surf-rac.exe.old`,
  moves the new file into place, starts it and closes the old one. Active
  sessions end.
- The new process removes `.old` and `.new` when it starts. The path does not
  change, so the Defender exclusion still applies.

The repository must be public, because the client calls the GitHub API
without a token.

## Recovery

If a new version does not start, close any surf-rac process, delete
`surf-rac.exe` and rename `surf-rac.exe.old` back to `surf-rac.exe`. The `.old`
file stays until a version starts successfully.

## The release key

- The private key (a base64 32-byte Ed25519 seed) is the repository secret
  `SURF_RAC_RELEASE_KEY`. Keep an offline backup. A key cannot be read back
  from GitHub.
- The public key is `RELEASE_PUBLIC_KEY` in `crates/app/src/update.rs`.
- `cargo run -p surf-rac-release -- keygen` prints a new private key on stdout
  and its public key on stderr.

### Rotating the key

1. Generate a new key pair.
2. Put the new public key in `crates/app/src/update.rs`, bump the version and
   release it while the secret still holds the **old** key. Clients verify
   this release with the key they have.
3. Replace the secret with the new private key. Every later release is signed
   with it.

If the private key is lost or leaked, clients must install a build that
contains the new public key by hand. A leaked key can sign updates that every
client accepts until that happens.
