# Scriptd Automation Bridge

This public repository contains the small privileged companion used by the direct-download Scriptd macOS app. The app owns automation rules, schedules, policies, package selection, and the user interface. The bridge accepts typed, paired requests for operations that require privileges unavailable to the app; it does not evaluate schedules or run Homebrew.

Homebrew remains responsible for package downloads, staging, dependency resolution, and package bookkeeping. Ordinary package work runs as the logged-in user. For an explicitly approved package, the bridge can perform only the fixed macOS `.pkg` installer operation as root; it never runs `sudo brew`, shell installers, package scripts directly, or user-provided commands.

## Bridge scope

The bridge authenticates the paired app's signed identity, reports available capabilities, accepts narrowly typed operations, records durable operation receipts, supports revocation, and avoids replaying uncertain work after restart. Protocol v3 continues to expose the existing Wi-Fi operation to older clients. Protocol v4 adds `installer_package_v1` for the direct-download bundle identifier only; capability responses to the Store bundle do not include package installation. Unsupported capabilities are unavailable.

The bridge is installed separately from the Mac App Store app and runs as a root-owned LaunchDaemon. Its package is signed and notarized in release automation. Installation, pairing, and package authorization require explicit macOS administrator approval. Before the app can pair, an administrator grants one pairing for the exact signing team and bundle identifier with `sudo /usr/local/libexec/scriptd-bridge authorize-pairing TEAM_IDENTIFIER BUNDLE_IDENTIFIER`. Pairing does not authorize package installation.

The Mac App Store edition cannot connect to or execute operations through this bridge. Installing Bridge does not enable privileged features in that edition. Bridge setup is for the direct-download edition; the Store app remains self-contained and does not download or install Bridge, run its installer, request root privileges, or execute package operations. Direct-download users can get the signed Bridge from [GitHub Releases](https://github.com/omar391/macmodules-helper/releases/latest).

### Install Scriptd Bridge

1. Download the signed Bridge `.pkg` from GitHub Releases.
2. Open the package and follow the macOS Installer prompts. macOS asks an administrator to approve installation of the root-owned Bridge service.
3. Open the direct-download Scriptd app. Pair it with Bridge only when an action needs Bridge, then approve each eligible publisher and package separately when prompted.

The Mac App Store edition cannot use Bridge. Installing Bridge does not enable package installation or privileged Wi-Fi actions in that edition; its Bridge link is informational.

For each package that may need an administrator installer step, approve the direct app identity and the vendor's Developer ID Installer team and package identifier:

```sh
sudo /usr/local/libexec/scriptd-bridge set-package-approval approve APP_TEAM_IDENTIFIER com.astronlab.scriptd PUBLISHER_TEAM_IDENTIFIER PACKAGE_IDENTIFIER
```

This approval covers later package versions only while the publisher, package identifier, and supported installer method stay the same. Package components with their own identifiers need their own approval. Approved vendors' installer scripts may run with administrator privileges as part of Apple's installer lifecycle. Revoke future authorization with the same command and `revoke` in place of `approve`. At run time, the bridge copies the user-owned package into root-only staging, checks its Developer ID signature and Gatekeeper notarization, verifies package identifiers against grants, and invokes only `/usr/sbin/installer -pkg … -target /`. Uncertain operations are recorded and never replayed automatically.

## Build and test

Requires Rust stable and macOS:

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --release -p scriptd-bridge
```

The `scriptd-bridge-protocol` crate defines the versioned wire types shared with the private desktop app. Release artifacts are built from this public repository alone.

## Tracked helper source

`assets/mbrew/brew_askpass.sh` is retained as a tracked source asset for compatibility with existing installs. It is not used by the package installer operation and does not grant administrator access to Homebrew.

## License

The bridge and protocol are available under Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
