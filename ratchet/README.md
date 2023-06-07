Asymmetric Ratchet as an Android library.

Usage:

```bash
# Ensure that you have the rust targets installed
rustup target add i686-linux-android x86_64-linux-android armv7-linux-androideabi
# Compile the Rust library
./gradlew cargoBuild
# Compile the Android library
./gradlew build
# Copy/Import/Add the dependency to
#   build/outputs/aar/ratchet-release.aar
# in the Android project.
```

If you change the code (either of the Rust ratchet implementation, or of the
wrapper), repeat the above steps to re-build the Android library.
