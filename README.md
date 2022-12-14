# Asym Ratchet

Crate providing an asymmetric ratchet to provide forward secrecy in
public-key/private-key encryption settings.

Documentation: run `cargo doc` to build, it will be in
`target/doc/asym_ratchet/index.html`

Benchmarks: run `cargo bench`

## Maths

Idea and first implementation (`src/bte.rs`): Ran Canetti, Shai Halevi,
Jonathan Katz: *A Foward-Secure Public-Key Encryption Scheme*

Small & constant size ciphertext (`src/bbg.rs`): Dan Boneh, Xavier Boyen,
Eu-Jin Goh: *Hierarchical Identity Based Encryption with Constant Size
Ciphertext*
