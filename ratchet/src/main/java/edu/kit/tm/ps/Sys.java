package edu.kit.tm.ps;

/**
 * Native interface to the asym_ratchet implementation.
 */
class Sys {
    static {
        System.loadLibrary("jni_bridge");
    }

    public static native long[] keypair_generate();

    public static native long[] keypair_generate_epoch(long epoch);

    public static native void pubkey_ratchet(long pointer);

    public static native byte[] pubkey_encrypt(long pointer, byte[] payload);

    public static native byte[] pubkey_serialize(long pointer);

    public static native long pubkey_deserialize(byte[] data);

    public static native void pubkey_drop(long pointer);

    public static native void privkey_ratchet(long pointer);

    public static native byte[] privkey_decrypt(long pointer, byte[] payload);

    public static native byte[] privkey_serialize(long pointer);

    public static native long privkey_deserialize(byte[] data);

    public static native void privkey_drop(long pointer);
}
