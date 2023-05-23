package edu.kit.tm.ps;

import io.questdb.jar.jni.JarJniLoader;

/**
 * Native interface to the asym_ratchet implementation.
 */
class Sys {
    static {
        JarJniLoader.loadLib(Sys.class, "/edu/kit/tm/ps/ratchet/libs", "jni_bridge");
    }

    public static native long[] keypair_generate();

    public static native long[] keypair_generate_epoch(long epoch);

    public static native void pubkey_ratchet(long pointer);

    public static native byte[] pubkey_encrypt(long pointer, byte[] payload);

    public static native void pubkey_drop(long pointer);

    public static native void privkey_ratchet(long pointer);

    public static native byte[] privkey_decrypt(long pointer, byte[] payload);

    public static native void privkey_drop(long pointer);
}
