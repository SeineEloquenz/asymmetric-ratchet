package edu.kit.tm.ps;

/**
 * Representation of a ratchetable public key.
 */
public class PublicKey {
    long pointer;

    PublicKey(long pointer) {
        this.pointer = pointer;
    }

    @SuppressWarnings({"deprecation", "removal"})
    protected void finalize() {
        Sys.pubkey_drop(pointer);
    }

    public void ratchet() throws RatchetException {
        Sys.pubkey_ratchet(pointer);
    }

    public byte[] encrypt(byte[] payload) throws RatchetException {
        return Sys.pubkey_encrypt(pointer, payload);
    }

    public byte[] serialize() {
        return Sys.pubkey_serialize(pointer);
    }

    public static PublicKey deserialize(byte[] data) throws RatchetException {
        return new PublicKey(Sys.pubkey_deserialize(data));
    }
}
