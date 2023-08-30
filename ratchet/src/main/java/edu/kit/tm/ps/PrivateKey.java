package edu.kit.tm.ps;

public class PrivateKey {
    long pointer;

    PrivateKey(long pointer) {
        this.pointer = pointer;
    }

    @SuppressWarnings({"deprecation", "removal"})
    protected void finalize() {
        Sys.privkey_drop(pointer);
    }

    public synchronized void ratchet() throws RatchetException {
        Sys.privkey_ratchet(pointer);
    }

    public synchronized void fastForward(long count) throws RatchetException {
        Sys.privkey_fast_forward(pointer, count);
    }

    public synchronized byte[] decrypt(byte[] ciphertext) throws RatchetException {
        return Sys.privkey_decrypt(pointer, ciphertext);
    }

    public byte[] serialize() {
        return Sys.privkey_serialize(pointer);
    }

    public static PrivateKey deserialize(byte[] data) throws RatchetException {
        return new PrivateKey(Sys.privkey_deserialize(data));
    }

    public PrivateKey clone() {
        return new PrivateKey(Sys.privkey_clone(pointer));
    }

    public long currentEpoch() {
        return Sys.privkey_current_epoch(pointer);
    }
}


