package edu.kit.tm.ps;

/**
 * Interface to key generation.
 */
public class KeyGen {
    public static class KeyPair {
        private PublicKey publicKey;
        private PrivateKey privateKey;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }

        public PublicKey publicKey() {
            return publicKey;
        }

        public PrivateKey privateKey() {
            return privateKey;
        }
    }

    private KeyGen() {}

    public static KeyPair generateKeypair() {
        var pair = Sys.keypair_generate();
        assert(pair.length == 2);
        var pubKey = new PublicKey(pair[0]);
        var privKey = new PrivateKey(pair[1]);
        return new KeyPair(pubKey, privKey);
    }

    public static KeyPair generateKeypair(long epoch) throws RatchetException {
        var pair = Sys.keypair_generate_epoch(epoch);
        assert(pair.length == 2);
        var pubKey = new PublicKey(pair[0]);
        var privKey = new PrivateKey(pair[1]);
        return new KeyPair(pubKey, privKey);
    }
}
