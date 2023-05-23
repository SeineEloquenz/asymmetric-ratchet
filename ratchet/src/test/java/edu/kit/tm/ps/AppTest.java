package edu.kit.tm.ps;

import static org.junit.Assert.assertArrayEquals;

import org.junit.Test;
import java.util.Arrays;

/**
 * Unit test for simple App.
 */
public class AppTest
{
    /**
     * Rigorous Test :-)
     */
    @Test
    public void encryptDecryptRoundtripWorks() throws RatchetException {
        var keypair = KeyGen.generateKeypair();

        keypair.publicKey().ratchet();
        keypair.privateKey().ratchet();

        var payload = new byte[]{0x41, 0x42, 0x43};
        var enc = keypair.publicKey().encrypt(payload);
        var dec = keypair.privateKey().decrypt(enc);

        assertArrayEquals(payload, dec);
    }

    @Test
    public void encryptDecryptRoundtripInEpochWorks() throws RatchetException {
        var keypair = KeyGen.generateKeypair(1337);

        var payload = new byte[]{0x47, 0x48, 0x49};
        var enc = keypair.publicKey().encrypt(payload);
        var dec = keypair.privateKey().decrypt(enc);

        assertArrayEquals(payload, dec);
    }

    @Test(expected = RatchetException.class)
    public void negativeEpochFails() throws RatchetException {
        KeyGen.generateKeypair(-1);
    }
}
