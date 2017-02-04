package com.codeheadsystems.crypto.cipher;

import com.codeheadsystems.crypto.Utilities;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

import static com.codeheadsystems.crypto.Utilities.bytesToString;
import static com.codeheadsystems.crypto.cipher.CipherProvider.KEY_BYTE_SIZE;

/**
 * BSD-Style License 2016
 */
public class EncryptedByteHolder implements Serializable {

    private static Logger logger = LoggerFactory.getLogger(EncryptedByteHolder.class);

    protected byte[] encryptedBytes;
    protected byte[] iv;

    public EncryptedByteHolder(byte[] encryptedBytes, byte[] iv) {
        logger.debug("EncryptedByteHolder()");
        this.encryptedBytes = encryptedBytes;
        this.iv = iv;
    }

    public static EncryptedByteHolder fromString(String string) {
        byte[] bytes = Utilities.stringToBytes(string);
        return fromBytes(bytes);
    }

    public static EncryptedByteHolder fromBytes(byte[] a) {
        byte[] iv = new byte[KEY_BYTE_SIZE];
        System.arraycopy(a, 0, iv, 0, KEY_BYTE_SIZE);
        byte[] encryptedBytes = new byte[a.length - KEY_BYTE_SIZE];
        System.arraycopy(a, KEY_BYTE_SIZE, encryptedBytes, 0, encryptedBytes.length);
        return new EncryptedByteHolder(encryptedBytes, iv);
    }

    public byte[] toBytes() {
        return Utilities.add(iv, encryptedBytes);
    }

    public String toString() {
        return bytesToString(toBytes());
    }

    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }

    public byte[] getIv() {
        return iv;
    }
}
