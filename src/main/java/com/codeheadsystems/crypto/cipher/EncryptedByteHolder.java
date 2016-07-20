package com.codeheadsystems.crypto.cipher;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;
import java.util.StringTokenizer;

import static com.codeheadsystems.crypto.Utilities.bytesToString;
import static com.codeheadsystems.crypto.Utilities.stringToBytes;

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
        StringTokenizer st = new StringTokenizer(string, ":");
        if (st.countTokens() != 2) {
            return null;
        }
        String ivStr = st.nextToken();
        String ebStr = st.nextToken();
        return new EncryptedByteHolder(stringToBytes(ebStr), stringToBytes(ivStr));
    }

    public String toString() {
        return bytesToString(iv) + ":" + bytesToString(encryptedBytes);
    }

    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }

    public byte[] getIv() {
        return iv;
    }
}
