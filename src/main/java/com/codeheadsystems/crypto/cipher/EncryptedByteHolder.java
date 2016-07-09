package com.codeheadsystems.crypto.cipher;

/**
 * BSD-Style License 2016
 */
public class EncryptedByteHolder {

    protected byte[] encryptedBytes;
    protected byte[] iv;

    public EncryptedByteHolder(byte[] encryptedBytes, byte[] iv) {
        this.encryptedBytes = encryptedBytes;
        this.iv = iv;
    }

    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }

    public byte[] getIv() {
        return iv;
    }
}
