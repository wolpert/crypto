package com.codeheadsystems.crypto.hasher;

/**
 * Created by wolpert on 7/19/16.
 */
public class HashHolder {

    private byte[] salt;
    private byte[] hash;

    public HashHolder(byte[] salt, byte[] hash) {
        this.salt = salt;
        this.hash = hash;
    }

    public byte[] getSalt() {
        return salt;
    }

    public byte[] getHash() {
        return hash;
    }
}
