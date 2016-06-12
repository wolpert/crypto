package com.codeheadsystems.crypto;

/**
 * BSD-Style License 2016
 */
public interface Hasher {

    public byte[] generateHash(String unhashedString);

    public boolean isSame(byte[] hashedString, String unhashedString);

}
