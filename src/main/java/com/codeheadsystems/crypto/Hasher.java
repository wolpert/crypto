package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.hasher.HashHolder;

/**
 * BSD-Style License 2016
 */
public interface Hasher {

    public String getDigest();

    public HashHolder generateHash(String unhashedString);

    public HashHolder generateHash(String unhashedString, byte[] salt);

    public boolean isSame(HashHolder hashedString, String unhashedString);

}
