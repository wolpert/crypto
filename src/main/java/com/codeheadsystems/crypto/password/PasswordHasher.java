package com.codeheadsystems.crypto.password;

import com.codeheadsystems.crypto.hasher.HashHolder;

/**
 * BSD-Style License 2016.
 * Provides a way to create a hash from a password.
 */
public interface PasswordHasher {

    HashHolder generateHash(String unhashedString);

    HashHolder generateHash(String unhashedString, byte[] salt);

    boolean isSame(HashHolder hashedString, String unhashedString);
}
