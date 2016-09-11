package com.codeheadsystems.crypto;

import com.codeheadsystems.crypto.hasher.ByteHasher;
import com.codeheadsystems.crypto.password.PasswordHasher;

/**
 * BSD-Style License 2016
 */
public interface Hasher extends PasswordHasher, ByteHasher {

    String getDigest();

}
