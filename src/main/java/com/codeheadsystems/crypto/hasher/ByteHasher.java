package com.codeheadsystems.crypto.hasher;

/**
 * BSD-Style License 2016
 */
public interface ByteHasher {

    HashHolder generateHash(byte[] bytes);

    HashHolder generateHash(byte[] bytes, byte[] salt);
}
