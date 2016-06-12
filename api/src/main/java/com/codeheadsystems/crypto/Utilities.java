package com.codeheadsystems.crypto;

import java.security.SecureRandom;

/**
 * BSD-Style License 2016
 */
public class Utilities {
    public static final SecureRandom RANDOM = new SecureRandom();

    public static byte[] add(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length + a2.length];
        System.arraycopy(a1, 0, result, 0, a1.length);
        System.arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    public static byte[] randomBytes(int size) {
        byte[] result = new byte[size];
        RANDOM.nextBytes(result);
        return result;
    }
}
