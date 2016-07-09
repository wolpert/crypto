package com.codeheadsystems.crypto;

import java.nio.charset.Charset;
import java.security.SecureRandom;

/**
 * BSD-Style License 2016
 */
public class Utilities {

    private static final Charset charset = Charset.forName("UTF-16LE");

    public static SecureRandom getRandom() {
        SecureRandom random = new SecureRandom();
        random.setSeed(random.generateSeed(16));
        return random;
    }

    public static byte[] add(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length + a2.length];
        System.arraycopy(a1, 0, result, 0, a1.length);
        System.arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    public static byte[] randomBytes(int size) {
        byte[] result = new byte[size];
        getRandom().nextBytes(result);
        return result;
    }

    public static Charset getCharset() {
        return charset;
    }
}
