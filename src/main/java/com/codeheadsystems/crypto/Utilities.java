package com.codeheadsystems.crypto;

import org.bouncycastle.util.encoders.Base64;

import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Date;

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

    public static byte[] reduce(byte[] bytes, int length) {
        byte[] finalBytes = new byte[length];
        System.arraycopy(bytes, 0, finalBytes, 0, length);
        return finalBytes;
    }

    public static byte[] add(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length + a2.length];
        System.arraycopy(a1, 0, result, 0, a1.length);
        System.arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    public static boolean isSame(byte[] a1, byte[] a2) {
        if (a1 == null || a2 == null || a1.length != a2.length) {
            return false;
        }
        for (int i = 0; i < a1.length; i++) {
            if (a1[i] != a2[i]) {
                return false;
            }
        }
        return true;
    }

    public static byte[] randomBytes(int size) {
        byte[] result = new byte[size];
        getRandom().nextBytes(result);
        return result;
    }

    public static Charset getCharset() {
        return charset;
    }

    public static String bytesToString(byte[] bytes) {
        if (bytes != null) {
            return Base64.toBase64String(bytes);
        } else {
            return "null";
        }
    }

    public static byte[] stringToBytes(String string) {
        if (string == null || string.equals("null")) {
            return null;
        } else {
            return Base64.decode(string);
        }
    }
}
