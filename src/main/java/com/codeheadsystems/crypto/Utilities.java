package com.codeheadsystems.crypto;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.Charset;
import java.util.UUID;

import static java.lang.System.arraycopy;

/**
 * BSD-Style License 2016
 */
public class Utilities {

    public static byte[] reduce(byte[] bytes, int length) {
        byte[] finalBytes = new byte[length];
        arraycopy(bytes, 0, finalBytes, 0, length);
        return finalBytes;
    }

    public static byte[] add(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length + a2.length];
        arraycopy(a1, 0, result, 0, a1.length);
        arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    public static boolean isSame(byte[] a1, byte[] a2) {
        if (a1 == null || a2 == null || a1.length != a2.length) {
            return false;
        }
        boolean result = true;
        for (int i = 0; i < a1.length; i++) {
            result = (a1[i] == a2[i]) && result;
        }
        return result;
    }

    public static Charset getCharset() {
        return Charset.forName("UTF-16LE");
    }

    public static String bytesToString(byte[] bytes) {
        if (bytes != null) {
            return Base64.toBase64String(bytes);
        } else {
            return "null";
        }
    }

    public static String toHex(byte[] bytes) {
        return Hex.toHexString(bytes);
    }

    public static byte[] fromHex(String hexString) {
        return Hex.decode(hexString);
    }

    public static byte[] stringToBytes(String string) {
        if (string == null || string.equals("null")) {
            return null;
        } else {
            return Base64.decode(string);
        }
    }

    public static byte[] cloneBytes(byte[] array) {
        byte[] result = new byte[array.length];
        arraycopy(array, 0, result, 0, array.length);
        return result;
    }

    public static byte[] getBytes(String hashedValue) {
        return hashedValue.getBytes(getCharset());
    }

    public static String getUuid() {
        return UUID.randomUUID().toString();
    }

    // Extra paranoia mode.... always clears
    // bytes, and returns a null
    public static byte[] clear(byte[] array) {
        if (array != null) {
            for (int i = 0; i < array.length; i++) {
                array[i] = Byte.MAX_VALUE;
            }
        }
        return null;
    }
}
