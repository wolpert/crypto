package com.codeheadsystems.crypto;

/**
 * BSD-Style License 2016
 */
public interface Decrypter {

    public String decryptText(String string);

    public byte[] decryptBytes(byte[] bytes);

}
