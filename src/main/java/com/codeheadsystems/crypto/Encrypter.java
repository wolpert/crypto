package com.codeheadsystems.crypto;

/**
 * BSD-Style License 2016
 */
public interface Encrypter {

    public String encryptText(String string);

    public byte[] encryptBytes(byte[] bytes);

}
