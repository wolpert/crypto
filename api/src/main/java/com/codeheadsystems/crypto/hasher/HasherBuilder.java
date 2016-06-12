package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import java.nio.charset.Charset;

/**
 * BSD-Style License 2016
 */
public class HasherBuilder {

    private String digest = "SHA-256";
    private String charSet = "UTF-16LE";
    private int saltSize = 2;
    private int iterations = 1024;
    private int keySize = 256;

    public HasherBuilder digest(String digest) {
        this.digest = digest;
        return this;
    }

    public HasherBuilder saltSize(int saltSize) {
        this.saltSize = saltSize;
        return this;
    }

    public HasherBuilder charSet(String charSet) {
        this.charSet = charSet;
        return this;
    }

    public HasherBuilder iterations(int iterations) {
        this.iterations = iterations;
        return this;
    }

    public HasherBuilder keySize(int keySize) {
        this.keySize = keySize;
        return this;
    }

    public Hasher build() {
        if (digest.startsWith("PBK")) {
            return new OWASPHasherImpl(digest, saltSize, iterations, Charset.forName(charSet), keySize);
        } else {
            return new StandardHasherImpl(digest, saltSize, iterations, Charset.forName(charSet));
        }
    }
}
