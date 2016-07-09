package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;
import com.codeheadsystems.crypto.Utilities;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.Charset;

/**
 * BSD-Style License 2016
 */
public class HasherBuilder {

    private String digest = "SHA-256";
    private int saltSize = 2;
    private int iterations = 1024;
    private int keySize = 256;
    private Class<? extends HasherProvider> hasherProviderClass;

    public HasherBuilder hasherProviderClass(Class<? extends HasherProvider> hasherProviderClass) {
        this.hasherProviderClass = hasherProviderClass;
        return this;
    }

    public HasherBuilder digest(String digest) {
        this.digest = digest;
        return this;
    }

    public HasherBuilder saltSize(int saltSize) {
        this.saltSize = saltSize;
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

    protected HasherProvider getHasherProvider() {
        try {
            Constructor<? extends HasherProvider> constructor = hasherProviderClass.getConstructor();
            return constructor.newInstance();
        } catch (NoSuchMethodException | IllegalAccessException | InstantiationException | InvocationTargetException e) {
            throw new HasherException("Unable to constructor hasher from provider " + hasherProviderClass, e);
        }
    }

    public Hasher build() {
        Charset usableCharset = Utilities.getCharset();
        HasherConfiguration hasherConfiguration = new HasherConfiguration(digest, saltSize, iterations, usableCharset, keySize);
        HasherProvider hasherProvider = getHasherProvider();
        return hasherProvider.getHasher(hasherConfiguration);
    }
}
