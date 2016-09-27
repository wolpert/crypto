package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

/**
 * BSD-Style License 2016
 */
public class HasherBuilder {

    private String digest = "SKEIN-1024-1024";
    private int saltSize = 20;
    private int iterations = 1024;
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

    protected HasherProvider getHasherProvider() {
        try {
            Constructor<? extends HasherProvider> constructor = hasherProviderClass.getConstructor();
            return constructor.newInstance();
        } catch (NoSuchMethodException e) {
            throw new HasherException("Unable to constructor hasher from provider " + hasherProviderClass, e);
        } catch (IllegalAccessException e) {
            throw new HasherException("Unable to constructor hasher from provider " + hasherProviderClass, e);
        } catch (InstantiationException e) {
            throw new HasherException("Unable to constructor hasher from provider " + hasherProviderClass, e);
        } catch (InvocationTargetException e) {
            throw new HasherException("Unable to constructor hasher from provider " + hasherProviderClass, e);
        }
    }

    public Hasher build() {
        HasherConfiguration hasherConfiguration = new HasherConfiguration(digest, saltSize, iterations);
        HasherProvider hasherProvider = getHasherProvider();
        return hasherProvider.getHasher(hasherConfiguration);
    }
}
