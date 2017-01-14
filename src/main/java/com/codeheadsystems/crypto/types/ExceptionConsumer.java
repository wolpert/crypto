package com.codeheadsystems.crypto.types;

/**
 * BSD-Style License 2017
 */
@FunctionalInterface
public interface ExceptionConsumer<T, E extends Exception> {

    void accept(T t) throws E;
}
