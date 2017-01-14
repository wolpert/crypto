package com.codeheadsystems.crypto.types;

/**
 * BSD-Style License 2017
 */
@FunctionalInterface
public interface ExceptionFunction<T, R, E extends Exception> {

    R apply(T t) throws E;

}
