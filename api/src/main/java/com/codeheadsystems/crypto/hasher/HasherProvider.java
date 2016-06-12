package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

/**
 * BSD-Style License 2016
 */
public interface HasherProvider {

    Hasher getHasher(HasherConfiguration hasherConfiguration);

}
