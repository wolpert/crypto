package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

/**
 * BSD-Style License 2016
 */
public class ParanoidHasherProviderImpl implements HasherProvider {

    @Override
    public Hasher getHasher(HasherConfiguration hasherConfiguration) {
        return new ParanoidHasher(hasherConfiguration);
    }
}
