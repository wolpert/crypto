package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Hasher;

/**
 * BSD-Style License 2016
 */
public class HasherProviderImpl implements HasherProvider {

    @Override
    public Hasher getHasher(HasherConfiguration hasherConfiguration) {
        return new OWASPHasherImpl(hasherConfiguration);
    }
}
