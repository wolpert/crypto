package com.codeheadsystems.crypto.hasher;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;

import junit.framework.TestCase;

import org.junit.Before;
import org.junit.Test;

/**
 * BSD-Style License 2016
 */
public class HasherBuilderTest {

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Test
    public void testValuesAreReused() {
        AbstractSaltedHasher hasher = (AbstractSaltedHasher) new HasherBuilder()
                .saltSize(5)
                .iterations(9)
                .build();
        TestCase.assertEquals(5, hasher.saltSize);
        TestCase.assertEquals(9, hasher.iterations);
    }
}
