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
                .hasherProviderClass(TestHasherProvider.class)
                .saltSize(5)
                .digest("blah")
                .iterations(9)
                .build();
        TestCase.assertEquals(5, hasher.saltSize);
        TestCase.assertEquals(9, hasher.iterations);
        TestCase.assertEquals("blah", hasher.digest);
    }
}
