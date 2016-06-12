package com.codeheadsystems.crypto.hasher;

import junit.framework.TestCase;

import org.junit.Test;

import java.nio.charset.Charset;

/**
 * BSD-Style License 2016
 */
public class HasherBuilderTest {

    @Test
    public void testValuesAreReused() {
        AbstractSaltedHasher hasher = (AbstractSaltedHasher) new HasherBuilder().hasherProviderClass(TestHasherProvider.class)
                .saltSize(5).digest("blah").charSet("UTF-8").iterations(9).build();
        TestCase.assertEquals(5, hasher.saltSize);
        TestCase.assertEquals(9, hasher.iterations);
        TestCase.assertEquals("blah", hasher.digest);
        TestCase.assertEquals(Charset.forName("UTF-8"), hasher.charset);
    }
}
