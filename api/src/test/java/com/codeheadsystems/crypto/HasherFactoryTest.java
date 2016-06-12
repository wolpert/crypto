package com.codeheadsystems.crypto;

import org.junit.Test;

import static junit.framework.TestCase.assertNotNull;

/**
 * BSD-Style License 2016
 */
public class HasherFactoryTest {

    @Test
    public void testGetUsableHasher() {
        assertNotNull(new HasherFactory().getUsableHasher());
    }

}
