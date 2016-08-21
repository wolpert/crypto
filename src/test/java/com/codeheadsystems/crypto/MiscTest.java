package com.codeheadsystems.crypto;

import org.bouncycastle.crypto.engines.AESFastEngine;
import org.junit.Test;

import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class MiscTest {

    AESFastEngine aesFastEngine = new AESFastEngine();

    @Test
    public void testThis() {
        assertEquals(1,1);
    }

}
