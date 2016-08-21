package com.codeheadsystems.crypto.manager;

import org.junit.Test;

import java.io.IOException;

import static com.codeheadsystems.crypto.Utilities.getUuid;
import static junit.framework.TestCase.assertEquals;

/**
 * BSD-Style License 2016
 */
public class ObjectConverterTest {

    private ObjectConverter objectConverter = new ObjectConverter();

    @Test
    public void testStandardMovement() throws IOException {
        String username = "fdsafads";
        String password = "fd05uoh32k";
        String note = "fkldsa fauysdiof hkdlsa fklsadh lfksh da";
        String id = getUuid();
        SensitiveDetails sensitiveDetails1 = new SensitiveDetails(username, password, note, id, null);

        byte[] compressedBytes = objectConverter.toByteArray(sensitiveDetails1);
        SensitiveDetails sensitiveDetails2 = objectConverter.fromByteArray(compressedBytes, SensitiveDetails.class);
        assertEquals(username, sensitiveDetails1.getUsername());
        assertEquals(password, sensitiveDetails1.getPassword());
        assertEquals(note, sensitiveDetails1.getNotes());
        assertEquals(id, sensitiveDetails1.getId());

        assertEquals(username, sensitiveDetails2.getUsername());
        assertEquals(password, sensitiveDetails2.getPassword());
        assertEquals(note, sensitiveDetails2.getNotes());
        assertEquals(id, sensitiveDetails2.getId());
    }

}
