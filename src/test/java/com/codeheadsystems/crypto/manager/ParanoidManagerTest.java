package com.codeheadsystems.crypto.manager;

import com.codeheadsystems.crypto.Utilities;
import com.codeheadsystems.crypto.password.KeyParameterWrapper;
import com.codeheadsystems.crypto.password.SecretKeyExpiredException;
import com.codeheadsystems.crypto.random.UnsecureRandomProvider;

import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.codeheadsystems.crypto.Utilities.getUuid;
import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

/**
 * BSD-Style License 2016
 */
public class ParanoidManagerTest {

    private ParanoidManager paranoidManager;
    private KeyParameterWrapper keyParameterWrapper;

    @Before
    public void setRandomFactory() {
        Utilities.setRandomProvider(new UnsecureRandomProvider());
    }

    @Before
    public void init() throws ParanoidManagerException {
        paranoidManager = new ParanoidManager();
        keyParameterWrapper = new KeyParameterWrapper(paranoidManager.generateRandomAesKey(), null);
    }

    @Test
    public void testSensitiveDetails() throws IOException, SecretKeyExpiredException {
        String username = "uname";
        String password = "pw054";
        String note = "This is not a test";
        String id = getUuid();
        Map<String, String> attr = new HashMap<>();
        attr.put("a", "A");
        attr.put("b", "B");
        SensitiveDetails sensitiveDetails1 = new SensitiveDetails(username, password, note, id, attr);
        byte[] bytes = paranoidManager.encode(sensitiveDetails1, keyParameterWrapper);
        SensitiveDetails sensitiveDetails2 = paranoidManager.decodeSensitiveDetails(bytes, keyParameterWrapper);

        assertEquals(username, sensitiveDetails1.getUsername());
        assertEquals(password, sensitiveDetails1.getPassword());
        assertEquals(note, sensitiveDetails1.getNotes());
        assertEquals(id, sensitiveDetails1.getId());
        for (Map.Entry<String, String> entry : attr.entrySet()) {
            assertTrue(entry.getValue().equals(sensitiveDetails1.getAttr().get(entry.getKey())));
        }

        assertEquals(username, sensitiveDetails2.getUsername());
        assertEquals(password, sensitiveDetails2.getPassword());
        assertEquals(note, sensitiveDetails2.getNotes());
        assertEquals(id, sensitiveDetails2.getId());
        for (Map.Entry<String, String> entry : attr.entrySet()) {
            assertTrue(entry.getValue().equals(sensitiveDetails2.getAttr().get(entry.getKey())));
        }
    }
}
