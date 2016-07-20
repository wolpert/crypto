package com.codeheadsystems.crypto.cipher;

import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

/**
 * BSD-Style License 2016
 */
public class EncryptedByteHolder implements Serializable {

    private static Logger logger = LoggerFactory.getLogger(EncryptedByteHolder.class);

    protected byte[] encryptedBytes;
    protected byte[] iv;

    public EncryptedByteHolder(byte[] encryptedBytes, byte[] iv) {
        this.encryptedBytes = encryptedBytes;
        this.iv = iv;
    }

    public static EncryptedByteHolder fromString(String string) {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(Base64.decode(string));
        try {
            ObjectInputStream ois = new ObjectInputStream(byteArrayInputStream);
            return (EncryptedByteHolder) ois.readObject();
        } catch (ClassNotFoundException | IOException e) {
            e.printStackTrace();
            logger.error("Unable to extract logger:" + string, e);
            return null;
        }
    }

    public String toString() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(this);
            oos.flush();
            oos.close();
            return Base64.toBase64String(baos.toByteArray());
        } catch (IOException e) {
            logger.error("Unable to create logger string", e);
            return null;
        }
    }

    public byte[] getEncryptedBytes() {
        return encryptedBytes;
    }

    public byte[] getIv() {
        return iv;
    }
}
