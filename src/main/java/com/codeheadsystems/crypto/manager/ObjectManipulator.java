package com.codeheadsystems.crypto.manager;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static com.codeheadsystems.crypto.Utilities.getCharset;

/**
 * Provides the ability to convert objects from typeA to compressed bytes and back again.
 * BSD-Style License 2016
 */
public class ObjectManipulator {

    public ObjectManipulator() {
    }

    public byte[] compress(byte[] uncompressedBytes) throws IOException {
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream);
        gzipOutputStream.write(uncompressedBytes);
        gzipOutputStream.flush();
        gzipOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    public byte[] uncompress(byte[] compressedData) throws IOException {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedData);
        final GZIPInputStream gzipInputStream = new GZIPInputStream(byteArrayInputStream);
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try {
            byte[] array = new byte[1024];
            int read = gzipInputStream.read(array);
            while (read >= 0) {
                byteArrayOutputStream.write(array, 0, read);
                read = gzipInputStream.read(array);
            }
            return byteArrayOutputStream.toByteArray();
        } finally {
            gzipInputStream.close();
        }
    }

    public byte[] compressString(String string) throws IOException {
        return compress(string.getBytes(getCharset()));
    }

    public String uncompressString(byte[] bytes) throws IOException {
        return new String(uncompress(bytes), getCharset());
    }
}
