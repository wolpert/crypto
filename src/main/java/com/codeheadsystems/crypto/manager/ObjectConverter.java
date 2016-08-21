package com.codeheadsystems.crypto.manager;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static com.codeheadsystems.crypto.Utilities.getCharset;

/**
 * Provides the ability to convert objects from typeA to compressed bytes and back again
 * <p/>
 * BSD-Style License 2016
 */
public class ObjectConverter {

    private final ObjectMapper objectMapper;

    public ObjectConverter() {
        objectMapper = new ObjectMapper();
    }

    public byte[] toByteArray(Object obj) throws IOException {
        final String jsonString = objectMapper.writeValueAsString(obj);
        final byte[] uncompressedBytes = jsonString.getBytes(getCharset());
        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream);
        gzipOutputStream.write(uncompressedBytes);
        gzipOutputStream.flush();
        gzipOutputStream.close();
        return byteArrayOutputStream.toByteArray();
    }

    // TODO: clazz seems redundant
    public <T> T fromByteArray(byte[] compressedData, Class<T> clazz) throws IOException {
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
            byte[] uncompressed = byteArrayOutputStream.toByteArray();
            String json = new String(uncompressed, getCharset());
            return objectMapper.readValue(json, clazz);
        } finally {
            gzipInputStream.close();
        }
    }
}
