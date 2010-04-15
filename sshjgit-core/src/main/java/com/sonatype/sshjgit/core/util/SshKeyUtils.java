package com.sonatype.sshjgit.core.util;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.mina.util.Base64;
import org.apache.sshd.common.util.Buffer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.List;

/**
 * <p>Utils related to ssh keys.</p>
 * <p>The {@code toPublicKey} methods need an implementation of slf4j, and one way to give them that is to depend on slf4j-simple in the project where you call these methods from:</p>
 * <pre>
 *      &lt;dependency>
 *          &lt;groupId>org.slf4j&lt;/groupId>
 *          &lt;artifactId>slf4j-simple&lt;/artifactId>
 *          &lt;version>1.4.3&lt;/version>
 *          &lt;scope>compile&lt;/scope>
 *      &lt;/dependency>
 * </pre>
 *
 * @author hugo@josefson.org
 */
public class SshKeyUtils {
    /**
     * Reads the first line of an {@code id_rsa.pub} file and parses it to a {@link PublicKey}.
     * @param file the {@code id_rsa.pub} file
     * @return a {@code PublicKey} instance
     * @throws IOException if there is a problem reading the file
     * @throws NoSuchAlgorithmException if {@link Buffer#getPublicKey()} has a problem with the key
     * @throws InvalidKeySpecException if {@link Buffer#getPublicKey()} has a problem with the key
     * @throws NoSuchProviderException if {@link Buffer#getPublicKey()} has a problem with the key
     */
    public static PublicKey toPublicKey(File file) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        List<String> lines = FileUtils.readLines(file);
        return toPublicKey(lines.get(0));
    }

    /**
     * Reads the first line of an {@code InputStream} from an {@code id_rsa.pub} fie and parses it to a {@link PublicKey}.
     * @param inputStream from the {@code id_rsa.pub} file
     * @return a {@code PublicKey} instance
     * @throws IOException if there is a problem reading the file
     * @throws NoSuchAlgorithmException if {@link Buffer#getPublicKey()} has a problem with the key
     * @throws InvalidKeySpecException if {@link Buffer#getPublicKey()} has a problem with the key
     * @throws NoSuchProviderException if {@link Buffer#getPublicKey()} has a problem with the key
     */
    public static PublicKey toPublicKey(InputStream inputStream) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        List<String> lines = IOUtils.readLines(inputStream);
        return toPublicKey(lines.get(0));
    }

    /**
     * Parses a line from an {@code id_rsa.pub} file to a {@link PublicKey}.
     * @param line the entire line of text from an {@code id_rsa.pub} file
     * @return a {@code PublicKey} instance
     * @throws NoSuchAlgorithmException if {@link Buffer#getPublicKey()} has a problem with the key
     * @throws InvalidKeySpecException if {@link Buffer#getPublicKey()} has a problem with the key
     * @throws NoSuchProviderException if {@link Buffer#getPublicKey()} has a problem with the key
     */
    public static PublicKey toPublicKey(String line) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
        final String base64encodedKey = extractKeyPart(line);
        final byte[] decodedKey = Base64.decodeBase64(base64encodedKey.getBytes());
        return new Buffer(decodedKey).getPublicKey();
    }

    /**
     * Extracts the key part from a line of text from an {@code id_rsa.pub} file.
     * @param idRsaPubLine an entire line of text from a public key file, such as {@code id_rsa.pub}
     * @return just the long base64 encoded part in the middle
     */
    public static String extractKeyPart(String idRsaPubLine) {
        return idRsaPubLine.split(" +")[1];
    }
}
