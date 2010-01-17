package com.sonatype.sshjgit.testsupport;

import com.sonatype.sshjgit.core.util.SshKeyUtils;
import org.apache.commons.lang.StringUtils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertTrue;
                
/**
 * Utility methods for testing.
 *
 * @author hugo@josefson.org
 */
public class TestUtils {
    public static File createNewTempFile() throws IOException {
        return createNewTempFile("");
    }

    /**
     * Creates a new temp file. It will automatically be deleted when the JVM shuts down.
     * @param identifier string identifier which will be added after {@code "sshjgit-"} in the filename.
     * @return the created temp file
     * @throws IOException in case there is a problem creating the file.
     */
    public static File createNewTempFile(String identifier) throws IOException {
        String prefix = "sshjgit-";
        if (!StringUtils.isBlank(identifier)){
            prefix += identifier + "-";
        }
        final File tempFile = File.createTempFile(prefix, "");
        tempFile.deleteOnExit();
        return tempFile;
    }

    /**
     * Creates a new temp directory. You need to delete it yourself {@link org.junit.After} your test.
     * @return the created directory.
     * @throws IOException in case there is a problem creating the directory.
     */
    public static File createNewTempDirectory() throws IOException {
        final File file = createNewTempFile();
        assertTrue(file.delete());
        assertTrue(file.mkdir());
        return file;
    }

    /**
     * Loads an ssh public key from classpath.
     * @param classpathResource Useful values for existing test keys are: {@code "/id_rsa.pub"}, {@code "/id_rsa2.pub"}
     * and {@code "/id_rsa3.pub"}.
     * @return the public key.
     * @throws NoSuchAlgorithmException in case {@link SshKeyUtils#toPublicKey} has any problem
     * reading/parsing/constructing the key.
     * @throws InvalidKeySpecException in case {@link SshKeyUtils#toPublicKey} has any problem
     * reading/parsing/constructing the key.
     * @throws NoSuchProviderException in case {@link SshKeyUtils#toPublicKey} has any problem
     * reading/parsing/constructing the key.
     * @throws IOException in case {@link SshKeyUtils#toPublicKey} has any problem reading/parsing/constructing the key.
     */
    public static PublicKey loadPublicKey(String classpathResource)
            throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        final InputStream inputStream = TestUtils.class.getResourceAsStream(classpathResource);
        return SshKeyUtils.toPublicKey(inputStream);
    }

}
