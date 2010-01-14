package com.sonatype.sshjgit.xstream;

import com.sonatype.sshjgit.core.util.SshKeyUtils;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Exercises the {@link XStreamFilePublicKeyRepository}.
 *
 * @author hugo@josefson.org
 */
public class XStreamFilePublicKeyRepositoryTest {
    protected File xmlFile;
    protected XStreamFilePublicKeyRepository repo;
    protected static final String UTF_8 = "UTF-8";

    @After
    public void tearDown(){
        FileUtils.deleteQuietly(xmlFile);
    }

    @Test
    public void givenNonExistingFileThenRepoConstructsSuccessfully() throws IOException {
        xmlFile = createNewTempFile();
        FileUtils.deleteQuietly(xmlFile);
        repo = new XStreamFilePublicKeyRepository(xmlFile);
    }

    @Test
    public void givenNonExistingFileThenFileHasEmptyMap() throws IOException {
        givenNonExistingFileThenRepoConstructsSuccessfully();
        final String contents = FileUtils.readFileToString(xmlFile, UTF_8);
        assertEquals("<map/>", contents);
    }

    @Test
    public void givenEmptyFileThenRepoConstructsSuccessfully() throws IOException {
        xmlFile = createNewTempFile();
        repo = new XStreamFilePublicKeyRepository(xmlFile);
    }

    @Test
    public void givenEmptyFileThenFileHasEmptyMap() throws IOException {
        givenEmptyFileThenRepoConstructsSuccessfully();
        final String contents = FileUtils.readFileToString(xmlFile, UTF_8);
        assertEquals("<map/>", contents);
    }

    @Test(expected = IllegalArgumentException.class)
    public void givenDirectoryThenRepoConstructionFails() throws IOException {
        xmlFile = createNewTempDirectory();
        repo = new XStreamFilePublicKeyRepository(xmlFile);
    }

    @Test
    public void givenEmptyFileAndConstructingOnceThenNewRepoCanLoadIt() throws IOException {
        givenEmptyFileThenFileHasEmptyMap();
        repo = new XStreamFilePublicKeyRepository(xmlFile);
    }

    @Test
    public void givenAddedOneKeyAndReloadedFileThenEqualKeyExists() throws IOException, NoSuchProviderException, InvalidKeySpecException, NoSuchAlgorithmException {
        givenEmptyFileThenFileHasEmptyMap();
        final PublicKey key = loadDefaultPublicKey();
        repo.addPublicKey("username", key);
        repo = new XStreamFilePublicKeyRepository(xmlFile);
        assertTrue(repo.getPublicKeys("username").contains(key));
    }

    protected File createNewTempFile() throws IOException {
        return File.createTempFile("ssshjgit-publickeys-", ".xml");
    }
    protected File createNewTempDirectory() throws IOException {
        final File file = createNewTempFile();
        assertTrue(file.delete());
        assertTrue(file.mkdir());
        return file;
    }

    private PublicKey loadDefaultPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {
        final InputStream inputStream = this.getClass().getResourceAsStream("/id_rsa.pub");
        return SshKeyUtils.toPublicKey(inputStream);
    }

}
