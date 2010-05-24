package com.sonatype.sshjgit.xstream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import junit.framework.Assert;

import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Test;
import org.sonatype.security.realms.publickey.PublicKeyRepository;
import org.sonatype.security.realms.publickey.PublicKeyRepositoryTest;

import com.sonatype.sshjgit.testsupport.TestUtils;

/**
 * Exercises the {@link XStreamFilePublicKeyRepository}.
 *
 * @author hugo@josefson.org
 */
public class XStreamFilePublicKeyRepositoryTest extends PublicKeyRepositoryTest {
    protected File xmlFile;
    protected XStreamFilePublicKeyRepository repo;
    protected static final String UTF_8 = "UTF-8";

    @After
    public void tearDown(){
        FileUtils.deleteQuietly(xmlFile);
    }
    
    protected PublicKeyRepository getPublicKeyRepository()
    {
        try
        {
            givenEmptyFileThenFileHasEmptyMap();
        }
        catch ( IOException e )
        {
            Assert.fail( "Failed to construct xml file for PublicKey storage." );
        }
        return new XStreamFilePublicKeyRepository(xmlFile);
    }

    @Test
    public void givenNonExistingFileThenRepoConstructsSuccessfully() throws IOException {
        xmlFile = TestUtils.createNewTempFile("publickeys");
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
        xmlFile = TestUtils.createNewTempFile("publickeys");
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
        xmlFile = TestUtils.createNewTempDirectory();
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
        final PublicKey key = TestUtils.loadPublicKey("/id_rsa.pub");
        repo.addPublicKey("username", key);
        repo = new XStreamFilePublicKeyRepository(xmlFile);
        assertTrue(repo.getPublicKeys("username").contains(key));
    }

    @Test
    public void givenAddedTwoKeysAndReloadedFileThenBothKeysExists() throws IOException, NoSuchProviderException, InvalidKeySpecException, NoSuchAlgorithmException {
        givenEmptyFileThenFileHasEmptyMap();
        final PublicKey key1 = TestUtils.loadPublicKey("/id_rsa.pub");
        final PublicKey key2 = TestUtils.loadPublicKey("/id_rsa2.pub");
        repo.addPublicKey("username", key1);
        repo.addPublicKey("username", key2);
        repo = new XStreamFilePublicKeyRepository(xmlFile);
        assertTrue(repo.getPublicKeys("username").contains(key1));
        assertTrue(repo.getPublicKeys("username").contains(key2));
    }

    @Test
    public void givenAddedKeysToDifferentUsersAndReloadedFileThenKeysExistsInCorrectUserAndNotIncorrectUser() throws IOException, NoSuchProviderException, InvalidKeySpecException, NoSuchAlgorithmException {
        givenEmptyFileThenFileHasEmptyMap();
        final PublicKey key1 = TestUtils.loadPublicKey("/id_rsa.pub");
        final PublicKey key2 = TestUtils.loadPublicKey("/id_rsa2.pub");
        final PublicKey key3 = TestUtils.loadPublicKey("/id_rsa3.pub");
        repo.addPublicKey("username1", key1);
        repo.addPublicKey("username2", key2);
        repo.addPublicKey("username1", key3);
        repo = new XStreamFilePublicKeyRepository(xmlFile);

        assertTrue(repo.getPublicKeys("username1").contains(key1));
        assertFalse(repo.getPublicKeys("username1").contains(key2));
        assertTrue(repo.getPublicKeys("username1").contains(key3));

        assertFalse(repo.getPublicKeys("username2").contains(key1));
        assertTrue(repo.getPublicKeys("username2").contains(key2));
        assertFalse(repo.getPublicKeys("username2").contains(key3));
    }

}
