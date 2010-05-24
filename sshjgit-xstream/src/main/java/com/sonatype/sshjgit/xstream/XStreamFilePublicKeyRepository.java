package com.sonatype.sshjgit.xstream;

import java.io.File;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import org.apache.commons.io.FileUtils;
import org.sonatype.security.realms.publickey.SimplePublicKeyRepository;

import com.thoughtworks.xstream.XStream;

/**
 * Stores and loads keys crudely in a file, using XStream.
 *
 * @author hugo@josefson.org
 */
public class XStreamFilePublicKeyRepository extends SimplePublicKeyRepository {
    private static final String                 ENCODING = "UTF-8";
    private        final File                   storageFile;
    private        final ReentrantReadWriteLock storageFileLock = new ReentrantReadWriteLock();

    public XStreamFilePublicKeyRepository(File storageFile) {
        this.storageFile = storageFile;
        if (storageFile.exists() && !storageFile.isFile()){
            throw new IllegalArgumentException("storage file must be a file.");
        }
        if (storageFile.exists() && storageFile.length() > 0) {
            loadFromFile();
        } else {
            saveToFile();
        }
    }

    @Override
    public void addPublicKeys(Object principal, Set<PublicKey> publicKeys) {
        super.addPublicKeys(principal, publicKeys);
        saveToFile();
    }

    @Override
    public void removePublicKey(Object principal, PublicKey publicKey) {
        super.removePublicKey(principal, publicKey);
        saveToFile();
    }

    private void loadFromFile() {
        accountsLock.writeLock().lock();
        try {
            final String xml;
            // using the file's writelock on purpose here, because we never want to mess with the file from two angles at the same time at all.
            storageFileLock.writeLock().lock();
            try {
                xml = FileUtils.readFileToString(storageFile, ENCODING);
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                storageFileLock.writeLock().unlock();
            }

            final Map<Object, Set<PublicKey>> loadedAccounts = (Map<Object, Set<PublicKey>>) new XStream().fromXML(xml);

            accounts.clear();
            accounts.putAll(loadedAccounts);
        } finally {
            accountsLock.writeLock().unlock();
        }
    }

    private void saveToFile() {
        final String xml;

        accountsLock.readLock().lock();
        try {
            xml = new XStream().toXML(accounts);
        } finally {
            accountsLock.readLock().unlock();
        }

        storageFileLock.writeLock().lock();
        try {
            FileUtils.writeStringToFile(storageFile, xml, ENCODING);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            storageFileLock.writeLock().unlock();
        }
    }
}
