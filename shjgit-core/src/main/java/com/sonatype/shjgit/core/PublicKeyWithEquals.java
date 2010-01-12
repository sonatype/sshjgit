package com.sonatype.shjgit.core;

import java.security.PublicKey;
import java.util.Arrays;

/**
 * A {@link PublicKey} wrapper which implements {@code equals}, so they can be compared.
 *
 * @author hugo@josefson.org
 */
class PublicKeyWithEquals implements PublicKey {

    private final PublicKey key;

    /**
     * Constructs this wrapper with the specified key.
     * @param key the {@link PublicKey} to wrap.
     */
    public PublicKeyWithEquals(PublicKey key) {
        this.key = key;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof PublicKeyWithEquals)) return false;

        PublicKeyWithEquals that = (PublicKeyWithEquals) o;

        final String algorithm = getAlgorithm();
        final String thatAlgorithm = that.getAlgorithm();
        if (algorithm != null ? !algorithm.equals(thatAlgorithm) : thatAlgorithm != null)
            return false;

        if (!Arrays.equals(getEncoded(), that.getEncoded())) return false;

        final String format = getFormat();
        final String thatFormat = that.getFormat();
        if (format != null ? !format.equals(thatFormat) : thatFormat != null)
            return false;

        return true;
    }

    @Override
    public int hashCode() {
        final String algorithm = getAlgorithm();
        final String format = getFormat();
        final byte[] encoded = getEncoded();
        int result = algorithm != null ? algorithm.hashCode() : 0;
        result = 31 * result + (format != null ? format.hashCode() : 0);
        result = 31 * result + (encoded != null ? Arrays.hashCode(encoded) : 0);
        return result;
    }

    @Override
    public String getAlgorithm() {
        return key.getAlgorithm();
    }

    @Override
    public String getFormat() {
        return key.getFormat();
    }

    @Override
    public byte[] getEncoded() {
        return key.getEncoded();
    }
}
