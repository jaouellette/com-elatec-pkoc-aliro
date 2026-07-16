package com.psia.pkoc.core;

import androidx.annotation.Nullable;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Discovery-and-pin certificate cache — PKOC BLE Transport Profile 2.0.1, §7.2.
 *
 * <p>An OPTIONAL performance optimization: after a reader's identity is
 * established through full certificate verification on first encounter, the
 * device may pin the reader's public key for fast verification on later
 * encounters. It is explicitly <em>not</em> a trust mechanism — an attacker
 * cannot forge a certificate that both matches a legitimate fingerprint and
 * verifies against the Site Issuer key.</p>
 *
 * <p>Keyed by Reader Location Identifier; devices SHOULD cache at least 256
 * readers with LRU eviction (§7.2). This class stores the pinned material only;
 * revocation is always checked separately against the live revocation list by
 * the caller.</p>
 */
public final class ReaderCertificateCache
{
    /** Recommended minimum capacity per §7.2. */
    public static final int DEFAULT_CAPACITY = 256;

    /** A single pinned entry (§7.2 cache fields). */
    public static final class Entry
    {
        public final byte[] readerLocationId;   // 16 (cache key)
        public final byte[] readerPublicKey33;  // compressed P-256, from the certificate
        public final byte[] siteIssuerId;       // 16 (anchor the entry was verified against)
        public final byte[] certificateFingerprint; // 32 (SHA-256 over the 138-byte cert)
        public final long   notAfter;           // entry expiry, copied from the certificate

        public Entry(byte[] readerLocationId, byte[] readerPublicKey33,
                     byte[] siteIssuerId, byte[] certificateFingerprint, long notAfter)
        {
            this.readerLocationId = readerLocationId.clone();
            this.readerPublicKey33 = readerPublicKey33.clone();
            this.siteIssuerId = siteIssuerId.clone();
            this.certificateFingerprint = certificateFingerprint.clone();
            this.notAfter = notAfter;
        }
    }

    private final int capacity;
    private final LinkedHashMap<String, Entry> map;

    public ReaderCertificateCache()
    {
        this(DEFAULT_CAPACITY);
    }

    public ReaderCertificateCache(int capacity)
    {
        this.capacity = Math.max(1, capacity);
        // access-order LinkedHashMap gives us LRU eviction for free.
        this.map = new LinkedHashMap<String, Entry>(16, 0.75f, true)
        {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, ReaderCertificateCache.Entry> eldest)
            {
                return size() > ReaderCertificateCache.this.capacity;
            }
        };
    }

    /** Pin (or refresh) an entry derived from a fully verified certificate. */
    public void put(ReaderCertificate cert)
    {
        Entry e = new Entry(
                cert.getSubjectLocationId(),
                cert.getReaderPublicKeyCompressed(),
                cert.getIssuerId(),
                cert.fingerprint(),
                cert.getNotAfter());
        map.put(key(e.readerLocationId), e);
    }

    /** Retrieve a pinned entry for a Reader Location Identifier, or {@code null}. */
    @Nullable
    public Entry get(byte[] readerLocationId)
    {
        if (readerLocationId == null)
        {
            return null;
        }
        return map.get(key(readerLocationId));
    }

    /**
     * Discovery-and-pin hit test (§7.2). Returns {@code true} only when the
     * presented certificate matches a pinned entry exactly: same fingerprint,
     * same Site Issuer, and Not-After still in the future. On a hit the device
     * MAY skip full signature verification and use the pinned key. The caller
     * still performs the revocation check separately.
     *
     * <p>Any mismatch (especially a fingerprint change from a replaced reader,
     * BLE Appendix A.6) is a miss and forces full re-verification followed by
     * {@link #put(ReaderCertificate)}.</p>
     */
    public boolean isPinned(ReaderCertificate presented, long nowEpochSeconds)
    {
        Entry e = get(presented.getSubjectLocationId());
        if (e == null)
        {
            return false;
        }
        if (!Arrays.equals(e.certificateFingerprint, presented.fingerprint()))
        {
            return false;
        }
        if (!Arrays.equals(e.siteIssuerId, presented.getIssuerId()))
        {
            return false;
        }
        return e.notAfter == ReaderCertificate.NOT_AFTER_FOREVER || nowEpochSeconds <= e.notAfter;
    }

    public int size()  { return map.size(); }
    public void clear() { map.clear(); }

    private static String key(byte[] locationId)
    {
        StringBuilder sb = new StringBuilder(locationId.length * 2);
        for (byte b : locationId)
        {
            sb.append(Character.forDigit((b >> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }
        return sb.toString();
    }
}
