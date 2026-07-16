package com.psia.pkoc.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Reader Certificate Revocation List — PKOC BLE Transport Profile 2.0.1, §7.3.
 *
 * <p>A Site Issuer-signed list distributed over the provisioning channel that
 * revokes individual readers (by Reader Location Identifier) before their
 * certificates expire.</p>
 *
 * <pre>
 *  Field            Len   Description
 *  ---------------  ----  -----------------------------------------------------
 *  Version          1     0x01
 *  Issuer Id        16    Site Issuer that authored the list
 *  Issued Time      4     Unix epoch seconds, BE (rollback protection)
 *  Entry Count      2     Number of entries, BE
 *  Entries          20*n  16-byte Reader Location Identifier + 4-byte timestamp
 *  Signature        64    raw R||S, ECDSA-SHA256 by the Site Issuer over all
 *                         preceding fields
 * </pre>
 *
 * Before honoring a list the Device MUST verify its signature and MUST accept it
 * only if its Issued Time exceeds the cached list's Issued Time (§7.3).
 */
public final class ReaderRevocationList
{
    public static final int VERSION_1  = 0x01;
    public static final int ENTRY_SIZE = 20;   // 16-byte location id + 4-byte timestamp

    private final int version;
    private final byte[] issuerId;             // 16
    private final long issuedTime;             // unsigned 32-bit
    private final List<byte[]> revokedLocationIds; // each 16 bytes
    private final long[] revokedTimestamps;    // parallel to revokedLocationIds
    private final byte[] signature64;
    private final byte[] raw;

    private ReaderRevocationList(byte[] raw, int version, byte[] issuerId, long issuedTime,
                                 List<byte[]> ids, long[] timestamps, byte[] signature64)
    {
        this.raw = raw;
        this.version = version;
        this.issuerId = issuerId;
        this.issuedTime = issuedTime;
        this.revokedLocationIds = ids;
        this.revokedTimestamps = timestamps;
        this.signature64 = signature64;
    }

    /** An empty, unsigned list — a safe default before any list has been provisioned. */
    public static ReaderRevocationList empty(byte[] issuerId16)
    {
        return new ReaderRevocationList(new byte[0], VERSION_1,
                issuerId16 != null ? issuerId16.clone() : new byte[16],
                0L, new ArrayList<>(), new long[0], new byte[64]);
    }

    // ---------------------------------------------------------------------
    // Parsing
    // ---------------------------------------------------------------------

    @Nullable
    public static ReaderRevocationList parse(byte[] data)
    {
        if (data == null)
        {
            return null;
        }
        int fixed = 1 + 16 + 4 + 2; // version + issuer + issuedTime + count
        if (data.length < fixed + 64)
        {
            return null;
        }
        ByteBuffer buf = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN);
        int version = buf.get() & 0xFF;
        byte[] issuerId = new byte[16];
        buf.get(issuerId);
        long issuedTime = buf.getInt() & 0xFFFFFFFFL;
        int count = buf.getShort() & 0xFFFF;

        int expectedLen = fixed + count * ENTRY_SIZE + 64;
        if (data.length != expectedLen)
        {
            return null;
        }

        List<byte[]> ids = new ArrayList<>(count);
        long[] timestamps = new long[count];
        for (int i = 0; i < count; i++)
        {
            byte[] id = new byte[16];
            buf.get(id);
            ids.add(id);
            timestamps[i] = buf.getInt() & 0xFFFFFFFFL;
        }
        byte[] sig = new byte[64];
        buf.get(sig);

        return new ReaderRevocationList(data.clone(), version, issuerId, issuedTime, ids, timestamps, sig);
    }

    // ---------------------------------------------------------------------
    // Construction (reader/simulator + self-tests)
    // ---------------------------------------------------------------------

    /**
     * Build and sign a revocation list with the Site Issuer private key.
     *
     * @param issuerId16          16-byte Site Issuer Identifier
     * @param issuedTimeEpochSecs issued time (must exceed any prior list's time)
     * @param revokedLocationIds  list of 16-byte Reader Location Identifiers
     * @param revokedTimestamps   parallel revocation timestamps (epoch seconds)
     * @param siteIssuerPrivate   Site Issuer private key
     * @return a signed {@code ReaderRevocationList}, or {@code null} on failure
     */
    @Nullable
    public static ReaderRevocationList buildAndSign(
            @NonNull byte[] issuerId16,
            long issuedTimeEpochSecs,
            @NonNull List<byte[]> revokedLocationIds,
            @NonNull long[] revokedTimestamps,
            @NonNull PrivateKey siteIssuerPrivate)
    {
        if (issuerId16.length != 16 || revokedLocationIds.size() != revokedTimestamps.length)
        {
            return null;
        }
        int count = revokedLocationIds.size();
        int bodyLen = 1 + 16 + 4 + 2 + count * ENTRY_SIZE;
        ByteBuffer buf = ByteBuffer.allocate(bodyLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) VERSION_1);
        buf.put(issuerId16);
        buf.putInt((int) (issuedTimeEpochSecs & 0xFFFFFFFFL));
        buf.putShort((short) count);
        for (int i = 0; i < count; i++)
        {
            byte[] id = revokedLocationIds.get(i);
            if (id.length != 16)
            {
                return null;
            }
            buf.put(id);
            buf.putInt((int) (revokedTimestamps[i] & 0xFFFFFFFFL));
        }
        byte[] body = buf.array();

        byte[] sig = EcKeyUtil.signRaw(siteIssuerPrivate, body);
        if (sig == null || sig.length != 64)
        {
            return null;
        }
        byte[] full = new byte[body.length + 64];
        System.arraycopy(body, 0, full, 0, body.length);
        System.arraycopy(sig, 0, full, body.length, 64);
        return parse(full);
    }

    // ---------------------------------------------------------------------
    // Verification / queries
    // ---------------------------------------------------------------------

    /**
     * Verify the list signature against the Site Issuer public key (§7.3).
     * Only meaningful for a parsed (non-empty) list.
     */
    public boolean verifySignature(byte[] siteIssuerPublicKey)
    {
        if (raw.length < 64)
        {
            return false; // empty/default list has no signature to verify
        }
        byte[] body = Arrays.copyOfRange(raw, 0, raw.length - 64);
        return EcKeyUtil.verifyRaw(siteIssuerPublicKey, body, signature64);
    }

    /**
     * Rollback protection (§7.3): a newer list is accepted only if its Issued
     * Time strictly exceeds the currently cached list's Issued Time.
     */
    public boolean isNewerThan(@Nullable ReaderRevocationList cached)
    {
        return cached == null || this.issuedTime > cached.issuedTime;
    }

    /** Whether a given 16-byte Reader Location Identifier is revoked (error 0x08). */
    public boolean isRevoked(byte[] readerLocationId)
    {
        if (readerLocationId == null)
        {
            return false;
        }
        for (byte[] id : revokedLocationIds)
        {
            if (Arrays.equals(id, readerLocationId))
            {
                return true;
            }
        }
        return false;
    }

    public int getVersion()      { return version; }
    public byte[] getIssuerId()  { return issuerId.clone(); }
    public long getIssuedTime()  { return issuedTime; }
    public int getEntryCount()   { return revokedLocationIds.size(); }
    public byte[] encode()       { return raw.clone(); }
}
