package com.psia.pkoc.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class SiteDto
{
    @NonNull
    public byte[] siteUUID;

    /**
     * Legacy per-site shared Site Key (65-byte uncompressed public key).
     *
     * <p>Retained for backward compatibility with the PKOC BLE 3.1.1
     * shared-Site-Key ECDHE flow (BLE Transport Profile 2.0.1, Appendix B).
     * On the per-reader path this is not used to verify the handshake; the
     * reader's key comes from a verified Reader Certificate instead.</p>
     */
    @NonNull
    public byte[] publicKey;

    /**
     * Per-site Trust Anchor for the per-reader (Validated) model: the Site
     * Issuer public key (65-byte uncompressed) provisioned to the device at
     * enrollment (BLE §6.2.1 / Core §6.3). Used to verify Reader Certificates
     * (TLV 0x10) and revocation lists.
     *
     * <p>{@code null} or empty means the per-reader anchor is not provisioned
     * for this site, in which case the device uses the legacy {@link #publicKey}
     * path (Appendix B).</p>
     */
    @Nullable
    public byte[] siteIssuerPublicKey;

    public SiteDto()
    {
        this.siteUUID = new byte[16];
        this.publicKey = new byte[65];
        this.siteIssuerPublicKey = null;
    }

    public SiteDto(@NonNull byte[] siteUUID, @NonNull byte[] publicKey)
    {
        this.siteUUID = siteUUID;
        this.publicKey = publicKey;
        this.siteIssuerPublicKey = null;
    }

    public SiteDto(@NonNull byte[] siteUUID, @NonNull byte[] publicKey, @Nullable byte[] siteIssuerPublicKey)
    {
        this.siteUUID = siteUUID;
        this.publicKey = publicKey;
        this.siteIssuerPublicKey = siteIssuerPublicKey;
    }

    /** Whether this site has a per-reader Trust Anchor (Site Issuer key) provisioned. */
    public boolean hasSiteIssuerKey()
    {
        return siteIssuerPublicKey != null && siteIssuerPublicKey.length > 0;
    }
}
