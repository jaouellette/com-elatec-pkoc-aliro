package com.psia.pkoc.core;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class ReaderDto
{
    @Nullable
    public byte[] protocolVersion;

    @Nullable
    public byte[] readerTransientPublicKey;

    @NonNull
    public byte[] readerIdentifier;

    @NonNull
    public byte[] siteIdentifier;

    /**
     * Optional Site Issuer-signed Reader Certificate (138 bytes) associated with
     * this reader (PKOC BLE Transport Profile 2.0.1, §7.1).
     *
     * <p>On the reader/simulator side this is the certificate the reader presents
     * as TLV 0x10. On the device side it may hold a pinned/last-seen certificate.
     * {@code null} means no certificate is configured and the reader operates on
     * the legacy shared-Site-Key path (Appendix B).</p>
     */
    @Nullable
    public byte[] readerCertificate;

    public ReaderDto()
    {
        readerIdentifier = new byte[16];
        siteIdentifier = new byte[16];
    }

    public ReaderDto(
        @Nullable byte[] protocolVersion,
        @Nullable byte[] readerTransientPublicKey,
        @NonNull byte[] readerIdentifier,
        @NonNull byte[] siteIdentifier
    ) {
        this.protocolVersion = protocolVersion;
        this.readerTransientPublicKey = readerTransientPublicKey;
        this.readerIdentifier = readerIdentifier;
        this.siteIdentifier = siteIdentifier;
    }

    public ReaderDto(
        @Nullable byte[] protocolVersion,
        @Nullable byte[] readerTransientPublicKey,
        @NonNull byte[] readerIdentifier,
        @NonNull byte[] siteIdentifier,
        @Nullable byte[] readerCertificate
    ) {
        this.protocolVersion = protocolVersion;
        this.readerTransientPublicKey = readerTransientPublicKey;
        this.readerIdentifier = readerIdentifier;
        this.siteIdentifier = siteIdentifier;
        this.readerCertificate = readerCertificate;
    }

    /** Whether this reader has a Reader Certificate configured (per-reader path). */
    public boolean hasReaderCertificate()
    {
        return readerCertificate != null && readerCertificate.length > 0;
    }
}
