package com.psia.pkoc.core.transactions;

import static com.psia.pkoc.core.CryptoProvider.CreateTransientKeyPair;
import static com.psia.pkoc.core.CryptoProvider.getSharedSecret;

import android.app.Activity;
import android.util.Log;

import androidx.annotation.Nullable;

import com.psia.pkoc.core.BLE_Packet;
import com.psia.pkoc.core.CryptoProvider;
import com.psia.pkoc.core.PkocBleTrustStore;
import com.psia.pkoc.core.ReaderCertificate;
import com.psia.pkoc.core.ReaderCertificateCache;
import com.psia.pkoc.core.ReaderDto;
import com.psia.pkoc.core.ReaderRevocationList;
import com.psia.pkoc.core.SiteDto;
import com.psia.pkoc.core.TLVProvider;
import com.psia.pkoc.core.ValidationResult;
import com.psia.pkoc.core.messages.DeviceEncryptedCredentialMessage;
import com.psia.pkoc.core.messages.DeviceIdentifierMessage;
import com.psia.pkoc.core.messages.ReaderDigitalSignatureMessage;
import com.psia.pkoc.core.messages.ReaderIdentifierMessage;
import com.psia.pkoc.core.messages.ReaderResponseMessage;
import com.psia.pkoc.core.packets.DeviceEphemeralPublicKeyPacket;
import com.psia.pkoc.core.packets.LastUpdateTimePacket;
import com.psia.pkoc.core.packets.ProtocolVersionPacket;
import com.psia.pkoc.core.packets.ReaderCertificatePacket;
import com.psia.pkoc.core.validations.ReaderCertificateInvalidResult;
import com.psia.pkoc.core.validations.ReaderCertificateRevokedResult;
import com.psia.pkoc.core.validations.SuccessResult;
import com.psia.pkoc.core.validations.UnexpectedPacketResult;
import com.psia.pkoc.core.validations.UnrecognizedReaderResult;

import org.bouncycastle.util.Arrays;

import java.security.KeyPair;
import java.util.ArrayList;

public class BleEcdheFlowTransaction extends BleNormalFlowTransaction
{
    private static final String TAG = "BleEcdheFlowTransaction";

    // Process-wide discovery-and-pin cache (PKOC BLE Transport Profile 2.0.1 §7.2).
    // Static so pins persist across short-lived transactions. Optional accelerator
    // only — it never changes the security outcome.
    private static final ReaderCertificateCache PIN_CACHE = new ReaderCertificateCache();

    // Optional cached revocation list (§7.3), provisioned out-of-band. When null,
    // no reader is treated as revoked. Set via setRevocationList(...).
    @Nullable
    private static volatile ReaderRevocationList revocationList = null;

    /**
     * Provision (or replace) the cached Reader Certificate revocation list.
     * The caller is expected to have verified its signature and rollback ordering
     * (see {@link ReaderRevocationList#verifySignature} / {@link ReaderRevocationList#isNewerThan}).
     */
    public static void setRevocationList(@Nullable ReaderRevocationList list)
    {
        revocationList = list;
    }

    private byte[] sharedSecret;
    private byte[] sitePublicKey;
    private ReaderIdentifierMessage<BLE_Packet> readerIdentifierMessage;
    private final ArrayList<SiteDto> siteDtos;
    private final ArrayList<ReaderDto> readerDtos;
    private int counter = 1;
    private final Activity activity;
    private DeviceEphemeralPublicKeyPacket deviceEphemeralPublicKeyPacket;

    public BleEcdheFlowTransaction(boolean _isDevice, ArrayList<SiteDto> _siteDtos, ArrayList<ReaderDto> _readerDtos, Activity _activity)
    {
        super(_isDevice, _activity);
        siteDtos = _siteDtos;
        readerDtos = _readerDtos;
        activity = _activity;
        Log.d(TAG, "Constructor called. siteDtos count: " + siteDtos.size() + ", readerDtos count: " + readerDtos.size());
    }

    @Override
    public ValidationResult processNewData(byte[] packets)
    {
        Log.d(TAG, "processNewData called with data length: " + (packets != null ? packets.length : "null"));
        java.util.ArrayList<BLE_Packet> __parsed = TLVProvider.GetBleValues(packets);
        for (int __i = 0; __i < __parsed.size(); __i++)
        {
            var packet = __parsed.get(__i);
            Log.d(TAG, "Processing packet: " + packet.PacketType + ". Current message type: " + currentMessage.getClass().getSimpleName());
            if (currentMessage instanceof ReaderIdentifierMessage)
            {
                readerIdentifierMessage = (ReaderIdentifierMessage<BLE_Packet>) currentMessage;
                ValidationResult vr = readerIdentifierMessage.processNewPacket(packet);

                if (!vr.isValid)
                {
                    return vr;
                }

                var messageValidation = readerIdentifierMessage.validate();
                if (messageValidation.isValid)
                {
                    // The four base fields validate after SiteIdentifier, but an
                    // optional ReaderCertificate (TLV 0x10) may follow in the same
                    // buffer. Keep consuming until the last packet so the cert is
                    // seen before we choose the per-reader vs legacy path.
                    if (__i < __parsed.size() - 1)
                    {
                        continue;
                    }
                    Log.i(TAG, "ReaderIdentifierMessage validated successfully. Checking site and reader recognition.");
                    SiteDto matchedSite = null;
                    for (SiteDto siteDto : siteDtos)
                    {
                        if(java.util.Arrays.equals(siteDto.siteUUID, readerIdentifierMessage.getSiteId().encode()))
                        {
                            matchedSite = siteDto;
                            sitePublicKey = siteDto.publicKey;
                            Log.i(TAG, "Site recognized.");
                            break;
                        }
                    }

                    if (matchedSite == null)
                    {
                        Log.w(TAG, "Site ID not recognized.");
                        return new UnrecognizedReaderResult();
                    }

                    boolean readerIdFound = false;
                    for (ReaderDto readerDto : readerDtos)
                    {
                        if(java.util.Arrays.equals(readerDto.readerIdentifier, readerIdentifierMessage.getReaderLocationId().encode()) &&
                           java.util.Arrays.equals(readerDto.siteIdentifier, readerIdentifierMessage.getSiteId().encode()))
                        {
                            readerIdFound = true;
                            Log.i(TAG, "Reader recognized.");
                            break;
                        }
                    }

                    if(!readerIdFound)
                    {
                        Log.w(TAG, "Reader ID not recognized.");
                        return new UnrecognizedReaderResult();
                    }

                    // ----------------------------------------------------------------
                    // Select the key that will verify the reader's handshake signature.
                    //  - Per-reader (Validated) path: a Reader Certificate (TLV 0x10) is
                    //    present AND the site has a Site Issuer trust anchor. Verify the
                    //    certificate and use its Reader Public Key.
                    //  - Legacy path (Appendix B): no certificate / no anchor -> keep the
                    //    shared Site Key exactly as before.
                    // ----------------------------------------------------------------
                    byte[] readerVerifyKey = sitePublicKey;
                    ReaderCertificatePacket certPacket = readerIdentifierMessage.getReaderCertificate();

                    // Resolve the Site Issuer trust anchor. Prefer the value carried on
                    // the SiteDto (populated by the caller from PkocBleTrustStore); fall
                    // back to reading the trust store directly here. The direct read makes
                    // the per-reader decision independent of caller wiring / cross-module
                    // build state — a scanned anchor is always honoured.
                    byte[] siteIssuerAnchor = matchedSite.hasSiteIssuerKey()
                            ? matchedSite.siteIssuerPublicKey
                            : null;
                    if (siteIssuerAnchor == null && activity != null)
                    {
                        siteIssuerAnchor = PkocBleTrustStore.getSiteIssuerKey(activity, matchedSite.siteUUID);
                    }

                    boolean certPresent = certPacket != null;
                    boolean anchorPresent = siteIssuerAnchor != null;
                    Log.i(TAG, "Per-reader gate: certPresent=" + certPresent + ", anchorPresent=" + anchorPresent
                            + " (dtoAnchor=" + matchedSite.hasSiteIssuerKey()
                            + ", trustStore=" + (activity != null && PkocBleTrustStore.hasSiteIssuerKey(activity, matchedSite.siteUUID)) + ").");

                    if (certPresent && anchorPresent)
                    {
                        ValidationResult certResult = verifyReaderCertificate(certPacket, siteIssuerAnchor);
                        if (!certResult.isValid)
                        {
                            return certResult;
                        }
                        ReaderCertificate cert = certPacket.toReaderCertificate();
                        readerVerifyKey = cert.getReaderPublicKeyUncompressed();
                        Log.i(TAG, "Per-reader certificate accepted; verifying handshake against Reader Public Key.");
                    }
                    else
                    {
                        Log.i(TAG, "Legacy shared-Site-Key path (no certificate / no Site Issuer anchor).");
                    }

                    Log.d(TAG, "Generating transient key pair and shared secret.");
                    KeyPair transientKeyPair = CreateTransientKeyPair();
                    assert transientKeyPair != null;
                    byte[] rawSharedSecret = getSharedSecret(
                            transientKeyPair.getPrivate(),
                            readerIdentifierMessage.getCompressedKey().encode());

                    sharedSecret = CryptoProvider.deriveAesKeyFromSharedSecretSimple(rawSharedSecret);

                    var publicKeyDes = transientKeyPair.getPublic().getEncoded();
                    var publicKey = CryptoProvider.getUncompressedPublicKeyBytes(publicKeyDes);
                    deviceEphemeralPublicKeyPacket = new DeviceEphemeralPublicKeyPacket(publicKey);
                    var protocolVersionPacket = new ProtocolVersionPacket(readerIdentifierMessage.getProtocolVersion().encode());

                    var deviceIdentifierMessage = new DeviceIdentifierMessage(deviceEphemeralPublicKeyPacket, protocolVersionPacket);
                    toWrite = deviceIdentifierMessage.encodePackets();

                    byte[] deviceX = CryptoProvider.getPublicKeyComponentX(publicKeyDes);
                    byte[] readerPk = readerIdentifierMessage.getCompressedKey().encode();
                    byte[] readerX = new byte[32];
                    java.lang.System.arraycopy(readerPk, 1, readerX, 0, 32);

                    byte[] originalMessage = Arrays.concatenate(readerIdentifierMessage.getSiteId().encode(), readerIdentifierMessage.getReaderLocationId().encode(), deviceX, readerX);

                    Log.i(TAG, "Transitioning to ReaderDigitalSignatureMessage.");
                    currentMessage = new ReaderDigitalSignatureMessage(readerVerifyKey, originalMessage);
                    return new SuccessResult();
                }
                else if (messageValidation.cancelTransaction)
                {
                    Log.w(TAG, "Transaction cancelled during ReaderIdentifierMessage validation.");
                    return messageValidation;
                }
            }
            else if (currentMessage instanceof ReaderDigitalSignatureMessage)
            {
                var readerDigitalSignatureMessage = (ReaderDigitalSignatureMessage) currentMessage;
                var vr = readerDigitalSignatureMessage.processNewPacket(packet);

                if (!vr.isValid)
                {
                    return vr;
                }

                var messageValidation = readerDigitalSignatureMessage.validate();
                if (messageValidation.isValid)
                {
                    Log.i(TAG, "ReaderDigitalSignatureMessage validated successfully.");

                    byte[] toSign = Arrays.concatenate(
                        readerIdentifierMessage.getSiteId().encode(),
                        readerIdentifierMessage.getReaderLocationId().encode(),
                        deviceEphemeralPublicKeyPacket.getX(),
                        readerIdentifierMessage.getCompressedKey().getX()
                    );

                    var deviceEncryptedCredentialMessage = new DeviceEncryptedCredentialMessage(
                            toSign,
                            readerIdentifierMessage.getProtocolVersion(),
                            sharedSecret,
                            counter,
                            new LastUpdateTimePacket(CryptoProvider.getLastUpdateTime(activity))
                    );
                    toWrite = deviceEncryptedCredentialMessage.encodePackets();
                    counter++;
                    Log.i(TAG, "Transitioning to ReaderResponseMessage.");
                    currentMessage = new ReaderResponseMessage<>();
                    return new SuccessResult();
                }
                else if (messageValidation.cancelTransaction)
                {
                    Log.w(TAG, "Transaction cancelled during ReaderDigitalSignatureMessage validation.");
                    return messageValidation;
                }
            }
            else if (currentMessage instanceof ReaderResponseMessage)
            {
                var readerResponseMessage = (ReaderResponseMessage<BLE_Packet>) currentMessage;
                var vr = readerResponseMessage.processNewPacket(packet);

                if (!vr.isValid)
                {
                    return vr;
                }

                var messageValidation = readerResponseMessage.validate();
                if (messageValidation.isValid)
                {
                    Log.i(TAG, "ReaderResponseMessage validated successfully. Transaction complete.");
                    return new SuccessResult();
                }
                else if (messageValidation.cancelTransaction)
                {
                    Log.w(TAG, "Transaction cancelled during ReaderResponseMessage validation.");
                    return messageValidation;
                }
            }
        }
        Log.e(TAG, "No more packets to process, but transaction is not complete.");
        return new UnexpectedPacketResult();
    }

    /**
     * Verify a presented Reader Certificate against the recognized site's Site
     * Issuer trust anchor, applying discovery-and-pin (§7.2) and revocation (§7.3).
     */
    private ValidationResult verifyReaderCertificate(ReaderCertificatePacket certPacket, byte[] siteIssuerAnchor)
    {
        ReaderCertificate cert = certPacket.toReaderCertificate();
        if (cert == null)
        {
            return new ReaderCertificateInvalidResult("Reader Certificate could not be parsed.");
        }

        byte[] expectedLocationId = readerIdentifierMessage.getReaderLocationId().encode();
        byte[] expectedIssuerId = readerIdentifierMessage.getSiteId().encode();
        long now = System.currentTimeMillis() / 1000L;

        // Revocation is always enforced, even on a pin hit (§7.2/§7.3).
        ReaderRevocationList rl = revocationList;
        if (rl != null && rl.isRevoked(expectedLocationId))
        {
            Log.w(TAG, "Reader Certificate is revoked.");
            return new ReaderCertificateRevokedResult();
        }

        // Fast path: pinned, fingerprint-identical, unexpired -> skip signature re-check.
        if (PIN_CACHE.isPinned(cert, now))
        {
            Log.d(TAG, "Reader Certificate matched a pinned entry (discovery-and-pin).");
            return new SuccessResult();
        }

        // Full verification against the Site Issuer trust anchor.
        ValidationResult certResult = cert.verify(expectedLocationId, expectedIssuerId, siteIssuerAnchor, now);
        if (!certResult.isValid)
        {
            return certResult;
        }

        // Pin for subsequent encounters.
        PIN_CACHE.put(cert);
        return new SuccessResult();
    }
}
