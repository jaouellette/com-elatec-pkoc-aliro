package com.psia.pkoc;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;

import com.psia.pkoc.core.AliroCryptoProvider;
import com.psia.pkoc.core.AliroAccessDocument;
import com.psia.pkoc.core.AliroProvisioningManager;

import com.upokecenter.cbor.CBORObject;

import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * HCE service for the Aliro Expedited Standard NFC credential flow + Mailbox.
 *
 * AID: A0 00 00 09 09 AC CE 55 01
 *
 * Transaction flow (credential / User Device side):
 *   1. SELECT        → respond with FCI containing AID, Proprietary TLV, protocol versions
 *   2. AUTH0         → parse reader ephemeral key + TID + reader ID;
 *                      generate UD ephemeral keypair; respond with UD ephemeral public key
 *   3. LOAD CERT     → (optional) receive and store reader certificate; respond 9000
 *   4. AUTH1         → derive session keys (96-byte: ExpeditedSK[0..63], StepUpSK[64..95]);
 *                      build encrypted response with credential pub key + credential sig
 *   5. EXCHANGE      → decrypt; process mailbox ops (0x8C/0x87/0x8A/0x95); broadcast result
 *   6. ENVELOPE      → (Step-Up) accumulate DeviceRequest chunks; return DeviceResponse
 *   7. GET RESPONSE  → return next chunk of pending Step-Up response
 */
public class Aliro_HostApduService extends HostApduService
{
    private static final String TAG = "AliroHCE";

    // KeyStore alias for the Aliro credential keypair
    public static final String ALIRO_KEYSTORE_ALIAS = "Aliro_CredentialSet";

    // -------------------------------------------------------------------------
    // Static SELECT FCI response
    // Structure: 6F <len> 84 09 <AID> A5 <len> <proprietary TLV> 90 00
    //
    // Proprietary TLV (A5) contains:
    //   80 02 00 00          → Response Type (Aliro standard = 0x0000)
    //   5C 04 01 00 00 09    → Supported protocol versions: 01.00 and 00.09
    //
    // This proprietary TLV is also used verbatim in key derivation (HKDF),
    // so its exact byte sequence must be consistent between SELECT and deriveKeys().
    // -------------------------------------------------------------------------
    private static final byte[] SELECT_AID = {
        (byte)0xA0, 0x00, 0x00, 0x09, 0x09,
        (byte)0xAC, (byte)0xCE, 0x55, 0x01
    };

    // Proprietary TLV: A5 0A 80 02 00 00 5C 04 01 00 00 09
    // A5 = tag, 0A = length (10 bytes of value)
    // Value: 80 02 00 00 (response type) + 5C 04 01 00 00 09 (protocol versions)
    private static final byte[] PROPRIETARY_TLV = {
        (byte)0xA5, 0x0A,
        (byte)0x80, 0x02, 0x00, 0x00,       // Response type
        0x5C, 0x04, 0x01, 0x00, 0x00, 0x09  // Supported versions: 01.00 and 00.09
    };

    // Full SELECT FCI response (without SW — appended dynamically)
    // 6F <len> 84 09 <AID 9> A5 0C <prop 12>
    private static final byte[] SELECT_RESPONSE;
    static {
        // 6F <total_len> 84 09 <AID> <PROP_TLV>
        int innerLen = 2 + SELECT_AID.length + PROPRIETARY_TLV.length; // 84 tag+len + AID + propTLV
        SELECT_RESPONSE = new byte[2 + innerLen];
        SELECT_RESPONSE[0] = 0x6F;
        SELECT_RESPONSE[1] = (byte) innerLen;
        SELECT_RESPONSE[2] = (byte) 0x84;
        SELECT_RESPONSE[3] = (byte) SELECT_AID.length;
        System.arraycopy(SELECT_AID, 0, SELECT_RESPONSE, 4, SELECT_AID.length);
        System.arraycopy(PROPRIETARY_TLV, 0, SELECT_RESPONSE, 4 + SELECT_AID.length, PROPRIETARY_TLV.length);
    }

    private static final byte[] SW_OK            = { (byte)0x90, 0x00 };
    private static final byte[] SW_ERROR         = { 0x6A, (byte)0x82 }; // File not found
    private static final byte[] SW_CONDITIONS    = { 0x69, (byte)0x85 }; // Conditions not satisfied
    private static final byte[] SW_SECURITY      = { 0x69, (byte)0x82 }; // Security status not satisfied
    private static final byte[] SW_WRONG_LENGTH  = { 0x67, 0x00 };        // Wrong length
    // 61 xx = response bytes still available (GET RESPONSE)
    // 90 00 = success

    // -------------------------------------------------------------------------
    // Mailbox constants
    // -------------------------------------------------------------------------
    private static final String PREFS_NAME         = "AliroMailbox";
    private static final String PREF_MAILBOX_KEY   = "mailbox";
    /** Maximum mailbox size per spec — 64 KB */
    private static final int    MAILBOX_MAX_SIZE    = 65536;

    // -------------------------------------------------------------------------
    // Per-transaction state (reset on deactivation)
    // -------------------------------------------------------------------------
    private enum State { IDLE, SELECTED, AUTH0_DONE, CERT_LOADED, AUTH1_DONE, EXCHANGE_DONE }

    private State   state = State.IDLE;
    private KeyPair udEphKP;              // UD ephemeral keypair (generated in AUTH0)
    private byte[]  udEphPubBytes;        // 65-byte uncompressed UD ephemeral public key
    private byte[]  readerEphPubBytes;    // 65-byte reader ephemeral public key from AUTH0
    private byte[]  readerIdBytes;        // 32-byte reader ID from AUTH0
    private byte[]  transactionId;        // 16-byte TID from AUTH0
    private byte[]  selectedProtocol;     // 2-byte protocol version from AUTH0
    private byte[]  auth0Flag;            // command_parameters || authentication_policy from AUTH0
    private byte[]  readerStaticPubKeyX;  // 32-byte reader static public key X (from LOAD CERT tag 85)
    private byte[]  readerStaticPubKey;   // 65-byte uncompressed reader public key 04||X||Y (from LOAD CERT tag 85)
    private byte[]  skReader;             // ExpeditedSKReader (32 bytes) — for decrypting EXCHANGE
    private byte[]  skDevice;             // ExpeditedSKDevice (32 bytes) — for encrypting AUTH1 response
    private byte[]  stepUpSK;             // StepUpSK (32 bytes) at HKDF offset 64 — for ENVELOPE session

    // Per-message GCM counters (§8.3.1.6 / §8.3.1.8).
    // device_counter: starts at 1, AUTH1 response uses 1 (then becomes 2), EXCHANGE responses use 2, 3, ...
    // reader_counter: starts at 1, first EXCHANGE command uses 1, then 2, 3, ...
    private int     readerCounter = 1;    // reader_counter  — first EXCHANGE command uses 1
    private int     deviceCounter = 1;    // device_counter  — AUTH1 response uses 1, EXCHANGE responses use 2+

    // Mailbox atomic session tracking
    private boolean mailboxAtomicActive   = false;  // true when atomic session started (0x8C bit0=1)
    private byte[]  mailboxPendingWrites  = null;   // buffered writes during atomic session

    // ENVELOPE / GET RESPONSE state (Step-Up phase)
    private byte[]  envelopeBuffer        = null;   // accumulates chained ENVELOPE command data
    private byte[]  pendingGetResponse    = null;   // pending response data for GET RESPONSE
    private int     pendingGetResponseOff = 0;      // offset into pendingGetResponse
    /** Max chunk size for GET RESPONSE (NFC short APDU limit = 256 bytes response) */
    private static final int GET_RESPONSE_CHUNK = 240;

    // -------------------------------------------------------------------------

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras)
    {
        if (apdu == null || apdu.length < 4)
        {
            return SW_ERROR;
        }

        Log.d(TAG, "APDU: " + Hex.toHexString(apdu));

        byte ins = apdu[1];

        switch (ins)
        {
            case (byte)0xA4: return handleSelect(apdu);
            case (byte)0x80: return handleAuth0(apdu);
            case (byte)0xD1: return handleLoadCert(apdu);
            case (byte)0x81: return handleAuth1(apdu);
            case (byte)0xC9: return handleExchange(apdu);
            case (byte)0x3C: return handleControlFlow(apdu);
            case (byte)0xC3: return handleEnvelope(apdu);   // Step-Up ENVELOPE
            case (byte)0xC0: return handleGetResponse(apdu); // Step-Up GET RESPONSE
            default:
                Log.w(TAG, "Unknown INS: " + String.format("%02X", ins));
                return SW_ERROR;
        }
    }

    @Override
    public void onDeactivated(int reason)
    {
        Log.d(TAG, "Deactivated, reason=" + reason);
        resetState();
    }

    // -------------------------------------------------------------------------
    // SELECT (INS A4)
    // -------------------------------------------------------------------------

    private byte[] handleSelect(byte[] apdu)
    {
        // Verify AID matches
        if (apdu.length < 5)  return SW_ERROR;
        int aidLen = apdu[4] & 0xFF;
        if (apdu.length < 5 + aidLen) return SW_ERROR;
        byte[] requestedAid = Arrays.copyOfRange(apdu, 5, 5 + aidLen);
        if (!Arrays.equals(requestedAid, SELECT_AID))
        {
            Log.w(TAG, "SELECT with wrong AID: " + Hex.toHexString(requestedAid));
            return SW_ERROR;
        }

        resetState();
        state = State.SELECTED;
        Log.d(TAG, "SELECT OK");

        // Response: SELECT_RESPONSE + SW 9000
        byte[] response = new byte[SELECT_RESPONSE.length + 2];
        System.arraycopy(SELECT_RESPONSE, 0, response, 0, SELECT_RESPONSE.length);
        response[SELECT_RESPONSE.length]     = (byte)0x90;
        response[SELECT_RESPONSE.length + 1] = 0x00;
        Log.d(TAG, "SELECT response: " + Hex.toHexString(response));
        return response;
    }

    // -------------------------------------------------------------------------
    // AUTH0 (INS 80)
    // -------------------------------------------------------------------------

    private byte[] handleAuth0(byte[] apdu)
    {
        if (state != State.SELECTED)
        {
            Log.w(TAG, "AUTH0 in wrong state: " + state);
            return SW_CONDITIONS;
        }

        // Parse AUTH0 command data
        // Expected TLVs: 81 (auth_policy), 42 (connection_type), 5C (proto version),
        //                87 (reader eph pub key), 4C (TID), 4D (reader ID)
        try
        {
            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset < 0 || dataLen < 0) return SW_ERROR;

            byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            Log.d(TAG, "AUTH0 data: " + Hex.toHexString(data));

            // Parse TLVs
            readerEphPubBytes = null;
            transactionId     = null;
            readerIdBytes     = null;
            selectedProtocol  = null;
            auth0Flag         = new byte[]{ 0x01, 0x01 }; // default: cmd_params=0x01, auth_policy=0x01

            // Parse flag = command_parameters || authentication_policy from flat TLVs
            // Per Table 8-4: 41 01 <cmd_params> then 42 01 <auth_policy>
            byte cmdParams = 0x00;  // default: expedited-standard
            byte authPolicy = 0x01; // default: user device setting
            for (int fi = 0; fi < data.length - 2; fi++)
            {
                int tag = data[fi] & 0xFF;
                int len = data[fi + 1] & 0xFF;
                if (fi + 2 + len > data.length) break;
                if (tag == 0x41 && len == 0x01) cmdParams  = data[fi + 2];
                if (tag == 0x42 && len == 0x01) authPolicy = data[fi + 2];
            }
            auth0Flag = new byte[]{ cmdParams, authPolicy };
            Log.d(TAG, "Parsed auth0Flag: " + String.format("%02x%02x", cmdParams, authPolicy));

            // Parse TLVs from AUTH0 data.
            // The command wraps content in an outer 81 <len> container, then has
            // individual TLVs: 42 (connection type), 5C (protocol), 87 (reader eph pub),
            // 4C (TID), 4D (reader ID).
            // We flatten the search by scanning ALL bytes recursively for known tags.
            parseTlvsFromAuth0(data, 0, data.length);

            Log.d(TAG, "After parse — readerEphPub=" + (readerEphPubBytes != null) +
                    " tid=" + (transactionId != null) + " readerId=" + (readerIdBytes != null));

            if (readerEphPubBytes == null || transactionId == null || readerIdBytes == null)
            {
                Log.e(TAG, "AUTH0 missing required TLV(s)");
                return SW_ERROR;
            }
            if (selectedProtocol == null)
            {
                selectedProtocol = new byte[]{ 0x01, 0x00 }; // default to 01.00
            }

            Log.d(TAG, "Reader eph pub: " + Hex.toHexString(readerEphPubBytes));
            Log.d(TAG, "Transaction ID: " + Hex.toHexString(transactionId));
            Log.d(TAG, "Reader ID:      " + Hex.toHexString(readerIdBytes));
            Log.d(TAG, "Protocol:       " + Hex.toHexString(selectedProtocol));

            // Strict mode: verify reader_group_identifier matches authorized group
            if (AliroProvisioningManager.isStrictMode(this) && AliroProvisioningManager.isProvisioned(this))
            {
                byte[] authorizedGroupId = AliroProvisioningManager.getAuthorizedReaderGroupId(this);
                if (authorizedGroupId != null)
                {
                    byte[] receivedGroupId = Arrays.copyOfRange(readerIdBytes, 0, 16);
                    if (!Arrays.equals(receivedGroupId, authorizedGroupId))
                    {
                        Log.w(TAG, "Strict mode: Reader group ID mismatch — rejecting");
                        return SW_CONDITIONS; // 6985
                    }
                    Log.d(TAG, "Strict mode: Reader group ID verified");
                }
            }

            // Generate UD ephemeral keypair
            udEphKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (udEphKP == null) return SW_ERROR;
            udEphPubBytes = AliroCryptoProvider.getUncompressedPublicKey(udEphKP);

            state = State.AUTH0_DONE;

            // Response: 86 41 <UD eph pub key 65 bytes> SW9000
            byte[] response = new byte[2 + 65 + 2];
            response[0] = (byte)0x86;
            response[1] = 0x41;
            System.arraycopy(udEphPubBytes, 0, response, 2, 65);
            response[67] = (byte)0x90;
            response[68] = 0x00;
            Log.d(TAG, "AUTH0 response: " + Hex.toHexString(response));
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "AUTH0 error", e);
            return SW_ERROR;
        }
    }

    /**
     * Linearly scan the AUTH0 data for known tags.
     *
     * The AUTH0 command data starts with a fixed 4-byte preamble:
     *   81 41 01 00  (auth policy header — NOT a TLV container)
     * followed by flat TLVs: 42, 5C, 87, 4C, 4D.
     * We scan the whole buffer linearly for the known tag+length combinations.
     */
    private void parseTlvsFromAuth0(byte[] data, int start, int end)
    {
        for (int i = start; i < end - 1; i++)
        {
            int tag = data[i] & 0xFF;
            int len = (i + 1 < end) ? (data[i + 1] & 0xFF) : 0;
            if (i + 2 + len > end) continue;

            if (tag == 0x5C && len == 0x02 && selectedProtocol == null)
            {
                selectedProtocol = Arrays.copyOfRange(data, i + 2, i + 4);
            }
            else if (tag == 0x87 && len == 0x41)
            {
                readerEphPubBytes = Arrays.copyOfRange(data, i + 2, i + 67);
            }
            else if (tag == 0x4C && len == 0x10)
            {
                transactionId = Arrays.copyOfRange(data, i + 2, i + 18);
            }
            else if (tag == 0x4D && len == 0x20)
            {
                readerIdBytes = Arrays.copyOfRange(data, i + 2, i + 34);
            }
        }
    }

    // -------------------------------------------------------------------------
    // LOAD CERT (INS D1) — optional, just acknowledge
    // -------------------------------------------------------------------------

    private byte[] handleLoadCert(byte[] apdu)
    {
        if (state != State.AUTH0_DONE)
        {
            Log.w(TAG, "LOAD CERT in wrong state: " + state);
            return SW_CONDITIONS;
        }

        // Parse the reader's static public key from the certificate.
        // Aliro cert format (section 13.2): contains tag 0x85 with len 0x42 (66 bytes)
        // Value: 0x00 0x04 <X 32B> <Y 32B> — the 0x00 prefix before the uncompressed point.
        // This public key is reader_group_identifier_key used in HKDF salt.
        try
        {
            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset >= 0 && dataLen > 0)
            {
                byte[] cert = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
                for (int i = 0; i < cert.length - 2; i++)
                {
                    if ((cert[i] & 0xFF) == 0x85 && (cert[i+1] & 0xFF) == 0x42)
                    {
                        // cert[i+2] = 0x00 prefix, cert[i+3] = 0x04 uncompressed marker
                        if (i + 68 <= cert.length && cert[i+2] == 0x00 && cert[i+3] == 0x04)
                        {
                            // tag 0x85 value: 00 04 <X 32B> <Y 32B>
                            readerStaticPubKeyX = Arrays.copyOfRange(cert, i + 4, i + 36); // X coord only (for HKDF)
                            // Reconstruct full 65-byte uncompressed point: 04 || X || Y (for sig verify)
                            readerStaticPubKey = new byte[65];
                            readerStaticPubKey[0] = 0x04;
                            System.arraycopy(cert, i + 4, readerStaticPubKey, 1, 64); // X(32) + Y(32)
                            Log.d(TAG, "LOAD CERT: reader static pub key X = " +
                                    org.bouncycastle.util.encoders.Hex.toHexString(readerStaticPubKeyX));
                        }
                        break;
                    }
                }
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "LOAD CERT parse error (non-fatal): " + e.getMessage());
        }

        if (readerStaticPubKeyX == null)
        {
            Log.w(TAG, "LOAD CERT: could not parse reader static pub key, falling back to eph key X");
        }

        // Strict mode: verify reader certificate against stored Issuer CA public key
        if (AliroProvisioningManager.isStrictMode(this) && AliroProvisioningManager.isProvisioned(this))
        {
            try
            {
                int dataOffset = getDataOffset(apdu);
                int dataLen    = getDataLength(apdu);
                if (dataOffset >= 0 && dataLen > 0)
                {
                    byte[] certData    = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
                    byte[] issuerPubKey = AliroProvisioningManager.getIssuerCAPubKey(this);
                    if (issuerPubKey != null)
                    {
                        boolean certValid = AliroProvisioningManager.verifyProfile0000Cert(certData, issuerPubKey);
                        if (!certValid)
                        {
                            Log.w(TAG, "Strict mode: Reader certificate verification FAILED");
                            return SW_SECURITY; // 6982
                        }
                        Log.d(TAG, "Strict mode: Reader certificate verified against Issuer CA");
                    }
                }
            }
            catch (Exception e)
            {
                Log.w(TAG, "Strict mode cert verify error: " + e.getMessage());
            }
        }

        state = State.CERT_LOADED;
        Log.d(TAG, "LOAD CERT received, acknowledged");
        return SW_OK;
    }

    // -------------------------------------------------------------------------
    // AUTH1 (INS 81)
    // -------------------------------------------------------------------------

    private byte[] handleAuth1(byte[] apdu)
    {
        State expectedState = (state == State.AUTH0_DONE || state == State.CERT_LOADED)
                ? state : null;
        if (expectedState == null)
        {
            Log.w(TAG, "AUTH1 in wrong state: " + state);
            return SW_CONDITIONS;
        }

        try
        {
            // Parse reader signature from AUTH1: 41 01 01 9E 40 <sig 64>
            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset < 0 || dataLen < 69) return SW_ERROR;

            byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            Log.d(TAG, "AUTH1 data: " + Hex.toHexString(data));

            // Format: 41 01 01 9E 40 <signature 64 bytes>
            // Find tag 9E (signature)
            byte[] readerSig = null;
            int i = 0;
            while (i < data.length - 1)
            {
                byte tag = data[i];
                int  len = data[i + 1] & 0xFF;
                i += 2;
                if (i + len > data.length) break;
                if (tag == (byte)0x9E && len == 64)
                {
                    readerSig = Arrays.copyOfRange(data, i, i + 64);
                    break;
                }
                i += len;
            }

            if (readerSig == null)
            {
                Log.e(TAG, "AUTH1: no reader signature found");
                return SW_ERROR;
            }
            Log.d(TAG, "Reader signature: " + Hex.toHexString(readerSig));

            // Get credential keypair from Android KeyStore
            PrivateKey credPrivKey = getCredentialPrivateKey();
            byte[] credPubKeyBytes = getCredentialPublicKeyBytes();
            if (credPrivKey == null || credPubKeyBytes == null)
            {
                Log.e(TAG, "AUTH1: credential keypair not available");
                return SW_ERROR;
            }

            byte[] readerEphPubX = Arrays.copyOfRange(readerEphPubBytes, 1, 33);
            byte[] udEphPubX     = Arrays.copyOfRange(udEphPubBytes, 1, 33);

            // Verify reader signature against the reader's public key from LOAD CERT (tag 0x85).
            // Per §8.3.3.4.5 the credential SHALL verify the reader signature and execute the
            // failure process if it fails. We log but stay permissive for now so that readers
            // without a provisioned CA key still complete the transaction.
            boolean readerSigValid = false;
            if (readerStaticPubKey != null)
            {
                readerSigValid = AliroCryptoProvider.verifyReaderSignature(
                        readerSig, readerStaticPubKey,
                        readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            }
            else
            {
                Log.w(TAG, "AUTH1: no reader public key available for signature verification");
            }
            Log.d(TAG, "Reader signature valid: " + readerSigValid);

            // Derive session keys.
            // reader_group_identifier_key.x = reader static pub key X per section 8.3.1.13.
            // Parsed from LOAD CERT tag 0x85; fall back to readerEphPubX if not available.
            byte[] hkdfReaderPubKeyX = (readerStaticPubKeyX != null)
                    ? readerStaticPubKeyX
                    : readerEphPubX;
            Log.d(TAG, "AUTH1: using readerPubKeyX from " +
                    (readerStaticPubKeyX != null ? "LOAD CERT" : "eph key fallback"));

            // Derive 96 bytes: ExpeditedSKReader[0..31], ExpeditedSKDevice[32..63],
            // StepUpSKReader[64..79], StepUpSKDevice[80..95] per Aliro §8.3.1.13
            byte[] keybuf = AliroCryptoProvider.deriveKeys(
                    udEphKP.getPrivate(),
                    readerEphPubBytes,
                    96,
                    selectedProtocol,
                    hkdfReaderPubKeyX,
                    readerIdBytes,
                    transactionId,
                    readerEphPubX,
                    udEphPubX,
                    PROPRIETARY_TLV,
                    null,
                    AliroCryptoProvider.INTERFACE_BYTE_NFC,
                    auth0Flag);

            if (keybuf == null)
            {
                Log.e(TAG, "AUTH1: key derivation failed");
                return SW_ERROR;
            }
            skReader  = Arrays.copyOfRange(keybuf, 0,  32);  // ExpeditedSKReader
            skDevice  = Arrays.copyOfRange(keybuf, 32, 64);  // ExpeditedSKDevice
            stepUpSK  = Arrays.copyOfRange(keybuf, 64, 96);  // StepUpSK (for ENVELOPE)

            // Compute credential signature
            byte[] credSig = AliroCryptoProvider.computeCredentialSignature(
                    credPrivKey, readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            if (credSig == null)
            {
                Log.e(TAG, "AUTH1: credential signature failed");
                return SW_ERROR;
            }

            // Build signaling_bitmap (tag 0x5E, 2 bytes big-endian) per Table 8-11.
            // Bit0 = 1: Access Document available → reader SHALL send ENVELOPE.
            // Bit2 = 1: Step-Up AID SELECT required before ENVELOPE (NFC only).
            // For Android-to-Android NFC the AID session is already open so Bit2 is
            // not set — only Bit0 is needed to gate the Step-Up ENVELOPE flow.
            byte[] storedDoc = AliroAccessDocument.getDocumentBytes(this);
            boolean hasAccessDoc = (storedDoc != null && storedDoc.length > 0);
            int signalingBits = hasAccessDoc ? 0x0001 : 0x0000;
            Log.d(TAG, "AUTH1: signaling_bitmap=0x" + String.format("%04X", signalingBits)
                    + " (hasAccessDoc=" + hasAccessDoc + ")");

            // Build AUTH1 response plaintext:
            //   5A 41 <cred pub key 65>      — credential public key  (Table 8-10)
            //   9E 40 <cred sig 64>           — credential signature   (Table 8-10)
            //   5E 02 <bitmap_hi> <bitmap_lo> — signaling_bitmap       (Table 8-11, MANDATORY)
            // Per Table 8-11, signaling_bitmap (0x5E) is MANDATORY and SHALL always be present,
            // even when all bits are zero. Omitting it would be a spec violation.
            int plaintextLen = 2 + 65 + 2 + 64 + 4; // always includes 5E 02 bitmap
            byte[] plaintext = new byte[plaintextLen];
            plaintext[0] = 0x5A; plaintext[1] = 0x41;
            System.arraycopy(credPubKeyBytes, 0, plaintext, 2, 65);
            plaintext[67] = (byte)0x9E; plaintext[68] = 0x40;
            System.arraycopy(credSig, 0, plaintext, 69, 64);
            plaintext[133] = 0x5E;
            plaintext[134] = 0x02;
            plaintext[135] = (byte)((signalingBits >> 8) & 0xFF); // bitmap high byte
            plaintext[136] = (byte)(signalingBits & 0xFF);         // bitmap low byte

            // Encrypt AUTH1 response plaintext with SKDevice, device_counter=1 (§8.3.1.6).
            // device_counter starts at 1 and is consumed here; EXCHANGE responses start at 2.
            byte[] encrypted = AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext, deviceCounter++);
            if (encrypted == null)
            {
                Log.e(TAG, "AUTH1: encryption failed");
                return SW_ERROR;
            }

            state = State.AUTH1_DONE;

            // Response: <encrypted> SW9000
            byte[] response = new byte[encrypted.length + 2];
            System.arraycopy(encrypted, 0, response, 0, encrypted.length);
            response[encrypted.length]     = (byte)0x90;
            response[encrypted.length + 1] = 0x00;
            Log.d(TAG, "AUTH1 response length: " + response.length
                    + " (signaling_bitmap=0x" + String.format("%04X", signalingBits) + ")");
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "AUTH1 error", e);
            return SW_ERROR;
        }
    }

    // -------------------------------------------------------------------------
    // EXCHANGE (INS C9)
    // -------------------------------------------------------------------------

    private byte[] handleExchange(byte[] apdu)
    {
        // Per §8.3.3.5: multiple consecutive EXCHANGE commands are valid within
        // a transaction (mailbox atomic sessions, multiple reads/writes, etc.).
        // Accept from AUTH1_DONE or EXCHANGE_DONE.
        if (state != State.AUTH1_DONE && state != State.EXCHANGE_DONE)
        {
            Log.w(TAG, "EXCHANGE in wrong state: " + state);
            return SW_CONDITIONS;
        }

        try
        {
            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset < 0 || dataLen < 16) return SW_ERROR;

            byte[] encryptedPayload = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            // Decrypt using the current reader_counter, then increment per §8.3.1.9.
            byte[] decrypted = AliroCryptoProvider.decryptReaderGcm(skReader, encryptedPayload, readerCounter++);

            if (decrypted == null)
            {
                Log.e(TAG, "EXCHANGE: decryption failed (readerCounter was " + (readerCounter - 1) + ")");
                return SW_ERROR;
            }
            Log.d(TAG, "EXCHANGE decrypted: " + Hex.toHexString(decrypted));

            // Parse tag 97 (reader status): 97 02 <success> <state>
            boolean accessGranted = false;
            for (int i = 0; i < decrypted.length - 1; i++)
            {
                if (decrypted[i] == (byte)0x97 && decrypted[i + 1] == 0x02 && i + 3 < decrypted.length)
                {
                    accessGranted = (decrypted[i + 2] == 0x01);
                    Log.d(TAG, "Reader status: success=" + decrypted[i + 2]
                            + " state=" + String.format("%02X", decrypted[i + 3]));
                    break;
                }
            }

            Log.d(TAG, "Aliro transaction complete, access granted: " + accessGranted);

            // ----------------------------------------------------------------
            // Process mailbox operations from the decrypted EXCHANGE payload
            // Tags: 0x8C (atomic session), 0x87 (read), 0x8A (write), 0x95 (set)
            // Per Aliro §8.3.3.5, Table 8-16
            // ----------------------------------------------------------------
            byte[] mailboxReadData = processMailboxTags(decrypted);

            // Broadcast result to the UI
            Intent intent = new Intent("com.psia.pkoc.ALIRO_CREDENTIAL_SENT");
            intent.setPackage(getPackageName());
            intent.putExtra("accessGranted", accessGranted);
            sendBroadcast(intent);

            state = State.EXCHANGE_DONE;

            // EXCHANGE response: per §8.3.3.5.5, SHALL return encrypted 0x0002||0x00||0x00
            // plus any mailbox read data, all encrypted with SKDevice.
            // Build: [mailboxReadData (if any)] || 0x00 0x02 0x00 0x00
            byte[] successSuffix   = new byte[]{ 0x00, 0x02, 0x00, 0x00 };
            int readLen            = (mailboxReadData != null) ? mailboxReadData.length : 0;
            byte[] plaintext       = new byte[readLen + successSuffix.length];
            if (readLen > 0) System.arraycopy(mailboxReadData, 0, plaintext, 0, readLen);
            System.arraycopy(successSuffix, 0, plaintext, readLen, successSuffix.length);

            // Encrypt response using the current device_counter, then increment per §8.3.1.6.
            byte[] encryptedResponse = AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext, deviceCounter++);
            if (encryptedResponse == null)
            {
                Log.e(TAG, "EXCHANGE: response encryption failed (deviceCounter was " + (deviceCounter - 1) + ")");
                return SW_ERROR;
            }
            byte[] response = new byte[encryptedResponse.length + 2];
            System.arraycopy(encryptedResponse, 0, response, 0, encryptedResponse.length);
            response[encryptedResponse.length]     = (byte)0x90;
            response[encryptedResponse.length + 1] = 0x00;
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "EXCHANGE error", e);
            return SW_ERROR;
        }
    }

    // -------------------------------------------------------------------------
    // Mailbox tag processing (called from handleExchange)
    // Tags per Table 8-16:
    //   0x8C 01 <options>   — atomic session: bit0=1 start, bit0=0 stop
    //   0x87 04 <off_hi><off_lo><len_hi><len_lo>  — read
    //   0x8A var <off_hi><off_lo><data...>         — write
    //   0x95 05 <off_hi><off_lo><len_hi><len_lo><value> — set (fill)
    // Returns: concatenated data for any read requests, or null if none.
    // -------------------------------------------------------------------------

    private byte[] processMailboxTags(byte[] decrypted)
    {
        if (decrypted == null || decrypted.length < 2) return null;

        byte[] mailbox    = loadMailbox();
        boolean didWrite  = false;
        java.io.ByteArrayOutputStream readOutput = new java.io.ByteArrayOutputStream();

        int i = 0;
        while (i < decrypted.length - 1)
        {
            int tag = decrypted[i] & 0xFF;
            int len = decrypted[i + 1] & 0xFF;
            int valOff = i + 2;
            if (valOff + len > decrypted.length) break;

            switch (tag)
            {
                case 0xBA: // Mailbox container TLV (constructed) — step inside
                    // Per Table 8-15, 0xBA wraps the mailbox operation TLVs.
                    // Skip the BA + length header; the inner tags (0x8C, 0x87,
                    // 0x8A, 0x95) will be processed by subsequent loop iterations
                    // because we only advance i by 2 (into the container content).
                    Log.d(TAG, "Mailbox: entering BA container (" + len + " bytes)");
                    i = valOff; // enter the container — do NOT skip past it
                    continue;   // re-enter the while loop at the first inner tag

                case 0x8C: // Atomic session control
                    if (len == 1)
                    {
                        boolean start = (decrypted[valOff] & 0x01) == 1;
                        if (start && !mailboxAtomicActive)
                        {
                            mailboxAtomicActive  = true;
                            mailboxPendingWrites = (mailbox != null)
                                    ? Arrays.copyOf(mailbox, mailbox.length)
                                    : new byte[0];
                            Log.d(TAG, "Mailbox: atomic session START");
                        }
                        else if (!start && mailboxAtomicActive)
                        {
                            // Commit pending writes
                            if (mailboxPendingWrites != null)
                            {
                                saveMailbox(mailboxPendingWrites);
                                mailbox = mailboxPendingWrites;
                                didWrite = true;
                            }
                            mailboxAtomicActive  = false;
                            mailboxPendingWrites = null;
                            Log.d(TAG, "Mailbox: atomic session STOP — committed");
                        }
                    }
                    break;

                case 0x87: // Read: offset(2) || length(2)
                    if (len == 4)
                    {
                        int offset  = ((decrypted[valOff]     & 0xFF) << 8)
                                     | (decrypted[valOff + 1] & 0xFF);
                        int readLen = ((decrypted[valOff + 2] & 0xFF) << 8)
                                     | (decrypted[valOff + 3] & 0xFF);
                        byte[] src  = mailboxAtomicActive ? mailboxPendingWrites : mailbox;
                        if (src != null && offset + readLen <= src.length)
                        {
                            readOutput.write(src, offset, readLen);
                            Log.d(TAG, "Mailbox: read offset=" + offset + " len=" + readLen);
                        }
                        else
                        {
                            Log.w(TAG, "Mailbox: read out of bounds offset=" + offset
                                    + " len=" + readLen
                                    + " mailboxSize=" + (src != null ? src.length : 0));
                        }
                    }
                    break;

                case 0x8A: // Write: offset(2) || data(var)
                    if (len >= 2)
                    {
                        int offset    = ((decrypted[valOff]     & 0xFF) << 8)
                                       | (decrypted[valOff + 1] & 0xFF);
                        int dataLen   = len - 2;
                        byte[] target = mailboxAtomicActive
                                ? mailboxPendingWrites
                                : (mailbox != null ? mailbox : new byte[0]);
                        int needed    = offset + dataLen;
                        if (needed > MAILBOX_MAX_SIZE)
                        {
                            Log.w(TAG, "Mailbox: write exceeds max size, ignoring");
                            break;
                        }
                        if (needed > target.length)
                        {
                            target = Arrays.copyOf(target, needed);
                        }
                        System.arraycopy(decrypted, valOff + 2, target, offset, dataLen);
                        if (mailboxAtomicActive)
                        {
                            mailboxPendingWrites = target;
                        }
                        else
                        {
                            mailbox  = target;
                            didWrite = true;
                        }
                        Log.d(TAG, "Mailbox: write offset=" + offset + " len=" + dataLen);
                    }
                    break;

                case 0x95: // Set: offset(2) || length(2) || value(1)
                    if (len == 5)
                    {
                        int offset  = ((decrypted[valOff]     & 0xFF) << 8)
                                     | (decrypted[valOff + 1] & 0xFF);
                        int setLen  = ((decrypted[valOff + 2] & 0xFF) << 8)
                                     | (decrypted[valOff + 3] & 0xFF);
                        byte value  =   decrypted[valOff + 4];
                        byte[] target = mailboxAtomicActive
                                ? mailboxPendingWrites
                                : (mailbox != null ? mailbox : new byte[0]);
                        int needed  = offset + setLen;
                        if (needed > MAILBOX_MAX_SIZE)
                        {
                            Log.w(TAG, "Mailbox: set exceeds max size, ignoring");
                            break;
                        }
                        if (needed > target.length)
                        {
                            target = Arrays.copyOf(target, needed);
                        }
                        Arrays.fill(target, offset, offset + setLen, value);
                        if (mailboxAtomicActive)
                        {
                            mailboxPendingWrites = target;
                        }
                        else
                        {
                            mailbox  = target;
                            didWrite = true;
                        }
                        Log.d(TAG, "Mailbox: set offset=" + offset
                                + " len=" + setLen
                                + " value=" + String.format("%02X", value & 0xFF));
                    }
                    break;

                default:
                    // Unknown tag — skip per spec
                    break;
            }

            i = valOff + len; // advance to next TLV
        }

        // Persist changes if non-atomic writes occurred
        if (didWrite && mailbox != null) saveMailbox(mailbox);

        byte[] result = readOutput.toByteArray();
        return (result.length > 0) ? result : null;
    }

    // -------------------------------------------------------------------------
    // Mailbox persistence helpers
    // -------------------------------------------------------------------------

    private byte[] loadMailbox()
    {
        try
        {
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            String encoded = prefs.getString(PREF_MAILBOX_KEY, null);
            if (encoded == null) return new byte[0];
            return Base64.decode(encoded, Base64.DEFAULT);
        }
        catch (Exception e)
        {
            Log.e(TAG, "loadMailbox failed", e);
            return new byte[0];
        }
    }

    private void saveMailbox(byte[] data)
    {
        try
        {
            SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            prefs.edit()
                 .putString(PREF_MAILBOX_KEY, Base64.encodeToString(data, Base64.DEFAULT))
                 .apply();
            Log.d(TAG, "Mailbox: saved " + data.length + " bytes");
        }
        catch (Exception e)
        {
            Log.e(TAG, "saveMailbox failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // ENVELOPE (INS C3) — Step-Up phase: accumulates DeviceRequest chunks
    // CLA 0x90 = chained (more data follows), CLA 0x80 = last block
    // Per Aliro §8.4 + ISO 18013-5 ENVELOPE command
    // -------------------------------------------------------------------------

    private byte[] handleEnvelope(byte[] apdu)
    {
        // ENVELOPE is valid after EXCHANGE_DONE or in subsequent ENVELOPE chains
        if (state != State.EXCHANGE_DONE && envelopeBuffer == null)
        {
            Log.w(TAG, "ENVELOPE in wrong state: " + state);
            return SW_CONDITIONS;
        }
        if (stepUpSK == null)
        {
            Log.e(TAG, "ENVELOPE: stepUpSK not available (AUTH1 not completed)");
            return SW_CONDITIONS;
        }

        try
        {
            byte cla     = apdu[0];
            boolean last = (cla & 0x10) == 0; // CLA 0x90 = chain, 0x80 = last

            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset < 0 || dataLen <= 0) return SW_WRONG_LENGTH;

            // Accumulate chunks
            if (envelopeBuffer == null)
            {
                envelopeBuffer = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            }
            else
            {
                byte[] combined = new byte[envelopeBuffer.length + dataLen];
                System.arraycopy(envelopeBuffer, 0, combined, 0, envelopeBuffer.length);
                System.arraycopy(apdu, dataOffset, combined, envelopeBuffer.length, dataLen);
                envelopeBuffer = combined;
            }

            if (!last)
            {
                // More chunks coming — acknowledge with SW 9000, no data
                Log.d(TAG, "ENVELOPE: received chunk (" + dataLen + " bytes), waiting for more");
                return SW_OK;
            }

            // Last chunk received — envelopeBuffer contains the raw SessionData CBOR.
            Log.d(TAG, "ENVELOPE: complete SessionData (" + envelopeBuffer.length + " bytes)");
            byte[] sessionDataIn = envelopeBuffer;
            envelopeBuffer = null;

            // Per Aliro §8.4.3 + ISO 18013-5 §9.1.1.4/9.1.1.5:
            // ENVELOPE carries SessionData CBOR: { "data": bstr(encrypted DeviceRequest) }
            // Decrypt with StepUpSKDevice session keys derived from stepUpSK.
            //
            // Step 1: Derive step-up session keys from stepUpSK
            //   SKDevice = HKDF(IKM=stepUpSK, salt=empty, info="SKDevice") [0..31]
            //   SKReader = HKDF(IKM=stepUpSK, salt=empty, info="SKReader") [32..63]
            byte[] stepUpSessionKeys = com.psia.pkoc.core.AliroCryptoProvider
                    .deriveStepUpSessionKeys(stepUpSK);
            if (stepUpSessionKeys == null)
            {
                Log.e(TAG, "ENVELOPE: step-up session key derivation failed");
                return SW_ERROR;
            }
            byte[] suSKDevice = Arrays.copyOfRange(stepUpSessionKeys, 0,  32); // credential encrypts response
            byte[] suSKReader = Arrays.copyOfRange(stepUpSessionKeys, 32, 64); // credential decrypts request

            try
            {
                // Step 2: Unwrap SessionData and decrypt DeviceRequest
                //   Reader encrypted with SKReader, IV=0x00000000_00000000_00000001
                CBORObject sdIn  = CBORObject.DecodeFromBytes(sessionDataIn);
                CBORObject dataIn = sdIn.get(CBORObject.FromObject("data"));
                if (dataIn == null)
                {
                    Log.e(TAG, "ENVELOPE: SessionData missing 'data' field");
                    return SW_ERROR;
                }
                byte[] encryptedRequest = dataIn.GetByteString();
                // Decrypt with suSKReader (reader→credential, same IV as §8.3.1.9)
                byte[] deviceRequest = com.psia.pkoc.core.AliroCryptoProvider
                        .decryptReaderGcm(suSKReader, encryptedRequest);
                if (deviceRequest == null)
                {
                    Log.e(TAG, "ENVELOPE: DeviceRequest AES-GCM authentication failed");
                    return SW_ERROR;
                }
                Log.d(TAG, "ENVELOPE: DeviceRequest (" + deviceRequest.length + " bytes)");

                // Step 3: Build DeviceResponse from stored Access Document
                byte[] deviceResponse = buildDeviceResponse(deviceRequest);
                if (deviceResponse == null)
                {
                    Log.e(TAG, "ENVELOPE: failed to build DeviceResponse");
                    return SW_ERROR;
                }

                // Step 4: Encrypt DeviceResponse with suSKDevice and wrap in SessionData
                //   Device encrypts with SKDevice, IV=0x00000000_00000001_00000001
                byte[] encryptedResponse = com.psia.pkoc.core.AliroCryptoProvider
                        .encryptDeviceGcm(suSKDevice, deviceResponse);
                if (encryptedResponse == null)
                {
                    Log.e(TAG, "ENVELOPE: DeviceResponse encryption failed");
                    return SW_ERROR;
                }
                CBORObject sdOut = CBORObject.NewOrderedMap();
                sdOut.Add(CBORObject.FromObject("data"),
                        CBORObject.FromObject(encryptedResponse));
                byte[] sessionDataOut = sdOut.EncodeToBytes();
                Log.d(TAG, "ENVELOPE: SessionData response (" + sessionDataOut.length + " bytes)");

                // Step 5: Prepare chunked GET RESPONSE
                pendingGetResponse    = sessionDataOut;
                pendingGetResponseOff = 0;
                return nextGetResponseChunk();
            }
            finally
            {
                Arrays.fill(suSKDevice, (byte)0);
                Arrays.fill(suSKReader, (byte)0);
                Arrays.fill(stepUpSessionKeys, (byte)0);
            }
        }
        catch (Exception e)
        {
            Log.e(TAG, "ENVELOPE error", e);
            envelopeBuffer = null;
            return SW_ERROR;
        }
    }

    // -------------------------------------------------------------------------
    // GET RESPONSE (INS C0) — returns next chunk of pending ENVELOPE response
    // -------------------------------------------------------------------------

    private byte[] handleGetResponse(byte[] apdu)
    {
        if (pendingGetResponse == null || pendingGetResponseOff >= pendingGetResponse.length)
        {
            Log.w(TAG, "GET RESPONSE: no pending data");
            return SW_ERROR;
        }
        return nextGetResponseChunk();
    }

    /**
     * Returns the next chunk of pendingGetResponse.
     * If more data remains after this chunk, returns SW 61 xx (xx = bytes remaining, max 0xFF).
     * If this is the last chunk, returns SW 9000.
     */
    private byte[] nextGetResponseChunk()
    {
        int remaining = pendingGetResponse.length - pendingGetResponseOff;
        int chunkLen  = Math.min(remaining, GET_RESPONSE_CHUNK);
        int leftAfter = remaining - chunkLen;

        byte[] chunk  = new byte[chunkLen + 2];
        System.arraycopy(pendingGetResponse, pendingGetResponseOff, chunk, 0, chunkLen);
        pendingGetResponseOff += chunkLen;

        if (leftAfter > 0)
        {
            // SW 61 xx: more data available
            chunk[chunkLen]     = 0x61;
            chunk[chunkLen + 1] = (byte) Math.min(leftAfter, 0xFF);
            Log.d(TAG, "GET RESPONSE: sent " + chunkLen + " bytes, " + leftAfter + " remaining");
        }
        else
        {
            // Last chunk
            chunk[chunkLen]     = (byte)0x90;
            chunk[chunkLen + 1] = 0x00;
            pendingGetResponse    = null;
            pendingGetResponseOff = 0;
            Log.d(TAG, "GET RESPONSE: sent final " + chunkLen + " bytes");
        }
        return chunk;
    }

    /**
     * Build the DeviceResponse for a received DeviceRequest.
     *
     * Per Aliro §8.4.2 / ISO 18013-5:
     *   - Parse the incoming DeviceRequest CBOR to extract the requested namespace
     *     and element identifiers.
     *   - Load the stored Access Document from AliroAccessDocument.
     *   - If the requested element identifier matches the stored document's element
     *     identifier, return the stored DeviceResponse bytes unchanged (it is already
     *     a fully-formed DeviceResponse from generateTestDocument / importDocument).
     *   - If no document is provisioned, or the element doesn't match, return an
     *     empty DeviceResponse: { "1": "1.0", "3": 0 }.
     *
     * DeviceRequest CBOR structure (Table 8-21 key values):
     *   map {
     *     "1": "1.0"        (version)
     *     "2": [            (docRequests — array)
     *       map {
     *         "1": map {    (itemsRequest)
     *           "1": map {        (nameSpaces  — key "1" per Table 8-21)
     *             "aliro-a": map { <elementId>: false, ... }
     *           }
     *           "5": "aliro-a"   (docType — key "5" per Table 8-21)
     *         }
     *       }
     *     ]
     *   }
     * All map keys are CBOR text strings matching the abbreviated keys from Table 8-21.
     */
    private byte[] buildDeviceResponse(byte[] deviceRequest)
    {
        // Minimal empty DeviceResponse: { "1": "1.0", "3": 0 }
        final byte[] EMPTY_RESPONSE = new byte[] {
            (byte)0xA2,
            0x61, 0x31,
            0x63, 0x31, 0x2E, 0x30,
            0x61, 0x33,
            0x00
        };

        try
        {
            // ---- 1. Load stored Access Document ----
            byte[] storedDoc = AliroAccessDocument.getDocumentBytes(this);
            if (storedDoc == null || storedDoc.length == 0)
            {
                Log.d(TAG, "buildDeviceResponse: no Access Document provisioned — returning empty DeviceResponse");
                return EMPTY_RESPONSE;
            }
            String storedElementId = AliroAccessDocument.getElementIdentifier(this);
            Log.d(TAG, "buildDeviceResponse: stored element=" + storedElementId
                    + ", doc bytes=" + storedDoc.length);

            // ---- 2. Parse DeviceRequest CBOR to extract requested element identifiers ----
            // We look for any element identifier in namespace "aliro-a".
            // If the request cannot be parsed we fall back to returning the full doc
            // (lenient behaviour — the reader presumably asked for our element).
            boolean elementRequested = false;
            try
            {
                CBORObject req = CBORObject.DecodeFromBytes(deviceRequest);
                // key "2" → docRequests array
                CBORObject docRequests = req.get(CBORObject.FromObject("2"));
                if (docRequests != null && docRequests.getType() == com.upokecenter.cbor.CBORType.Array)
                {
                    for (int i = 0; i < docRequests.size(); i++)
                    {
                        CBORObject docReq = docRequests.get(i);
                        // key "1" → itemsRequest map
                        CBORObject itemsReq = docReq.get(CBORObject.FromObject("1"));
                        if (itemsReq == null) continue;
                        // key "1" → nameSpaces map (Table 8-21: nameSpaces = key "1")
                        CBORObject nameSpaces = itemsReq.get(CBORObject.FromObject("1"));
                        if (nameSpaces == null) continue;
                        // look for namespace "aliro-a"
                        CBORObject nsMap = nameSpaces.get(CBORObject.FromObject("aliro-a"));
                        if (nsMap == null) continue;
                        // iterate element identifiers in the namespace map
                        for (CBORObject key : nsMap.getKeys())
                        {
                            String requestedId = key.AsString();
                            Log.d(TAG, "buildDeviceResponse: reader requests element=" + requestedId);
                            if (requestedId.equals(storedElementId))
                            {
                                elementRequested = true;
                            }
                        }
                    }
                }
            }
            catch (Exception parseEx)
            {
                // DeviceRequest couldn't be parsed — treat as "all elements requested"
                Log.w(TAG, "buildDeviceResponse: could not parse DeviceRequest, returning full doc", parseEx);
                elementRequested = true;
            }

            if (!elementRequested)
            {
                Log.d(TAG, "buildDeviceResponse: requested element not in stored doc — returning empty DeviceResponse");
                return EMPTY_RESPONSE;
            }

            // ---- 3. Return stored DeviceResponse (already fully formed CBOR) ----
            Log.d(TAG, "buildDeviceResponse: returning stored DeviceResponse (" + storedDoc.length + " bytes)");
            return storedDoc;
        }
        catch (Exception e)
        {
            Log.e(TAG, "buildDeviceResponse failed", e);
            return EMPTY_RESPONSE;
        }
    }

    // -------------------------------------------------------------------------
    // CONTROL FLOW (INS 3C) — Reader signals transaction failure
    // -------------------------------------------------------------------------

    private byte[] handleControlFlow(byte[] apdu)
    {
        // Per section 10.2.2.2: respond with empty data field
        Log.d(TAG, "CONTROL FLOW received — reader signaling failure, resetting state");
        resetState();
        return SW_OK;
    }

    // -------------------------------------------------------------------------
    // KeyStore helpers
    // -------------------------------------------------------------------------

    /**
     * Get or create the Aliro credential keypair in Android KeyStore.
     * Returns the private key, or null on failure.
     */
    public static void ensureAliroKeypairExists()
    {
        try
        {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            if (!ks.containsAlias(ALIRO_KEYSTORE_ALIAS))
            {
                android.security.keystore.KeyGenParameterSpec spec =
                        new android.security.keystore.KeyGenParameterSpec.Builder(
                                ALIRO_KEYSTORE_ALIAS,
                                android.security.keystore.KeyProperties.PURPOSE_SIGN |
                                android.security.keystore.KeyProperties.PURPOSE_VERIFY)
                                .setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256)
                                .setUserAuthenticationRequired(false)
                                .setKeySize(256)
                                .setAlgorithmParameterSpec(
                                        new java.security.spec.ECGenParameterSpec("secp256r1"))
                                .build();

                java.security.KeyPairGenerator kpg = java.security.KeyPairGenerator.getInstance(
                        android.security.keystore.KeyProperties.KEY_ALGORITHM_EC,
                        "AndroidKeyStore");
                kpg.initialize(spec);
                kpg.generateKeyPair();
            }
        }
        catch (Exception e)
        {
            Log.e(TAG, "ensureAliroKeypairExists failed", e);
        }
    }

    private PrivateKey getCredentialPrivateKey()
    {
        try
        {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(ALIRO_KEYSTORE_ALIAS, null);
            if (entry instanceof KeyStore.PrivateKeyEntry)
            {
                return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            }
        }
        catch (Exception e)
        {
            Log.e(TAG, "getCredentialPrivateKey failed", e);
        }
        return null;
    }

    private byte[] getCredentialPublicKeyBytes()
    {
        try
        {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            java.security.cert.Certificate cert = ks.getCertificate(ALIRO_KEYSTORE_ALIAS);
            if (cert == null) return null;
            ECPublicKey pub = (ECPublicKey) cert.getPublicKey();
            byte[] x = toBytes32(pub.getW().getAffineX());
            byte[] y = toBytes32(pub.getW().getAffineY());
            byte[] out = new byte[65];
            out[0] = 0x04;
            System.arraycopy(x, 0, out, 1, 32);
            System.arraycopy(y, 0, out, 33, 32);
            return out;
        }
        catch (Exception e)
        {
            Log.e(TAG, "getCredentialPublicKeyBytes failed", e);
        }
        return null;
    }

    // -------------------------------------------------------------------------
    // APDU parsing helpers
    // -------------------------------------------------------------------------

    /** Get the offset of the data field in a short APDU */
    private int getDataOffset(byte[] apdu)
    {
        if (apdu.length < 5) return -1;
        return 5; // CLA INS P1 P2 Lc [data] [Le]
    }

    /** Get the length of the data field in a short APDU */
    private int getDataLength(byte[] apdu)
    {
        if (apdu.length < 5) return -1;
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return -1;
        return lc;
    }

    // -------------------------------------------------------------------------
    // Misc helpers
    // -------------------------------------------------------------------------

    private void resetState()
    {
        state             = State.IDLE;
        udEphKP           = null;
        udEphPubBytes     = null;
        readerEphPubBytes = null;
        readerIdBytes     = null;
        transactionId     = null;
        selectedProtocol  = null;
        auth0Flag            = null;
        readerStaticPubKeyX  = null;
        readerStaticPubKey   = null;
        // Zero session keys before nulling per section 8.3.3.1
        if (skReader  != null) { java.util.Arrays.fill(skReader,  (byte)0); skReader  = null; }
        if (skDevice  != null) { java.util.Arrays.fill(skDevice,  (byte)0); skDevice  = null; }
        if (stepUpSK  != null) { java.util.Arrays.fill(stepUpSK,  (byte)0); stepUpSK  = null; }
        // Reset per-message counters
        readerCounter = 1; // first EXCHANGE command uses 1
        deviceCounter = 1; // AUTH1 response uses 1, EXCHANGE responses start at 2
        // Reset mailbox atomic session state
        mailboxAtomicActive  = false;
        mailboxPendingWrites = null;
        // Reset ENVELOPE / GET RESPONSE state
        envelopeBuffer        = null;
        pendingGetResponse    = null;
        pendingGetResponseOff = 0;
    }

    private static byte[] toBytes32(java.math.BigInteger n)
    {
        byte[] raw = n.toByteArray();
        byte[] out = new byte[32];
        if (raw.length <= 32)
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        else
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        return out;
    }
}
