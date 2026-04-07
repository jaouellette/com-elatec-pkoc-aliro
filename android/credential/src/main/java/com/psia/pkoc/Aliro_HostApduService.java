package com.psia.pkoc;

import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import com.psia.pkoc.core.AliroCryptoProvider;

import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;

/**
 * HCE service for the Aliro Expedited Standard NFC credential flow.
 *
 * AID: A0 00 00 09 09 AC CE 55 01
 *
 * Transaction flow (credential / User Device side):
 *   1. SELECT        → respond with FCI containing AID, Proprietary TLV, protocol versions
 *   2. AUTH0         → parse reader ephemeral key + TID + reader ID;
 *                      generate UD ephemeral keypair; respond with UD ephemeral public key
 *   3. LOAD CERT     → (optional) receive and store reader certificate; respond 9000
 *   4. AUTH1         → receive encrypted reader signature;
 *                      derive session keys; decrypt; verify reader sig;
 *                      build encrypted response with credential pub key + credential sig
 *   5. EXCHANGE      → decrypt reader access decision; broadcast result
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

    // -------------------------------------------------------------------------
    // Per-transaction state (reset on deactivation)
    // -------------------------------------------------------------------------
    private enum State { IDLE, SELECTED, AUTH0_DONE, CERT_LOADED, AUTH1_DONE }

    private State state = State.IDLE;
    private KeyPair udEphKP;              // UD ephemeral keypair (generated in AUTH0)
    private byte[] udEphPubBytes;         // 65-byte uncompressed UD ephemeral public key
    private byte[] readerEphPubBytes;     // 65-byte reader ephemeral public key from AUTH0
    private byte[] readerIdBytes;         // 32-byte reader ID from AUTH0
    private byte[] transactionId;         // 16-byte TID from AUTH0
    private byte[] selectedProtocol;      // 2-byte protocol version from AUTH0
    private byte[] auth0Flag;             // command_parameters || authentication_policy from AUTH0
    private byte[] readerStaticPubKeyX;   // 32-byte reader static public key X (from LOAD CERT tag 85)
    private byte[] skReader;              // ExpeditedSKReader (32 bytes) — for decrypting EXCHANGE
    private byte[] skDevice;              // ExpeditedSKDevice (32 bytes) — for encrypting AUTH1 response

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
                            readerStaticPubKeyX = Arrays.copyOfRange(cert, i + 4, i + 36); // X coord
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

            // Verify reader signature (optional for simulator — we log but don't block)
            boolean readerSigValid = AliroCryptoProvider.verifyReaderSignature(
                    readerSig, credPubKeyBytes,  // using credential pub key as stand-in
                    readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            Log.d(TAG, "Reader signature valid: " + readerSigValid);

            // Derive session keys.
            // reader_group_identifier_key.x = reader static pub key X per section 8.3.1.13.
            // Parsed from LOAD CERT tag 0x85; fall back to readerEphPubX if not available.
            byte[] hkdfReaderPubKeyX = (readerStaticPubKeyX != null)
                    ? readerStaticPubKeyX
                    : readerEphPubX;
            Log.d(TAG, "AUTH1: using readerPubKeyX from " +
                    (readerStaticPubKeyX != null ? "LOAD CERT" : "eph key fallback"));

            byte[] keybuf = AliroCryptoProvider.deriveKeys(
                    udEphKP.getPrivate(),
                    readerEphPubBytes,
                    64,
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
            skReader = Arrays.copyOfRange(keybuf, 0, 32);
            skDevice = Arrays.copyOfRange(keybuf, 32, 64);

            // Compute credential signature
            byte[] credSig = AliroCryptoProvider.computeCredentialSignature(
                    credPrivKey, readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            if (credSig == null)
            {
                Log.e(TAG, "AUTH1: credential signature failed");
                return SW_ERROR;
            }

            // Build AUTH1 response plaintext: 5A 41 <cred pub key 65> 9E 40 <sig 64>
            byte[] plaintext = new byte[2 + 65 + 2 + 64];
            plaintext[0] = 0x5A; plaintext[1] = 0x41;
            System.arraycopy(credPubKeyBytes, 0, plaintext, 2, 65);
            plaintext[67] = (byte)0x9E; plaintext[68] = 0x40;
            System.arraycopy(credSig, 0, plaintext, 69, 64);

            // Encrypt AUTH1 response with SKDevice using device_counter IV
            byte[] encrypted = AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext);
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
            Log.d(TAG, "AUTH1 response length: " + response.length);
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
        if (state != State.AUTH1_DONE)
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
            byte[] decrypted = AliroCryptoProvider.decryptReaderGcm(skReader, encryptedPayload);

            if (decrypted == null)
            {
                Log.e(TAG, "EXCHANGE: decryption failed");
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

            // Broadcast result to the UI
            Intent intent = new Intent("com.psia.pkoc.ALIRO_CREDENTIAL_SENT");
            intent.setPackage(getPackageName());
            intent.putExtra("accessGranted", accessGranted);
            sendBroadcast(intent);

            // EXCHANGE response: per §8.3.3.5.5, SHALL return encrypted 0x0002||0x00||0x00
            // indicating successful execution, encrypted with SKDevice.
            byte[] successPayload = new byte[]{ 0x00, 0x02, 0x00, 0x00 };
            byte[] encryptedResponse = AliroCryptoProvider.encryptDeviceGcm(skDevice, successPayload);
            if (encryptedResponse == null)
            {
                Log.e(TAG, "EXCHANGE: response encryption failed");
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
        // Zero session keys before nulling per section 8.3.3.1
        if (skReader != null) { java.util.Arrays.fill(skReader, (byte)0); skReader = null; }
        if (skDevice != null) { java.util.Arrays.fill(skDevice, (byte)0); skDevice = null; }
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
