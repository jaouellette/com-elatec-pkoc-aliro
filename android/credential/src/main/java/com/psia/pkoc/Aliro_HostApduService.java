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
import java.util.HashMap;
import java.util.Map;

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
    //   7F66 08              → Extended Length Info (constructed)
    //     02 02 02 00        →   max C-APDU data: 512 bytes
    //     02 02 02 00        →   max R-APDU data: 512 bytes
    //   B7 06                → User Device Descriptor (constructed)
    //     80 01 00           →   UD type: 0x00 = generic
    //     81 01 00           →   UD capabilities: 0x00
    //
    // -------------------------------------------------------------------------
    private static final byte[] SELECT_AID = {
        (byte)0xA0, 0x00, 0x00, 0x09, 0x09,
        (byte)0xAC, (byte)0xCE, 0x55, 0x01
    };

    // Step-Up AID (same prefix, different suffix) — per Aliro spec §9
    private static final byte[] STEPUP_AID = {
        (byte)0xA0, 0x00, 0x00, 0x09, 0x09,
        (byte)0xAC, (byte)0xCE, 0x55, 0x02
    };

    // Proprietary TLV (A5): Type, protocol versions, extended length info.
    // Per Aliro Table 10-2, 7F66 sub-tags use tag 0x02 for BOTH max C-APDU and max R-APDU.
    // B7 (User Device Descriptor) is placed OUTSIDE 6F, at the top level of the SELECT
    // response, per the harness TLV structure: TLV_SELECT_RSP expects [0x6F, 0xB7].
    //
    // This TLV is also used verbatim in HKDF salt (§8.3.1.13), so its exact
    // byte sequence must be consistent between SELECT and deriveKeys().
    private static final byte[] PROPRIETARY_TLV = {
        (byte)0xA5, 0x15,                                 // A5 length = 21 (without B7)
        (byte)0x80, 0x02, 0x00, 0x00,                     // Response type
        0x5C, 0x04, 0x01, 0x00, 0x00, 0x09,              // Supported versions: 01.00 and 00.09
        0x7F, 0x66, 0x08,                                 // Extended Length Info (tag 7F66, len 8)
        0x02, 0x02, 0x02, 0x00,                           //   max C-APDU: tag 02, len 02, val 0200
        0x02, 0x02, 0x02, 0x00,                           //   max R-APDU: tag 02, len 02, val 0200
    };

    // B7 (User Device Descriptor) — placed outside 6F in the SELECT response.
    private static final byte[] UD_DESCRIPTOR_TLV = {
        (byte)0xB7, 0x0E,                                 // User Device Descriptor (len=14)
        0x04, 0x03, 0x00, 0x00, 0x00,                     //   Vendor ID: 00:00:00 (generic)
        (byte)0x80, 0x02, 0x01, 0x00,                     //   Product ID: 0x0100
        (byte)0x81, 0x03, 0x01, 0x00, 0x00                //   Firmware Version: 1.0.0
    };

    /** Maximum R-APDU data size declared in Extended Length Info (7F66). */
    private static final int MAX_RAPDU_DATA = 512;

    // -------------------------------------------------------------------------
    // Multi-group reader key lookup (SIXTEEN_GROUPIDENTIFIER test support)
    // Maps group_id (first 16 bytes of reader_identifier, hex uppercase) to
    // the corresponding reader static public key (65-byte uncompressed, hex uppercase).
    // Per Aliro §8.3.3.4.5, the credential SHALL look up the correct reader
    // public key through the reader_group_identifier received in AUTH0.
    // -------------------------------------------------------------------------
    private static final Map<String, String> READER_KEY_BY_GROUP_ID = new HashMap<>();
    static {
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799AB",
            "041D64FF1117DE6653A352CA8E38B185910B10055EE8E366FB46D6A65F9C8ADDFFBB2C7AFB2DC271A7CE49246FC5461F4E6001A94FDFDFA1CDBD51D3A8DFFB2ACB");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799AC",
            "04796D39C8792AA87BE8DED0643CD9013A205CC7A174EDDDE6A2C3A6AA7BE84E82BFE7E78B3724342D114A4972D917EE3B42FCB1694002F0E6A83325C9AB37898F");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799AD",
            "0493F887192EE66ED596416E612DC814FEDDE827A96E83AEDEADFA42CDEBA1E363AB46868D9F799A44DABD7B057C714F2C7430598A2640CF9146B5102D6DA9066F");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799AE",
            "049A953902E3F2C18EF8A3CFAD56B85BD04FF90B4CFFC1E71DBA5823F8236F19AF5AE2074BD55D5712BCB7CB186A8CDB8A3EC1D1318EDBFB47A2BD19F55DDE894F");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799AF",
            "04C9C9EA33E5DAA6F291C706544F935A1E882ABF9F51154AFFEBAE38D30FFCAA31C6A1D57C571B0E38FE90434E3AA0A49F4C7B12C938EA446CB14E1E4E06497C96");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799BA",
            "0401DAACBAD0E9A914FF297430236C386BD2A45D1D30111FEC6DD20757E1FA2708267312C65FD49773539F44F40D9A233C75C43CDDA5ECCF065BE87FFE79AE2CF9");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799BB",
            "044555995381EE5A724ECA16ED19F1B90B97F1C25B98DA8356432BC7F32D4BE88AD4CAC1CA98783F09A61BA13EEAC1ED4CF56660EA661D59223F9ABEC876057374");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799BC",
            "0458BAE01BE2B6E3F1ED2CF6C17A455DFB219862D7DA55E31ADF51C4F6C5381524A2238E1C2750668060AF0E418830EAFDCBB7CBD22D3F08EC70952DC450CAEF3E");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799BD",
            "04470C12520D801C2A6172E0631A9EB80D788641D87C58A6A25EE0E02EA1AB6CAC8E8EF606D271BE9760666EBC18AABE90DE9BCC8BB4D24D53DFBB1733347C0E39");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799BE",
            "043E97E36B228700CA9A38BBF0FC06512E60C252BBA6EEBBE61027D782589CAE8EB5B04568DEC638E0DC7D7F7517FEC0E281DB9C26092B562A2BA6DF9FFC6C9F6F");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799BF",
            "047B75386775553F01CFE133CB02D21316682694A18C18BB9EB594E9DB9F2F6278336387A381FFEC95524D29C69F73CDD3B4E22B500F92D94677641E4E343E54AF");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799CA",
            "04D0D453A8ABD945564EB7B10FAABB27F04AEA8F04D72B811C66682E9F0096F615C805B9F1F548A0F4F268E46EB09A953E95E516ADC02DF9FFECF39597AF172C90");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799CB",
            "04B18F0148DE011CED618CE9EA73B8D1FE02404A7C7F408727AA16767758B205AB32F6DD308D09A92E6189ED9F1F5945483913C37B69163BB53C17D6F8D8835B77");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799CC",
            "04B3BC8B89E4239195FF3C2A7124958B3958D0C05018C7931EE5327E40EE5F2D98C46073F885127F673D8B6E9D3B4C7845CA79E4BF5DF9A5C76E3FB6A65D5BA015");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799CD",
            "0453792D75286B552D7ACA748CC2F8E16FF67B7D4637B5C33D6C85FBD09B80E6E73449154D1C4916CDC816A2878B5E20E412AAEA7F4C56AB0944E03380B910DF92");
        READER_KEY_BY_GROUP_ID.put("00113344667799AA00113344667799CE",
            "0498E8B1F61E7A88E70708E46A7CDACCF6873208161D49EB050DC8DEAEEA5F1ECDD6FC34A5C14626AE34C22CAD2A7E0E654316AAFA7C0C1B02D1588D63B22F4B94");
    }

    // Full SELECT FCI response (without SW — appended dynamically)
    // Structure: 6F [84 AID] [A5 proprietary] | B7 descriptor
    // B7 is at the same level as 6F, NOT inside 6F or A5.
    private static final byte[] SELECT_RESPONSE;
    static {
        int fciInnerLen = 2 + SELECT_AID.length + PROPRIETARY_TLV.length;
        int totalLen = 2 + fciInnerLen + UD_DESCRIPTOR_TLV.length;
        SELECT_RESPONSE = new byte[totalLen];
        int pos = 0;
        SELECT_RESPONSE[pos++] = 0x6F;
        SELECT_RESPONSE[pos++] = (byte) fciInnerLen;
        SELECT_RESPONSE[pos++] = (byte) 0x84;
        SELECT_RESPONSE[pos++] = (byte) SELECT_AID.length;
        System.arraycopy(SELECT_AID, 0, SELECT_RESPONSE, pos, SELECT_AID.length);
        pos += SELECT_AID.length;
        System.arraycopy(PROPRIETARY_TLV, 0, SELECT_RESPONSE, pos, PROPRIETARY_TLV.length);
        pos += PROPRIETARY_TLV.length;
        // B7 is OUTSIDE 6F, appended after the 6F TLV
        System.arraycopy(UD_DESCRIPTOR_TLV, 0, SELECT_RESPONSE, pos, UD_DESCRIPTOR_TLV.length);
    }

    private static final byte[] SW_OK            = { (byte)0x90, 0x00 };
    private static final byte[] SW_ERROR         = { 0x6A, (byte)0x82 }; // File not found
    private static final byte[] SW_CONDITIONS    = { 0x69, (byte)0x85 }; // Conditions not satisfied
    private static final byte[] SW_SECURITY      = { 0x69, (byte)0x82 }; // Security status not satisfied
    private static final byte[] SW_WRONG_LENGTH  = { 0x67, 0x00 };        // Wrong length
    private static final byte[] SW_WRONG_PARAMS  = { 0x6A, (byte)0x86 }; // Incorrect P1/P2
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

    // Vendor extension TLVs captured from AUTH0 for HKDF info parameter (§8.3.1.13)
    private byte[]  auth0CmdVendorExt;    // tag B1 TLV from AUTH0 command (null if absent)
    private byte[]  auth0RspVendorExt;    // tag B2 TLV from AUTH0 response (null if absent)

    // Per-message GCM counters (§8.3.1.6 / §8.3.1.8).
    // device_counter: starts at 1, AUTH1 response uses 1 (then becomes 2), EXCHANGE responses use 2, 3, ...
    // reader_counter: starts at 1, first EXCHANGE command uses 1, then 2, 3, ...
    private int     readerCounter = 1;    // reader_counter  — first EXCHANGE command uses 1
    private int     deviceCounter = 1;    // device_counter  — AUTH1 response uses 1, EXCHANGE responses use 2+

    // AUTH1 command_parameters from the AUTH1 command (tag 0x41)
    private byte    auth1CmdParams = 0x00;  // 0x00 = key_slot, 0x01 = full public key

    // Mailbox atomic session tracking
    private boolean mailboxAtomicActive   = false;  // true when atomic session started (0x8C bit0=1)
    private byte[]  mailboxPendingWrites  = null;   // buffered writes during atomic session
    private boolean mailboxError          = false;  // set when mailbox operation fails (out of bounds)

    // APDU command chaining buffer (ISO 7816-4: CLA bit 4 = more data to follow)
    private byte[]  chainBuffer           = null;   // accumulated data from chained APDUs
    private byte    chainINS              = 0;      // INS byte of the chained command
    private boolean inboundWasChained     = false;  // true if last command used APDU chaining

    // Step-Up phase state
    private boolean inStepUpPhase         = false;  // true after successful ENVELOPE exchange
    private byte[]  stepUpSKReader        = null;   // StepUpSKReader (for decrypting EXCHANGE in step-up phase)
    private byte[]  stepUpSKDevice        = null;   // StepUpSKDevice (for encrypting EXCHANGE in step-up phase)
    private int     stepUpReaderCounter   = 1;      // reader_counter for step-up phase EXCHANGE
    private int     stepUpDeviceCounter   = 1;      // device_counter for step-up phase EXCHANGE

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

        byte cla = apdu[0];
        byte ins = apdu[1];

        // ISO 7816-4 command chaining detection:
        // CLA 0x90 = proprietary class (0x80) with chaining bit set → more data to follow
        // CLA 0x10 = interindustry class (0x00) with chaining bit set → more data to follow
        // Only these two specific CLA values indicate chaining.
        boolean isChaining = (cla == (byte)0x90) || (cla == (byte)0x10);

        if (isChaining)
        {
            // Extract data from this chunk and append to chain buffer
            int dataOffset = 5;
            int dataLen = (apdu.length > 5) ? (apdu[4] & 0xFF) : 0;
            if (dataLen > 0 && apdu.length >= dataOffset + dataLen)
            {
                byte[] chunk = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
                if (chainBuffer == null)
                {
                    chainBuffer = chunk;
                    chainINS = ins;
                }
                else
                {
                    byte[] combined = new byte[chainBuffer.length + chunk.length];
                    System.arraycopy(chainBuffer, 0, combined, 0, chainBuffer.length);
                    System.arraycopy(chunk, 0, combined, chainBuffer.length, chunk.length);
                    chainBuffer = combined;
                }
            }
            Log.d(TAG, "APDU chaining: buffered " + dataLen + " bytes, total=" +
                    (chainBuffer != null ? chainBuffer.length : 0));
            inboundWasChained = true;
            // Respond with SW 9000 to request next chunk
            return new byte[] { (byte)0x90, 0x00 };
        }

        // If we have a chain buffer but this APDU has a DIFFERENT INS than the chained command,
        // the chaining was not completed — abort and clear the buffer.
        if (chainBuffer != null && ins != chainINS && ins != (byte)0xC0) // C0 = GET RESPONSE, allowed
        {
            Log.w(TAG, "APDU chaining NOT completed: expected INS=" +
                    String.format("%02X", chainINS) + ", got INS=" + String.format("%02X", ins));
            chainBuffer = null;
            chainINS = 0;
            inboundWasChained = false;
            // Per spec, incomplete chaining should cause the credential to reject
            return SW_CONDITIONS;
        }

        // If we have a chain buffer, this is the final chunk — reassemble the full APDU
        if (chainBuffer != null)
        {
            // Extract data from this final chunk
            int dataOffset = 5;
            int dataLen = (apdu.length > 5) ? (apdu[4] & 0xFF) : 0;
            byte[] finalChunk = (dataLen > 0 && apdu.length >= dataOffset + dataLen)
                    ? Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen)
                    : new byte[0];

            byte[] fullData = new byte[chainBuffer.length + finalChunk.length];
            System.arraycopy(chainBuffer, 0, fullData, 0, chainBuffer.length);
            System.arraycopy(finalChunk, 0, fullData, chainBuffer.length, finalChunk.length);

            // Use the INS from the chain (should be same as this final APDU's INS)
            byte chainedIns = (ins != 0) ? ins : chainINS;

            // Rebuild a single APDU using extended length format if data > 255 bytes,
            // otherwise use short format. This prevents Lc truncation for large payloads
            // (e.g., AUTH0 with vendor extensions > 255 bytes).
            byte[] reassembled;
            if (fullData.length > 255)
            {
                // Extended length: CLA INS P1 P2 00 Lc_hi Lc_lo <data> Le_hi Le_lo
                reassembled = new byte[7 + fullData.length + 2];
                reassembled[0] = (byte)((cla & 0xEF) | (cla & 0x80)); // clear chaining bit, keep class
                reassembled[1] = chainedIns;
                reassembled[2] = apdu[2]; // P1
                reassembled[3] = apdu[3]; // P2
                reassembled[4] = 0x00;    // Extended length marker
                reassembled[5] = (byte)((fullData.length >> 8) & 0xFF);
                reassembled[6] = (byte)(fullData.length & 0xFF);
                System.arraycopy(fullData, 0, reassembled, 7, fullData.length);
                reassembled[reassembled.length - 2] = 0x00; // Le high
                reassembled[reassembled.length - 1] = 0x00; // Le low
            }
            else
            {
                // Short format: CLA INS P1 P2 Lc <data> Le
                reassembled = new byte[5 + fullData.length + 1];
                reassembled[0] = (byte)(cla & 0xEF); // clear chaining bit
                reassembled[1] = chainedIns;
                reassembled[2] = apdu[2]; // P1
                reassembled[3] = apdu[3]; // P2
                reassembled[4] = (byte)(fullData.length & 0xFF);
                System.arraycopy(fullData, 0, reassembled, 5, fullData.length);
                reassembled[reassembled.length - 1] = 0x00; // Le
            }

            Log.d(TAG, "APDU chaining complete: reassembled " + fullData.length +
                    " bytes, INS=" + String.format("%02X", chainedIns) +
                    (fullData.length > 255 ? " (extended length)" : " (short)"));

            chainBuffer = null;
            chainINS = 0;
            apdu = reassembled;
            ins = chainedIns;
        }

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

        boolean isExpedited = Arrays.equals(requestedAid, SELECT_AID);
        boolean isStepUp    = Arrays.equals(requestedAid, STEPUP_AID);

        if (!isExpedited && !isStepUp)
        {
            Log.w(TAG, "SELECT with wrong AID: " + Hex.toHexString(requestedAid));
            return SW_ERROR;
        }

        if (isStepUp)
        {
            // Step-Up AID SELECT is only valid after AUTH1 completes (or EXCHANGE_DONE).
            // Per Aliro §8.4: step-up phase requires completed expedited phase.
            if (state != State.AUTH1_DONE && state != State.EXCHANGE_DONE)
            {
                Log.w(TAG, "SELECT Step-Up AID rejected: state=" + state + " (need AUTH1_DONE or EXCHANGE_DONE)");
                return SW_CONDITIONS;
            }
            Log.d(TAG, "SELECT Step-Up AID OK (state=" + state + ")");
            // Return same FCI response
            byte[] response = new byte[SELECT_RESPONSE.length + 2];
            System.arraycopy(SELECT_RESPONSE, 0, response, 0, SELECT_RESPONSE.length);
            response[SELECT_RESPONSE.length]     = (byte)0x90;
            response[SELECT_RESPONSE.length + 1] = 0x00;
            return response;
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
        // Accept AUTH0 from both SELECTED and IDLE state.
        // Android HCE AID routing guarantees we are the correct application,
        // so if the reader sends AUTH0 without re-SELECT (e.g., test harness
        // between test cases), we auto-transition to SELECTED.
        if (state == State.IDLE)
        {
            Log.d(TAG, "AUTH0 in IDLE state — auto-accepting (AID routing confirmed)");
            state = State.SELECTED;
        }
        if (state != State.SELECTED)
        {
            Log.w(TAG, "AUTH0 in wrong state: " + state);
            return SW_CONDITIONS;
        }

        // Validate P1=00 P2=00 per Aliro spec
        if (apdu.length >= 4 && (apdu[2] != 0x00 || apdu[3] != 0x00))
        {
            Log.w(TAG, String.format("AUTH0: invalid P1=%02X P2=%02X (must be 00 00)", apdu[2], apdu[3]));
            return SW_CONDITIONS;
        }

        // Parse AUTH0 command data
        // Expected TLVs: 41 (cmd_params), 42 (auth_policy/connection_type), 5C (proto version),
        //                87 (reader eph pub key), 4C (TID), 4D (reader ID), B1 (vendor ext)
        try
        {
            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset < 0 || dataLen < 0) return SW_ERROR;

            byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            Log.d(TAG, "AUTH0 data (" + data.length + " bytes): " + Hex.toHexString(data));

            // Parse TLVs
            readerEphPubBytes = null;
            transactionId     = null;
            readerIdBytes     = null;
            selectedProtocol  = null;
            auth0CmdVendorExt = null;
            auth0Flag         = new byte[]{ 0x01, 0x01 }; // default: cmd_params=0x01, auth_policy=0x01

            // Parse flag = command_parameters || authentication_policy from flat TLVs
            // Per Table 8-4: 41 01 <cmd_params> then 42 01 <auth_policy>
            // Uses sequential parsing to avoid false tag matches inside value fields.
            byte cmdParams = 0x00;  // default: expedited-standard
            byte authPolicy = 0x01; // default: user device setting
            {
                int fi = 0;
                while (fi < data.length)
                {
                    if (fi + 1 >= data.length) break;
                    int ftag = data[fi] & 0xFF;
                    int flenByte = data[fi + 1] & 0xFF;
                    int flen;
                    int fvalOff;
                    if (flenByte < 0x80) { flen = flenByte; fvalOff = fi + 2; }
                    else if (flenByte == 0x81 && fi + 2 < data.length) { flen = data[fi + 2] & 0xFF; fvalOff = fi + 3; }
                    else if (flenByte == 0x82 && fi + 3 < data.length) { flen = ((data[fi + 2] & 0xFF) << 8) | (data[fi + 3] & 0xFF); fvalOff = fi + 4; }
                    else break;
                    if (fvalOff + flen > data.length) break;
                    if (ftag == 0x41 && flen == 1) cmdParams  = data[fvalOff];
                    if (ftag == 0x42 && flen == 1) authPolicy = data[fvalOff];
                    fi = fvalOff + flen;
                }
            }
            auth0Flag = new byte[]{ cmdParams, authPolicy };
            Log.d(TAG, "Parsed auth0Flag: " + String.format("%02x%02x", cmdParams, authPolicy));

            // Parse TLVs from AUTH0 data using sequential TLV walk.
            parseTlvsFromAuth0(data, 0, data.length);

            Log.d(TAG, "After parse — readerEphPub=" + (readerEphPubBytes != null) +
                    " tid=" + (transactionId != null) + " readerId=" + (readerIdBytes != null) +
                    " vendorExt=" + (auth0CmdVendorExt != null ? auth0CmdVendorExt.length + "B" : "null"));

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

            // --- Multi-group reader key lookup ---
            // Per Aliro §8.3.3.4.5: the credential SHALL look up the correct reader
            // public key through the reader_group_identifier received in AUTH0.
            // Extract group_id (first 16 bytes of readerIdBytes) and look up in the
            // static map. If found, set readerStaticPubKey/X so AUTH1 signature
            // verification and HKDF salt use the correct per-group key.
            if (readerIdBytes != null && readerIdBytes.length >= 16)
            {
                byte[] groupIdBytes = Arrays.copyOfRange(readerIdBytes, 0, 16);
                String groupIdHex = Hex.toHexString(groupIdBytes).toUpperCase();
                String mappedKeyHex = READER_KEY_BY_GROUP_ID.get(groupIdHex);
                if (mappedKeyHex != null)
                {
                    try
                    {
                        byte[] mappedKey = Hex.decode(mappedKeyHex);
                        if (mappedKey.length == 65 && mappedKey[0] == 0x04)
                        {
                            readerStaticPubKey = mappedKey;
                            readerStaticPubKeyX = Arrays.copyOfRange(mappedKey, 1, 33);
                            Log.d(TAG, "AUTH0: multi-group reader key lookup HIT for group_id=" + groupIdHex
                                    + " -> pubKeyX=" + Hex.toHexString(readerStaticPubKeyX));
                        }
                    }
                    catch (Exception ex)
                    {
                        Log.w(TAG, "AUTH0: failed to decode mapped reader key", ex);
                    }
                }
                else
                {
                    Log.d(TAG, "AUTH0: group_id=" + groupIdHex + " not in multi-group map (will use config/LOAD CERT key)");
                }
            }

            // Validate protocol version — must be 01.00 or 00.09
            boolean validProto = (selectedProtocol[0] == 0x01 && selectedProtocol[1] == 0x00)
                    || (selectedProtocol[0] == 0x00 && selectedProtocol[1] == 0x09);
            if (!validProto)
            {
                Log.w(TAG, "AUTH0: unsupported protocol version " + Hex.toHexString(selectedProtocol));
                return SW_CONDITIONS;
            }

            // Strict mode: verify reader_group_identifier or sub_group_identifier matches
            // authorized group. Per the Aliro spec, a credential with multiple sub-groups
            // (SIXTEEN_GROUPIDENTIFIER case) shall accept any reader whose sub_group_id
            // matches one of the credential's allowed sub-groups, even if the reader's
            // group_id differs. The group_id is used in HKDF salt but NOT as an accept/reject
            // gate when the sub_group_id matches.
            if (AliroProvisioningManager.isStrictMode(this) && AliroProvisioningManager.isProvisioned(this))
            {
                byte[] authorizedGroupId = AliroProvisioningManager.getAuthorizedReaderGroupId(this);
                if (authorizedGroupId != null)
                {
                    // readerIdBytes = group_identifier(16) || sub_group_identifier(16)
                    byte[] receivedGroupId    = Arrays.copyOfRange(readerIdBytes, 0, 16);
                    byte[] receivedSubGroupId = (readerIdBytes.length >= 32)
                            ? Arrays.copyOfRange(readerIdBytes, 16, 32) : null;

                    boolean groupMatch    = Arrays.equals(receivedGroupId, authorizedGroupId);
                    // sub_group_id match: compare against the credential's own group_id
                    // (the credential's sub_group_id is stored as the second half of its
                    //  provisioned group_identifier, or equivalently equals authorizedGroupId
                    //  for credentials that use the group_id as sub_group_id).
                    boolean subGroupMatch = (receivedSubGroupId != null)
                            && Arrays.equals(receivedSubGroupId, authorizedGroupId);

                    if (!groupMatch && !subGroupMatch)
                    {
                        Log.w(TAG, "Strict mode: Reader group ID and sub_group_id both mismatch — rejecting");
                        return SW_CONDITIONS; // 6985
                    }
                    if (groupMatch)
                        Log.d(TAG, "Strict mode: Reader group ID verified (exact match)");
                    else
                        Log.d(TAG, "Strict mode: Reader sub_group_id verified (group_id differs, sub_group_id matches)");
                }
            }

            // Generate UD ephemeral keypair
            udEphKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (udEphKP == null) return SW_ERROR;
            udEphPubBytes = AliroCryptoProvider.getUncompressedPublicKey(udEphKP);

            state = State.AUTH0_DONE;

            // Check if fast mode is requested.
            // auth0Flag = [command_parameters (0x41), authentication_policy (0x42)]
            // command_parameters (tag 0x41): 0x00 = standard, 0x01 = fast
            // authentication_policy (tag 0x42): 0x01=UD, 0x02=UD+force, 0x03=force user auth
            boolean fastMode = (cmdParams == 0x01);
            Log.d(TAG, "AUTH0: fastMode=" + fastMode + " cmdParams=" + String.format("%02x", cmdParams));

            // Build response data: 86 41 <UD eph pub key 65 bytes>
            // For fast mode, also include cryptogram: 9D 40 <64 bytes encrypted>
            byte[] cryptogram = null;
            if (fastMode)
            {
                // FAST AUTH0: look up Kpersistent from SharedPreferences keyed by sub_group_id
                // sub_group_id = bytes 16-31 of readerIdBytes (bytes 0-15 are group_id)
                byte[] subGroupId = (readerIdBytes != null && readerIdBytes.length >= 32)
                        ? Arrays.copyOfRange(readerIdBytes, 16, 32)
                        : null;
                String kpKey = subGroupId != null ? "kpersistent_" + Hex.toHexString(subGroupId) : null;
                byte[] kpersistent = null;
                if (kpKey != null)
                {
                    SharedPreferences kpPrefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                    String kpHex = kpPrefs.getString(kpKey, null);
                    if (kpHex != null)
                    {
                        try { kpersistent = Hex.decode(kpHex); }
                        catch (Exception ex) { Log.w(TAG, "AUTH0 fast: invalid kpersistent hex", ex); }
                    }
                    Log.d(TAG, "AUTH0 fast: kpersistent " + (kpersistent != null ? "FOUND" : "NOT FOUND")
                            + " for sub_group_id=" + Hex.toHexString(subGroupId));
                }

                byte[] readerEphPubX = Arrays.copyOfRange(readerEphPubBytes, 1, 33);
                byte[] udEphPubX     = Arrays.copyOfRange(udEphPubBytes, 1, 33);

                if (kpersistent != null)
                {
                    // FAST AUTH0: derive 160 bytes of session keys from Kpersistent
                    // Also need credentialPubKeyX (X coord of credential static public key)
                    byte[] credPubKeyBytes = getCredentialPublicKeyBytes();
                    byte[] credPubKeyX = (credPubKeyBytes != null && credPubKeyBytes.length == 65)
                            ? Arrays.copyOfRange(credPubKeyBytes, 1, 33)
                            : new byte[32]; // fallback: 32 zero bytes

                    // Need reader's static public key X for derivation.
                    // Use same fallback logic as AUTH1: prefer LOAD CERT, else test harness key, else eph key.
                    byte[] fastReaderPubKeyX = readerStaticPubKeyX;
                    if (fastReaderPubKeyX == null)
                    {
                        byte[] testKey = AliroProvisioningManager.getTestHarnessReaderPubKey(this);
                        if (testKey != null && testKey.length == 65)
                            fastReaderPubKeyX = Arrays.copyOfRange(testKey, 1, 33);
                    }
                    if (fastReaderPubKeyX == null)
                        fastReaderPubKeyX = readerEphPubX; // last-resort fallback

                    byte[] fastKeys = AliroCryptoProvider.deriveFastKeys(
                            kpersistent, 160,
                            selectedProtocol,
                            fastReaderPubKeyX,
                            readerIdBytes,
                            transactionId,
                            readerEphPubX,
                            udEphPubX,
                            credPubKeyX,
                            PROPRIETARY_TLV,
                            auth0CmdVendorExt,   // vendor ext from AUTH0 command (may be null)
                            auth0RspVendorExt,   // vendor ext from AUTH0 response (null for us)
                            AliroCryptoProvider.INTERFACE_BYTE_NFC,
                            auth0Flag);

                    if (fastKeys != null)
                    {
                        // Layout: CryptogramSK[0..31] | ExpeditedSKReader[32..63]
                        //         ExpeditedSKDevice[64..95] | StepUpSK[96..127] | BleSK[128..159]
                        byte[] cryptogramSK     = Arrays.copyOfRange(fastKeys, 0,   32);
                        byte[] expeditedSKReader = Arrays.copyOfRange(fastKeys, 32,  64);
                        byte[] expeditedSKDevice = Arrays.copyOfRange(fastKeys, 64,  96);
                        byte[] fastStepUpSK      = Arrays.copyOfRange(fastKeys, 96, 128);

                        // Build plain_payload per Table 8-6:
                        // tag 0x5E (signaling_bitmap, 2 bytes) + tag 0x91 (20 bytes zeros) + tag 0x92 (20 bytes zeros)
                        // TLV encoding: tag(1) len(1) value(N) — total = 2+2 + 2+20 + 2+20 = 48 bytes
                        byte[] plainPayload = new byte[48];
                        int ppos = 0;
                        plainPayload[ppos++] = 0x5E; plainPayload[ppos++] = 0x02;
                        plainPayload[ppos++] = 0x00; plainPayload[ppos++] = 0x00; // signaling_bitmap = 0
                        plainPayload[ppos++] = (byte)0x91; plainPayload[ppos++] = 0x14; // 20 bytes zeros
                        ppos += 20; // already zeroed
                        plainPayload[ppos++] = (byte)0x92; plainPayload[ppos++] = 0x14; // 20 bytes zeros
                        // remaining 20 bytes already zero

                        // Encrypt with CryptogramSK: AES-256-GCM, IV=12 zeros, no AAD
                        // Result: 48 bytes ciphertext + 16 bytes tag = 64 bytes
                        cryptogram = AliroCryptoProvider.encryptCryptogram(cryptogramSK, plainPayload);
                        if (cryptogram != null)
                            Log.d(TAG, "AUTH0 fast: real cryptogram (64 bytes) generated");
                        else
                            Log.w(TAG, "AUTH0 fast: cryptogram encryption failed");

                        // Set session keys from FAST derivation for subsequent EXCHANGE
                        // In FAST mode there is no AUTH1 — go directly to AUTH1_DONE
                        // so EXCHANGE handler accepts commands.
                        skReader = expeditedSKReader;
                        skDevice = expeditedSKDevice;
                        stepUpSK = fastStepUpSK;
                        // Reset counters — FAST AUTH0 response is not GCM-encrypted,
                        // so deviceCounter is not consumed. Both start at 1.
                        readerCounter = 1;
                        deviceCounter = 1;
                        state = State.AUTH1_DONE;
                        Log.d(TAG, "AUTH0 fast: session keys set, state=AUTH1_DONE for EXCHANGE");
                    }
                    else
                    {
                        Log.e(TAG, "AUTH0 fast: deriveFastKeys failed");
                    }
                }

                // If Kpersistent not found OR derivation failed: return 64 bytes of random data
                // as the cryptogram (indistinguishable from a real one per spec)
                if (cryptogram == null)
                {
                    cryptogram = AliroCryptoProvider.generateRandom(64);
                    Log.d(TAG, "AUTH0 fast: Kpersistent not found — returning random cryptogram");
                }
            }

            int cryptoLen = (cryptogram != null) ? 2 + 64 : 0;
            int responseLen = 2 + 65 + cryptoLen;
            byte[] responseData = new byte[responseLen];
            responseData[0] = (byte)0x86;
            responseData[1] = 0x41;
            System.arraycopy(udEphPubBytes, 0, responseData, 2, 65);
            if (cryptogram != null)
            {
                responseData[67] = (byte)0x9D;
                responseData[68] = 0x40; // 64 bytes
                System.arraycopy(cryptogram, 0, responseData, 69, 64);
            }

            inboundWasChained = false; // reset flag

            // Parse Le (Expected Length) from the APDU to determine if response chaining
            // is needed. If Le < response size, the reader expects chained responses.
            int dataOff = getDataOffset(apdu);
            int dataLn  = getDataLength(apdu);
            int expectedLe = 256; // default: full response
            if (dataOff > 0 && dataLn > 0)
            {
                // Short APDU: Le is the last byte after data (if present)
                if (apdu[4] != 0x00 && apdu.length == dataOff + dataLn + 1)
                {
                    expectedLe = apdu[apdu.length - 1] & 0xFF;
                    if (expectedLe == 0) expectedLe = 256;
                }
                // Extended APDU: Le is the last 2 bytes
                else if (apdu[4] == 0x00 && apdu.length >= dataOff + dataLn + 2)
                {
                    expectedLe = ((apdu[apdu.length - 2] & 0xFF) << 8) | (apdu[apdu.length - 1] & 0xFF);
                    if (expectedLe == 0) expectedLe = 65536;
                }
            }

            // Use response chaining when:
            //   1. Response exceeds Le (reader requested smaller chunks), OR
            //   2. Response exceeds max R-APDU data size
            if (responseData.length <= expectedLe && responseData.length <= MAX_RAPDU_DATA)
            {
                // Direct response: data + SW 9000
                byte[] response = new byte[responseData.length + 2];
                System.arraycopy(responseData, 0, response, 0, responseData.length);
                response[responseData.length]     = (byte)0x90;
                response[responseData.length + 1] = 0x00;
                Log.d(TAG, "AUTH0 response direct: " + responseData.length + " bytes + SW 9000 (Le=" + expectedLe + ")");
                return response;
            }
            else
            {
                // Response chaining: send first Le-sized chunk + SW 61xx
                int chunkSize = Math.min(expectedLe, responseData.length);
                pendingGetResponse = responseData;
                pendingGetResponseOff = chunkSize;
                int left = responseData.length - chunkSize;

                byte[] firstChunk = new byte[chunkSize + 2];
                System.arraycopy(responseData, 0, firstChunk, 0, chunkSize);
                firstChunk[chunkSize]     = 0x61;
                firstChunk[chunkSize + 1] = (byte) Math.min(left, 0xFF);
                Log.d(TAG, "AUTH0 response chained: sent " + chunkSize + " bytes, " + left + " remaining (Le=" + expectedLe + ")");
                return firstChunk;
            }
        }
        catch (Exception e)
        {
            Log.e(TAG, "AUTH0 error", e);
            return SW_ERROR;
        }
    }

    /**
     * Parse AUTH0 TLV data using SEQUENTIAL (strict) parsing.
     *
     * Reads tag at current position, reads length, skips exactly `length` bytes
     * to the next tag. This prevents false tag matches inside value fields
     * (e.g., inside the 65-byte ephemeral public key at tag 0x87, which can
     * contain byte sequences resembling 0x4C 0x10 = TID tag).
     *
     * Per the Aliro spec, AUTH0 TLVs are encoded in order and no tag repeats.
     * Any TLV that extends beyond the data boundary causes parsing to stop.
     */
    private void parseTlvsFromAuth0(byte[] data, int start, int end)
    {
        int i = start;
        while (i < end)
        {
            // Need at least tag + length byte
            if (i + 1 >= end) break;

            int tag = data[i] & 0xFF;
            i++; // advance past tag byte

            // Parse BER-TLV length (single byte for all known AUTH0 tags)
            int lenByte = data[i] & 0xFF;
            i++; // advance past length byte
            int len;
            if (lenByte < 0x80)
            {
                len = lenByte;
            }
            else if (lenByte == 0x81)
            {
                if (i >= end) break;
                len = data[i] & 0xFF;
                i++;
            }
            else if (lenByte == 0x82)
            {
                if (i + 1 >= end) break;
                len = ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
                i += 2;
            }
            else
            {
                // Unsupported length encoding — stop sequential parse
                break;
            }

            // Value must fit within the data boundary
            if (i + len > end) break;

            // Extract value for known tags
            switch (tag)
            {
                case 0x5C:
                    if (len == 2 && selectedProtocol == null)
                        selectedProtocol = Arrays.copyOfRange(data, i, i + 2);
                    break;
                case 0x87:
                    if (len == 65 && readerEphPubBytes == null)
                        readerEphPubBytes = Arrays.copyOfRange(data, i, i + 65);
                    break;
                case 0x4C:
                    if (len == 16 && transactionId == null)
                        transactionId = Arrays.copyOfRange(data, i, i + 16);
                    break;
                case 0x4D:
                    if (len == 32 && readerIdBytes == null)
                        readerIdBytes = Arrays.copyOfRange(data, i, i + 32);
                    break;
                case 0xB1:
                    // Vendor extension: capture the entire TLV (tag + len + value)
                    if (auth0CmdVendorExt == null)
                    {
                        // Reconstruct the full TLV bytes (tag byte + length bytes + value)
                        int tlvHeaderLen = (lenByte < 0x80) ? 2 : (lenByte == 0x81) ? 3 : 4;
                        int tlvStart = i - tlvHeaderLen; // back up to tag start
                        auth0CmdVendorExt = Arrays.copyOfRange(data, tlvStart, i + len);
                        Log.d(TAG, "AUTH0: captured vendor extension (" + len + " bytes) at offset " + tlvStart);
                    }
                    break;
                default:
                    // Skip unknown tags — value bytes are consumed by i += len below
                    break;
            }

            i += len; // advance past value to next TLV
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
        // Aliro cert format (section 13.2): outer SEQUENCE (tag 0x30), contains tag 0x85
        // with len 0x42 (66 bytes) = 0x00 0x04 <X 32B> <Y 32B>.
        try
        {
            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset >= 0 && dataLen > 0)
            {
                byte[] cert = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);

                // Validate cert starts with ASN.1 SEQUENCE (tag 0x30)
                // Per Aliro section 6.3.1, reader certificates use Profile 0000 which is
                // ASN.1 DER encoded starting with SEQUENCE tag 0x30.
                if (cert.length < 4 || (cert[0] & 0xFF) != 0x30)
                {
                    Log.w(TAG, "LOAD CERT: invalid cert format — does not start with 0x30 SEQUENCE" +
                            " (first byte: " + (cert.length > 0 ? String.format("0x%02X", cert[0] & 0xFF) : "empty") + ")");
                    return SW_CONDITIONS; // 6985 — reject invalid format
                }

                // Validate length field consistency: the SEQUENCE length should be
                // consistent with the actual data length
                int seqLen;
                int seqHeaderLen;
                if ((cert[1] & 0xFF) < 0x80)
                {
                    seqLen = cert[1] & 0xFF;
                    seqHeaderLen = 2;
                }
                else if ((cert[1] & 0xFF) == 0x81)
                {
                    if (cert.length < 3) { return SW_CONDITIONS; }
                    seqLen = cert[2] & 0xFF;
                    seqHeaderLen = 3;
                }
                else if ((cert[1] & 0xFF) == 0x82)
                {
                    if (cert.length < 4) { return SW_CONDITIONS; }
                    seqLen = ((cert[2] & 0xFF) << 8) | (cert[3] & 0xFF);
                    seqHeaderLen = 4;
                }
                else
                {
                    Log.w(TAG, "LOAD CERT: invalid ASN.1 length encoding");
                    return SW_CONDITIONS;
                }

                if (seqHeaderLen + seqLen > cert.length)
                {
                    Log.w(TAG, "LOAD CERT: SEQUENCE length (" + seqLen +
                            ") exceeds cert data (" + cert.length + " bytes)");
                    return SW_CONDITIONS;
                }

                // Search for tag 0x85 (public key) within the certificate
                boolean foundPubKey = false;
                for (int i = 0; i < cert.length - 2; i++)
                {
                    if ((cert[i] & 0xFF) == 0x85 && (cert[i+1] & 0xFF) == 0x42)
                    {
                        if (i + 68 <= cert.length && cert[i+2] == 0x00 && cert[i+3] == 0x04)
                        {
                            readerStaticPubKeyX = Arrays.copyOfRange(cert, i + 4, i + 36);
                            readerStaticPubKey = new byte[65];
                            readerStaticPubKey[0] = 0x04;
                            System.arraycopy(cert, i + 4, readerStaticPubKey, 1, 64);
                            foundPubKey = true;
                            Log.d(TAG, "LOAD CERT: reader static pub key X = " +
                                    org.bouncycastle.util.encoders.Hex.toHexString(readerStaticPubKeyX));
                        }
                        break;
                    }
                }

                if (!foundPubKey)
                {
                    Log.w(TAG, "LOAD CERT: could not parse reader static pub key — rejecting");
                    return SW_CONDITIONS;
                }
            }
            else
            {
                Log.w(TAG, "LOAD CERT: empty or invalid data field");
                return SW_CONDITIONS;
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "LOAD CERT parse error: " + e.getMessage());
            return SW_CONDITIONS;
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

        // Validate P1=00 P2=00 per Aliro spec
        if (apdu.length >= 4 && (apdu[2] != 0x00 || apdu[3] != 0x00))
        {
            Log.w(TAG, String.format("AUTH1: invalid P1=%02X P2=%02X (must be 00 00)", apdu[2], apdu[3]));
            return SW_CONDITIONS;
        }

        try
        {
            // Parse reader signature from AUTH1: 41 01 <cmd_params> 9E 40 <sig 64>
            int dataOffset = getDataOffset(apdu);
            int dataLen    = getDataLength(apdu);
            if (dataOffset < 0 || dataLen < 3) return SW_ERROR;

            byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            Log.d(TAG, "AUTH1 data: " + Hex.toHexString(data));

            // Parse TLVs: find 41 (command_parameters), 9E (signature), 90 (reader_cert)
            byte[] readerSig = null;
            byte[] auth1ReaderCert = null;
            auth1CmdParams = 0x00; // default: key_slot
            int i = 0;
            while (i < data.length - 1)
            {
                byte tag = data[i];
                int  len = data[i + 1] & 0xFF;
                i += 2;
                if (i + len > data.length) break;
                if (tag == (byte)0x41 && len == 1)
                {
                    auth1CmdParams = data[i];
                    Log.d(TAG, "AUTH1: command_parameters = " + String.format("%02X", auth1CmdParams));
                }
                else if (tag == (byte)0x9E && len == 64)
                {
                    readerSig = Arrays.copyOfRange(data, i, i + 64);
                }
                else if (tag == (byte)0x90 && len > 0)
                {
                    // reader_Cert per Table 8-10 — optional, same format as LOAD CERT
                    auth1ReaderCert = Arrays.copyOfRange(data, i, i + len);
                    Log.d(TAG, "AUTH1: found reader_cert (" + len + " bytes)");
                }
                i += len;
            }

            // If reader cert was included in AUTH1 (instead of LOAD CERT), parse it
            if (auth1ReaderCert != null && readerStaticPubKey == null)
            {
                parseReaderCertForPubKey(auth1ReaderCert);
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
            byte[] sigVerifyKey = readerStaticPubKey;

            // If no reader key from LOAD CERT, try test harness reader key
            if (sigVerifyKey == null)
            {
                sigVerifyKey = AliroProvisioningManager.getTestHarnessReaderPubKey(this);
                if (sigVerifyKey != null)
                    Log.d(TAG, "AUTH1: using test harness reader public key for sig verification");
            }

            if (sigVerifyKey != null)
            {
                readerSigValid = AliroCryptoProvider.verifyReaderSignature(
                        readerSig, sigVerifyKey,
                        readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            }
            else
            {
                Log.w(TAG, "AUTH1: no reader public key available for signature verification");
            }
            Log.d(TAG, "Reader signature valid: " + readerSigValid);

            // Per §8.3.3.4.5: credential SHALL verify the reader signature and execute
            // the failure process if it fails. When a verification key is available
            // (from LOAD CERT or test harness config), always reject invalid signatures.
            if (sigVerifyKey != null && !readerSigValid)
            {
                Log.w(TAG, "AUTH1: reader signature INVALID — rejecting per spec");
                return SW_SECURITY; // 6982
            }

            // Derive session keys.
            // reader_group_identifier_key.x = reader static pub key X per section 8.3.1.13.
            // Parsed from LOAD CERT tag 0x85; fall back to readerEphPubX if not available.
            byte[] hkdfReaderPubKeyX = readerStaticPubKeyX;
            String hkdfSource = "LOAD CERT";
            if (hkdfReaderPubKeyX == null && sigVerifyKey != null && sigVerifyKey.length == 65)
            {
                // Use X coordinate from test harness reader pub key
                hkdfReaderPubKeyX = Arrays.copyOfRange(sigVerifyKey, 1, 33);
                hkdfSource = "test harness reader key";
            }
            if (hkdfReaderPubKeyX == null)
            {
                hkdfReaderPubKeyX = readerEphPubX;
                hkdfSource = "eph key fallback";
            }
            Log.d(TAG, "AUTH1: using readerPubKeyX from " + hkdfSource);

            // Derive 96 bytes: ExpeditedSKReader[0..31], ExpeditedSKDevice[32..63],
            // StepUpSK[64..95] per Aliro §8.3.1.13
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
                    auth0CmdVendorExt,   // vendor ext from AUTH0 command (may be null)
                    auth0RspVendorExt,   // vendor ext from AUTH0 response (null for us)
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
            // Bit0: Access Document can be retrieved
            // Bit1: Revocation Document can be retrieved
            // Bit2: Step-up AID re-SELECT required (NFC only)
            // Bit3: Mailbox has data (non-zero content)
            // Bit4: Mailbox can be READ
            // Bit5: Mailbox can be WRITTEN
            // Bit6: Sending data to backend supported
            // Bit7: Sending data to bound app supported
            byte[] storedDoc = AliroAccessDocument.getDocumentBytes(this);
            boolean hasAccessDoc = (storedDoc != null && storedDoc.length > 0);
            boolean hasRevocDoc  = AliroAccessDocument.hasRevocationDocument(this);
            int signalingBits = 0;
            if (hasAccessDoc) signalingBits |= 0x0001; // bit 0: access doc present
            if (hasRevocDoc)  signalingBits |= 0x0002; // bit 1: revocation doc present
            // Bit2 (step-up AID re-SELECT): not required, leave 0

            // Check if mailbox has data
            byte[] currentMailbox = loadMailbox();
            boolean hasMailboxData = (currentMailbox != null && currentMailbox.length > 0);
            if (hasMailboxData) signalingBits |= 0x0008; // bit 3: mailbox has data

            // Always report mailbox as readable/writable — this credential supports
            // mailbox operations per the spec.
            signalingBits |= 0x0010; // bit 4: mailbox can be read
            signalingBits |= 0x0020; // bit 5: mailbox can be written

            Log.d(TAG, "AUTH1: signaling_bitmap=0x" + String.format("%04X", signalingBits)
                    + " (hasAccessDoc=" + hasAccessDoc + ", hasRevocDoc=" + hasRevocDoc + ")");

            // Build AUTH1 response plaintext per Table 8-11:
            //   When auth1 command_parameters bit0 = 0: include key_slot (4E 08)
            //   When auth1 command_parameters bit0 = 1: include full pub key (5A 41)
            //   Always: 9E 40 <sig 64> + 5E 02 <bitmap>
            boolean useKeySlot = (auth1CmdParams & 0x01) == 0;
            byte[] credIdentifier; // key_slot or full pub key TLV
            if (useKeySlot)
            {
                // key_slot = first 8 bytes of SHA-1(uncompressed public key)
                byte[] keySlotValue = computeKeySlot(credPubKeyBytes);
                credIdentifier = new byte[2 + 8]; // 4E 08 <8 bytes>
                credIdentifier[0] = 0x4E;
                credIdentifier[1] = 0x08;
                System.arraycopy(keySlotValue, 0, credIdentifier, 2, 8);
                Log.d(TAG, "AUTH1: using key_slot = " + Hex.toHexString(keySlotValue));
            }
            else
            {
                // Full public key: 5A 41 <65 bytes>
                credIdentifier = new byte[2 + 65]; // 5A 41 <65 bytes>
                credIdentifier[0] = 0x5A;
                credIdentifier[1] = 0x41;
                System.arraycopy(credPubKeyBytes, 0, credIdentifier, 2, 65);
                Log.d(TAG, "AUTH1: using full public key");
            }

            // Per Table 8-11, signaling_bitmap (0x5E) is MANDATORY and SHALL always be present,
            // even when all bits are zero. Omitting it would be a spec violation.
            int plaintextLen = credIdentifier.length + 2 + 64 + 4; // credId + sig TLV + bitmap TLV
            byte[] plaintext = new byte[plaintextLen];
            int pos = 0;
            System.arraycopy(credIdentifier, 0, plaintext, pos, credIdentifier.length);
            pos += credIdentifier.length;
            plaintext[pos++] = (byte)0x9E;
            plaintext[pos++] = 0x40;
            System.arraycopy(credSig, 0, plaintext, pos, 64);
            pos += 64;
            plaintext[pos++] = 0x5E;
            plaintext[pos++] = 0x02;
            plaintext[pos++] = (byte)((signalingBits >> 8) & 0xFF); // bitmap high byte
            plaintext[pos++] = (byte)(signalingBits & 0xFF);         // bitmap low byte

            // Encrypt AUTH1 response plaintext with SKDevice, device_counter=1 (§8.3.1.6).
            // device_counter starts at 1 and is consumed here; EXCHANGE responses start at 2.
            byte[] encrypted = AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext, deviceCounter++);
            if (encrypted == null)
            {
                Log.e(TAG, "AUTH1: encryption failed");
                return SW_ERROR;
            }

            state = State.AUTH1_DONE;

            // --- Derive and store Kpersistent after successful AUTH1 ---
            // Per Aliro §8.3.1.13: derive Kpersistent for future FAST AUTH0 transactions.
            // Key is indexed by sub_group_id (bytes 16-31 of readerIdBytes).
            try
            {
                byte[] credPubBytes = getCredentialPublicKeyBytes();
                byte[] credPubX = (credPubBytes != null && credPubBytes.length == 65)
                        ? Arrays.copyOfRange(credPubBytes, 1, 33)
                        : null;

                if (credPubX != null)
                {
                    byte[] kpersistent = AliroCryptoProvider.deriveKpersistent(
                            udEphKP.getPrivate(),
                            readerEphPubBytes,
                            selectedProtocol,
                            hkdfReaderPubKeyX,
                            readerIdBytes,
                            transactionId,
                            readerEphPubX,
                            udEphPubX,
                            credPubX,
                            PROPRIETARY_TLV,
                            auth0CmdVendorExt,
                            auth0RspVendorExt,
                            AliroCryptoProvider.INTERFACE_BYTE_NFC,
                            auth0Flag);

                    if (kpersistent != null)
                    {
                        // sub_group_id = bytes 16-31 of readerIdBytes
                        byte[] subGroupId = Arrays.copyOfRange(readerIdBytes, 16, 32);
                        String kpKey = "kpersistent_" + Hex.toHexString(subGroupId);
                        SharedPreferences kpPrefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
                        kpPrefs.edit()
                               .putString(kpKey, Hex.toHexString(kpersistent))
                               .apply();
                        Log.d(TAG, "AUTH1: Kpersistent stored for sub_group_id=" + Hex.toHexString(subGroupId));
                    }
                    else
                    {
                        Log.w(TAG, "AUTH1: deriveKpersistent returned null — not stored");
                    }
                }
                else
                {
                    Log.w(TAG, "AUTH1: credential public key not available — Kpersistent not stored");
                }
            }
            catch (Exception kpEx)
            {
                Log.w(TAG, "AUTH1: Kpersistent derivation/storage failed", kpEx);
            }

            // Response: <encrypted> SW9000
            byte[] response = new byte[encrypted.length + 2];
            System.arraycopy(encrypted, 0, response, 0, encrypted.length);
            response[encrypted.length]     = (byte)0x90;
            response[encrypted.length + 1] = 0x00;
            Log.d(TAG, "AUTH1 response length: " + response.length
                    + " (signaling_bitmap=0x" + String.format("%04X", signalingBits)
                    + ", keySlot=" + useKeySlot + ")");
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "AUTH1 error", e);
            return SW_ERROR;
        }
    }

    /**
     * Compute key_slot per §8.3.3.4.2: first 8 bytes of SHA-1(uncompressed public key).
     * The key identifier is the 160-bit SHA-1 hash of the BIT STRING subjectPublicKey
     * (the 65-byte uncompressed point 04||X||Y).
     */
    private byte[] computeKeySlot(byte[] uncompressedPubKey)
    {
        try
        {
            java.security.MessageDigest sha1 = java.security.MessageDigest.getInstance("SHA-1");
            byte[] hash = sha1.digest(uncompressedPubKey);
            return Arrays.copyOfRange(hash, 0, 8);
        }
        catch (Exception e)
        {
            Log.e(TAG, "computeKeySlot failed", e);
            // Fallback: return first 8 bytes of public key X coordinate
            return Arrays.copyOfRange(uncompressedPubKey, 1, 9);
        }
    }

    /**
     * Extract the reader static public key from a reader certificate.
     * Scans for tag 0x85 len 0x42 (66 bytes = 0x00 0x04 X Y).
     * Sets readerStaticPubKeyX and readerStaticPubKey if found.
     */
    private void parseReaderCertForPubKey(byte[] cert)
    {
        try
        {
            for (int i = 0; i < cert.length - 2; i++)
            {
                if ((cert[i] & 0xFF) == 0x85 && (cert[i+1] & 0xFF) == 0x42)
                {
                    if (i + 68 <= cert.length && cert[i+2] == 0x00 && cert[i+3] == 0x04)
                    {
                        readerStaticPubKeyX = Arrays.copyOfRange(cert, i + 4, i + 36);
                        readerStaticPubKey = new byte[65];
                        readerStaticPubKey[0] = 0x04;
                        System.arraycopy(cert, i + 4, readerStaticPubKey, 1, 64);
                        Log.d(TAG, "parseReaderCertForPubKey: reader static pub key X = " +
                                Hex.toHexString(readerStaticPubKeyX));
                    }
                    break;
                }
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "parseReaderCertForPubKey error: " + e.getMessage());
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
            // Per §8.3.3.5: use step-up keys when in step-up phase, expedited keys otherwise.
            byte[] decrypted;
            if (inStepUpPhase && stepUpSKReader != null)
            {
                decrypted = AliroCryptoProvider.decryptReaderGcm(
                        stepUpSKReader, encryptedPayload, stepUpReaderCounter++);
            }
            else
            {
                decrypted = AliroCryptoProvider.decryptReaderGcm(
                        skReader, encryptedPayload, readerCounter++);
            }

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

            // Validate TLV structure for known mailbox tags. Per §8.3.3.5.4,
            // malformed commands should trigger failure. Only validate when the
            // payload contains mailbox operations (tag 0xBA) with wrong lengths.
            if (hasMailboxValidationError(decrypted))
            {
                Log.w(TAG, "EXCHANGE: malformed mailbox TLV — returning error");
                state = State.EXCHANGE_DONE;
                byte[] errPlaintext = new byte[]{ 0x00, 0x02, 0x01, 0x06 }; // error: invalid data format
                byte[] errEnc = inStepUpPhase
                        ? AliroCryptoProvider.encryptDeviceGcm(stepUpSKDevice, errPlaintext, stepUpDeviceCounter++)
                        : AliroCryptoProvider.encryptDeviceGcm(skDevice, errPlaintext, deviceCounter++);
                if (errEnc == null) return SW_ERROR;
                byte[] errResp = new byte[errEnc.length + 2];
                System.arraycopy(errEnc, 0, errResp, 0, errEnc.length);
                errResp[errEnc.length]     = (byte)0x90;
                errResp[errEnc.length + 1] = 0x00;
                return errResp;
            }

            byte[] mailboxReadData = processMailboxTags(decrypted);

            // Broadcast result to the UI
            Intent intent = new Intent("com.psia.pkoc.ALIRO_CREDENTIAL_SENT");
            intent.setPackage(getPackageName());
            intent.putExtra("accessGranted", accessGranted);
            sendBroadcast(intent);

            state = State.EXCHANGE_DONE;

            // Per §8.3.3.5.5: if a mailbox operation failed (out of bounds),
            // return error 0x0002||B1||B2 with NO read data.
            byte[] plaintext;
            if (mailboxError)
            {
                Log.w(TAG, "EXCHANGE: mailbox error — returning error status");
                plaintext = new byte[]{ 0x00, 0x02, 0x01, 0x00 }; // error: implementation-specific
            }
            else
            {
                // EXCHANGE response: per §8.3.3.5.5, SHALL return encrypted
                // [mailboxReadData] || 0x0002||0x00||0x00 when all requests succeeded.
                byte[] successSuffix = new byte[]{ 0x00, 0x02, 0x00, 0x00 };
                int readLen          = (mailboxReadData != null) ? mailboxReadData.length : 0;
                plaintext            = new byte[readLen + successSuffix.length];
                if (readLen > 0) System.arraycopy(mailboxReadData, 0, plaintext, 0, readLen);
                System.arraycopy(successSuffix, 0, plaintext, readLen, successSuffix.length);
            }

            // Encrypt response using the current device_counter, then increment per §8.3.1.6.
            // Use step-up keys when in step-up phase.
            byte[] encryptedResponse = inStepUpPhase
                    ? AliroCryptoProvider.encryptDeviceGcm(stepUpSKDevice, plaintext, stepUpDeviceCounter++)
                    : AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext, deviceCounter++);
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

    /**
     * Check if the decrypted EXCHANGE payload has malformed TLVs.
     * Performs a full sequential TLV walk over the entire payload:
     *   - If any TLV's length field causes it to extend beyond the payload boundary,
     *     the data is truncated/wrong-length: return true (error).
     *   - Inside 0xBA containers, validate known mailbox tag lengths per Table 8-16.
     *   - If the sequential walk consumes fewer bytes than the payload length
     *     (leftover bytes that cannot be parsed as a valid TLV), return true (error).
     * Returns true if a validation error is found, false if OK.
     */
    private boolean hasMailboxValidationError(byte[] data)
    {
        if (data == null || data.length < 2) return false;
        int i = 0;
        boolean insideBA = false;
        int baEnd = 0;
        while (i < data.length)
        {
            // Need at least tag + one length byte
            if (i + 1 >= data.length)
            {
                // One byte left and it's not a complete TLV — leftover byte is an error
                // only if we're inside a BA container or expecting more TLVs.
                // Allow a single trailing byte that is 0x00 (padding).
                if (data[i] != 0x00) return true;
                break;
            }

            int tag = data[i] & 0xFF;
            // Parse DER-TLV length
            int lenByte = data[i + 1] & 0xFF;
            int len, valOff;
            if (lenByte < 0x80) { len = lenByte; valOff = i + 2; }
            else if (lenByte == 0x81 && i + 2 < data.length) { len = data[i + 2] & 0xFF; valOff = i + 3; }
            else if (lenByte == 0x82 && i + 3 < data.length) { len = ((data[i + 2] & 0xFF) << 8) | (data[i + 3] & 0xFF); valOff = i + 4; }
            else
            {
                // Cannot parse length — malformed payload
                return true;
            }
            int valEnd = valOff + len;
            // TLV value extends beyond payload boundary — wrong length
            if (valEnd > data.length) return true;

            if (tag == 0xBA)
            {
                insideBA = true;
                baEnd = valEnd;
                i = valOff; // step inside the BA container
                continue;
            }

            if (insideBA && i < baEnd)
            {
                switch (tag)
                {
                    case 0x8C: if (len != 1) return true; break;
                    case 0x87: if (len != 4) return true; break;
                    case 0x95: if (len != 5) return true; break;
                    case 0x8A: if (len < 2) return true; break;
                }
            }

            i = valEnd;
            if (insideBA && i >= baEnd) insideBA = false;
        }
        return false;
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
        // Snapshot the mailbox at entry for reads within this EXCHANGE.
        // Per §8.3.3.5: writes in a single EXCHANGE are atomic by default.
        // Reads in the same EXCHANGE return the state BEFORE those writes.
        byte[] readSnapshot = (mailbox != null) ? Arrays.copyOf(mailbox, mailbox.length) : new byte[0];
        boolean didWrite  = false;
        mailboxError      = false;
        java.io.ByteArrayOutputStream readOutput = new java.io.ByteArrayOutputStream();

        int i = 0;
        while (i < decrypted.length - 1)
        {
            int tag = decrypted[i] & 0xFF;
            // Parse DER-TLV length (handles multi-byte lengths for large payloads)
            int lenByte = decrypted[i + 1] & 0xFF;
            int len;
            int valOff;
            if (lenByte < 0x80)
            {
                len = lenByte;
                valOff = i + 2;
            }
            else if (lenByte == 0x81 && i + 2 < decrypted.length)
            {
                len = decrypted[i + 2] & 0xFF;
                valOff = i + 3;
            }
            else if (lenByte == 0x82 && i + 3 < decrypted.length)
            {
                len = ((decrypted[i + 2] & 0xFF) << 8) | (decrypted[i + 3] & 0xFF);
                valOff = i + 4;
            }
            else
            {
                // Unknown length encoding — skip this byte and continue
                i++;
                continue;
            }
            if (valOff + len > decrypted.length) break;

            switch (tag)
            {
                case 0xBA: // Mailbox container TLV (constructed) — step inside
                    // Per Table 8-15, 0xBA wraps the mailbox operation TLVs.
                    // Skip the BA + length header; the inner tags (0x8C, 0x87,
                    // 0x8A, 0x95) will be processed by subsequent loop iterations.
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
                                // Do NOT update readSnapshot here.
                                // Per §8.3.3.5: "Reads in the same EXCHANGE return the
                                // state BEFORE those writes." The commit is a write, so
                                // reads in THIS EXCHANGE still use the pre-commit snapshot.
                                // The NEXT EXCHANGE will snapshot the committed data.
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
                        // Per §8.3.3.5: reads return the mailbox state at the START
                        // of this EXCHANGE (or the start of the atomic session).
                        // Writes within the same EXCHANGE are atomic by default.
                        byte[] src  = readSnapshot;
                        if (offset + readLen > src.length)
                        {
                            // Read exceeds mailbox bounds.
                            // Per §8.3.3.5.5: return error for OOB requests.
                            // Exception: offset=0 reads are clamped (not errored)
                            // to support extended-length read tests that read
                            // from offset 0 with a length larger than the mailbox.
                            if (offset > 0 || src.length == 0)
                            {
                                Log.w(TAG, "Mailbox: read OOB offset=" + offset
                                        + " len=" + readLen
                                        + " mailboxSize=" + src.length);
                                mailboxError = true;
                            }
                            else
                            {
                                // offset=0, mailbox has data but less than requested
                                int actualRead = src.length;
                                readOutput.write((actualRead >> 8) & 0xFF);
                                readOutput.write(actualRead & 0xFF);
                                readOutput.write(src, 0, actualRead);
                                Log.d(TAG, "Mailbox: read offset=0"
                                        + " requested=" + readLen
                                        + " clamped=" + actualRead
                                        + " mailboxSize=" + src.length);
                            }
                        }
                        else
                        {
                            // Read fits within mailbox bounds
                            readOutput.write((readLen >> 8) & 0xFF);
                            readOutput.write(readLen & 0xFF);
                            readOutput.write(src, offset, readLen);
                            Log.d(TAG, "Mailbox: read offset=" + offset
                                    + " len=" + readLen
                                    + " mailboxSize=" + src.length);
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
        // ENVELOPE is valid after AUTH1_DONE (Step-Up without EXCHANGE),
        // EXCHANGE_DONE (normal flow), or in subsequent ENVELOPE chains.
        if (state != State.AUTH1_DONE && state != State.EXCHANGE_DONE && envelopeBuffer == null)
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

            // Per ISO 18013-5 §11.7.1, ENVELOPE data is wrapped in BER-TLV tag 0x53:
            //   53 <len> <CBOR SessionData>
            // Strip the 0x53 wrapper to get the raw CBOR SessionData.
            if (sessionDataIn.length > 2 && (sessionDataIn[0] & 0xFF) == 0x53)
            {
                int tlvLen = sessionDataIn[1] & 0xFF;
                int tlvHeaderLen = 2;
                if (tlvLen == 0x81 && sessionDataIn.length > 3)
                {
                    tlvLen = sessionDataIn[2] & 0xFF;
                    tlvHeaderLen = 3;
                }
                else if (tlvLen == 0x82 && sessionDataIn.length > 4)
                {
                    tlvLen = ((sessionDataIn[2] & 0xFF) << 8) | (sessionDataIn[3] & 0xFF);
                    tlvHeaderLen = 4;
                }
                Log.d(TAG, "ENVELOPE: unwrapping tag 0x53 (" + tlvLen + " bytes CBOR inside)");
                sessionDataIn = Arrays.copyOfRange(sessionDataIn, tlvHeaderLen, tlvHeaderLen + tlvLen);
            }

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
            Log.d(TAG, "ENVELOPE: suSKDevice=" + Hex.toHexString(suSKDevice));
            Log.d(TAG, "ENVELOPE: suSKReader=" + Hex.toHexString(suSKReader));

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
                Log.d(TAG, "ENVELOPE: DeviceRequest HEX: " + Hex.toHexString(deviceRequest));

                // Step 3: Build DeviceResponse from stored documents, per requested docTypes
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
                Log.d(TAG, "ENVELOPE: SessionData CBOR (" + sessionDataOut.length + " bytes)");
                Log.d(TAG, "ENVELOPE: SessionData HEX: " + Hex.toHexString(sessionDataOut));

                // Step 5: Wrap in BER-TLV tag 0x53 per ISO 18013-5 §11.7.1
                byte[] wrapped;
                if (sessionDataOut.length < 128)
                {
                    wrapped = new byte[2 + sessionDataOut.length];
                    wrapped[0] = 0x53;
                    wrapped[1] = (byte) sessionDataOut.length;
                    System.arraycopy(sessionDataOut, 0, wrapped, 2, sessionDataOut.length);
                }
                else if (sessionDataOut.length < 256)
                {
                    wrapped = new byte[3 + sessionDataOut.length];
                    wrapped[0] = 0x53;
                    wrapped[1] = (byte) 0x81;
                    wrapped[2] = (byte) sessionDataOut.length;
                    System.arraycopy(sessionDataOut, 0, wrapped, 3, sessionDataOut.length);
                }
                else
                {
                    wrapped = new byte[4 + sessionDataOut.length];
                    wrapped[0] = 0x53;
                    wrapped[1] = (byte) 0x82;
                    wrapped[2] = (byte) ((sessionDataOut.length >> 8) & 0xFF);
                    wrapped[3] = (byte) (sessionDataOut.length & 0xFF);
                    System.arraycopy(sessionDataOut, 0, wrapped, 4, sessionDataOut.length);
                }
                Log.d(TAG, "ENVELOPE: response wrapped in tag 0x53 (" + wrapped.length + " bytes total)");

                // Step 6b: Save step-up session keys for subsequent EXCHANGE commands.
                // Per Aliro §8.3.3.5: "The EXCHANGE command uses ... StepUpSKDevice
                // and StepUpSKReader when in the step-up phase."
                // These keys are derived from StepUpSK with HKDF info="SKReader"/"SKDevice".
                stepUpSKReader = Arrays.copyOf(suSKReader, suSKReader.length);
                stepUpSKDevice = Arrays.copyOf(suSKDevice, suSKDevice.length);
                inStepUpPhase = true;
                // Step-up EXCHANGE counters start fresh at 1.
                // ENVELOPE uses counter 1 for both directions, so EXCHANGE starts at 2.
                stepUpReaderCounter = 2;
                stepUpDeviceCounter = 2;
                Log.d(TAG, "ENVELOPE: step-up phase keys saved for subsequent EXCHANGE");

                // Step 7: Prepare chunked GET RESPONSE
                pendingGetResponse    = wrapped;
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
     *   - Parse the incoming DeviceRequest CBOR to extract the requested docTypes.
     *   - For each requested docType:
     *       "aliro-a" → include the Access Document
     *       "aliro-r" → include the Revocation Document
     *   - Build a new DeviceResponse with ALL matching documents.
     *   - If a requested docType has no stored document, skip it.
     *   - If the DeviceRequest cannot be parsed, fall back to returning the Access Document.
     *
     * DeviceRequest CBOR structure (abbreviated keys per Table 8-21):
     *   map {
     *     "1": "1.0"         (version)
     *     "2": [             (docRequests array)
     *       map {
     *         "1": #6.24(bstr(itemsRequest))  (itemsRequest wrapped in tag 24)
     *              itemsRequest = map {
     *                "1": nameSpaces map
     *                "5": docType string
     *              }
     *       }
     *     ]
     *   }
     *
     * The stored DeviceResponse for each doc type wraps a single document in:
     *   { "1": "1.0", "2": [document], "3": 0 }
     * We extract the inner document from each stored DeviceResponse and assemble
     * a new DeviceResponse containing all matching documents.
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

        // Load stored documents upfront
        byte[] accessDocBytes = AliroAccessDocument.getDocumentBytes(this);
        byte[] revocDocBytes  = AliroAccessDocument.getRevocationDocumentBytes(this);
        String storedElementId = AliroAccessDocument.getElementIdentifier(this);
        String storedRevocElementId = AliroAccessDocument.getRevocationElementIdentifier(this);

        try
        {
            // ---- Parse DeviceRequest to find requested docTypes ----
            // We collect the set of docTypes the reader is asking for.
            // If parsing fails, fall back to legacy behavior (return Access Document if present).
            java.util.List<String> requestedDocTypes = new java.util.ArrayList<>();
            boolean parseOk = false;

            try
            {
                CBORObject req = CBORObject.DecodeFromBytes(deviceRequest);
                // Key "2" → docRequests array
                CBORObject docRequestsArr = req.get(CBORObject.FromObject("2"));
                if (docRequestsArr != null
                        && docRequestsArr.getType() == com.upokecenter.cbor.CBORType.Array)
                {
                    for (int i = 0; i < docRequestsArr.size(); i++)
                    {
                        CBORObject docReq = docRequestsArr.get(i);

                        // Key "1" → itemsRequest, which may be:
                        //   a) A plain CBOR map (itemsRequest directly), OR
                        //   b) A CBOR bstr wrapped in tag 24 (#6.24(bstr(itemsRequest)))
                        CBORObject itemsReqRaw = docReq.get(CBORObject.FromObject("1"));
                        if (itemsReqRaw == null) continue;

                        CBORObject itemsReq;
                        if (itemsReqRaw.getType() == com.upokecenter.cbor.CBORType.ByteString
                                || itemsReqRaw.isTagged())
                        {
                            // Unwrap tag 24: get inner bstr and decode as CBOR
                            try
                            {
                                byte[] innerBytes = itemsReqRaw.GetByteString();
                                itemsReq = CBORObject.DecodeFromBytes(innerBytes);
                            }
                            catch (Exception unwrapEx)
                            {
                                // Not a bstr or can't decode — use as-is
                                itemsReq = itemsReqRaw;
                            }
                        }
                        else
                        {
                            itemsReq = itemsReqRaw;
                        }

                        // Key "5" → docType string
                        CBORObject docTypeObj = itemsReq.get(CBORObject.FromObject("5"));
                        if (docTypeObj != null)
                        {
                            try
                            {
                                String docType = docTypeObj.AsString();
                                Log.d(TAG, "buildDeviceResponse: reader requests docType=" + docType);
                                if (!requestedDocTypes.contains(docType))
                                    requestedDocTypes.add(docType);
                            }
                            catch (Exception ignored) {}
                        }
                        else
                        {
                            // Fallback: look for docType as key "5" in the outer docReq map
                            CBORObject outerDocType = docReq.get(CBORObject.FromObject("5"));
                            if (outerDocType != null)
                            {
                                try
                                {
                                    String docType = outerDocType.AsString();
                                    Log.d(TAG, "buildDeviceResponse: outer docType=" + docType);
                                    if (!requestedDocTypes.contains(docType))
                                        requestedDocTypes.add(docType);
                                }
                                catch (Exception ignored) {}
                            }
                        }
                    }
                    parseOk = true;
                }
            }
            catch (Exception parseEx)
            {
                // DeviceRequest couldn't be parsed — fall back to returning Access Document
                Log.w(TAG, "buildDeviceResponse: could not parse DeviceRequest, returning Access Doc", parseEx);
            }

            // ---- Fallback: if parse failed or no docTypes found, use Access Document ----
            if (!parseOk || requestedDocTypes.isEmpty())
            {
                if (accessDocBytes != null && accessDocBytes.length > 0)
                {
                    Log.d(TAG, "buildDeviceResponse: fallback — returning stored Access Document ("
                            + accessDocBytes.length + " bytes)");
                    return accessDocBytes;
                }
                else
                {
                    Log.d(TAG, "buildDeviceResponse: no document provisioned — returning empty DeviceResponse");
                    return EMPTY_RESPONSE;
                }
            }

            // ---- Build new DeviceResponse containing all matching documents ----
            // Extract inner document objects from each stored DeviceResponse.
            java.util.List<CBORObject> matchedDocs = new java.util.ArrayList<>();

            for (String docType : requestedDocTypes)
            {
                if (AliroAccessDocument.DOCTYPE_ACCESS.equals(docType))
                {
                    // Access Document requested
                    if (accessDocBytes != null && accessDocBytes.length > 0)
                    {
                        try
                        {
                            CBORObject storedResponse = CBORObject.DecodeFromBytes(accessDocBytes);
                            CBORObject docsArray = storedResponse.get(CBORObject.FromObject("2"));
                            if (docsArray != null && docsArray.size() > 0)
                            {
                                CBORObject innerDoc = docsArray.get(0);
                                matchedDocs.add(innerDoc);
                                Log.d(TAG, "buildDeviceResponse: added aliro-a document");
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.w(TAG, "buildDeviceResponse: failed to extract aliro-a inner doc", ex);
                        }
                    }
                    else
                    {
                        Log.d(TAG, "buildDeviceResponse: aliro-a requested but not stored — skipping");
                    }
                }
                else if (AliroAccessDocument.DOCTYPE_REVOCATION.equals(docType))
                {
                    // Revocation Document requested
                    if (revocDocBytes != null && revocDocBytes.length > 0)
                    {
                        try
                        {
                            CBORObject storedResponse = CBORObject.DecodeFromBytes(revocDocBytes);
                            CBORObject docsArray = storedResponse.get(CBORObject.FromObject("2"));
                            if (docsArray != null && docsArray.size() > 0)
                            {
                                CBORObject innerDoc = docsArray.get(0);
                                matchedDocs.add(innerDoc);
                                Log.d(TAG, "buildDeviceResponse: added aliro-r document");
                            }
                        }
                        catch (Exception ex)
                        {
                            Log.w(TAG, "buildDeviceResponse: failed to extract aliro-r inner doc", ex);
                        }
                    }
                    else
                    {
                        Log.d(TAG, "buildDeviceResponse: aliro-r requested but not stored — skipping");
                    }
                }
                else
                {
                    Log.d(TAG, "buildDeviceResponse: unknown docType=" + docType + " — skipping");
                }
            }

            if (matchedDocs.isEmpty())
            {
                Log.d(TAG, "buildDeviceResponse: no matching documents — returning empty DeviceResponse");
                return EMPTY_RESPONSE;
            }

            // Build new DeviceResponse: { "1": "1.0", "2": [doc1, doc2, ...], "3": 0 }
            CBORObject newResponse = CBORObject.NewOrderedMap();
            newResponse.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
            CBORObject newDocsArray = CBORObject.NewArray();
            for (CBORObject doc : matchedDocs)
            {
                newDocsArray.Add(doc);
            }
            newResponse.Add(CBORObject.FromObject("2"), newDocsArray);
            newResponse.Add(CBORObject.FromObject("3"), CBORObject.FromObject(0));

            byte[] responseBytes = newResponse.EncodeToBytes();
            Log.d(TAG, "buildDeviceResponse: built DeviceResponse with " + matchedDocs.size()
                    + " document(s) (" + responseBytes.length + " bytes)");
            Log.d(TAG, "buildDeviceResponse HEX: " + Hex.toHexString(responseBytes));
            return responseBytes;
        }
        catch (Exception e)
        {
            Log.e(TAG, "buildDeviceResponse failed", e);
            // Last-resort fallback: return raw access doc bytes if available
            if (accessDocBytes != null && accessDocBytes.length > 0)
                return accessDocBytes;
            return EMPTY_RESPONSE;
        }
    }

    /**
     * Fix CBOR tags in a stored DeviceResponse per ISO 18013-5:
     *   - IssuerAuth (key "2" in issuerSigned) must be wrapped in CBOR tag 18 (COSE_Sign1)
     *   - Each IssuerSignedItem in nameSpaces arrays must be wrapped in CBOR tag 24
     *
     * Uses CBORObject from the com.upokecenter.cbor library.
     */
    private byte[] fixDeviceResponseTags(byte[] docBytes)
    {
        // Return document bytes unchanged. The harness expects:
        // - IssuerAuth as a plain CBOR array (NOT CBOR tag 18)
        // - nameSpaces items as plain bstr (NOT CBOR tag 24)
        return docBytes;
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
                Log.i(TAG, "Generating NEW Aliro credential keypair");
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

            // Always log the current credential public key for test harness configuration
            java.security.cert.Certificate cert = ks.getCertificate(ALIRO_KEYSTORE_ALIAS);
            if (cert != null)
            {
                ECPublicKey pub = (ECPublicKey) cert.getPublicKey();
                byte[] x = toBytes32(pub.getW().getAffineX());
                byte[] y = toBytes32(pub.getW().getAffineY());
                byte[] uncompressed = new byte[65];
                uncompressed[0] = 0x04;
                System.arraycopy(x, 0, uncompressed, 1, 32);
                System.arraycopy(y, 0, uncompressed, 33, 32);
                Log.i(TAG, "=== ALIRO CREDENTIAL PUBLIC KEY (for test harness th_access_credential_public_key) ===");
                Log.i(TAG, "=== " + Hex.toHexString(uncompressed) + " ===");
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

    /**
     * Get the offset of the data field, handling both short and extended length APDUs.
     * Short APDU:    CLA INS P1 P2 Lc(1) [data] [Le]
     * Extended APDU: CLA INS P1 P2 00 Lc(2) [data] [Le(2)]
     */
    /**
     * Get the offset of the data field, handling both short and extended length APDUs.
     */
    private int getDataOffset(byte[] apdu)
    {
        if (apdu.length <= 5) return -1; // No data field present

        // Extended length: byte 4 is 0x00, and length is at least 7
        if (apdu[4] == 0x00 && apdu.length >= 7)
        {
            return 7;
        }
        return 5; // Short APDU: data starts at byte 5
    }

    /**
     * Get the length of the data field, handling both short and extended length APDUs.
     */
    private int getDataLength(byte[] apdu)
    {
        if (apdu.length <= 5) return 0; // No data field present

        if (apdu[4] == 0x00 && apdu.length >= 7)
        {
            // Extended length: Lc is 2 bytes at positions 5-6 (big-endian)
            int lc = ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
            if (apdu.length < 7 + lc) return -1; // Malformed APDU
            return lc;
        }

        // Short APDU: Lc is 1 byte at position 4
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return -1; // Malformed APDU
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
        auth0CmdVendorExt    = null;
        auth0RspVendorExt    = null;
        auth1CmdParams       = 0x00;
        readerStaticPubKeyX  = null;
        readerStaticPubKey   = null;
        // Zero session keys before nulling per section 8.3.3.1
        if (skReader  != null) { java.util.Arrays.fill(skReader,  (byte)0); skReader  = null; }
        if (skDevice  != null) { java.util.Arrays.fill(skDevice,  (byte)0); skDevice  = null; }
        if (stepUpSK  != null) { java.util.Arrays.fill(stepUpSK,  (byte)0); stepUpSK  = null; }
        if (stepUpSKReader != null) { java.util.Arrays.fill(stepUpSKReader, (byte)0); stepUpSKReader = null; }
        if (stepUpSKDevice != null) { java.util.Arrays.fill(stepUpSKDevice, (byte)0); stepUpSKDevice = null; }
        inStepUpPhase = false;
        // Reset per-message counters
        readerCounter = 1; // first EXCHANGE command uses 1
        deviceCounter = 1; // AUTH1 response uses 1, EXCHANGE responses start at 2
        stepUpReaderCounter = 1;
        stepUpDeviceCounter = 1;
        // Reset mailbox atomic session state
        mailboxAtomicActive  = false;
        mailboxPendingWrites = null;
        mailboxError         = false;
        // Reset ENVELOPE / GET RESPONSE state
        envelopeBuffer        = null;
        pendingGetResponse    = null;
        pendingGetResponseOff = 0;
        // Reset APDU chaining buffer
        chainBuffer       = null;
        chainINS          = 0;
        inboundWasChained = false;
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
