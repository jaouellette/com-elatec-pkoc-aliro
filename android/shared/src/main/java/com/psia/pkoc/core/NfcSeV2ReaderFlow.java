package com.psia.pkoc.core;

import androidx.annotation.Nullable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * Reader-side PKOC SE V2 flow (NFC Transport Profile 2.0.1 §3, §6.2, §8).
 *
 * <p>Runs the common process order: Profile Detection (SELECT + GET DATA INFO),
 * Get PKOC-CVC (GET DATA), Validation (in Validated Mode), Authentication
 * (INTERNAL AUTHENTICATE), and Reader-to-PACS output (Core §4 or a CVC extension
 * credential). Decoupled from Android's {@link android.nfc.tech.IsoDep} through the
 * {@link ApduTransceiver} interface so it is unit-testable.</p>
 *
 * <p>Once the card is confirmed SE V2 (INFO returns {@code 02 00}) the flow commits:
 * a Validated-Mode failure fails the transaction and the caller MUST NOT fall back
 * to SE V1 (§2.1). If the card is not SE V2, {@link Result#isSeV2} is {@code false}
 * and the caller may fall back to the SE V1 flow.</p>
 */
public final class NfcSeV2ReaderFlow
{
    private NfcSeV2ReaderFlow() { }

    /** Abstraction over a connected ISO-DEP tag: {@code isoDep::transceive}. */
    public interface ApduTransceiver
    {
        byte[] transceive(byte[] apdu) throws IOException;
    }

    /** Reader-to-PACS output selection (§3.6, §5.5 of the NFC profile). */
    public enum OutputType { CREDENTIAL, DERIVED_IDENTIFIER, EXTENSION }

    /** Outcome of a reader SE V2 flow. */
    public static final class Result
    {
        public boolean isSeV2;              // card advertised SE V2 (INFO 02 00)
        public boolean success;             // full flow completed and authenticated
        public boolean validated;           // Validated-Mode validation passed
        public PkocCvc cvc;                 // retrieved certificate
        public byte[] subjectPublicKey;     // 65-byte uncompressed, from the CVC
        public byte[] pkocCredential;       // Core §4 credential
        public byte[] outputValue;          // the configured Reader-to-PACS value
        public String outputLabel;          // human-readable description of the output
        public String error;                // failure reason, when success == false
    }

    /**
     * Run the SE V2 reader flow.
     *
     * @param t              connected tag transceiver
     * @param validatedMode  whether to run Validated Mode (validate the CVC)
     * @param requireValidity whether the validity window is enforced (§3.4 MAY)
     * @param issuerKeys     configured Issuer Keys (Validated Mode)
     * @param outputType     which credential to output
     * @param idOctets       identifier length in octets (DERIVED_IDENTIFIER)
     * @param extensionOid   extension OID to output (EXTENSION)
     * @return a {@link Result}; check {@link Result#isSeV2} then {@link Result#success}
     */
    public static Result run(
            ApduTransceiver t,
            boolean validatedMode,
            boolean requireValidity,
            IssuerKeyStore issuerKeys,
            OutputType outputType,
            int idOctets,
            @Nullable byte[] extensionOid) throws IOException
    {
        Result r = new Result();

        // 1. Profile Detection: SELECT (baseline) + GET DATA (INFO).
        byte[] selectResp = t.transceive(NfcSeV2.SELECT_APDU);
        if (!NfcSeV2.isSuccess(selectResp))
        {
            r.isSeV2 = false;
            r.error = "SELECT failed";
            return r;
        }
        byte[] infoResp = t.transceive(NfcSeV2.GET_DATA_INFO_APDU);
        if (!NfcSeV2.parseInfoIsSeV2(infoResp))
        {
            r.isSeV2 = false;                 // not an SE V2 card → caller may fall back to SE V1
            return r;
        }
        r.isSeV2 = true;                      // committed to SE V2 from here on

        // 2. Get PKOC-CVC (with response chaining).
        byte[] cvcBytes = getCvc(t);
        if (cvcBytes == null)
        {
            r.error = "GET DATA (PKOC-CVC) failed";
            return r;
        }
        PkocCvc cvc = PkocCvc.parse(cvcBytes);
        if (cvc == null)
        {
            r.error = "PKOC-CVC could not be parsed";
            return r;
        }
        r.cvc = cvc;

        byte[] subjectPub = cvc.getSubjectEcPublicKeyUncompressed();
        if (subjectPub == null)
        {
            r.error = "Unsupported or missing subject EC public key in PKOC-CVC";
            return r;
        }
        r.subjectPublicKey = subjectPub;

        // 3. Validation (Validated Mode only).
        if (validatedMode)
        {
            ValidationResult vr = PkocCvcValidator.validate(cvc, issuerKeys, todayYyyymmdd(), requireValidity);
            if (!vr.isValid)
            {
                r.error = "Validation failed: " + vr.message;
                return r;   // MUST NOT fall back to Standard Mode
            }
            r.validated = true;
        }

        // 4. Authentication: INTERNAL AUTHENTICATE over a fresh challenge.
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        byte[] authResp = t.transceive(NfcSeV2.buildInternalAuthCommand(challenge));
        if (!NfcSeV2.isSuccess(authResp))
        {
            r.error = "INTERNAL AUTHENTICATE failed";
            return r;
        }
        byte[] signature = NfcSeV2.extractInternalAuthSignature(authResp);
        if (signature == null || !EcKeyUtil.verifyRaw(subjectPub, challenge, signature))
        {
            r.error = "Challenge signature did not verify (proof of possession failed)";
            return r;
        }

        // 5. Reader-to-PACS output (Core §4).
        byte[] credential = cvc.derivePkocCredential();
        r.pkocCredential = credential;
        if (credential == null)
        {
            r.error = "Could not derive PKOC Credential from subject key";
            return r;
        }

        switch (outputType)
        {
            case DERIVED_IDENTIFIER:
                try
                {
                    r.outputValue = PkocCredentialDerivation.deriveIdentifier(credential, idOctets, validatedMode);
                    r.outputLabel = (validatedMode ? "PKOC Validated Derived Identifier" : "PKOC Derived Identifier")
                            + " (" + idOctets + " octets)";
                }
                catch (Exception e)
                {
                    r.error = "Invalid Derived Identifier length: " + e.getMessage();
                    return r;
                }
                break;

            case EXTENSION:
                if (extensionOid == null)
                {
                    r.error = "No extension OID configured";
                    return r;
                }
                byte[] ext = cvc.getExtension(extensionOid);
                if (ext == null)
                {
                    r.error = "Configured extension credential OID is absent from the PKOC-CVC";
                    return r; // §3.6: MUST fail if the configured OID is absent
                }
                r.outputValue = ext;
                r.outputLabel = "PKOC-CVC extension credential";
                break;

            case CREDENTIAL:
            default:
                r.outputValue = credential;
                r.outputLabel = validatedMode ? "PKOC Validated Credential" : "PKOC Credential";
                break;
        }

        r.success = true;
        return r;
    }

    /** GET DATA (PKOC-CVC) with ISO 7816-4 response chaining (§8.1). */
    @Nullable
    private static byte[] getCvc(ApduTransceiver t) throws IOException
    {
        ByteArrayOutputStream acc = new ByteArrayOutputStream();
        byte[] resp = t.transceive(NfcSeV2.GET_DATA_CVC_APDU);
        acc.write(NfcSeV2.stripStatusWord(resp), 0, Math.max(0, resp.length - 2));
        while (NfcSeV2.isMoreData(resp))
        {
            resp = t.transceive(NfcSeV2.buildGetResponse(NfcSeV2.moreDataLength(resp)));
            byte[] chunk = NfcSeV2.stripStatusWord(resp);
            acc.write(chunk, 0, chunk.length);
        }
        if (!NfcSeV2.isSuccess(resp))
        {
            return null;
        }
        byte[] data = acc.toByteArray();
        return data.length == 0 ? null : data;
    }

    private static int todayYyyymmdd()
    {
        java.util.Calendar c = java.util.Calendar.getInstance();
        return c.get(java.util.Calendar.YEAR) * 10000
                + (c.get(java.util.Calendar.MONTH) + 1) * 100
                + c.get(java.util.Calendar.DAY_OF_MONTH);
    }
}
