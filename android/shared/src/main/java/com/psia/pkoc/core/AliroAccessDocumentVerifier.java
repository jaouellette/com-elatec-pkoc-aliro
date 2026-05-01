package com.pkoc.readersimulator;

import android.util.Log;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Aliro 1.0 Access Document and Revocation Document verifier.
 *
 * <p>Implements §7.4 (Access Document verification), §7.5 (Access Data Element
 * verification), and §7.2 (structure requirements).
 *
 * <p>CBOR integer key mappings (Table 8-22 / Table 7-1 / Table 7-2):
 * <ul>
 *   <li>DeviceResponse: "version"→1, "documents"→2, "issuerSigned"→1,
 *       "nameSpaces"→1, "IssuerAuth"→2, "docType"→5, "status"→3</li>
 *   <li>MobileSecurityObject: "version"→1, "digestAlgorithm"→2,
 *       "valueDigests"→3, "deviceKeyInfo"→4, "deviceKey"→1, "docType"→5,
 *       "validityInfo"→6, "signed"→1, "validFrom"→2, "validUntil"→3,
 *       "validityIteration"→5, "timeVerificationRequired"→7</li>
 *   <li>IssuerSignedItem: "digestID"→1, "random"→2, "elementIdentifier"→3,
 *       "elementValue"→4</li>
 * </ul>
 */
@SuppressWarnings("NewApi")
public class AliroAccessDocumentVerifier {

    private static final String TAG = "AliroDocVerifier";

    // -------------------------------------------------------------------------
    // COSE header labels
    // -------------------------------------------------------------------------
    private static final int COSE_HEADER_ALG   = 1;
    private static final int COSE_HEADER_KID   = 4;
    private static final int COSE_HEADER_X5CHAIN = 33;

    // -------------------------------------------------------------------------
    // COSE_Key parameters
    // -------------------------------------------------------------------------
    private static final int COSE_KEY_KTY = 1;
    private static final int COSE_KEY_CRV = -1;
    private static final int COSE_KEY_X   = -2;
    private static final int COSE_KEY_Y   = -3;

    // -------------------------------------------------------------------------
    // Reader status bytes (Table 8-18)
    // -------------------------------------------------------------------------
    /** Access Credential public key not trusted (cert issues). */
    public static final int STATUS_CERT_NOT_TRUSTED_B1 = 0x00;
    public static final int STATUS_CERT_NOT_TRUSTED_B2 = 0x03;

    /** Invalid User Device signature / invalid IssuerAuth signature. */
    public static final int STATUS_INVALID_SIGNATURE_B1 = 0x00;
    public static final int STATUS_INVALID_SIGNATURE_B2 = 0x04;

    /** Invalid data format. */
    public static final int STATUS_INVALID_FORMAT_B1 = 0x00;
    public static final int STATUS_INVALID_FORMAT_B2 = 0x06;

    /** Invalid data content. */
    public static final int STATUS_INVALID_CONTENT_B1 = 0x00;
    public static final int STATUS_INVALID_CONTENT_B2 = 0x07;

    /** Invalid access rights. */
    public static final int STATUS_INVALID_ACCESS_B1 = 0x00;
    public static final int STATUS_INVALID_ACCESS_B2 = 0x25;

    /** Success — reader state unknown. */
    public static final int STATUS_SUCCESS_B1 = 0x01;
    public static final int STATUS_SUCCESS_B2 = 0x82;

    // -------------------------------------------------------------------------
    // Change 7: Stored ValidityIteration state (§7.2.3)
    // Per spec: "The Reader SHALL store two ValidityIteration values per
    // Credential Issuer, called AccessIteration and RevocationIteration."
    // Keyed by issuer public key hex string.
    // -------------------------------------------------------------------------
    private static final Map<String, Integer> storedAccessIterations = new HashMap<>();
    private static final Map<String, Integer> storedRevocationIterations = new HashMap<>();

    /**
     * Resets the stored ValidityIteration counters for all issuers.
     * Call this when starting a new test session so iteration checks start fresh.
     */
    public static void resetStoredIterations() {
        storedAccessIterations.clear();
        storedRevocationIterations.clear();
    }

    /** Get stored iteration for a given issuer key. Returns 0 if unknown (§7.2.3). */
    private static int getStoredIteration(Map<String, Integer> map, String issuerKey) {
        Integer val = map.get(issuerKey);
        return val != null ? val : 0;
    }

    // -------------------------------------------------------------------------
    // Revocation database (§7.6)
    // Stores SHA-256 hashes (hex) of revoked public keys.
    // -------------------------------------------------------------------------
    private static final Set<String> revokedKeyHashes = new HashSet<>();

    /** Reset the revocation database. */
    public static void resetRevocationDatabase() {
        revokedKeyHashes.clear();
    }

    /**
     * Check if a public key is revoked.
     * @param pubKey Uncompressed public key (04 || x || y), 65 bytes.
     * @return true if the key's SHA-256 hash is in the revocation database.
     */
    public static boolean isRevoked(byte[] pubKey) {
        if (pubKey == null) return false;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(pubKey);
            String hashHex = Hex.toHexString(hash);
            boolean revoked = revokedKeyHashes.contains(hashHex);
            Log.d(TAG, "isRevoked: pubKey=" + Hex.toHexString(pubKey).substring(0, 16)
                    + "... hash=" + hashHex.substring(0, 16)
                    + "... revoked=" + revoked
                    + " dbSize=" + revokedKeyHashes.size());
            return revoked;
        } catch (Exception e) {
            Log.e(TAG, "isRevoked: SHA-256 failed", e);
            return false;
        }
    }

    // =========================================================================
    // Public API
    // =========================================================================

    /**
     * Encapsulates the result of document verification.
     */
    public static class VerificationResult {
        /** Whether all verification steps passed. */
        public final boolean valid;
        /** First byte of the 0x97 reader status. */
        public final int readerStatusByte1;
        /** Second byte of the 0x97 reader status. */
        public final int readerStatusByte2;
        /** Human-readable description of why verification failed (or "OK"). */
        public final String reason;
        /** Short summary text suitable for display in the UI. */
        public final String stepUpResultText;

        private VerificationResult(boolean valid, int b1, int b2,
                                   String reason, String stepUpResultText) {
            this.valid = valid;
            this.readerStatusByte1 = b1;
            this.readerStatusByte2 = b2;
            this.reason = reason;
            this.stepUpResultText = stepUpResultText;
        }

        /** Convenience constructor for failure. */
        static VerificationResult failure(int b1, int b2, String reason) {
            String text = String.format("Verification FAILED [%02X %02X]: %s", b1, b2, reason);
            Log.d(TAG, text);
            return new VerificationResult(false, b1, b2, reason, text);
        }

        /** Convenience constructor for success. */
        static VerificationResult success(String detail) {
            String text = "Verification OK: " + detail;
            Log.d(TAG, text);
            return new VerificationResult(true,
                    STATUS_SUCCESS_B1, STATUS_SUCCESS_B2,
                    "OK", text);
        }

        @Override
        public String toString() {
            return stepUpResultText;
        }
    }

    /**
     * Verifies an Aliro Access Document or Revocation Document received in the
     * step-up ENVELOPE phase.
     *
     * @param deviceResponseCbor Full decrypted DeviceResponse CBOR bytes.
     * @param expectedDocType    "aliro-a" for Access Document, "aliro-r" for
     *                           Revocation Document.
     * @param credentialPubKey   65-byte uncompressed EC public key (04 || x || y)
     *                           obtained from AUTH1.
     * @param requestedElementId The element identifier being requested (e.g. "floor1").
     * @param issuerPubKey       65-byte uncompressed EC public key (04 || x || y) of
     *                           the Credential Issuer (from harness config
     *                           dut_credential_issuer_public_key). May be null if not
     *                           configured.
     * @return A {@link VerificationResult} describing the outcome.
     */
    public static VerificationResult verifyDocument(
            byte[] deviceResponseCbor,
            String expectedDocType,
            byte[] credentialPubKey,
            String requestedElementId,
            byte[] issuerPubKey) {

        Log.d(TAG, "=== verifyDocument START ===");
        Log.d(TAG, "expectedDocType=" + expectedDocType
                + " requestedElementId=" + requestedElementId
                + " credentialPubKey=" + Hex.toHexString(credentialPubKey));
        if (issuerPubKey != null) {
            Log.d(TAG, "issuerPubKey=" + Hex.toHexString(issuerPubKey));
        } else {
            Log.d(TAG, "issuerPubKey=null");
        }

        // ------------------------------------------------------------------
        // Step 0: Parse DeviceResponse
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 0: Parsing DeviceResponse CBOR (" + deviceResponseCbor.length + " bytes)");

        CBORObject deviceResponse;
        try {
            deviceResponse = CBORObject.DecodeFromBytes(deviceResponseCbor);
        } catch (Exception e) {
            Log.e(TAG, "Step 0: Failed to decode DeviceResponse CBOR", e);
            return VerificationResult.failure(STATUS_INVALID_FORMAT_B1,
                    STATUS_INVALID_FORMAT_B2,
                    "Could not decode DeviceResponse CBOR: " + e.getMessage());
        }

        Log.d(TAG, "Step 0: DeviceResponse CBOR type=" + deviceResponse.getType());

        // Extract documents array (key "2")
        CBORObject documentsArray = deviceResponse.get(CBORObject.FromObject("2"));
        if (documentsArray == null || documentsArray.getType() != CBORType.Array
                || documentsArray.size() == 0) {
            Log.e(TAG, "Step 0: No documents found in DeviceResponse");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "DeviceResponse contains no documents");
        }
        Log.d(TAG, "Step 0: Found " + documentsArray.size() + " document(s)");

        // Use the first document
        CBORObject document = documentsArray.get(0);
        Log.d(TAG, "Step 0: Using first document: " + document.getType());

        // Verify docType (key "5")
        CBORObject docTypeObj = document.get(CBORObject.FromObject("5"));
        if (docTypeObj == null) {
            Log.e(TAG, "Step 0: Document missing docType key (5)");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "Document missing docType (key 5)");
        }
        String docType = docTypeObj.AsString();
        Log.d(TAG, "Step 0: Document docType=" + docType
                + " expected=" + expectedDocType);
        if (!expectedDocType.equals(docType)) {
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "DocType mismatch: got '" + docType
                            + "' expected '" + expectedDocType + "'");
        }

        // ------------------------------------------------------------------
        // Step 1: Parse IssuerAuth (COSE_Sign1)
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 1: Parsing IssuerAuth");

        // issuerSigned = key "1" in document
        CBORObject issuerSigned = document.get(CBORObject.FromObject("1"));
        if (issuerSigned == null) {
            Log.e(TAG, "Step 1: Document missing issuerSigned (key 1)");
            return VerificationResult.failure(STATUS_INVALID_FORMAT_B1,
                    STATUS_INVALID_FORMAT_B2,
                    "Document missing issuerSigned (key 1)");
        }

        // IssuerAuth = key "2" in issuerSigned
        CBORObject issuerAuth = issuerSigned.get(CBORObject.FromObject("2"));
        if (issuerAuth == null || issuerAuth.getType() != CBORType.Array
                || issuerAuth.size() < 4) {
            Log.e(TAG, "Step 1: IssuerAuth missing or malformed (key 2)");
            return VerificationResult.failure(STATUS_INVALID_FORMAT_B1,
                    STATUS_INVALID_FORMAT_B2,
                    "IssuerAuth (key 2) missing or not a 4-element COSE_Sign1 array");
        }
        Log.d(TAG, "Step 1: IssuerAuth array size=" + issuerAuth.size());

        // COSE_Sign1 = [protected, unprotected, payload, signature]
        CBORObject protectedHeaderBstr = issuerAuth.get(0); // bstr
        CBORObject unprotectedHeader   = issuerAuth.get(1); // map
        CBORObject payloadCbor         = issuerAuth.get(2); // bstr (Tag 24)
        CBORObject signatureCbor       = issuerAuth.get(3); // bstr

        // Decode protected header bstr → CBOR map
        byte[] protectedHeaderBytes = protectedHeaderBstr.GetByteString();
        CBORObject protectedHeaderMap;
        try {
            protectedHeaderMap = CBORObject.DecodeFromBytes(protectedHeaderBytes);
        } catch (Exception e) {
            Log.e(TAG, "Step 1: Failed to decode protected header", e);
            return VerificationResult.failure(STATUS_INVALID_FORMAT_B1,
                    STATUS_INVALID_FORMAT_B2,
                    "Cannot decode COSE protected header: " + e.getMessage());
        }
        Log.d(TAG, "Step 1: Protected header map=" + protectedHeaderMap.ToJSONString());

        // Extract x5chain (label 33) — may be a bstr or array of bstr
        byte[] x5chainCertBytes = null;
        CBORObject x5chainEntry = protectedHeaderMap.get(CBORObject.FromObject(COSE_HEADER_X5CHAIN));
        if (x5chainEntry == null && unprotectedHeader != null) {
            x5chainEntry = unprotectedHeader.get(CBORObject.FromObject(COSE_HEADER_X5CHAIN));
        }
        if (x5chainEntry != null) {
            if (x5chainEntry.getType() == CBORType.ByteString) {
                x5chainCertBytes = x5chainEntry.GetByteString();
                Log.d(TAG, "Step 1: x5chain found (single cert, "
                        + x5chainCertBytes.length + " bytes)");
            } else if (x5chainEntry.getType() == CBORType.Array && x5chainEntry.size() > 0) {
                // Use the first (leaf) certificate
                x5chainCertBytes = x5chainEntry.get(0).GetByteString();
                Log.d(TAG, "Step 1: x5chain found (array, using leaf cert, "
                        + x5chainCertBytes.length + " bytes)");
            }
        }

        // Extract kid (label 4)
        byte[] kid = null;
        CBORObject kidEntry = protectedHeaderMap.get(CBORObject.FromObject(COSE_HEADER_KID));
        if (kidEntry == null && unprotectedHeader != null) {
            kidEntry = unprotectedHeader.get(CBORObject.FromObject(COSE_HEADER_KID));
        }
        if (kidEntry != null) {
            kid = kidEntry.GetByteString();
            Log.d(TAG, "Step 1: kid found: " + Hex.toHexString(kid));
        }

        // Decode MobileSecurityObject from payload
        // The payload is a bstr containing a Tag 24-wrapped bstr
        byte[] payloadBytes = payloadCbor.GetByteString();
        Log.d(TAG, "Step 1: Payload bstr length=" + payloadBytes.length);

        CBORObject mso;
        try {
            CBORObject tag24Wrapper = CBORObject.DecodeFromBytes(payloadBytes);
            // Tag 24 means the inner bstr is an encoded CBOR item
            byte[] msoBytes;
            if (tag24Wrapper.isTagged() && tag24Wrapper.getMostOuterTag().ToInt32Checked() == 24) {
                msoBytes = tag24Wrapper.GetByteString();
                Log.d(TAG, "Step 1: Tag 24 wrapper found; inner MSO bytes length=" + msoBytes.length);
            } else if (tag24Wrapper.getType() == CBORType.ByteString) {
                // Some implementations wrap without explicit Tag 24
                msoBytes = tag24Wrapper.GetByteString();
                Log.d(TAG, "Step 1: No Tag 24 — treating payload bstr as raw MSO bytes");
            } else {
                msoBytes = payloadBytes;
                Log.d(TAG, "Step 1: Payload not bstr; using raw payloadBytes as MSO");
            }
            mso = CBORObject.DecodeFromBytes(msoBytes);
        } catch (Exception e) {
            Log.e(TAG, "Step 1: Failed to decode MSO", e);
            return VerificationResult.failure(STATUS_INVALID_FORMAT_B1,
                    STATUS_INVALID_FORMAT_B2,
                    "Cannot decode MobileSecurityObject: " + e.getMessage());
        }
        Log.d(TAG, "Step 1: MSO parsed successfully, keys=" + mso.getKeys().size());

        // ------------------------------------------------------------------
        // Step 2: Verify IssuerAuth signature (§7.4 step 2)
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 2: Verifying IssuerAuth signature");

        if (x5chainCertBytes != null) {
            // Parse the X.509 certificate
            X509Certificate cert;
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                cert = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(x5chainCertBytes));
            } catch (Exception e) {
                Log.e(TAG, "Step 2: Failed to parse X.509 certificate", e);
                return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                        STATUS_CERT_NOT_TRUSTED_B2,
                        "Cannot parse X.509 certificate from x5chain: " + e.getMessage());
            }
            Log.d(TAG, "Step 2: Cert subject=" + cert.getSubjectDN()
                    + " notBefore=" + cert.getNotBefore()
                    + " notAfter=" + cert.getNotAfter());

            // Check certificate validity (expiry)
            try {
                cert.checkValidity();
                Log.d(TAG, "Step 2: Certificate is currently valid");
            } catch (Exception e) {
                Log.e(TAG, "Step 2: Certificate validity check failed: " + e.getMessage());
                return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                        STATUS_CERT_NOT_TRUSTED_B2,
                        "Issuer certificate has expired or is not yet valid: " + e.getMessage());
            }

            // Verify cert was signed by a trusted CA using issuerPubKey (§7.4 step 1)
            if (issuerPubKey != null) {
                try {
                    PublicKey caPubKey = rawEcPubKeyToPublicKey(issuerPubKey);
                    cert.verify(caPubKey);
                    Log.d(TAG, "Step 2: Certificate signature verified against issuerPubKey (CA)");
                } catch (Exception e) {
                    Log.e(TAG, "Step 2: Certificate signature INVALID — not signed by trusted CA: " + e.getMessage());
                    return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                            STATUS_CERT_NOT_TRUSTED_B2,
                            "Issuer certificate signature invalid (not signed by trusted CA): " + e.getMessage());
                }
            } else {
                Log.w(TAG, "Step 2: No issuerPubKey configured — cannot verify cert was signed by trusted CA");
            }

            // Extract issuer public key from cert for COSE_Sign1 verification
            PublicKey issuerPublicKey = cert.getPublicKey();
            Log.d(TAG, "Step 2: Issuer public key algorithm=" + issuerPublicKey.getAlgorithm());

            // Verify COSE_Sign1 signature
            // Sig_structure = ["Signature1", protected, external_aad="", payload]
            byte[] externalAad = new byte[0];
            byte[] sigStructureEncoded = buildCoseSigStructure(
                    protectedHeaderBytes, externalAad, payloadBytes);
            Log.d(TAG, "Step 2: Sig_structure encoded length=" + sigStructureEncoded.length);

            byte[] rawSignature = signatureCbor.GetByteString();
            Log.d(TAG, "Step 2: Raw COSE signature length=" + rawSignature.length
                    + " hex=" + Hex.toHexString(rawSignature));

            // Convert raw (r||s) signature to DER
            byte[] derSignature;
            try {
                derSignature = rawEcSignatureToDer(rawSignature);
            } catch (Exception e) {
                Log.e(TAG, "Step 2: Failed to convert raw signature to DER", e);
                return VerificationResult.failure(STATUS_INVALID_SIGNATURE_B1,
                        STATUS_INVALID_SIGNATURE_B2,
                        "Cannot convert COSE signature to DER: " + e.getMessage());
            }
            Log.d(TAG, "Step 2: DER signature length=" + derSignature.length);

            boolean signatureValid;
            try {
                Signature verifier = Signature.getInstance("SHA256withECDSA");
                verifier.initVerify(issuerPublicKey);
                verifier.update(sigStructureEncoded);
                signatureValid = verifier.verify(derSignature);
            } catch (Exception e) {
                Log.e(TAG, "Step 2: Signature verification threw exception", e);
                return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                        STATUS_CERT_NOT_TRUSTED_B2,
                        "IssuerAuth signature verification error: " + e.getMessage());
            }

            if (!signatureValid) {
                Log.e(TAG, "Step 2: IssuerAuth signature is INVALID");
                return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                        STATUS_CERT_NOT_TRUSTED_B2,
                        "IssuerAuth COSE_Sign1 signature does not verify against issuer cert");
            }
            Log.d(TAG, "Step 2: IssuerAuth signature VERIFIED OK");

        } else if (kid != null) {
            // kid present but no x5chain — use issuerPubKey if provided (Change 2)
            if (issuerPubKey != null) {
                Log.d(TAG, "Step 2: x5chain absent, kid present ("
                        + Hex.toHexString(kid)
                        + "); verifying via issuerPubKey");

                // Compute expected kid: SHA256("key-identifier" || issuerPubKey)[0:8]
                // Per §7.2.1: issuerPubKey is already the full 65-byte uncompressed key
                // including the 0x04 prefix.
                byte[] expectedKid;
                try {
                    byte[] keyIdentifierPrefix = "key-identifier".getBytes("US-ASCII");
                    MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
                    sha256.update(keyIdentifierPrefix);
                    sha256.update(issuerPubKey);
                    byte[] hash = sha256.digest();
                    expectedKid = Arrays.copyOfRange(hash, 0, 8);
                } catch (Exception e) {
                    Log.e(TAG, "Step 2: Failed to compute expected kid", e);
                    return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                            STATUS_CERT_NOT_TRUSTED_B2,
                            "Failed to compute expected kid: " + e.getMessage());
                }
                Log.d(TAG, "Step 2: expectedKid=" + Hex.toHexString(expectedKid)
                        + " receivedKid=" + Hex.toHexString(kid));

                if (!Arrays.equals(expectedKid, kid)) {
                    Log.e(TAG, "Step 2: kid mismatch — issuer not trusted");
                    return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                            STATUS_CERT_NOT_TRUSTED_B2,
                            "IssuerAuth kid " + Hex.toHexString(kid)
                                    + " does not match expected kid "
                                    + Hex.toHexString(expectedKid)
                                    + " derived from issuerPubKey");
                }
                Log.d(TAG, "Step 2: kid matches issuerPubKey — proceeding to signature verification");

                // Build the public key object from the raw 65-byte uncompressed point
                PublicKey issuerPublicKey;
                try {
                    issuerPublicKey = rawEcPubKeyToPublicKey(issuerPubKey);
                } catch (Exception e) {
                    Log.e(TAG, "Step 2: Failed to build PublicKey from issuerPubKey", e);
                    return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                            STATUS_CERT_NOT_TRUSTED_B2,
                            "Cannot construct PublicKey from issuerPubKey: " + e.getMessage());
                }

                // Verify COSE_Sign1 signature using issuerPubKey
                byte[] externalAad = new byte[0];
                byte[] sigStructureEncoded = buildCoseSigStructure(
                        protectedHeaderBytes, externalAad, payloadBytes);
                Log.d(TAG, "Step 2: Sig_structure encoded length=" + sigStructureEncoded.length);

                byte[] rawSignature = signatureCbor.GetByteString();
                Log.d(TAG, "Step 2: Raw COSE signature length=" + rawSignature.length
                        + " hex=" + Hex.toHexString(rawSignature));

                byte[] derSignature;
                try {
                    derSignature = rawEcSignatureToDer(rawSignature);
                } catch (Exception e) {
                    Log.e(TAG, "Step 2: Failed to convert raw signature to DER", e);
                    return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                            STATUS_CERT_NOT_TRUSTED_B2,
                            "Cannot convert COSE signature to DER: " + e.getMessage());
                }
                Log.d(TAG, "Step 2: DER signature length=" + derSignature.length);

                boolean signatureValid;
                try {
                    Signature verifier = Signature.getInstance("SHA256withECDSA");
                    verifier.initVerify(issuerPublicKey);
                    verifier.update(sigStructureEncoded);
                    signatureValid = verifier.verify(derSignature);
                } catch (Exception e) {
                    Log.e(TAG, "Step 2: Signature verification threw exception", e);
                    return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                            STATUS_CERT_NOT_TRUSTED_B2,
                            "IssuerAuth signature verification error (kid path): " + e.getMessage());
                }

                if (!signatureValid) {
                    Log.e(TAG, "Step 2: IssuerAuth signature INVALID (kid path)");
                    return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                            STATUS_CERT_NOT_TRUSTED_B2,
                            "IssuerAuth COSE_Sign1 signature does not verify against issuerPubKey");
                }
                Log.d(TAG, "Step 2: IssuerAuth signature VERIFIED OK (kid path)");

            } else {
                // kid present but issuerPubKey not provided — skip with warning
                Log.w(TAG, "Step 2: x5chain absent but kid present ("
                        + Hex.toHexString(kid)
                        + "); issuerPubKey not configured — skipping signature verification");
            }
        } else {
            Log.e(TAG, "Step 2: Neither x5chain nor kid present — cannot verify");
            return VerificationResult.failure(STATUS_CERT_NOT_TRUSTED_B1,
                    STATUS_CERT_NOT_TRUSTED_B2,
                    "IssuerAuth has neither x5chain nor kid; cannot determine issuer trust");
        }

        // ------------------------------------------------------------------
        // Step 3: Verify digest values (§7.4 step 3)
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 3: Verifying digest values");

        // valueDigests = key "3" in MSO
        CBORObject valueDigests = mso.get(CBORObject.FromObject("3"));
        if (valueDigests == null) {
            Log.e(TAG, "Step 3: MSO missing valueDigests (key 3)");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "MSO missing valueDigests (key 3)");
        }

        // nameSpaces = key "1" in issuerSigned
        CBORObject nameSpaces = issuerSigned.get(CBORObject.FromObject("1"));
        if (nameSpaces == null) {
            Log.e(TAG, "Step 3: issuerSigned missing nameSpaces (key 1)");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "issuerSigned missing nameSpaces (key 1)");
        }

        // Determine digest algorithm from MSO key "2"
        CBORObject digestAlgObj = mso.get(CBORObject.FromObject("2"));
        String digestAlg = "SHA-256"; // default
        if (digestAlgObj != null) {
            String algStr = digestAlgObj.AsString();
            Log.d(TAG, "Step 3: MSO digestAlgorithm=" + algStr);
            if ("SHA-384".equalsIgnoreCase(algStr) || "SHA384".equalsIgnoreCase(algStr)) {
                digestAlg = "SHA-384";
            } else if ("SHA-512".equalsIgnoreCase(algStr) || "SHA512".equalsIgnoreCase(algStr)) {
                digestAlg = "SHA-512";
            }
        }
        Log.d(TAG, "Step 3: Using digest algorithm: " + digestAlg);

        // Iterate over namespaces
        for (CBORObject nsKey : nameSpaces.getKeys()) {
            String namespaceName = nsKey.AsString();
            Log.d(TAG, "Step 3: Processing namespace=" + namespaceName);

            CBORObject nsDigests = valueDigests.get(nsKey);
            if (nsDigests == null) {
                Log.e(TAG, "Step 3: No digest map in MSO for namespace=" + namespaceName);
                return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                        STATUS_INVALID_CONTENT_B2,
                        "MSO valueDigests missing entry for namespace '" + namespaceName + "'");
            }

            CBORObject itemsArray = nameSpaces.get(nsKey);
            if (itemsArray == null || itemsArray.getType() != CBORType.Array) {
                Log.w(TAG, "Step 3: namespace '" + namespaceName
                        + "' has null or non-array items; skipping");
                continue;
            }

            for (int i = 0; i < itemsArray.size(); i++) {
                CBORObject itemEntry = itemsArray.get(i);

                // Each entry is Tag 24-wrapped encoded CBOR bstr
                byte[] tag24Bytes = itemEntry.EncodeToBytes();
                Log.d(TAG, "Step 3: namespace=" + namespaceName
                        + " item[" + i + "] tag24 encoded length=" + tag24Bytes.length);

                // Compute digest over the Tag 24 encoded bytes
                byte[] computedHash;
                try {
                    MessageDigest md = MessageDigest.getInstance(digestAlg);
                    computedHash = md.digest(tag24Bytes);
                } catch (Exception e) {
                    Log.e(TAG, "Step 3: Digest computation failed", e);
                    return VerificationResult.failure(STATUS_INVALID_FORMAT_B1,
                            STATUS_INVALID_FORMAT_B2,
                            "Digest computation error: " + e.getMessage());
                }

                // Decode the IssuerSignedItem to get digestID
                CBORObject issuerSignedItem;
                try {
                    // itemEntry should be Tag 24 bstr → inner CBOR
                    if (itemEntry.isTagged()
                            && itemEntry.getMostOuterTag().ToInt32Checked() == 24) {
                        issuerSignedItem = CBORObject.DecodeFromBytes(
                                itemEntry.GetByteString());
                    } else {
                        issuerSignedItem = itemEntry;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Step 3: Cannot decode IssuerSignedItem at index " + i, e);
                    return VerificationResult.failure(STATUS_INVALID_FORMAT_B1,
                            STATUS_INVALID_FORMAT_B2,
                            "Cannot decode IssuerSignedItem: " + e.getMessage());
                }

                // digestID = key "1"
                CBORObject digestIdObj = issuerSignedItem.get(CBORObject.FromObject("1"));
                if (digestIdObj == null) {
                    Log.e(TAG, "Step 3: IssuerSignedItem missing digestID (key 1)");
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "IssuerSignedItem missing digestID (key 1)");
                }
                int digestId = digestIdObj.AsInt32();
                Log.d(TAG, "Step 3: digestID=" + digestId);

                // Look up expected hash in MSO
                CBORObject expectedHashObj = nsDigests.get(CBORObject.FromObject(digestId));
                if (expectedHashObj == null) {
                    Log.e(TAG, "Step 3: MSO has no digest for digestID=" + digestId
                            + " in namespace=" + namespaceName);
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "MSO missing digest for digestID=" + digestId
                                    + " in namespace='" + namespaceName + "'");
                }
                byte[] expectedHash = expectedHashObj.GetByteString();

                if (!Arrays.equals(computedHash, expectedHash)) {
                    Log.e(TAG, "Step 3: Digest MISMATCH for digestID=" + digestId
                            + " namespace=" + namespaceName
                            + " computed=" + Hex.toHexString(computedHash)
                            + " expected=" + Hex.toHexString(expectedHash));
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "Digest mismatch for digestID=" + digestId
                                    + " in namespace '" + namespaceName + "'");
                }
                Log.d(TAG, "Step 3: digestID=" + digestId + " MATCH OK");
            }
        }
        Log.d(TAG, "Step 3: All digests verified OK");

        // ------------------------------------------------------------------
        // Step 4: Verify DocType match between MSO and document (§7.4 step 4)
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 4: Verifying MSO docType matches document docType");

        CBORObject msoDocTypeObj = mso.get(CBORObject.FromObject("5"));
        if (msoDocTypeObj == null) {
            Log.e(TAG, "Step 4: MSO missing docType (key 5)");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "MSO missing docType (key 5)");
        }
        String msoDocType = msoDocTypeObj.AsString();
        Log.d(TAG, "Step 4: MSO docType=" + msoDocType + " document docType=" + docType);
        if (!msoDocType.equals(docType)) {
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "MSO docType '" + msoDocType
                            + "' does not match document docType '" + docType + "'");
        }
        Log.d(TAG, "Step 4: DocType match OK");

        // ------------------------------------------------------------------
        // Step 5: Verify validity times (§7.4 step 5)
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 5: Verifying validity times");

        CBORObject validityInfo = mso.get(CBORObject.FromObject("6"));
        if (validityInfo == null) {
            Log.e(TAG, "Step 5: MSO missing validityInfo (key 6)");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "MSO missing validityInfo (key 6)");
        }

        // Parse signed (key "1"), validFrom (key "2"), validUntil (key "3")
        CBORObject signedObj    = validityInfo.get(CBORObject.FromObject("1"));
        CBORObject validFromObj = validityInfo.get(CBORObject.FromObject("2"));
        CBORObject validUntilObj= validityInfo.get(CBORObject.FromObject("3"));
        // Per Table 7-1: timeVerificationRequired is key "7" at the MSO level
        // (sibling of validityInfo key "6"), NOT inside validityInfo.
        CBORObject timeVerifReqObj = mso.get(CBORObject.FromObject("7"));

        if (signedObj == null || validFromObj == null || validUntilObj == null) {
            Log.e(TAG, "Step 5: validityInfo missing required time fields");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "validityInfo missing signed/validFrom/validUntil");
        }

        Instant signedInstant;
        Instant validFromInstant;
        Instant validUntilInstant;
        try {
            signedInstant    = parseTdate(signedObj);
            validFromInstant = parseTdate(validFromObj);
            validUntilInstant= parseTdate(validUntilObj);
        } catch (Exception e) {
            Log.e(TAG, "Step 5: Failed to parse validity dates", e);
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "Cannot parse validity dates: " + e.getMessage());
        }
        Log.d(TAG, "Step 5: signed=" + signedInstant
                + " validFrom=" + validFromInstant
                + " validUntil=" + validUntilInstant);

        // Capture timeVerificationRequired for use in Step 8 schedule evaluation.
        // Per §7.2.4: this field is OPTIONAL; when absent, the default is false
        // (no time verification requirement imposed on the Reader).
        boolean timeVerificationRequired = false; // default: absent → no requirement
        if (timeVerifReqObj != null) {
            timeVerificationRequired = timeVerifReqObj.AsBoolean();
        }
        Log.d(TAG, "Step 5: timeVerificationRequired=" + timeVerificationRequired);

        // Per §7.2.4 (Aliro 1.0 spec): When TimeVerificationRequired=true and the Reader
        // cannot validate time-based fields, the Reader SHALL consider all time-based checks
        // as failed. This Reader does not support the time concept (PICS: NOT time-based
        // elements), so if timeVerificationRequired=true, we immediately fail.
        if (timeVerificationRequired) {
            Log.w(TAG, "Step 5: timeVerificationRequired=true but Reader does not support"
                    + " time concept — all time-based checks fail per §7.2.4");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "TimeVerificationRequired=true but Reader cannot validate time"
                            + " (Reader does not support time concept per PICS)");
        }

        Instant now = Instant.now();
        Log.d(TAG, "Step 5: current time=" + now);

        boolean timeCheckFailed = now.isBefore(validFromInstant) || now.isAfter(validUntilInstant);
        if (timeCheckFailed) {
            Log.w(TAG, "Step 5: Current time is outside [validFrom, validUntil]"
                    + " validFrom=" + validFromInstant
                    + " validUntil=" + validUntilInstant
                    + " now=" + now);
            // §7.4 step 5a: validFrom <= currentTime <= validUntil is mandatory.
            // This check is always fatal regardless of timeVerificationRequired.
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "Time check failed: currentTime is outside [validFrom, validUntil]");
        } else {
            Log.d(TAG, "Step 5: Time validity OK");
        }

        // If x5chain cert present: check that "signed" date is within cert validity
        if (x5chainCertBytes != null) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate cert = (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(x5chainCertBytes));
                Date certNotBefore = cert.getNotBefore();
                Date certNotAfter  = cert.getNotAfter();
                Instant certNB = certNotBefore.toInstant();
                Instant certNA = certNotAfter.toInstant();
                Log.d(TAG, "Step 5: Cert validity: " + certNB + " – " + certNA);
                if (signedInstant.isBefore(certNB) || signedInstant.isAfter(certNA)) {
                    Log.e(TAG, "Step 5: MSO 'signed' date " + signedInstant
                            + " is outside issuer cert validity period ["
                            + certNB + " – " + certNA + "]");
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "MSO 'signed' date " + signedInstant
                                    + " is outside issuer cert validity ["
                                    + certNB + " – " + certNA + "]");
                }
                Log.d(TAG, "Step 5: MSO 'signed' date within cert validity OK");
            } catch (Exception e) {
                Log.e(TAG, "Step 5: Could not re-parse cert for signed-date check", e);
                // Non-fatal warning — we already verified the cert above
            }
        }

        // ------------------------------------------------------------------
        // Step 6: Verify DeviceKeyInfo (§7.4)
        // Per §7.6: "The IssuerAuth structure SHALL NOT contain the
        // deviceKeyInfo field" for Revocation Documents. So this check
        // only applies to Access Documents (aliro-a).
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 6: Verifying DeviceKeyInfo");

        boolean isRevocationDoc = "aliro-r".equals(expectedDocType);
        CBORObject deviceKeyInfo = mso.get(CBORObject.FromObject("4"));
        if (isRevocationDoc) {
            if (deviceKeyInfo != null) {
                Log.w(TAG, "Step 6: Revocation document contains deviceKeyInfo — ignoring per §7.6");
            } else {
                Log.d(TAG, "Step 6: Revocation document — deviceKeyInfo absent as expected per §7.6");
            }
            // Skip deviceKey matching for revocation documents
        } else if (deviceKeyInfo == null) {
            Log.e(TAG, "Step 6: MSO missing deviceKeyInfo (key 4)");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "MSO missing deviceKeyInfo (key 4)");
        }

        if (!isRevocationDoc) {
            // Only verify deviceKey match for Access Documents
            CBORObject deviceKey = deviceKeyInfo.get(CBORObject.FromObject("1"));
            if (deviceKey == null) {
                Log.e(TAG, "Step 6: deviceKeyInfo missing deviceKey (key 1)");
                return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                        STATUS_INVALID_CONTENT_B2,
                        "deviceKeyInfo missing deviceKey (key 1)");
            }
            Log.d(TAG, "Step 6: deviceKey COSE_Key map=" + deviceKey.ToJSONString());

            // Reconstruct uncompressed public key (04 || x || y)
            byte[] reconstructed;
            try {
                reconstructed = coseKeyToUncompressedPoint(deviceKey);
            } catch (Exception e) {
                Log.e(TAG, "Step 6: Cannot reconstruct device public key", e);
                return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                        STATUS_INVALID_CONTENT_B2,
                        "Cannot reconstruct device public key: " + e.getMessage());
            }
            Log.d(TAG, "Step 6: Reconstructed deviceKey=" + Hex.toHexString(reconstructed));
            Log.d(TAG, "Step 6: credentialPubKey=" + Hex.toHexString(credentialPubKey));

            if (!Arrays.equals(reconstructed, credentialPubKey)) {
                Log.e(TAG, "Step 6: DeviceKey MISMATCH");
                return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                        STATUS_INVALID_CONTENT_B2,
                        "DeviceKey in MSO does not match credentialPubKey from AUTH1");
            }
            Log.d(TAG, "Step 6: DeviceKey matches credentialPubKey OK");
        }

        // ------------------------------------------------------------------
        // Step 7: Verify ValidityIteration (§7.2.3)
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 7: Checking validityIteration");

        // Per §7.2.3: iterations are tracked per Credential Issuer.
        // Use the issuer public key (hex) as the map key. If issuerPubKey
        // was not provided, fall back to "unknown" (single bucket).
        String issuerMapKey = (issuerPubKey != null)
                ? Hex.toHexString(issuerPubKey) : "unknown";

        CBORObject validityIterObj = validityInfo.get(CBORObject.FromObject("5"));
        if (validityIterObj != null) {
            int iter = validityIterObj.AsInt32();
            boolean isRevocation = "aliro-r".equals(expectedDocType);
            Map<String, Integer> iterMap = isRevocation
                    ? storedRevocationIterations : storedAccessIterations;
            int storedIter = getStoredIteration(iterMap, issuerMapKey);

            Log.d(TAG, "Step 7: validityIteration=" + iter + " storedIteration=" + storedIter
                    + " isRevocation=" + isRevocation
                    + " issuer=" + issuerMapKey.substring(0, Math.min(16, issuerMapKey.length())) + "...");

            if (iter >= storedIter) {
                // Valid — update the stored iteration for this issuer
                iterMap.put(issuerMapKey, iter);
                Log.d(TAG, "Step 7: validityIteration is current; updated storedIteration=" + iter);
            } else {
                int diff = storedIter - iter;
                Log.d(TAG, "Step 7: validityIteration is older than stored; diff=" + diff);
                if (isRevocation) {
                    // §7.2.3: "When the ValidityIteration field in the Revocation
                    // Document is less than RevocationIteration, then the
                    // Revocation Document is invalid."
                    Log.e(TAG, "Step 7: Revocation ValidityIteration too old: iter=" + iter
                            + " stored=" + storedIter);
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "Revocation ValidityIteration " + iter
                                    + " is less than stored (" + storedIter + ")");
                } else if (diff >= 8) {
                    // §7.2.3: "When the ValidityIteration field in the Access
                    // Document is less than AccessIteration and the difference
                    // is equal to or greater than 8, the Access Document is
                    // not valid."
                    Log.e(TAG, "Step 7: ValidityIteration too old: iter=" + iter
                            + " stored=" + storedIter + " diff=" + diff);
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "ValidityIteration " + iter + " is too old (stored="
                                    + storedIter + ", diff=" + diff + " >= 8)");
                }
                // diff < 8 — still acceptable per §7.2.3
                Log.d(TAG, "Step 7: validityIteration diff=" + diff + " < 8 — acceptable");
            }
        } else {
            Log.d(TAG, "Step 7: validityIteration not present — skipping");
        }

        // ------------------------------------------------------------------
        // Step 8: Verify Access Data Elements (§7.5)
        // ------------------------------------------------------------------
        Log.d(TAG, "Step 8: Verifying Access Data Elements");

        boolean foundValidElement = false;
        String elementSummary = null;

        for (CBORObject nsKey : nameSpaces.getKeys()) {
            String namespaceName = nsKey.AsString();
            CBORObject itemsArray = nameSpaces.get(nsKey);
            if (itemsArray == null || itemsArray.getType() != CBORType.Array) {
                continue;
            }

            for (int i = 0; i < itemsArray.size(); i++) {
                CBORObject itemEntry = itemsArray.get(i);

                // Decode IssuerSignedItem
                CBORObject issuerSignedItem;
                try {
                    if (itemEntry.isTagged()
                            && itemEntry.getMostOuterTag().ToInt32Checked() == 24) {
                        issuerSignedItem = CBORObject.DecodeFromBytes(
                                itemEntry.GetByteString());
                    } else {
                        issuerSignedItem = itemEntry;
                    }
                } catch (Exception e) {
                    Log.w(TAG, "Step 8: Cannot decode IssuerSignedItem at ["
                            + namespaceName + "][" + i + "]: " + e.getMessage());
                    continue;
                }

                // elementIdentifier = key "3"
                CBORObject elemIdObj = issuerSignedItem.get(CBORObject.FromObject("3"));
                String elementId = (elemIdObj != null) ? elemIdObj.AsString() : null;
                Log.d(TAG, "Step 8: namespace=" + namespaceName
                        + " elementIdentifier=" + elementId);

                // elementValue = key "4"
                CBORObject elementValue = issuerSignedItem.get(CBORObject.FromObject("4"));
                if (elementValue == null) {
                    Log.w(TAG, "Step 8: IssuerSignedItem missing elementValue (key 4); skipping");
                    continue;
                }

                // If this element doesn't match the requested one, still check structure
                // but note whether it applies to our request.
                boolean isRequestedElement = requestedElementId != null
                        && requestedElementId.equals(elementId);
                Log.d(TAG, "Step 8: isRequestedElement=" + isRequestedElement);

                // The element value is an Access Data map per §7.5
                // Check AccessData_Version (key 0) == 1
                CBORObject versionObj = elementValue.get(CBORObject.FromObject(0));
                if (versionObj == null) {
                    Log.e(TAG, "Step 8: AccessData missing version (key 0)");
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "AccessData element '" + elementId
                                    + "' missing version field (key 0)");
                }
                int accessDataVersion = versionObj.AsInt32();
                Log.d(TAG, "Step 8: AccessData_Version=" + accessDataVersion);
                if (accessDataVersion != 1) {
                    Log.e(TAG, "Step 8: Unsupported AccessData version " + accessDataVersion);
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "AccessData element '" + elementId
                                    + "' has unsupported version=" + accessDataVersion
                                    + " (expected 1)");
                }

                // ----- Revocation document processing (§7.6) -----
                if (isRevocationDoc) {
                    processRevocationData(elementValue, elementId);
                    foundValidElement = true;
                    continue; // skip access rule / extension checks for revocation docs
                }

                // AccessData_AccessExtensions (key 6) — check for unknown critical extensions
                // Must be checked BEFORE AccessRules to detect critical extension rejections
                CBORObject accessExtensions = elementValue.get(CBORObject.FromObject(6));
                if (accessExtensions != null) {
                    Log.d(TAG, "Step 8: AccessData_AccessExtensions present");
                    VerificationResult extResult = verifyAccessExtensions(
                            accessExtensions, elementId);
                    if (extResult != null) {
                        return extResult;
                    }
                }

                // AccessData_ReaderRuleIds (key 4)
                // If present and none of our configured rule IDs match → 0x00,0x25
                CBORObject readerRuleIds = elementValue.get(CBORObject.FromObject(4));
                if (readerRuleIds != null) {
                    Log.d(TAG, "Step 8: AccessData_ReaderRuleIds present, type="
                            + readerRuleIds.getType());
                    // We have no configured reader rule IDs in this test app.
                    // Per §7.5: if the rule IDs list is present and we don't match
                    // any, access is denied.
                    Log.e(TAG, "Step 8: ReaderRuleIds present but reader has no"
                            + " configured rule ID — denying access");
                    return VerificationResult.failure(STATUS_INVALID_ACCESS_B1,
                            STATUS_INVALID_ACCESS_B2,
                            "AccessData element '" + elementId
                                    + "' contains ReaderRuleIds but reader has no configured"
                                    + " rule ID; access denied");
                }

                // Change 3 & 5: Full AccessRule validation per §7.3.3
                // Extract AccessData_Schedules (key 3) for schedule evaluation
                CBORObject schedulesArray = elementValue.get(CBORObject.FromObject(3));
                Log.d(TAG, "Step 8: AccessData_Schedules (key 3) present="
                        + (schedulesArray != null)
                        + (schedulesArray != null
                           ? " size=" + (schedulesArray.getType() == CBORType.Array
                                         ? schedulesArray.size() : "non-array")
                           : ""));

                // AccessData_AccessRules (key 2) — full validation per §7.3.3
                CBORObject accessRules = elementValue.get(CBORObject.FromObject(2));
                if (accessRules != null) {
                    Log.d(TAG, "Step 8: AccessData_AccessRules present, type="
                            + accessRules.getType()
                            + (accessRules.getType() == CBORType.Array
                               ? " count=" + accessRules.size() : ""));

                    if (accessRules.getType() == CBORType.Array) {
                        if (accessRules.size() == 0) {
                            Log.w(TAG, "Step 8: AccessData_AccessRules is empty array");
                        } else {
                            // Evaluate each AccessRule; at least one must be valid
                            boolean anyRuleValid = false;
                            for (int rIdx = 0; rIdx < accessRules.size(); rIdx++) {
                                CBORObject rule = accessRules.get(rIdx);
                                boolean ruleValid = evaluateAccessRule(
                                        rule, rIdx, elementId,
                                        schedulesArray, timeVerificationRequired);
                                Log.d(TAG, "Step 8: AccessRule[" + rIdx + "] valid=" + ruleValid);
                                if (ruleValid) {
                                    anyRuleValid = true;
                                    break; // one valid rule is sufficient
                                }
                            }
                            if (!anyRuleValid) {
                                Log.e(TAG, "Step 8: All AccessRules invalid for element '"
                                        + elementId + "'");
                                // Include document content in failure result for UI display
                                String summary = buildElementSummary(elementValue, elementId);
                                String reason = "AccessData element '" + elementId
                                        + "': all AccessRules are invalid — access denied";
                                if (summary != null) reason += "\n\n" + summary;
                                return VerificationResult.failure(STATUS_INVALID_ACCESS_B1,
                                        STATUS_INVALID_ACCESS_B2, reason);
                            }
                            Log.d(TAG, "Step 8: At least one AccessRule is valid");
                        }
                    }
                } else {
                    Log.d(TAG, "Step 8: AccessData_AccessRules (key 2) not present");
                }

                // Element looks valid
                if (isRequestedElement) {
                    foundValidElement = true;
                    Log.d(TAG, "Step 8: Found and validated requested element '"
                            + elementId + "'");

                    // Extract human-readable summary for UI display
                    elementSummary = buildElementSummary(elementValue, elementId);
                } else {
                    // Count any valid element for the "no valid data elements" check
                    foundValidElement = true;
                }
            }
        }

        if (!foundValidElement) {
            Log.e(TAG, "Step 8: No valid data elements received");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "No valid Access Data elements received in the document");
        }
        Log.d(TAG, "Step 8: Access Data Elements verified OK");

        // ------------------------------------------------------------------
        // All steps passed — SUCCESS
        // ------------------------------------------------------------------
        Log.d(TAG, "=== verifyDocument PASSED for docType=" + docType + " ===");
        String detail = "Signature Valid";
        if (elementSummary != null) detail += "\n" + elementSummary;
        return VerificationResult.success(detail);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    /**
     * Build a human-readable summary of an AccessData element's content for UI display.
     * Extracts Employee ID, element name, version, access rules, and schedule descriptions.
     */
    private static String buildElementSummary(CBORObject elementValue, String elementId) {
        try {
            StringBuilder sb = new StringBuilder();

            // Version (key 0)
            CBORObject versionObj = elementValue.get(CBORObject.FromObject(0));
            int version = (versionObj != null) ? versionObj.AsInt32() : 1;

            // ID (key 1) — e.g. "ELATEC001" (may be CBOR text string or byte string)
            CBORObject idObj = elementValue.get(CBORObject.FromObject(1));
            String empId = null;
            if (idObj != null) {
                if (idObj.getType() == CBORType.TextString) {
                    empId = idObj.AsString();
                } else if (idObj.getType() == CBORType.ByteString) {
                    empId = new String(idObj.GetByteString(), java.nio.charset.StandardCharsets.UTF_8);
                }
            }
            if (empId != null) sb.append("Employee ID:  ").append(empId).append("\n");
            sb.append(" Element:      ").append(elementId).append(" (v").append(version).append(")\n");

            // AccessRules (key 2)
            CBORObject rulesArray = elementValue.get(CBORObject.FromObject(2));
            CBORObject schedulesArray = elementValue.get(CBORObject.FromObject(3));
            if (rulesArray != null && rulesArray.getType() == CBORType.Array) {
                sb.append(" Access Rules: ").append(rulesArray.size()).append("\n");
                for (int r = 0; r < rulesArray.size(); r++) {
                    CBORObject rule = rulesArray.get(r);
                    if (rule == null || rule.getType() != CBORType.Map) continue;

                    // Capabilities (key 0)
                    CBORObject capObj = rule.get(CBORObject.FromObject(0));
                    int caps = (capObj != null) ? capObj.AsInt32() : 0;
                    StringBuilder capStr = new StringBuilder();
                    if ((caps & 0x01) != 0) capStr.append("Secure");
                    if ((caps & 0x02) != 0) { if (capStr.length() > 0) capStr.append(", "); capStr.append("Unsecure"); }
                    if ((caps & 0x08) != 0) { if (capStr.length() > 0) capStr.append(", "); capStr.append("Momentary Unsecure"); }
                    if (capStr.length() == 0) capStr.append("0x" + Integer.toHexString(caps));

                    sb.append("   Rule ").append(r + 1).append(":  ").append(capStr);

                    // AllowScheduleIds (key 1) — resolve to schedule description
                    CBORObject allowObj = rule.get(CBORObject.FromObject(1));
                    if (allowObj != null && schedulesArray != null) {
                        int schedBits = allowObj.AsInt32();
                        String schedDesc = describeScheduleBits(schedBits, schedulesArray);
                        if (schedDesc != null) sb.append("\n           Schedule: ").append(schedDesc);
                    }
                    sb.append("\n");
                }
            }
            return sb.toString().trim();
        } catch (Exception e) {
            Log.w(TAG, "buildElementSummary failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Describe which schedules are referenced by the given bitmask, in human-readable form.
     * Returns e.g. "Mon-Fri 07:00-19:00 UTC" or "Sat-Sun 09:00-17:00 UTC".
     *
     * The start time-of-day is derived from startPeriod (key 0) % 86400.
     * The end time-of-day is start + durationSeconds.
     * Falls back to "(Nh)" if startPeriod is absent.
     */
    private static String describeScheduleBits(int bits, CBORObject schedulesArray) {
        try {
            StringBuilder sb = new StringBuilder();
            for (int bit = 0; bit < 8; bit++) {
                if ((bits & (1 << bit)) == 0) continue;
                if (bit >= schedulesArray.size()) continue;
                CBORObject schedule = schedulesArray.get(bit);
                if (schedule == null) continue;

                CBORObject recurrObj = schedule.get(CBORObject.FromObject(2));
                if (recurrObj != null && recurrObj.getType() == CBORType.Array && recurrObj.size() >= 2) {
                    long duration = recurrObj.get(0).AsInt64();
                    int mask = recurrObj.get(1).AsInt32();

                    // Build day-of-week string from mask
                    String[] dayNames = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"};
                    java.util.List<String> days = new java.util.ArrayList<>();
                    for (int d = 0; d < 7; d++) {
                        if ((mask & (1 << d)) != 0) days.add(dayNames[d]);
                    }
                    String daysStr;
                    if (days.size() == 5 && mask == 0x1F) daysStr = "Mon-Fri";
                    else if (days.size() == 2 && mask == 0x60) daysStr = "Sat-Sun";
                    else if (days.size() == 7) daysStr = "Every day";
                    else daysStr = String.join(", ", days);

                    // Build time-window string from startPeriod (key 0) % 86400.
                    // When the window crosses midnight (e.g. night-shift 22:00-06:00)
                    // the raw todEnd will exceed 86400; we mod-wrap and append the
                    // "(+1d)" indicator so users understand the schedule rolls into
                    // the next day rather than showing nonsensical "30:00" hours.
                    CBORObject startObj = schedule.get(CBORObject.FromObject(0));
                    String windowStr;
                    if (startObj != null) {
                        long startPeriod = startObj.AsInt64();
                        long todStart = startPeriod % 86400;  // seconds-since-midnight of window open
                        long todEndRaw = todStart + duration; // raw seconds-since-midnight of window close
                        long todEnd    = todEndRaw % 86400;   // wrap into 0..86399
                        boolean wrapsMidnight = todEndRaw >= 86400;
                        windowStr = String.format("%02d:%02d-%02d:%02d UTC%s",
                                todStart / 3600, (todStart % 3600) / 60,
                                todEnd   / 3600, (todEnd   % 3600) / 60,
                                wrapsMidnight ? " (+1d)" : "");
                    } else {
                        int hours = (int)(duration / 3600);
                        int mins  = (int)((duration % 3600) / 60);
                        windowStr = "(" + ((mins == 0) ? hours + "h" : hours + "h " + mins + "m") + ")";
                    }

                    if (sb.length() > 0) sb.append("; ");
                    sb.append(daysStr).append(" ").append(windowStr);
                }
            }
            return sb.length() > 0 ? sb.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Evaluates a single AccessRule per §7.3.3.
     *
     * <p>An AccessRule is valid if NONE of the checks below invalidate it:
     * <ul>
     *   <li>Capabilities (key 0): invalid if our intended action bit (Unsecure=bit 1) is NOT set.</li>
     *   <li>AllowScheduleIds (key 1): invalid if none of the referenced schedules is in-range.</li>
     *   <li>DenyScheduleIds (key 2): invalid if ANY of the referenced schedules is in-range.</li>
     *   <li>If Allow/Deny present and timeVerificationRequired=true and Reader cannot validate
     *       time: invalid. (Our Reader CAN validate time, so this only applies to cases where
     *       schedules reference undefined schedule entries.)</li>
     * </ul>
     *
     * @param rule                    CBOR map representing the AccessRule.
     * @param ruleIndex               Index for logging.
     * @param elementId               Element identifier for logging.
     * @param schedulesArray          AccessData_Schedules (key 3) array, may be null.
     * @param timeVerificationRequired Whether timeVerificationRequired is set in MSO.
     * @return {@code true} if the rule is valid, {@code false} if it is invalid.
     */
    /**
     * Process a RevocationData element and update the revocation database.
     * Per §7.6.1:
     *   ChangeMode 0 (Overwrite) → replace entire revocation list with entries
     *   ChangeMode 1 (Update/Append) → add entries, remove entries_to_remove
     *
     * RevocationData keys: 0=Version, 1=ChangeMode, 2=Entries, 3=EntriesRemove, 4=Extensions
     * RevocationEntry keys: 0=PublicKeyHash, 1=ID, 2=ExpiryTime
     */
    private static void processRevocationData(CBORObject elementValue, String elementId) {
        Log.d(TAG, "processRevocationData: element=" + elementId);

        CBORObject changeModeObj = elementValue.get(CBORObject.FromObject(1));
        int changeMode = (changeModeObj != null) ? changeModeObj.AsInt32() : 0;
        Log.d(TAG, "processRevocationData: changeMode=" + changeMode
                + " (" + (changeMode == 0 ? "Overwrite" : "Append") + ")");

        CBORObject entriesArray = elementValue.get(CBORObject.FromObject(2));
        CBORObject entriesToRemoveArray = elementValue.get(CBORObject.FromObject(3));

        if (changeMode == 0) {
            // Overwrite — clear the revocation list and add all entries
            // §7.6.3: EntriesRemove (key 3) is forbidden in Overwrite mode
            if (entriesToRemoveArray != null && entriesToRemoveArray.size() > 0) {
                Log.w(TAG, "processRevocationData: EntriesRemove present in Overwrite mode "
                        + "— rejected per §7.6.3");
                return;
            }
            revokedKeyHashes.clear();
            Log.d(TAG, "processRevocationData: Overwrite — cleared revocation database");
        }

        // Add entries (key 2)
        if (entriesArray != null && entriesArray.getType() == CBORType.Array) {
            for (int i = 0; i < entriesArray.size(); i++) {
                CBORObject entry = entriesArray.get(i);
                if (entry != null && entry.getType() == CBORType.Map) {
                    CBORObject hashObj = entry.get(CBORObject.FromObject(0));
                    if (hashObj != null) {
                        byte[] hashBytes = hashObj.GetByteString();
                        String hashHex = Hex.toHexString(hashBytes);
                        revokedKeyHashes.add(hashHex);
                        Log.d(TAG, "processRevocationData: added revoked hash="
                                + hashHex.substring(0, 16) + "...");
                    }
                }
            }
        }

        // Remove entries (key 3) — only valid for Update/Append mode (changeMode == 1)
        if (changeMode == 1 && entriesToRemoveArray != null
                && entriesToRemoveArray.getType() == CBORType.Array) {
            for (int i = 0; i < entriesToRemoveArray.size(); i++) {
                CBORObject entry = entriesToRemoveArray.get(i);
                if (entry != null && entry.getType() == CBORType.Map) {
                    CBORObject hashObj = entry.get(CBORObject.FromObject(0));
                    if (hashObj != null) {
                        byte[] hashBytes = hashObj.GetByteString();
                        String hashHex = Hex.toHexString(hashBytes);
                        revokedKeyHashes.remove(hashHex);
                        Log.d(TAG, "processRevocationData: removed revoked hash="
                                + hashHex.substring(0, 16) + "...");
                    }
                }
            }
        }

        Log.d(TAG, "processRevocationData: revocation database now has "
                + revokedKeyHashes.size() + " entries");
    }

    private static boolean evaluateAccessRule(
            CBORObject rule,
            int ruleIndex,
            String elementId,
            CBORObject schedulesArray,
            boolean timeVerificationRequired) {

        boolean ruleValid = true;

        // Check Capabilities (key 0)
        // Our Reader intends "Unsecure" (bit 1) — a standard door unlock
        CBORObject capsObj = rule.get(CBORObject.FromObject(0));
        if (capsObj != null) {
            int caps = capsObj.AsInt32();
            Log.d(TAG, "Step 8: AccessRule[" + ruleIndex + "] Capabilities=0x"
                    + Integer.toHexString(caps));
            boolean unsecureBitSet = (caps & (1 << 1)) != 0;
            if (!unsecureBitSet) {
                Log.d(TAG, "Step 8: AccessRule[" + ruleIndex
                        + "] Capabilities does not include Unsecure (bit 1) — rule invalid");
                ruleValid = false;
            }
        }

        // Check AllowScheduleIds (key 1) — need at least one referenced schedule in-range.
        // Per §7.3.3: If AllowScheduleIds is present, the check results in invalid
        // if none of the referenced schedules is in-range.
        CBORObject allowObj = rule.get(CBORObject.FromObject(1));
        if (allowObj != null && ruleValid) {
            int allowBits = allowObj.AsInt32();
            Log.d(TAG, "Step 8: AccessRule[" + ruleIndex + "] AllowScheduleIds=0x"
                    + Integer.toHexString(allowBits));
            if (schedulesArray == null) {
                Log.d(TAG, "Step 8: AccessRule[" + ruleIndex
                        + "] AllowScheduleIds present but no Schedules array — rule invalid");
                ruleValid = false;
            } else {
                boolean anyAllowInRange = isAnyScheduleInRange(
                        allowBits, schedulesArray, timeVerificationRequired);
                Log.d(TAG, "Step 8: AccessRule[" + ruleIndex
                        + "] AllowScheduleIds in-range=" + anyAllowInRange);
                if (!anyAllowInRange) {
                    ruleValid = false;
                }
            }
        }

        // Check DenyScheduleIds (key 2) — deny takes precedence if any in-range.
        // Per §7.3.3: If DenyScheduleIds is present, the check results in invalid
        // if at least one of the referenced schedules is in-range.
        CBORObject denyObj = rule.get(CBORObject.FromObject(2));
        if (denyObj != null && ruleValid) {
            int denyBits = denyObj.AsInt32();
            Log.d(TAG, "Step 8: AccessRule[" + ruleIndex + "] DenyScheduleIds=0x"
                    + Integer.toHexString(denyBits));
            if (schedulesArray != null) {
                boolean anyDenyInRange = isAnyScheduleInRange(
                        denyBits, schedulesArray, timeVerificationRequired);
                Log.d(TAG, "Step 8: AccessRule[" + ruleIndex
                        + "] DenyScheduleIds in-range=" + anyDenyInRange);
                if (anyDenyInRange) {
                    ruleValid = false;
                }
            }
        }

        return ruleValid;
    }

    /**
     * Returns true if at least one schedule referenced by the bitmask is currently in-range.
     *
     * <p>Per §7.3.4: each bit in {@code scheduleBits} (bit N) references the schedule at
     * index N in the {@code schedulesArray}. A schedule is in-range if the current time
     * falls within [StartPeriod, EndPeriod].
     *
     * @param scheduleBits         Bitmask of referenced schedule indices (bits 0–7).
     * @param schedulesArray       AccessData_Schedules array from the element value, or null.
     * @param timeVerifRequired    Whether timeVerificationRequired is set in the MSO.
     * @return {@code true} if at least one referenced schedule is in-range.
     */
    private static boolean isAnyScheduleInRange(
            int scheduleBits,
            CBORObject schedulesArray,
            boolean timeVerifRequired) {

        if (schedulesArray == null) {
            // No schedules defined but schedule IDs referenced.
            // We support schedule evaluation but there are simply no schedules — none in range.
            Log.d(TAG, "isAnyScheduleInRange: schedulesArray is null; returning false");
            return false;
        }

        long nowEpoch = System.currentTimeMillis() / 1000L;
        for (int bit = 0; bit < 8; bit++) {
            if ((scheduleBits & (1 << bit)) != 0) {
                // Schedule at index 'bit' is referenced
                if (bit < schedulesArray.size()) {
                    CBORObject schedule = schedulesArray.get(bit);
                    boolean inRange = isScheduleInRange(schedule, nowEpoch);
                    Log.d(TAG, "isAnyScheduleInRange: schedule[" + bit + "] inRange=" + inRange);
                    if (inRange) {
                        return true;
                    }
                } else {
                    Log.w(TAG, "isAnyScheduleInRange: referenced schedule index " + bit
                            + " is out of bounds (schedulesArray.size()="
                            + schedulesArray.size() + ")");
                    // Referenced schedule does not exist — cannot be in-range
                }
            }
        }
        return false;
    }

    /**
     * Determines whether a single schedule entry is currently in-range.
     *
     * <p>Schedule keys per §7.3.4:
     * <ul>
     *   <li>StartPeriod = 0 (uint, seconds since Unix epoch)</li>
     *   <li>EndPeriod   = 1 (uint, seconds since Unix epoch)</li>
     *   <li>RecurrenceRule = 2</li>
     *   <li>Flags = 3</li>
     * </ul>
     *
     * <p>A schedule is in-range if {@code StartPeriod <= nowEpoch < EndPeriod} (non-inclusive end).
     * If EndPeriod is absent, only {@code StartPeriod <= nowEpoch} is checked.
     *
     * @param schedule  CBOR map representing the schedule entry.
     * @param nowEpoch  Current time in seconds since Unix epoch.
     * @return {@code true} if the schedule is currently in-range.
     */
    private static boolean isScheduleInRange(CBORObject schedule, long nowEpoch) {
        CBORObject startObj = schedule.get(CBORObject.FromObject(0));
        CBORObject endObj   = schedule.get(CBORObject.FromObject(1));
        CBORObject recurrObj = schedule.get(CBORObject.FromObject(2));

        long start = (startObj != null) ? startObj.AsInt64() : 0L;
        long end   = (endObj   != null) ? endObj.AsInt64()   : Long.MAX_VALUE;

        // Must be within overall [start, end) window — EndPeriod is non-inclusive per §7.3.4
        if (nowEpoch < start || nowEpoch >= end) {
            Log.d(TAG, "isScheduleInRange: outside [start=" + start + ", end=" + end
                    + "] now=" + nowEpoch + " -> false");
            return false;
        }

        // If no recurrence rule, the entire [start, end] range is in effect
        if (recurrObj == null || recurrObj.getType() != CBORType.Array || recurrObj.size() < 5) {
            Log.d(TAG, "isScheduleInRange: no recurrence, start=" + start
                    + " end=" + end + " now=" + nowEpoch + " -> true");
            return true;
        }

        // RecurrenceRule = [DurationSeconds, Mask, Pattern, Interval, Ordinal]
        long duration = recurrObj.get(0).AsInt64();       // window duration in seconds
        int  mask     = recurrObj.get(1).AsInt32();       // day/month mask
        int  pattern  = recurrObj.get(2).AsInt32();       // 1=Daily, 2=Weekly, etc.
        int  interval = recurrObj.get(3).AsInt32();       // recurrence interval
        int  ordinal  = recurrObj.get(4).AsInt32();       // ordinal value

        Log.d(TAG, "isScheduleInRange: recurrence duration=" + duration + " mask=" + mask
                + " pattern=" + pattern + " interval=" + interval + " ordinal=" + ordinal);

        if (interval <= 0) interval = 1;

        // Per §7.3.4: evaluate the recurrence rule based on the pattern type.
        // The day-of-week Mask determines which days the schedule applies.
        // The DurationSeconds determines the window length on applicable days.
        // The window starts at startPeriod's time-of-day (TOD) on each applicable day.

        switch (pattern) {
            case 1: // Daily — every N days
            {
                long elapsed = nowEpoch - start;
                if (elapsed < 0) return false;
                long daysSinceStart = elapsed / 86400L;
                long todStart = start % 86400L; // time-of-day from startPeriod
                long todNow   = nowEpoch % 86400L;

                // Cross-midnight wrap: when todStart + duration > 86400 the
                // window straddles into the next day. We must consider both
                // today's recurrence (late-night portion: todNow >= todStart)
                // AND yesterday's recurrence still in its early-morning
                // carry-over (todNow < (todStart + duration) - 86400).
                // §7.3.4 says the recurrence "fires" each interval at todStart
                // and remains open for `duration`; nothing in the spec restricts
                // duration to ≤ 86400.
                long endRaw = todStart + duration;
                boolean wraps = endRaw > 86400L;
                boolean inWindowToday;
                boolean inWindowYesterday = false;

                if (wraps)
                {
                    long endWrapped = endRaw - 86400L;
                    inWindowToday     = todNow >= todStart;
                    inWindowYesterday = todNow < endWrapped;
                }
                else
                {
                    inWindowToday = todNow >= todStart && todNow < endRaw;
                }

                // Determine which "day" we attribute the open window to and
                // gate it by interval. interval=1 means every day, so this
                // simplifies; interval>1 needs the day-of-recurrence check.
                boolean intervalOkToday     = (daysSinceStart % interval) == 0;
                boolean intervalOkYesterday = ((daysSinceStart - 1) % interval) == 0
                        && daysSinceStart >= 1;

                boolean inWindow = (inWindowToday     && intervalOkToday)
                                || (inWindowYesterday && intervalOkYesterday);

                Log.d(TAG, "isScheduleInRange: Daily todNow=" + todNow
                        + " todStart=" + todStart + " duration=" + duration
                        + " wraps=" + wraps
                        + " inWindowToday=" + inWindowToday
                        + " inWindowYesterday=" + inWindowYesterday
                        + " intervalOkToday=" + intervalOkToday
                        + " intervalOkYesterday=" + intervalOkYesterday
                        + " -> " + inWindow);
                return inWindow;
            }

            case 2: // Weekly — use day-of-week Mask
            {
                // Determine current day-of-week (0=Mon, 1=Tue, ... 5=Sat, 6=Sun)
                // Java Calendar: MONDAY=2, TUESDAY=3, ... SATURDAY=7, SUNDAY=1
                java.util.Calendar cal = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"));
                cal.setTimeInMillis(nowEpoch * 1000L);
                int javaDow = cal.get(java.util.Calendar.DAY_OF_WEEK); // 1=Sun, 2=Mon, ... 7=Sat
                // Convert to Aliro mask convention: bit0=Mon, bit1=Tue, ..., bit5=Sat, bit6=Sun
                int aliroDow;
                switch (javaDow) {
                    case java.util.Calendar.MONDAY:    aliroDow = 0; break;
                    case java.util.Calendar.TUESDAY:   aliroDow = 1; break;
                    case java.util.Calendar.WEDNESDAY: aliroDow = 2; break;
                    case java.util.Calendar.THURSDAY:  aliroDow = 3; break;
                    case java.util.Calendar.FRIDAY:    aliroDow = 4; break;
                    case java.util.Calendar.SATURDAY:  aliroDow = 5; break;
                    case java.util.Calendar.SUNDAY:    aliroDow = 6; break;
                    default: aliroDow = -1; break;
                }
                int aliroDowYesterday = (aliroDow >= 0) ? (aliroDow + 6) % 7 : -1;

                boolean dayMatchToday     = aliroDow >= 0
                        && (mask & (1 << aliroDow)) != 0;
                boolean dayMatchYesterday = aliroDowYesterday >= 0
                        && (mask & (1 << aliroDowYesterday)) != 0;
                Log.d(TAG, "isScheduleInRange: Weekly javaDow=" + javaDow
                        + " aliroDow=" + aliroDow + " mask=0x" + Integer.toHexString(mask)
                        + " dayMatchToday=" + dayMatchToday
                        + " dayMatchYesterday=" + dayMatchYesterday);

                if (!dayMatchToday && !dayMatchYesterday) return false;

                // Check week interval: how many weeks since startPeriod?
                long elapsed = nowEpoch - start;
                if (elapsed < 0) return false;
                long weeksSinceStart = elapsed / 604800L;
                if (interval > 1 && weeksSinceStart % interval != 0) {
                    Log.d(TAG, "isScheduleInRange: Weekly interval=" + interval
                            + " weeksSinceStart=" + weeksSinceStart + " -> not an active week");
                    return false;
                }

                // Check time-of-day window with cross-midnight wrap support.
                // §7.3.4 recurrence fires at todStart on each masked day and
                // remains open for `duration` seconds. When duration carries
                // past midnight, today's early-morning hours actually belong
                // to yesterday's recurrence, so we evaluate both branches.
                long todStart = start % 86400L;
                long todNow   = nowEpoch % 86400L;
                long endRaw   = todStart + duration;
                boolean wraps = endRaw > 86400L;

                boolean inWindowToday;
                boolean inWindowYesterday = false;
                if (wraps)
                {
                    long endWrapped = endRaw - 86400L;
                    inWindowToday     = todNow >= todStart;
                    inWindowYesterday = todNow < endWrapped;
                }
                else
                {
                    inWindowToday = todNow >= todStart && todNow < endRaw;
                }

                boolean inWindow = (inWindowToday     && dayMatchToday)
                                || (inWindowYesterday && dayMatchYesterday);
                Log.d(TAG, "isScheduleInRange: Weekly todNow=" + todNow
                        + " todStart=" + todStart + " duration=" + duration
                        + " wraps=" + wraps
                        + " inWindowToday=" + inWindowToday
                        + " inWindowYesterday=" + inWindowYesterday
                        + " -> " + inWindow);
                return inWindow;
            }

            case 3: // Monthly
            case 4: // Yearly
            {
                // For Monthly/Yearly: check Ordinal (which occurrence in the month/year)
                // and Mask (which days). Approximate with calendar.
                java.util.Calendar cal = java.util.Calendar.getInstance(java.util.TimeZone.getTimeZone("UTC"));
                cal.setTimeInMillis(nowEpoch * 1000L);
                int javaDow = cal.get(java.util.Calendar.DAY_OF_WEEK);
                int aliroDow;
                switch (javaDow) {
                    case java.util.Calendar.MONDAY:    aliroDow = 0; break;
                    case java.util.Calendar.TUESDAY:   aliroDow = 1; break;
                    case java.util.Calendar.WEDNESDAY: aliroDow = 2; break;
                    case java.util.Calendar.THURSDAY:  aliroDow = 3; break;
                    case java.util.Calendar.FRIDAY:    aliroDow = 4; break;
                    case java.util.Calendar.SATURDAY:  aliroDow = 5; break;
                    case java.util.Calendar.SUNDAY:    aliroDow = 6; break;
                    default: aliroDow = -1; break;
                }
                int aliroDowYesterday = (aliroDow >= 0) ? (aliroDow + 6) % 7 : -1;
                boolean dayMatchToday     = mask == 0
                        || (aliroDow >= 0 && (mask & (1 << aliroDow)) != 0);
                boolean dayMatchYesterday = mask == 0
                        || (aliroDowYesterday >= 0 && (mask & (1 << aliroDowYesterday)) != 0);
                if (!dayMatchToday && !dayMatchYesterday) return false;

                long todStart = start % 86400L;
                long todNow   = nowEpoch % 86400L;
                long endRaw   = todStart + duration;
                boolean wraps = endRaw > 86400L;
                boolean inWindowToday;
                boolean inWindowYesterday = false;
                if (wraps)
                {
                    long endWrapped = endRaw - 86400L;
                    inWindowToday     = todNow >= todStart;
                    inWindowYesterday = todNow < endWrapped;
                }
                else
                {
                    inWindowToday = todNow >= todStart && todNow < endRaw;
                }
                boolean inWindow = (inWindowToday     && dayMatchToday)
                                || (inWindowYesterday && dayMatchYesterday);
                Log.d(TAG, "isScheduleInRange: pattern=" + pattern
                        + " dayMatchToday=" + dayMatchToday
                        + " dayMatchYesterday=" + dayMatchYesterday
                        + " wraps=" + wraps
                        + " inWindowToday=" + inWindowToday
                        + " inWindowYesterday=" + inWindowYesterday
                        + " -> " + inWindow);
                return inWindow;
            }

            default:
                Log.w(TAG, "isScheduleInRange: unknown pattern=" + pattern + " -> false");
                return false;
        }
    }

    /**
     * Verifies AccessData_AccessExtensions for unknown critical extensions per §7.3.7.
     *
     * <p>AccessData_AccessExtensions structure:
     * <pre>
     * AccessData_AccessExtensions => { + Vendor_RegisteredID => [+ AccessExtension] }
     * AccessExtension = [Criticality, Vendor_ExtensionID, Version, Data]
     * Criticality_Bits: bit 0 = Critical
     * </pre>
     *
     * <p>Per §7.3.7: "If the Flag is not set, the Reader SHALL consider access extension
     * to be critical." This means:
     * <ul>
     *   <li>Criticality == 0 (no bits set) → critical by default rule</li>
     *   <li>Criticality has bit 0 set → explicitly critical</li>
     * </ul>
     * Since we do not interpret any Aliro vendor extensions, any critical extension causes
     * the element to be rejected.
     *
     * @param extensions CBOR object representing the AccessExtensions map
     *                   ({Vendor_RegisteredID → [AccessExtension...]}).
     * @param elementId  Element identifier for logging.
     * @return {@code null} if OK (no critical extensions found), or a failure
     *         {@link VerificationResult} if a critical unknown extension is present.
     */
    private static VerificationResult verifyAccessExtensions(
            CBORObject extensions, String elementId) {

        // AccessData_AccessExtensions is a map: { Vendor_RegisteredID => [AccessExtension...] }
        if (extensions.getType() == CBORType.Map) {
            for (CBORObject vendorKey : extensions.getKeys()) {
                CBORObject extList = extensions.get(vendorKey);
                Log.d(TAG, "Step 8: verifyAccessExtensions vendorKey="
                        + vendorKey.ToJSONString()
                        + " extList type=" + (extList != null ? extList.getType() : "null"));

                if (extList == null || extList.getType() != CBORType.Array) {
                    Log.w(TAG, "Step 8: Extension entry for vendor "
                            + vendorKey.ToJSONString()
                            + " is not an array; treating as critical and rejecting");
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "AccessData element '" + elementId
                                    + "' contains malformed AccessExtension entry for vendor "
                                    + vendorKey.ToJSONString());
                }

                for (int eIdx = 0; eIdx < extList.size(); eIdx++) {
                    CBORObject ext = extList.get(eIdx);
                    Log.d(TAG, "Step 8: Checking AccessExtension[" + eIdx + "]="
                            + ext.ToJSONString());

                    // AccessExtension = [Criticality, Vendor_ExtensionID, Version, Data]
                    if (ext.getType() != CBORType.Array || ext.size() < 1) {
                        Log.w(TAG, "Step 8: AccessExtension[" + eIdx
                                + "] is not an array or is empty; treating as critical");
                        return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                                STATUS_INVALID_CONTENT_B2,
                                "AccessData element '" + elementId
                                        + "' contains malformed AccessExtension at index " + eIdx);
                    }

                    // Criticality is the first element (index 0) of the AccessExtension array
                    CBORObject critObj = ext.get(0);
                    int criticality = 0;
                    if (critObj != null && critObj.getType() == CBORType.Integer) {
                        criticality = critObj.AsInt32();
                    }

                    // Per §7.3.7 and the CDDL:
                    //   Criticality_Bits = &( Critical : 0 )
                    // The enum value 0 = "Critical". So criticality == 0 means
                    // the extension IS critical. Any other value (1–7 are RFU)
                    // means the critical flag is NOT set → non-critical.
                    // An unknown non-critical extension is ignored per §7.3.7.
                    boolean isCritical = (criticality == 0);

                    Log.d(TAG, "Step 8: AccessExtension[" + eIdx + "] criticality=0x"
                            + Integer.toHexString(criticality) + " isCritical=" + isCritical);

                    if (isCritical) {
                        Log.e(TAG, "Step 8: Unknown critical AccessExtension at index "
                                + eIdx + " (vendor=" + vendorKey.ToJSONString()
                                + ") in element '" + elementId + "' — rejecting");
                        return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                                STATUS_INVALID_CONTENT_B2,
                                "AccessData element '" + elementId
                                        + "' contains an unknown critical AccessExtension"
                                        + " at index " + eIdx
                                        + " (vendor=" + vendorKey.ToJSONString()
                                        + ", criticality=0x"
                                        + Integer.toHexString(criticality) + ")");
                    } else {
                        Log.d(TAG, "Step 8: AccessExtension[" + eIdx + "] is non-critical; ignoring");
                    }
                }
            }
        } else if (extensions.getType() == CBORType.Array) {
            // Legacy / alternate encoding: array of AccessExtension arrays
            for (int i = 0; i < extensions.size(); i++) {
                CBORObject ext = extensions.get(i);
                Log.d(TAG, "Step 8: Checking extension (array form)[" + i + "]="
                        + ext.ToJSONString());

                if (ext.getType() == CBORType.Array && ext.size() >= 1) {
                    CBORObject critObj = ext.get(0);
                    int criticality = 0;
                    if (critObj != null && critObj.getType() == CBORType.Integer) {
                        criticality = critObj.AsInt32();
                    }
                    boolean isCritical = (criticality == 0);
                    Log.d(TAG, "Step 8: Extension[" + i + "] criticality=0x"
                            + Integer.toHexString(criticality) + " isCritical=" + isCritical);
                    if (isCritical) {
                        Log.e(TAG, "Step 8: Unknown critical AccessExtension[" + i
                                + "] in element '" + elementId + "' — rejecting");
                        return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                                STATUS_INVALID_CONTENT_B2,
                                "AccessData element '" + elementId
                                        + "' contains an unknown critical extension at index " + i);
                    } else {
                        Log.d(TAG, "Step 8: Extension[" + i + "] is non-critical; ignoring");
                    }
                } else {
                    // Unknown structure — treat as critical
                    Log.w(TAG, "Step 8: Extension[" + i
                            + "] has unexpected structure; treating as critical — rejecting");
                    return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                            STATUS_INVALID_CONTENT_B2,
                            "AccessData element '" + elementId
                                    + "' contains an unknown critical extension at index " + i);
                }
            }
        } else {
            Log.w(TAG, "Step 8: AccessData_AccessExtensions is neither map nor array; type="
                    + extensions.getType() + "; treating as critical — rejecting");
            return VerificationResult.failure(STATUS_INVALID_CONTENT_B1,
                    STATUS_INVALID_CONTENT_B2,
                    "AccessData element '" + elementId
                            + "' has AccessExtensions of unexpected type "
                            + extensions.getType());
        }
        return null; // OK — no critical unknown extensions found
    }

    /**
     * Converts a 65-byte uncompressed EC P-256 public key (04 || x || y) to a
     * Java {@link PublicKey} object using a SubjectPublicKeyInfo DER encoding.
     *
     * <p>The SubjectPublicKeyInfo header for P-256 (OID 1.2.840.10045.2.1, curve
     * OID 1.2.840.10045.3.1.7) with an uncompressed 65-byte key is the 27-byte
     * prefix: {@code 3059 3013 0607 2a86 48ce 3d02 0106 082a 8648 ce3d 0301 0703 4200}.
     *
     * @param uncompressedKey 65-byte uncompressed EC point (04 || x || y).
     * @return A Java {@link PublicKey} usable with {@link Signature}.
     * @throws Exception if key construction fails.
     */
    private static PublicKey rawEcPubKeyToPublicKey(byte[] uncompressedKey) throws Exception {
        // SubjectPublicKeyInfo DER header for P-256 uncompressed point (27 bytes)
        byte[] header = Hex.decode("3059301306072a8648ce3d020106082a8648ce3d030107034200");
        byte[] der = new byte[header.length + uncompressedKey.length];
        System.arraycopy(header, 0, der, 0, header.length);
        System.arraycopy(uncompressedKey, 0, der, header.length, uncompressedKey.length);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("EC").generatePublic(spec);
    }

    /**
     * Builds a COSE Sig_structure for COSE_Sign1 per RFC 9052 §4.4:
     * <pre>
     * Sig_structure = [
     *   "Signature1",
     *   protected,          ; bstr
     *   external_aad,       ; bstr
     *   payload             ; bstr
     * ]
     * </pre>
     *
     * @param protectedHeaderBytes Raw protected header bytes (already bstr-encoded).
     * @param externalAad          External AAD bytes (empty byte array if none).
     * @param payloadBytes         Payload bytes (bstr content of the COSE payload field).
     * @return CBOR-encoded Sig_structure bytes.
     */
    private static byte[] buildCoseSigStructure(
            byte[] protectedHeaderBytes,
            byte[] externalAad,
            byte[] payloadBytes) {

        CBORObject sigStructure = CBORObject.NewArray();
        sigStructure.Add(CBORObject.FromObject("Signature1"));
        sigStructure.Add(CBORObject.FromObject(protectedHeaderBytes));
        sigStructure.Add(CBORObject.FromObject(externalAad));
        sigStructure.Add(CBORObject.FromObject(payloadBytes));
        return sigStructure.EncodeToBytes();
    }

    /**
     * Converts a raw ECDSA signature (r || s, each 32 bytes for P-256) to
     * DER-encoded SEQUENCE format expected by Java's {@code SHA256withECDSA}.
     *
     * <p>DER SEQUENCE:
     * <pre>
     * 30 <total-len>
     *   02 <r-len> <r>
     *   02 <s-len> <s>
     * </pre>
     *
     * @param rawSignature 64-byte raw signature (r || s).
     * @return DER-encoded signature bytes.
     * @throws IllegalArgumentException if the raw signature length is unexpected.
     */
    private static byte[] rawEcSignatureToDer(byte[] rawSignature) {
        if (rawSignature.length != 64) {
            throw new IllegalArgumentException(
                    "Expected 64-byte raw EC signature (r||s), got " + rawSignature.length);
        }

        byte[] r = Arrays.copyOfRange(rawSignature, 0, 32);
        byte[] s = Arrays.copyOfRange(rawSignature, 32, 64);

        // Convert to positive BigInteger to add leading 0x00 if high bit set
        BigInteger rInt = new BigInteger(1, r);
        BigInteger sInt = new BigInteger(1, s);

        byte[] rBytes = toUnsignedByteArray(rInt);
        byte[] sBytes = toUnsignedByteArray(sInt);

        int rLen = rBytes.length;
        int sLen = sBytes.length;
        int seqLen = 2 + rLen + 2 + sLen;

        byte[] der = new byte[2 + seqLen];
        int idx = 0;
        der[idx++] = 0x30;
        der[idx++] = (byte) seqLen;
        der[idx++] = 0x02;
        der[idx++] = (byte) rLen;
        System.arraycopy(rBytes, 0, der, idx, rLen);
        idx += rLen;
        der[idx++] = 0x02;
        der[idx++] = (byte) sLen;
        System.arraycopy(sBytes, 0, der, idx, sLen);

        return der;
    }

    /**
     * Returns the minimal unsigned byte array for a non-negative {@link BigInteger},
     * with a leading 0x00 byte if the high bit is set (to keep sign positive in DER).
     */
    private static byte[] toUnsignedByteArray(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes[0] == 0 && bytes.length > 1) {
            // Already has leading zero; return as-is
            return bytes;
        }
        // If high bit is set, BigInteger adds a leading 0x00 — we keep that.
        return bytes;
    }

    /**
     * Reconstructs an uncompressed EC public key point (04 || x || y) from a
     * COSE_Key CBOR map.
     *
     * <p>COSE_Key EC2 parameters:
     * <ul>
     *   <li>kty = 1 → 2 (EC2)</li>
     *   <li>crv = -1 → 1 (P-256)</li>
     *   <li>x   = -2</li>
     *   <li>y   = -3</li>
     * </ul>
     *
     * @param coseKey CBOR map representing the COSE_Key.
     * @return 65-byte uncompressed point.
     * @throws IllegalArgumentException if required components are missing.
     */
    private static byte[] coseKeyToUncompressedPoint(CBORObject coseKey) {
        CBORObject xObj = coseKey.get(CBORObject.FromObject(COSE_KEY_X));
        CBORObject yObj = coseKey.get(CBORObject.FromObject(COSE_KEY_Y));

        if (xObj == null || yObj == null) {
            throw new IllegalArgumentException(
                    "COSE_Key missing x (-2) or y (-3) component; map="
                            + coseKey.ToJSONString());
        }

        byte[] x = xObj.GetByteString();
        byte[] y = yObj.GetByteString();
        Log.d(TAG, "coseKeyToUncompressedPoint: x=" + Hex.toHexString(x)
                + " y=" + Hex.toHexString(y));

        // Pad x and y to 32 bytes each (P-256)
        x = padTo32(x);
        y = padTo32(y);

        byte[] uncompressed = new byte[65];
        uncompressed[0] = 0x04;
        System.arraycopy(x, 0, uncompressed, 1, 32);
        System.arraycopy(y, 0, uncompressed, 33, 32);
        return uncompressed;
    }

    /**
     * Pads or trims a byte array to exactly 32 bytes (P-256 coordinate size).
     * Leading zero bytes may be stripped by CBOR encoding; we restore them.
     */
    private static byte[] padTo32(byte[] coord) {
        if (coord.length == 32) {
            return coord;
        }
        byte[] result = new byte[32];
        if (coord.length < 32) {
            // Left-pad with zeros
            System.arraycopy(coord, 0, result, 32 - coord.length, coord.length);
        } else {
            // Trim leading zeros (e.g. 33 bytes from BigInteger sign byte)
            System.arraycopy(coord, coord.length - 32, result, 0, 32);
        }
        return result;
    }

    /**
     * Parses an Aliro/mdoc {@code tdate} string (ISO 8601 / RFC 3339) from a
     * {@link CBORObject}.
     *
     * <p>Aliro represents dates as CBOR text strings tagged with tag 0 (tdate)
     * or as plain text strings.
     *
     * @param dateObj CBOR object representing the date.
     * @return The parsed {@link Instant}.
     */
    private static Instant parseTdate(CBORObject dateObj) {
        String dateStr;
        if (dateObj.isTagged()) {
            // Tag 0 = tdate (text string)
            dateStr = dateObj.AsString();
        } else if (dateObj.getType() == CBORType.TextString) {
            dateStr = dateObj.AsString();
        } else {
            throw new IllegalArgumentException(
                    "Expected tdate text string, got type=" + dateObj.getType()
                            + " value=" + dateObj.ToJSONString());
        }
        Log.d(TAG, "parseTdate: parsing '" + dateStr + "'");
        // ISO 8601 / RFC 3339; DateTimeFormatter.ISO_INSTANT handles trailing Z and offsets
        return Instant.from(DateTimeFormatter.ISO_DATE_TIME.parse(dateStr));
    }
}
