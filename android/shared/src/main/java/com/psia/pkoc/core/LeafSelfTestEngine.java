package com.psia.pkoc.core;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * LEAF Verified Self-Test Engine.
 *
 * Runs all LEAF protocol test cases in-process — no NFC hardware required.
 * Tests cover cryptographic primitives, certificate parsing, provisioning,
 * HCE APDU simulation, and negative/boundary cases.
 *
 * All crypto uses BouncyCastle with {@code new BouncyCastleProvider()} — NOT the string "BC".
 *
 * Test groups:
 *   1. CRYPTO_      — Cryptographic primitives (keygen, cert gen/verify, ECDSA)
 *   2. CERT_        — Certificate parsing and field extraction
 *   3. PROV_        — Provisioning round-trip (requires Context)
 *   4. HCE_         — HCE APDU format validation
 *   5. NEG_         — Negative / boundary tests
 */
public class LeafSelfTestEngine
{
    private static final String TAG = "LeafSelfTest";

    // Optional Android Context — used by tests that exercise SharedPreferences-backed methods.
    // May be null; tests requiring it will skip gracefully if null.
    private final Context context;

    public LeafSelfTestEngine() { this.context = null; }
    public LeafSelfTestEngine(Context context) { this.context = context; }

    // =========================================================================
    // TestResult
    // =========================================================================
    public static class TestResult
    {
        public String testId;
        public String group;
        public String name;
        public boolean passed;
        public boolean skipped;
        public String detail;
        public long durationMs;

        public TestResult(String testId, String group, String name,
                          boolean passed, boolean skipped, String detail, long durationMs)
        {
            this.testId    = testId;
            this.group     = group;
            this.name      = name;
            this.passed    = passed;
            this.skipped   = skipped;
            this.detail    = detail;
            this.durationMs = durationMs;
        }
    }

    // =========================================================================
    // Callback
    // =========================================================================
    public interface Callback
    {
        void onTestComplete(TestResult result);
        void onAllComplete(List<TestResult> results);
    }

    // =========================================================================
    // Run all tests
    // =========================================================================
    public List<TestResult> runAll(Callback cb)
    {
        List<TestResult> results = new ArrayList<>();

        // Register BouncyCastle once for the full run
        Security.addProvider(new BouncyCastleProvider());

        // Group 1: Crypto
        runAndReport(results, cb, this::testCryptoKeyGen);
        runAndReport(results, cb, this::testCryptoCertGen);
        runAndReport(results, cb, this::testCryptoCertVerify);
        runAndReport(results, cb, this::testCryptoCertVerifyWrongCA);
        runAndReport(results, cb, this::testCryptoEcdsaChallenge);

        // Group 2: Certificate Parsing
        runAndReport(results, cb, this::testCertExtractPubKey);
        runAndReport(results, cb, this::testCertExtractOpenID);
        runAndReport(results, cb, this::testCertExtractSignature);
        runAndReport(results, cb, this::testCertExtractTBS);
        runAndReport(results, cb, this::testCertRoundTrip);

        // Group 3: Provisioning (require Context)
        runAndReport(results, cb, this::testProvProvision);
        runAndReport(results, cb, this::testProvExportJson);
        runAndReport(results, cb, this::testProvClear);

        // Group 4: HCE Simulation
        runAndReport(results, cb, this::testHceSelectAid);
        runAndReport(results, cb, this::testHceReadBinary);
        runAndReport(results, cb, this::testHceInternalAuth);

        // Group 5: Negative
        runAndReport(results, cb, this::testNegWrongChallengeSig);
        runAndReport(results, cb, this::testNegTamperedCert);
        runAndReport(results, cb, this::testNegShortCert);

        // Group 6: Spec Compliance
        runAndReport(results, cb, this::testOpenIdFormat);
        runAndReport(results, cb, this::testWiegandEncode);
        runAndReport(results, cb, this::testWiegandParityEven);
        runAndReport(results, cb, this::testWiegandParityOdd);

        if (cb != null) cb.onAllComplete(results);
        return results;
    }

    // =========================================================================
    // Internal dispatch helpers
    // =========================================================================
    private interface TestMethod
    {
        TestResult run();
    }

    private void runAndReport(List<TestResult> results, Callback cb, TestMethod test)
    {
        try
        {
            TestResult result = test.run();
            results.add(result);
            if (cb != null) cb.onTestComplete(result);
        }
        catch (Throwable t)
        {
            // Safety net — individual test methods already catch their own exceptions,
            // but if a test method itself throws unexpectedly we catch it here.
            TestResult errResult = new TestResult(
                    "UNKNOWN", "Engine", "Unexpected engine error",
                    false, false, t.getMessage(), 0L);
            results.add(errResult);
            if (cb != null) cb.onTestComplete(errResult);
        }
    }

    // Helper to record a skipped test
    private static TestResult skip(String id, String group, String name, String reason)
    {
        return new TestResult(id, group, name, false, true, reason, 0L);
    }

    // Helper to record a passed test
    private static TestResult pass(String id, String group, String name, String detail, long ms)
    {
        return new TestResult(id, group, name, true, false, detail, ms);
    }

    // Helper to record a failed test
    private static TestResult fail(String id, String group, String name, String detail, long ms)
    {
        return new TestResult(id, group, name, false, false, detail, ms);
    }

    // =========================================================================
    // Group 1: Crypto Tests
    // =========================================================================

    /** LEAF_KEYGEN: Generate P-256 keypair; verify public key is 65 bytes starting with 0x04. */
    private TestResult testCryptoKeyGen()
    {
        String id    = "LEAF_KEYGEN";
        String group = "Crypto";
        String name  = "P-256 Key Generation";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            KeyPair kp = kpg.generateKeyPair();

            byte[] pub = LeafVerifiedManager.getUncompressedPublicKey(kp.getPublic());
            if (pub == null)
                return fail(id, group, name, "getUncompressedPublicKey returned null", elapsed(t0));
            if (pub.length != 65)
                return fail(id, group, name, "Public key length = " + pub.length + " (expected 65)", elapsed(t0));
            if ((pub[0] & 0xFF) != 0x04)
                return fail(id, group, name, "Public key prefix = 0x" + Integer.toHexString(pub[0] & 0xFF) + " (expected 0x04)", elapsed(t0));

            return pass(id, group, name, "P-256 keypair generated; pub key 65 bytes, prefix=04", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_CERT_GEN: Generate X.509 certificate; verify DER starts with 0x30 and length > 100 bytes. */
    private TestResult testCryptoCertGen()
    {
        String id    = "LEAF_CERT_GEN";
        String group = "Crypto";
        String name  = "X.509 Certificate Generation";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair issuerKP  = generateP256KeyPair();
            KeyPair credKP    = generateP256KeyPair();
            byte[] credPub    = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            String openId     = "123456789012";

            byte[] certDER = LeafVerifiedManager.generateX509Cert(issuerKP, credPub, openId);
            if (certDER == null)
                return fail(id, group, name, "generateX509Cert returned null", elapsed(t0));
            if (certDER.length <= 100)
                return fail(id, group, name, "Cert DER too short: " + certDER.length + " bytes", elapsed(t0));
            if ((certDER[0] & 0xFF) != 0x30)
                return fail(id, group, name, "DER prefix = 0x" + Integer.toHexString(certDER[0] & 0xFF) + " (expected 0x30)", elapsed(t0));

            return pass(id, group, name, "Cert generated; " + certDER.length + " bytes, prefix=30", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_CERT_VERIFY: Generate Root CA + credential cert, verify cert against Root CA public key. */
    private TestResult testCryptoCertVerify()
    {
        String id    = "LEAF_CERT_VERIFY";
        String group = "Crypto";
        String name  = "Certificate Signature Verification";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair rootCA  = generateP256KeyPair();
            KeyPair credKP  = generateP256KeyPair();
            byte[] credPub  = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            byte[] certDER  = LeafVerifiedManager.generateX509Cert(rootCA, credPub, "987654321098");
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            byte[] rootCAPub = LeafVerifiedManager.getUncompressedPublicKey(rootCA.getPublic());
            boolean valid = LeafVerifiedManager.verifyCertificate(certDER, rootCAPub);
            if (!valid)
                return fail(id, group, name, "verifyCertificate returned false for valid cert/CA pair", elapsed(t0));

            return pass(id, group, name, "Certificate verified against correct Root CA", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_CERT_VERIFY_WRONG_CA: Cert signed by CA-A, verify with CA-B's public key — must return false. */
    private TestResult testCryptoCertVerifyWrongCA()
    {
        String id    = "LEAF_CERT_VERIFY_WRONG_CA";
        String group = "Crypto";
        String name  = "Certificate Verification Fails with Wrong CA";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair rootCA_A  = generateP256KeyPair();
            KeyPair rootCA_B  = generateP256KeyPair();
            KeyPair credKP    = generateP256KeyPair();
            byte[] credPub    = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());

            // Cert signed by CA-A
            byte[] certDER = LeafVerifiedManager.generateX509Cert(rootCA_A, credPub, "111111111111");
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            // Verify with CA-B's public key — must fail
            byte[] wrongCAPub = LeafVerifiedManager.getUncompressedPublicKey(rootCA_B.getPublic());
            boolean valid = LeafVerifiedManager.verifyCertificate(certDER, wrongCAPub);
            if (valid)
                return fail(id, group, name, "verifyCertificate returned TRUE for wrong CA — security failure", elapsed(t0));

            return pass(id, group, name, "Correctly rejected cert verified with wrong CA public key", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_ECDSA_CHALLENGE: Generate keypair, sign 32-byte challenge, verify — must return true. */
    private TestResult testCryptoEcdsaChallenge()
    {
        String id    = "LEAF_ECDSA_CHALLENGE";
        String group = "Crypto";
        String name  = "ECDSA Challenge Sign/Verify Round-Trip";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair kp = generateP256KeyPair();
            byte[] pub = LeafVerifiedManager.getUncompressedPublicKey(kp.getPublic());

            // Extract raw private key bytes
            java.security.interfaces.ECPrivateKey ecPriv = (java.security.interfaces.ECPrivateKey) kp.getPrivate();
            byte[] privBytes = LeafVerifiedManager.toBytes32(ecPriv.getS());

            // Generate 32-byte random challenge
            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);

            // Sign
            byte[] sigDER = LeafVerifiedManager.signChallenge(challenge, privBytes);
            if (sigDER == null)
                return fail(id, group, name, "signChallenge returned null", elapsed(t0));

            // Verify
            boolean ok = LeafVerifiedManager.verifyChallenge(challenge, sigDER, pub);
            if (!ok)
                return fail(id, group, name, "verifyChallenge returned false for valid signature", elapsed(t0));

            return pass(id, group, name, "ECDSA-SHA256 sign+verify OK; sig DER " + sigDER.length + " bytes", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    // =========================================================================
    // Group 2: Certificate Parsing Tests
    // =========================================================================

    /** LEAF_EXTRACT_PUBKEY: Generate cert, extract public key — must match original key. */
    private TestResult testCertExtractPubKey()
    {
        String id    = "LEAF_EXTRACT_PUBKEY";
        String group = "Certificate Parsing";
        String name  = "Extract Public Key from Certificate";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair rootCA  = generateP256KeyPair();
            KeyPair credKP  = generateP256KeyPair();
            byte[] credPub  = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            byte[] certDER  = LeafVerifiedManager.generateX509Cert(rootCA, credPub, "222222222222");
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            byte[] extracted = LeafVerifiedManager.extractPublicKeyFromCert(certDER);
            if (extracted == null)
                return fail(id, group, name, "extractPublicKeyFromCert returned null", elapsed(t0));
            if (!Arrays.equals(credPub, extracted))
                return fail(id, group, name,
                        "Extracted key does not match original. Expected len=" + credPub.length
                                + " Got len=" + extracted.length, elapsed(t0));

            return pass(id, group, name, "Extracted 65-byte public key matches original", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_EXTRACT_OPEN_ID: Generate cert with known Open ID, extract — must match. */
    private TestResult testCertExtractOpenID()
    {
        String id    = "LEAF_EXTRACT_OPEN_ID";
        String group = "Certificate Parsing";
        String name  = "Extract Open ID from Certificate";
        long t0 = System.currentTimeMillis();
        try
        {
            String expectedOpenId = "334455667788";
            KeyPair rootCA  = generateP256KeyPair();
            KeyPair credKP  = generateP256KeyPair();
            byte[] credPub  = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            byte[] certDER  = LeafVerifiedManager.generateX509Cert(rootCA, credPub, expectedOpenId);
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            String extracted = LeafVerifiedManager.extractOpenIDFromCert(certDER);
            if (extracted == null)
                return fail(id, group, name, "extractOpenIDFromCert returned null", elapsed(t0));
            if (!expectedOpenId.equals(extracted))
                return fail(id, group, name,
                        "Open ID mismatch. Expected=\"" + expectedOpenId + "\" Got=\"" + extracted + "\"", elapsed(t0));

            return pass(id, group, name, "Open ID \"" + extracted + "\" extracted correctly", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_EXTRACT_SIGNATURE: Generate cert, extract signature — must be 64 bytes (r||s). */
    private TestResult testCertExtractSignature()
    {
        String id    = "LEAF_EXTRACT_SIGNATURE";
        String group = "Certificate Parsing";
        String name  = "Extract Signature (R||S) from Certificate";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair rootCA  = generateP256KeyPair();
            KeyPair credKP  = generateP256KeyPair();
            byte[] credPub  = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            byte[] certDER  = LeafVerifiedManager.generateX509Cert(rootCA, credPub, "556677889900");
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            byte[] rawRS = LeafVerifiedManager.extractSignatureFromCert(certDER);
            if (rawRS == null)
                return fail(id, group, name, "extractSignatureFromCert returned null", elapsed(t0));
            if (rawRS.length != 64)
                return fail(id, group, name, "Signature length = " + rawRS.length + " (expected 64)", elapsed(t0));

            return pass(id, group, name, "Signature extracted; 64-byte R||S form confirmed", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_EXTRACT_TBS: Generate cert, extract TBS — must be non-null and shorter than full cert. */
    private TestResult testCertExtractTBS()
    {
        String id    = "LEAF_EXTRACT_TBS";
        String group = "Certificate Parsing";
        String name  = "Extract TBSCertificate from Certificate";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair rootCA  = generateP256KeyPair();
            KeyPair credKP  = generateP256KeyPair();
            byte[] credPub  = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            byte[] certDER  = LeafVerifiedManager.generateX509Cert(rootCA, credPub, "667788990011");
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            byte[] tbs = LeafVerifiedManager.extractTBSFromCert(certDER);
            if (tbs == null)
                return fail(id, group, name, "extractTBSFromCert returned null", elapsed(t0));
            if (tbs.length == 0)
                return fail(id, group, name, "TBS length is 0", elapsed(t0));
            if (tbs.length >= certDER.length)
                return fail(id, group, name,
                        "TBS (" + tbs.length + " bytes) >= full cert (" + certDER.length + " bytes)", elapsed(t0));

            return pass(id, group, name, "TBS=" + tbs.length + " bytes, full cert=" + certDER.length + " bytes", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /**
     * LEAF_CERT_ROUND_TRIP: Generate cert, extract all fields, rebuild verification —
     * public key matches, Open ID matches, signature verifies.
     */
    private TestResult testCertRoundTrip()
    {
        String id    = "LEAF_CERT_ROUND_TRIP";
        String group = "Certificate Parsing";
        String name  = "Certificate Full Round-Trip";
        long t0 = System.currentTimeMillis();
        try
        {
            String openId   = "778899001122";
            KeyPair rootCA  = generateP256KeyPair();
            KeyPair credKP  = generateP256KeyPair();
            byte[] credPub  = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            byte[] certDER  = LeafVerifiedManager.generateX509Cert(rootCA, credPub, openId);
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            // Extract all fields
            byte[] extractedPub = LeafVerifiedManager.extractPublicKeyFromCert(certDER);
            String extractedId  = LeafVerifiedManager.extractOpenIDFromCert(certDER);
            byte[] extractedSig = LeafVerifiedManager.extractSignatureFromCert(certDER);
            byte[] extractedTBS = LeafVerifiedManager.extractTBSFromCert(certDER);

            if (extractedPub == null) return fail(id, group, name, "extractPublicKeyFromCert returned null", elapsed(t0));
            if (extractedId  == null) return fail(id, group, name, "extractOpenIDFromCert returned null", elapsed(t0));
            if (extractedSig == null) return fail(id, group, name, "extractSignatureFromCert returned null", elapsed(t0));
            if (extractedTBS == null) return fail(id, group, name, "extractTBSFromCert returned null", elapsed(t0));

            if (!Arrays.equals(credPub, extractedPub))
                return fail(id, group, name, "Public key mismatch", elapsed(t0));

            if (!openId.equals(extractedId))
                return fail(id, group, name, "Open ID mismatch: expected=" + openId + " got=" + extractedId, elapsed(t0));

            byte[] rootCAPub = LeafVerifiedManager.getUncompressedPublicKey(rootCA.getPublic());
            boolean sigOk = LeafVerifiedManager.verifyCertificate(certDER, rootCAPub);
            if (!sigOk)
                return fail(id, group, name, "Signature verification failed", elapsed(t0));

            return pass(id, group, name,
                    "Round-trip OK: pubKey match, openId=" + extractedId
                    + ", sig=" + extractedSig.length + "B, tbs=" + extractedTBS.length + "B", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    // =========================================================================
    // Group 3: Provisioning Tests (require Context)
    // =========================================================================

    /** LEAF_PROVISION: Call provisionLeafCredential(context) — verify non-null return, isProvisioned=true. */
    private TestResult testProvProvision()
    {
        String id    = "LEAF_PROVISION";
        String group = "Provisioning";
        String name  = "Provision LEAF Credential";
        if (context == null) return skip(id, group, name, "Context is null — cannot access SharedPreferences");
        long t0 = System.currentTimeMillis();
        try
        {
            // Clear any existing state first to ensure a clean test
            LeafVerifiedManager.clearProvisioning(context);

            String result = LeafVerifiedManager.provisionLeafCredential(context);
            if (result == null)
                return fail(id, group, name, "provisionLeafCredential returned null", elapsed(t0));

            boolean provisioned = LeafVerifiedManager.isProvisioned(context);
            if (!provisioned)
                return fail(id, group, name, "isProvisioned returned false after provisioning", elapsed(t0));

            return pass(id, group, name, result.replace('\n', ' '), elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_EXPORT_JSON: Call buildExportJson(context) — verify valid JSON with rootCAPubKey (130 hex chars). */
    private TestResult testProvExportJson()
    {
        String id    = "LEAF_EXPORT_JSON";
        String group = "Provisioning";
        String name  = "Export Root CA JSON";
        if (context == null) return skip(id, group, name, "Context is null — cannot access SharedPreferences");
        long t0 = System.currentTimeMillis();
        try
        {
            // Ensure provisioned (may have been cleared; provision if needed)
            if (!LeafVerifiedManager.isProvisioned(context))
            {
                String provResult = LeafVerifiedManager.provisionLeafCredential(context);
                if (provResult == null)
                    return fail(id, group, name, "Provisioning failed before export test", elapsed(t0));
            }

            String json = LeafVerifiedManager.buildExportJson(context);
            if (json == null)
                return fail(id, group, name, "buildExportJson returned null", elapsed(t0));
            if (!json.startsWith("{") || !json.endsWith("}"))
                return fail(id, group, name, "JSON missing braces: " + json, elapsed(t0));
            if (!json.contains("rootCAPubKey"))
                return fail(id, group, name, "JSON missing 'rootCAPubKey' field", elapsed(t0));

            // Extract value of rootCAPubKey and check it is 130 hex chars (65 bytes uncompressed)
            int keyStart = json.indexOf("\"rootCAPubKey\":\"") + "\"rootCAPubKey\":\"".length();
            int keyEnd   = json.indexOf("\"", keyStart);
            if (keyStart < 0 || keyEnd < 0 || keyEnd - keyStart != 130)
            {
                String extracted = (keyStart >= 0 && keyEnd > keyStart) ? json.substring(keyStart, keyEnd) : "?";
                return fail(id, group, name,
                        "rootCAPubKey length=" + (keyEnd - keyStart) + " (expected 130). val=" + extracted, elapsed(t0));
            }

            return pass(id, group, name, "JSON valid; rootCAPubKey=" + (keyEnd - keyStart) + " hex chars", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_CLEAR: Call clearProvisioning(context) — verify isProvisioned returns false. */
    private TestResult testProvClear()
    {
        String id    = "LEAF_CLEAR";
        String group = "Provisioning";
        String name  = "Clear LEAF Provisioning";
        if (context == null) return skip(id, group, name, "Context is null — cannot access SharedPreferences");
        long t0 = System.currentTimeMillis();
        try
        {
            // Ensure provisioned before clearing
            if (!LeafVerifiedManager.isProvisioned(context))
            {
                LeafVerifiedManager.provisionLeafCredential(context);
            }

            LeafVerifiedManager.clearProvisioning(context);
            boolean stillProvisioned = LeafVerifiedManager.isProvisioned(context);
            if (stillProvisioned)
                return fail(id, group, name, "isProvisioned returned true after clearProvisioning()", elapsed(t0));

            return pass(id, group, name, "clearProvisioning() cleared all LEAF SharedPreferences", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    // =========================================================================
    // Group 4: HCE APDU Simulation Tests
    // =========================================================================

    /**
     * LEAF_SELECT_AID: Build SELECT APDU for LEAF AID.
     * Expected: 00 A4 04 00 07 D2 76 00 00 85 01 01 00
     */
    private TestResult testHceSelectAid()
    {
        String id    = "LEAF_SELECT_AID";
        String group = "HCE Simulation";
        String name  = "SELECT APDU Format for LEAF AID";
        long t0 = System.currentTimeMillis();
        try
        {
            byte[] aid = LeafVerifiedManager.LEAF_OPEN_APP_AID;
            // CLA=00, INS=A4, P1=04 (by AID), P2=00, Lc=len(AID), AID bytes, Le=00
            byte[] apdu = buildSelectApdu(aid);

            // Expected header: 00 A4 04 00
            if ((apdu[0] & 0xFF) != 0x00) return fail(id, group, name, "CLA != 0x00", elapsed(t0));
            if ((apdu[1] & 0xFF) != 0xA4) return fail(id, group, name, "INS != 0xA4", elapsed(t0));
            if ((apdu[2] & 0xFF) != 0x04) return fail(id, group, name, "P1 != 0x04", elapsed(t0));
            if ((apdu[3] & 0xFF) != 0x00) return fail(id, group, name, "P2 != 0x00", elapsed(t0));
            if ((apdu[4] & 0xFF) != 0x07) return fail(id, group, name, "Lc != 0x07", elapsed(t0));

            // AID bytes: D2 76 00 00 85 01 01
            byte[] expectedAid = { (byte)0xD2, 0x76, 0x00, 0x00, (byte)0x85, 0x01, 0x01 };
            for (int i = 0; i < 7; i++)
            {
                if (apdu[5 + i] != expectedAid[i])
                    return fail(id, group, name, "AID byte[" + i + "] mismatch", elapsed(t0));
            }

            // Le byte
            if ((apdu[12] & 0xFF) != 0x00) return fail(id, group, name, "Le != 0x00", elapsed(t0));

            return pass(id, group, name,
                    "SELECT APDU: " + bytesToHex(apdu), elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /**
     * LEAF_READ_BINARY: Build READ BINARY APDU at offset 0, length 224.
     * Expected: 00 B0 00 00 E0
     */
    private TestResult testHceReadBinary()
    {
        String id    = "LEAF_READ_BINARY";
        String group = "HCE Simulation";
        String name  = "READ BINARY APDU Format";
        long t0 = System.currentTimeMillis();
        try
        {
            int offset = 0;
            int length = 224; // 0xE0

            byte[] apdu = buildReadBinaryApdu(offset, length);

            if ((apdu[0] & 0xFF) != 0x00) return fail(id, group, name, "CLA != 0x00", elapsed(t0));
            if ((apdu[1] & 0xFF) != 0xB0) return fail(id, group, name, "INS != 0xB0", elapsed(t0));
            if ((apdu[2] & 0xFF) != 0x00) return fail(id, group, name, "P1 (offset high) != 0x00", elapsed(t0));
            if ((apdu[3] & 0xFF) != 0x00) return fail(id, group, name, "P2 (offset low) != 0x00", elapsed(t0));
            if ((apdu[4] & 0xFF) != 0xE0) return fail(id, group, name, "Le != 0xE0 (224)", elapsed(t0));

            return pass(id, group, name,
                    "READ BINARY APDU: " + bytesToHex(apdu), elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /**
     * LEAF_INTERNAL_AUTH: Build INTERNAL AUTHENTICATE APDU with 32-byte challenge.
     * Expected format: 00 88 00 00 20 <32 bytes> 00
     */
    private TestResult testHceInternalAuth()
    {
        String id    = "LEAF_INTERNAL_AUTH";
        String group = "HCE Simulation";
        String name  = "INTERNAL AUTHENTICATE APDU Format";
        long t0 = System.currentTimeMillis();
        try
        {
            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);

            byte[] apdu = buildInternalAuthApdu(challenge);

            if (apdu.length != 38)
                return fail(id, group, name, "APDU length = " + apdu.length + " (expected 38)", elapsed(t0));

            if ((apdu[0] & 0xFF) != 0x00) return fail(id, group, name, "CLA != 0x00", elapsed(t0));
            if ((apdu[1] & 0xFF) != 0x88) return fail(id, group, name, "INS != 0x88", elapsed(t0));
            if ((apdu[2] & 0xFF) != 0x00) return fail(id, group, name, "P1 != 0x00", elapsed(t0));
            if ((apdu[3] & 0xFF) != 0x00) return fail(id, group, name, "P2 != 0x00", elapsed(t0));
            if ((apdu[4] & 0xFF) != 0x20) return fail(id, group, name, "Lc != 0x20 (32)", elapsed(t0));

            // Verify challenge bytes are embedded correctly
            for (int i = 0; i < 32; i++)
            {
                if (apdu[5 + i] != challenge[i])
                    return fail(id, group, name, "Challenge byte[" + i + "] mismatch in APDU", elapsed(t0));
            }
            if ((apdu[37] & 0xFF) != 0x00)
                return fail(id, group, name, "Le != 0x00", elapsed(t0));

            return pass(id, group, name,
                    "INTERNAL AUTH APDU: 00 88 00 00 20 <32-byte challenge> 00", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    // =========================================================================
    // Group 5: Negative Tests
    // =========================================================================

    /** LEAF_NEG_WRONG_CHALLENGE_SIG: Sign challenge with key A, verify with key B — must fail. */
    private TestResult testNegWrongChallengeSig()
    {
        String id    = "LEAF_NEG_WRONG_CHALLENGE_SIG";
        String group = "Negative";
        String name  = "Challenge Signature Fails with Wrong Public Key";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair keyA = generateP256KeyPair();
            KeyPair keyB = generateP256KeyPair();

            java.security.interfaces.ECPrivateKey ecPrivA = (java.security.interfaces.ECPrivateKey) keyA.getPrivate();
            byte[] privBytesA = LeafVerifiedManager.toBytes32(ecPrivA.getS());

            byte[] pubB = LeafVerifiedManager.getUncompressedPublicKey(keyB.getPublic());

            byte[] challenge = new byte[32];
            new SecureRandom().nextBytes(challenge);

            // Sign with Key A
            byte[] sigDER = LeafVerifiedManager.signChallenge(challenge, privBytesA);
            if (sigDER == null)
                return fail(id, group, name, "signChallenge returned null", elapsed(t0));

            // Verify with Key B's public key — must fail
            boolean valid = LeafVerifiedManager.verifyChallenge(challenge, sigDER, pubB);
            if (valid)
                return fail(id, group, name, "verifyChallenge returned TRUE with wrong public key — security failure", elapsed(t0));

            return pass(id, group, name, "Correctly rejected: signature from key A does not verify with key B", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_NEG_TAMPERED_CERT: Modify one byte of cert, verify — must fail. */
    private TestResult testNegTamperedCert()
    {
        String id    = "LEAF_NEG_TAMPERED_CERT";
        String group = "Negative";
        String name  = "Tampered Certificate Fails Verification";
        long t0 = System.currentTimeMillis();
        try
        {
            KeyPair rootCA  = generateP256KeyPair();
            KeyPair credKP  = generateP256KeyPair();
            byte[] credPub  = LeafVerifiedManager.getUncompressedPublicKey(credKP.getPublic());
            byte[] certDER  = LeafVerifiedManager.generateX509Cert(rootCA, credPub, "999888777666");
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            // Tamper: flip a byte in the middle of the certificate (in the TBS body area)
            byte[] tampered = Arrays.copyOf(certDER, certDER.length);
            int tamperedIdx = certDER.length / 2;
            tampered[tamperedIdx] ^= (byte) 0xFF;

            byte[] rootCAPub = LeafVerifiedManager.getUncompressedPublicKey(rootCA.getPublic());
            boolean valid = LeafVerifiedManager.verifyCertificate(tampered, rootCAPub);
            if (valid)
                return fail(id, group, name, "Tampered cert passed verification — security failure", elapsed(t0));

            return pass(id, group, name, "Tampered cert (byte " + tamperedIdx + " flipped) correctly rejected", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_NEG_SHORT_CERT: Try to extract fields from a 10-byte buffer — must return null/false gracefully. */
    private TestResult testNegShortCert()
    {
        String id    = "LEAF_NEG_SHORT_CERT";
        String group = "Negative";
        String name  = "Short/Invalid Buffer Handled Gracefully";
        long t0 = System.currentTimeMillis();
        try
        {
            byte[] shortBuf = new byte[10];
            new SecureRandom().nextBytes(shortBuf);

            byte[] pubKey = LeafVerifiedManager.extractPublicKeyFromCert(shortBuf);
            String openId = LeafVerifiedManager.extractOpenIDFromCert(shortBuf);
            byte[] sig    = LeafVerifiedManager.extractSignatureFromCert(shortBuf);
            byte[] tbs    = LeafVerifiedManager.extractTBSFromCert(shortBuf);
            boolean valid = LeafVerifiedManager.verifyCertificate(shortBuf, new byte[65]);

            StringBuilder results = new StringBuilder("10-byte buffer: ");
            results.append("pubKey=").append(pubKey == null ? "null(OK)" : "non-null(FAIL)").append(", ");
            results.append("openId=").append(openId == null ? "null(OK)" : "non-null(FAIL)").append(", ");
            results.append("sig=").append(sig    == null ? "null(OK)" : "non-null(FAIL)").append(", ");
            results.append("tbs=").append(tbs    == null ? "null(OK)" : "non-null(FAIL)").append(", ");
            results.append("verify=").append(!valid ? "false(OK)" : "true(FAIL)");

            boolean allOk = (pubKey == null && openId == null && sig == null && tbs == null && !valid);
            if (!allOk)
                return fail(id, group, name, results.toString(), elapsed(t0));

            return pass(id, group, name, results.toString(), elapsed(t0));
        }
        catch (Exception e)
        {
            // All methods must not throw — any uncaught exception here means they didn't handle gracefully
            return fail(id, group, name, "Unexpected exception thrown: " + e.getClass().getSimpleName() + ": " + e.getMessage(), elapsed(t0));
        }
    }

    // =========================================================================
    // APDU Construction helpers
    // =========================================================================

    /**
     * Build a SELECT (by AID) APDU: 00 A4 04 00 Lc <AID> 00
     */
    private static byte[] buildSelectApdu(byte[] aid)
    {
        // CLA INS P1 P2 Lc <AID> Le
        byte[] apdu = new byte[5 + aid.length + 1];
        apdu[0] = 0x00;           // CLA
        apdu[1] = (byte) 0xA4;   // INS = SELECT
        apdu[2] = 0x04;           // P1 = select by AID
        apdu[3] = 0x00;           // P2
        apdu[4] = (byte) aid.length; // Lc
        System.arraycopy(aid, 0, apdu, 5, aid.length);
        apdu[5 + aid.length] = 0x00; // Le
        return apdu;
    }

    /**
     * Build a READ BINARY APDU: 00 B0 P1 P2 Le
     * P1 = high byte of offset, P2 = low byte, Le = length
     */
    private static byte[] buildReadBinaryApdu(int offset, int length)
    {
        return new byte[] {
                0x00,                          // CLA
                (byte) 0xB0,                   // INS = READ BINARY
                (byte) ((offset >> 8) & 0xFF), // P1 = offset high
                (byte) (offset & 0xFF),        // P2 = offset low
                (byte) (length & 0xFF)         // Le
        };
    }

    /**
     * Build an INTERNAL AUTHENTICATE APDU: 00 88 00 00 20 <32-byte challenge> 00
     */
    private static byte[] buildInternalAuthApdu(byte[] challenge32)
    {
        byte[] apdu = new byte[5 + 32 + 1];
        apdu[0] = 0x00;           // CLA
        apdu[1] = (byte) 0x88;   // INS = INTERNAL AUTHENTICATE
        apdu[2] = 0x00;           // P1
        apdu[3] = 0x00;           // P2
        apdu[4] = 0x20;           // Lc = 32
        System.arraycopy(challenge32, 0, apdu, 5, 32);
        apdu[37] = 0x00;          // Le
        return apdu;
    }

    // =========================================================================
    // Utility helpers
    // =========================================================================

    /** Generate a fresh P-256 keypair using BouncyCastle provider. */
    private static KeyPair generateP256KeyPair() throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
        return kpg.generateKeyPair();
    }

    /** Elapsed time in ms since t0. */
    private static long elapsed(long t0)
    {
        return System.currentTimeMillis() - t0;
    }

    /** Format a byte array as uppercase hex string. */
    private static String bytesToHex(byte[] bytes)
    {
        if (bytes == null) return "null";
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (byte b : bytes)
        {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    // =========================================================================
    // Group 6: Spec Compliance Tests
    // =========================================================================

    /** LEAF_OPEN_ID_FORMAT: Verify Open ID is exactly 12 decimal digits. */
    private TestResult testOpenIdFormat()
    {
        String id    = "LEAF_OPEN_ID_FORMAT";
        String group = "Spec Compliance";
        String name  = "Open ID 12-Digit Numeric Format";
        long t0 = System.currentTimeMillis();
        try
        {
            // Generate a cert and extract the Open ID
            KeyPair rootCA = generateP256KeyPair();
            KeyPair cred   = generateP256KeyPair();
            byte[] credPub = LeafVerifiedManager.getUncompressedPublicKey(cred.getPublic());
            String testId  = "112233445566";
            byte[] certDER = LeafVerifiedManager.generateX509Cert(rootCA, credPub, testId);
            if (certDER == null)
                return fail(id, group, name, "Certificate generation failed", elapsed(t0));

            String extracted = LeafVerifiedManager.extractOpenIDFromCert(certDER);
            if (extracted == null)
                return fail(id, group, name, "Open ID extraction returned null", elapsed(t0));

            // Validate exactly 12 decimal digits
            if (!extracted.matches("\\d{12}"))
                return fail(id, group, name, "Open ID '" + extracted
                        + "' does not match \\d{12}", elapsed(t0));

            // Also test edge cases: verify we correctly get 12 digits from provisioning
            if (extracted.length() != 12)
                return fail(id, group, name, "Open ID length " + extracted.length()
                        + ", expected 12", elapsed(t0));

            return pass(id, group, name, "Open ID '" + extracted
                    + "' is valid 12-digit numeric", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, "Exception: " + e.getMessage(), elapsed(t0));
        }
    }

    /** Delegate to the canonical implementation in LeafVerifiedManager. */
    static byte[] encodeWiegand40(String openId12)
    {
        return LeafVerifiedManager.encodeWiegand40(openId12);
    }

    /** LEAF_WIEGAND_ENCODE: Encode a known Open ID, verify 40-bit (5-byte) output. */
    private TestResult testWiegandEncode()
    {
        String id    = "LEAF_WIEGAND_ENCODE";
        String group = "Spec Compliance";
        String name  = "Wiegand 40-bit Encoding";
        long t0 = System.currentTimeMillis();
        try
        {
            String testOpenId = "100000000001";
            byte[] wiegand = encodeWiegand40(testOpenId);

            if (wiegand == null || wiegand.length != 5)
                return fail(id, group, name, "Expected 5-byte output, got "
                        + (wiegand == null ? "null" : wiegand.length), elapsed(t0));

            // Verify the data bits contain our ID
            long frame = 0;
            for (int i = 0; i < 5; i++)
                frame = (frame << 8) | (wiegand[i] & 0xFF);

            // Extract 38-bit data from bits 1–38 (shift right 1, mask 38 bits)
            long data38 = (frame >> 1) & 0x3FFFFFFFFFL;
            long expected = Long.parseLong(testOpenId);
            if (data38 != (expected & 0x3FFFFFFFFFL))
                return fail(id, group, name, "Data bits mismatch: expected "
                        + expected + ", got " + data38, elapsed(t0));

            return pass(id, group, name, "40-bit Wiegand frame: " + bytesToHex(wiegand), elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, "Exception: " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_WIEGAND_PARITY_EVEN: Verify bit 0 is correct even parity over bits 1–19. */
    private TestResult testWiegandParityEven()
    {
        String id    = "LEAF_WIEGAND_PARITY_EVEN";
        String group = "Spec Compliance";
        String name  = "Wiegand Even Parity (Bit 0)";
        long t0 = System.currentTimeMillis();
        try
        {
            // Test with multiple known IDs
            String[] testIds = { "100000000001", "999999999999", "123456789012", "555555555555" };
            for (String openId : testIds)
            {
                byte[] wiegand = encodeWiegand40(openId);
                long frame = 0;
                for (int i = 0; i < 5; i++)
                    frame = (frame << 8) | (wiegand[i] & 0xFF);

                int bit0 = (int) ((frame >> 39) & 1);
                // Count 1-bits in bits 1–19 (the upper 19 of the 38 data bits)
                long data38 = (frame >> 1) & 0x3FFFFFFFFFL;
                long upper19 = (data38 >> 19) & 0x7FFFFL;
                int ones = Long.bitCount(upper19);
                // Even parity: bit0 + ones must be even
                if ((bit0 + ones) % 2 != 0)
                    return fail(id, group, name, "Even parity failed for ID "
                            + openId + " (bit0=" + bit0 + ", ones=" + ones + ")", elapsed(t0));
            }

            return pass(id, group, name, "Even parity correct for all test IDs", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, "Exception: " + e.getMessage(), elapsed(t0));
        }
    }

    /** LEAF_WIEGAND_PARITY_ODD: Verify bit 39 is correct odd parity over bits 20–38. */
    private TestResult testWiegandParityOdd()
    {
        String id    = "LEAF_WIEGAND_PARITY_ODD";
        String group = "Spec Compliance";
        String name  = "Wiegand Odd Parity (Bit 39)";
        long t0 = System.currentTimeMillis();
        try
        {
            String[] testIds = { "100000000001", "999999999999", "123456789012", "555555555555" };
            for (String openId : testIds)
            {
                byte[] wiegand = encodeWiegand40(openId);
                long frame = 0;
                for (int i = 0; i < 5; i++)
                    frame = (frame << 8) | (wiegand[i] & 0xFF);

                int bit39 = (int) (frame & 1);
                long data38 = (frame >> 1) & 0x3FFFFFFFFFL;
                long lower19 = data38 & 0x7FFFFL;
                int ones = Long.bitCount(lower19);
                // Odd parity: bit39 + ones must be odd
                if ((bit39 + ones) % 2 != 1)
                    return fail(id, group, name, "Odd parity failed for ID "
                            + openId + " (bit39=" + bit39 + ", ones=" + ones + ")", elapsed(t0));
            }

            return pass(id, group, name, "Odd parity correct for all test IDs", elapsed(t0));
        }
        catch (Exception e)
        {
            return fail(id, group, name, "Exception: " + e.getMessage(), elapsed(t0));
        }
    }
}
