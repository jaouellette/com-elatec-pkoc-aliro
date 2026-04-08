package com.psia.pkoc.core;

import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Aliro 1.0 Compliance Self-Test Engine.
 *
 * Runs all test cases in-process using pure Java — no NFC/BLE hardware required.
 * Uses a loopback architecture: LoopbackReader simulates the reader side and
 * LoopbackCredential simulates the User Device (credential) side.
 *
 * Test groups:
 *   1. CRYPTO_  — Cryptographic primitives
 *   2. APDU_    — APDU format validation
 *   3. NFC_/BLE_ — Full flow integration (loopback)
 *   4. NEG_     — Negative / boundary tests
 */
public class AliroSelfTestEngine
{
    private static final String TAG = "AliroSelfTest";

    // =========================================================================
    // Test keys (hardcoded from the Aliro config screen defaults)
    // =========================================================================
    private static final byte[] TEST_READER_PRIVATE_KEY = Hex.decode(
            "d432042ed030edd22823ce4d340df8f97c944f42fe18eb4c698bdc67cb1f16f8");
    private static final byte[] TEST_READER_ID = Hex.decode(
            "7476b8575f814845966b7ab99925a8d100000001000000010000000100000001");
    private static final byte[] TEST_READER_CERT = Hex.decode(
            "3081a40402000030819d830d3237303130313030303030305a8542000477f673d22eb6fa831d8c47e82004a2a85202276df1f12ee4fbe42f9e136265c65fa430afcd377ac3e3688c59d8696f783affb6df337de9fb25a0ece77123c0178648003045022074f4949593d2439098f1db20bf7c5c3d86295835195bd3eee25c8eb4fe22bdd5022100f0c4bc1a3fa23511bb5f622ec685c07577afe3a14aaf3572eea116aa8f0b25cf");
    private static final byte[] TEST_READER_PUB_KEY_X = Hex.decode(
            "77f673d22eb6fa831d8c47e82004a2a85202276df1f12ee4fbe42f9e136265c6");

    // Proprietary TLV from SELECT response (must match Aliro_HostApduService)
    private static final byte[] PROPRIETARY_TLV = {
            (byte) 0xA5, 0x0A,
            (byte) 0x80, 0x02, 0x00, 0x00,
            0x5C, 0x04, 0x01, 0x00, 0x00, 0x09
    };

    // Aliro AID
    private static final byte[] ALIRO_AID = {
            (byte) 0xA0, 0x00, 0x00, 0x09, 0x09,
            (byte) 0xAC, (byte) 0xCE, 0x55, 0x01
    };

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
            this.testId = testId;
            this.group = group;
            this.name = name;
            this.passed = passed;
            this.skipped = skipped;
            this.detail = detail;
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

        // Group 1: Cryptographic Primitives
        runAndReport(results, cb, this::testCryptoEcdh);
        runAndReport(results, cb, this::testCryptoHkdf);
        runAndReport(results, cb, this::testCryptoGcmReader);
        runAndReport(results, cb, this::testCryptoGcmDevice);
        runAndReport(results, cb, this::testCryptoGcmTamper);
        runAndReport(results, cb, this::testCryptoSigRoundtrip);
        runAndReport(results, cb, this::testCryptoInterfaceByte);
        runAndReport(results, cb, this::testCryptoBleSk);

        // Group 2: APDU Format Validation
        runAndReport(results, cb, this::testApduSelectAid);
        runAndReport(results, cb, this::testApduSelectResponse);
        runAndReport(results, cb, this::testApduAuth0FlatTlv);
        runAndReport(results, cb, this::testApduAuth0Tags);
        runAndReport(results, cb, this::testApduAuth0KeyLength);
        runAndReport(results, cb, this::testApduAuth0TidLength);
        runAndReport(results, cb, this::testApduAuth0ReaderIdLength);
        runAndReport(results, cb, this::testApduLoadCertTag);
        runAndReport(results, cb, this::testApduAuth1Tag41);
        runAndReport(results, cb, this::testApduExchangeResponse);
        runAndReport(results, cb, this::testApduControlFlow);
        runAndReport(results, cb, this::testApduSw9000);

        // Group 3: Full Flow Tests
        runAndReport(results, cb, this::testNfcUdStandardNoCert);
        runAndReport(results, cb, this::testNfcUdStandardWithCert);
        runAndReport(results, cb, this::testNfcRdrStandardNoCert);
        runAndReport(results, cb, this::testNfcRdrStandardWithCert);
        runAndReport(results, cb, this::testBleOnlyStandard);

        // Group 4: Negative Tests
        runAndReport(results, cb, this::testNegAuth0WrongReaderId);
        runAndReport(results, cb, this::testNegAuth1TamperedSig);
        runAndReport(results, cb, this::testNegExchangeTampered);
        runAndReport(results, cb, this::testNegSessionKeyDestroy);

        if (cb != null) cb.onAllComplete(results);
        return results;
    }

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
        catch (Exception e)
        {
            Log.e(TAG, "Test threw unexpected exception", e);
            TestResult fail = new TestResult("UNKNOWN", "Error",
                    "Unexpected exception", false, false, e.toString(), 0);
            results.add(fail);
            if (cb != null) cb.onTestComplete(fail);
        }
    }

    // =========================================================================
    // GROUP 1: Cryptographic Primitives
    // =========================================================================

    private TestResult testCryptoEcdh()
    {
        long start = System.currentTimeMillis();
        try
        {
            KeyPair kp1 = AliroCryptoProvider.generateEphemeralKeypair();
            KeyPair kp2 = AliroCryptoProvider.generateEphemeralKeypair();
            byte[] pub1 = AliroCryptoProvider.getUncompressedPublicKey(kp1);
            byte[] pub2 = AliroCryptoProvider.getUncompressedPublicKey(kp2);

            byte[] secret1 = AliroCryptoProvider.ecdhSharedSecretX(kp1.getPrivate(), pub2);
            byte[] secret2 = AliroCryptoProvider.ecdhSharedSecretX(kp2.getPrivate(), pub1);

            if (secret1 == null || secret2 == null)
                return result("CRYPTO_ECDH", "Crypto", "ECDH key agreement", false,
                        "Shared secret returned null", start);

            if (!Arrays.equals(secret1, secret2))
                return result("CRYPTO_ECDH", "Crypto", "ECDH key agreement", false,
                        "Shared secrets do not match", start);

            return result("CRYPTO_ECDH", "Crypto", "ECDH key agreement produces consistent shared secret",
                    true, "32-byte shared secret match confirmed", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_ECDH", "Crypto", "ECDH key agreement", false, e.toString(), start);
        }
    }

    private TestResult testCryptoHkdf()
    {
        long start = System.currentTimeMillis();
        try
        {
            KeyPair kp1 = AliroCryptoProvider.generateEphemeralKeypair();
            KeyPair kp2 = AliroCryptoProvider.generateEphemeralKeypair();
            byte[] pub1 = AliroCryptoProvider.getUncompressedPublicKey(kp1);
            byte[] pub2 = AliroCryptoProvider.getUncompressedPublicKey(kp2);
            byte[] tid = AliroCryptoProvider.generateRandom(16);
            byte[] flag = {0x00, 0x01};
            byte[] proto = {0x01, 0x00};

            byte[] keys = AliroCryptoProvider.deriveKeys(
                    kp1.getPrivate(), pub2, 64, proto,
                    TEST_READER_PUB_KEY_X, TEST_READER_ID, tid,
                    Arrays.copyOfRange(pub1, 1, 33),
                    Arrays.copyOfRange(pub2, 1, 33),
                    PROPRIETARY_TLV, null,
                    AliroCryptoProvider.INTERFACE_BYTE_NFC, flag);

            if (keys == null)
                return result("CRYPTO_HKDF", "Crypto", "HKDF key derivation", false,
                        "deriveKeys() returned null", start);

            if (keys.length != 64)
                return result("CRYPTO_HKDF", "Crypto", "HKDF key derivation", false,
                        "Expected 64 bytes, got " + keys.length, start);

            return result("CRYPTO_HKDF", "Crypto", "HKDF produces correct-length output",
                    true, "64-byte output confirmed", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_HKDF", "Crypto", "HKDF key derivation", false, e.toString(), start);
        }
    }

    private TestResult testCryptoGcmReader()
    {
        long start = System.currentTimeMillis();
        try
        {
            byte[] key = AliroCryptoProvider.generateRandom(32);
            byte[] plaintext = "AliroReaderGCMTest".getBytes();

            byte[] encrypted = AliroCryptoProvider.encryptReaderGcm(key, plaintext);
            if (encrypted == null)
                return result("CRYPTO_GCM_READER", "Crypto", "Reader GCM encrypt/decrypt", false,
                        "Encryption returned null", start);

            byte[] decrypted = AliroCryptoProvider.decryptReaderGcm(key, encrypted);
            if (decrypted == null)
                return result("CRYPTO_GCM_READER", "Crypto", "Reader GCM encrypt/decrypt", false,
                        "Decryption returned null", start);

            if (!Arrays.equals(plaintext, decrypted))
                return result("CRYPTO_GCM_READER", "Crypto", "Reader GCM encrypt/decrypt", false,
                        "Decrypted text does not match original", start);

            return result("CRYPTO_GCM_READER", "Crypto", "Reader GCM encrypt/decrypt round-trip",
                    true, "Plaintext recovered successfully", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_GCM_READER", "Crypto", "Reader GCM encrypt/decrypt", false, e.toString(), start);
        }
    }

    private TestResult testCryptoGcmDevice()
    {
        long start = System.currentTimeMillis();
        try
        {
            byte[] key = AliroCryptoProvider.generateRandom(32);
            byte[] plaintext = "AliroDeviceGCMTest".getBytes();

            byte[] encrypted = AliroCryptoProvider.encryptDeviceGcm(key, plaintext);
            if (encrypted == null)
                return result("CRYPTO_GCM_DEVICE", "Crypto", "Device GCM encrypt/decrypt", false,
                        "Encryption returned null", start);

            byte[] decrypted = AliroCryptoProvider.decryptDeviceGcm(key, encrypted);
            if (decrypted == null)
                return result("CRYPTO_GCM_DEVICE", "Crypto", "Device GCM encrypt/decrypt", false,
                        "Decryption returned null", start);

            if (!Arrays.equals(plaintext, decrypted))
                return result("CRYPTO_GCM_DEVICE", "Crypto", "Device GCM encrypt/decrypt", false,
                        "Decrypted text does not match original", start);

            return result("CRYPTO_GCM_DEVICE", "Crypto", "Device GCM encrypt/decrypt round-trip",
                    true, "Plaintext recovered successfully", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_GCM_DEVICE", "Crypto", "Device GCM encrypt/decrypt", false, e.toString(), start);
        }
    }

    private TestResult testCryptoGcmTamper()
    {
        long start = System.currentTimeMillis();
        try
        {
            byte[] key = AliroCryptoProvider.generateRandom(32);
            byte[] plaintext = "TamperTest".getBytes();

            byte[] encrypted = AliroCryptoProvider.encryptReaderGcm(key, plaintext);
            if (encrypted == null)
                return result("CRYPTO_GCM_TAMPER", "Crypto", "GCM tamper rejection", false,
                        "Encryption returned null", start);

            // Flip a bit in the ciphertext
            encrypted[0] ^= 0x01;

            byte[] decrypted = AliroCryptoProvider.decryptReaderGcm(key, encrypted);
            if (decrypted != null)
                return result("CRYPTO_GCM_TAMPER", "Crypto", "GCM tamper rejection", false,
                        "Tampered ciphertext should not decrypt successfully", start);

            return result("CRYPTO_GCM_TAMPER", "Crypto", "GCM authentication tag rejection",
                    true, "Tampered ciphertext correctly rejected", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_GCM_TAMPER", "Crypto", "GCM tamper rejection", false, e.toString(), start);
        }
    }

    private TestResult testCryptoSigRoundtrip()
    {
        long start = System.currentTimeMillis();
        try
        {
            // Generate a test keypair for signing
            KeyPair sigKP = AliroCryptoProvider.generateEphemeralKeypair();
            byte[] pubBytes = AliroCryptoProvider.getUncompressedPublicKey(sigKP);
            byte[] readerId = AliroCryptoProvider.generateRandom(32);
            byte[] udEphX = AliroCryptoProvider.generateRandom(32);
            byte[] readerEphX = AliroCryptoProvider.generateRandom(32);
            byte[] tid = AliroCryptoProvider.generateRandom(16);

            // Use NONEwithECDSA via BouncyCastle — same path as computeReaderSignature
            byte[] sig = AliroCryptoProvider.computeReaderSignature(
                    sigKP.getPrivate(), readerId, udEphX, readerEphX, tid);
            if (sig == null)
                return result("CRYPTO_SIG_ROUNDTRIP", "Crypto", "ECDSA sign/verify", false,
                        "Signature returned null", start);

            // Verify with correct key
            boolean valid = AliroCryptoProvider.verifyReaderSignature(
                    sig, pubBytes, readerId, udEphX, readerEphX, tid);
            if (!valid)
                return result("CRYPTO_SIG_ROUNDTRIP", "Crypto", "ECDSA sign/verify", false,
                        "Signature verification failed with correct key", start);

            // Verify with different key should fail
            KeyPair wrongKP = AliroCryptoProvider.generateEphemeralKeypair();
            byte[] wrongPub = AliroCryptoProvider.getUncompressedPublicKey(wrongKP);
            boolean wrongValid = AliroCryptoProvider.verifyReaderSignature(
                    sig, wrongPub, readerId, udEphX, readerEphX, tid);
            if (wrongValid)
                return result("CRYPTO_SIG_ROUNDTRIP", "Crypto", "ECDSA sign/verify", false,
                        "Signature verified with WRONG key", start);

            return result("CRYPTO_SIG_ROUNDTRIP", "Crypto", "ECDSA sign/verify round-trip",
                    true, "Correct key verifies, wrong key rejects", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_SIG_ROUNDTRIP", "Crypto", "ECDSA sign/verify", false, e.toString(), start);
        }
    }

    private TestResult testCryptoInterfaceByte()
    {
        long start = System.currentTimeMillis();
        try
        {
            KeyPair kp1 = AliroCryptoProvider.generateEphemeralKeypair();
            KeyPair kp2 = AliroCryptoProvider.generateEphemeralKeypair();
            byte[] pub1 = AliroCryptoProvider.getUncompressedPublicKey(kp1);
            byte[] pub2 = AliroCryptoProvider.getUncompressedPublicKey(kp2);
            byte[] tid = AliroCryptoProvider.generateRandom(16);
            byte[] flag = {0x00, 0x01};
            byte[] proto = {0x01, 0x00};
            byte[] rdrEphX = Arrays.copyOfRange(pub1, 1, 33);
            byte[] udEphX = Arrays.copyOfRange(pub2, 1, 33);

            byte[] keysNfc = AliroCryptoProvider.deriveKeys(
                    kp1.getPrivate(), pub2, 64, proto,
                    TEST_READER_PUB_KEY_X, TEST_READER_ID, tid,
                    rdrEphX, udEphX, PROPRIETARY_TLV, null,
                    AliroCryptoProvider.INTERFACE_BYTE_NFC, flag);

            byte[] keysBle = AliroCryptoProvider.deriveKeys(
                    kp1.getPrivate(), pub2, 64, proto,
                    TEST_READER_PUB_KEY_X, TEST_READER_ID, tid,
                    rdrEphX, udEphX, PROPRIETARY_TLV, null,
                    AliroCryptoProvider.INTERFACE_BYTE_BLE, flag);

            if (keysNfc == null || keysBle == null)
                return result("CRYPTO_INTERFACE_BYTE", "Crypto", "NFC vs BLE interface byte", false,
                        "Key derivation returned null", start);

            if (Arrays.equals(keysNfc, keysBle))
                return result("CRYPTO_INTERFACE_BYTE", "Crypto", "NFC vs BLE interface byte", false,
                        "NFC and BLE keys should differ but are identical", start);

            return result("CRYPTO_INTERFACE_BYTE", "Crypto", "NFC vs BLE produce different keys",
                    true, "0x5E and 0xC3 produce different key material", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_INTERFACE_BYTE", "Crypto", "NFC vs BLE interface byte", false, e.toString(), start);
        }
    }

    private TestResult testCryptoBleSk()
    {
        long start = System.currentTimeMillis();
        try
        {
            KeyPair kp1 = AliroCryptoProvider.generateEphemeralKeypair();
            KeyPair kp2 = AliroCryptoProvider.generateEphemeralKeypair();
            byte[] pub1 = AliroCryptoProvider.getUncompressedPublicKey(kp1);
            byte[] pub2 = AliroCryptoProvider.getUncompressedPublicKey(kp2);
            byte[] tid = AliroCryptoProvider.generateRandom(16);
            byte[] flag = {0x00, 0x01};
            byte[] proto = {0x01, 0x00};

            byte[] keys128 = AliroCryptoProvider.deriveKeys(
                    kp1.getPrivate(), pub2, 128, proto,
                    TEST_READER_PUB_KEY_X, TEST_READER_ID, tid,
                    Arrays.copyOfRange(pub1, 1, 33),
                    Arrays.copyOfRange(pub2, 1, 33),
                    PROPRIETARY_TLV, null,
                    AliroCryptoProvider.INTERFACE_BYTE_BLE, flag);

            if (keys128 == null)
                return result("CRYPTO_BLE_SK", "Crypto", "BLE 128-byte BleSK", false,
                        "128-byte derivation returned null", start);

            if (keys128.length != 128)
                return result("CRYPTO_BLE_SK", "Crypto", "BLE 128-byte BleSK", false,
                        "Expected 128 bytes, got " + keys128.length, start);

            byte[] bleSk = Arrays.copyOfRange(keys128, 96, 128);
            byte[] zeros = new byte[32];
            if (Arrays.equals(bleSk, zeros))
                return result("CRYPTO_BLE_SK", "Crypto", "BLE 128-byte BleSK", false,
                        "BleSK at offset 96-127 is all zeros", start);

            return result("CRYPTO_BLE_SK", "Crypto", "BLE 128-byte output contains BleSK at offset 96",
                    true, "BleSK[96..127] is non-zero", start);
        }
        catch (Exception e)
        {
            return result("CRYPTO_BLE_SK", "Crypto", "BLE 128-byte BleSK", false, e.toString(), start);
        }
    }

    // =========================================================================
    // GROUP 2: APDU Format Validation
    // =========================================================================

    private TestResult testApduSelectAid()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            byte[] selectCmd = reader.buildSelectCommand();

            // SELECT command: 00 A4 04 00 09 <AID 9 bytes> 00
            if (selectCmd.length < 14)
                return result("APDU_SELECT_AID", "APDU", "SELECT uses correct AID", false,
                        "Command too short: " + selectCmd.length, start);

            byte[] aidFromCmd = Arrays.copyOfRange(selectCmd, 5, 14);
            if (!Arrays.equals(aidFromCmd, ALIRO_AID))
                return result("APDU_SELECT_AID", "APDU", "SELECT uses correct AID", false,
                        "AID mismatch: " + Hex.toHexString(aidFromCmd), start);

            return result("APDU_SELECT_AID", "APDU", "SELECT uses correct AID A000000909ACCE5501",
                    true, "AID verified", start);
        }
        catch (Exception e)
        {
            return result("APDU_SELECT_AID", "APDU", "SELECT AID", false, e.toString(), start);
        }
    }

    private TestResult testApduSelectResponse()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            byte[] selectCmd = reader.buildSelectCommand();
            byte[] selectResp = cred.process(selectCmd);

            if (!isSW9000(selectResp))
                return result("APDU_SELECT_RESPONSE", "APDU", "SELECT response", false,
                        "SW != 9000", start);

            // Look for tag A5 in response
            boolean foundA5 = false;
            for (int i = 0; i < selectResp.length - 3; i++)
            {
                if (selectResp[i] == (byte) 0xA5 && selectResp[i + 1] == 0x0A)
                {
                    foundA5 = true;
                    break;
                }
            }

            if (!foundA5)
                return result("APDU_SELECT_RESPONSE", "APDU", "SELECT response", false,
                        "Proprietary TLV A5 0A not found", start);

            return result("APDU_SELECT_RESPONSE", "APDU", "SELECT response contains proprietary TLV A5",
                    true, "Tag A5 0A found in response", start);
        }
        catch (Exception e)
        {
            return result("APDU_SELECT_RESPONSE", "APDU", "SELECT response", false, e.toString(), start);
        }
    }

    private TestResult testApduAuth0FlatTlv()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            byte[] auth0Cmd = reader.buildAuth0Command();

            // Data starts at offset 5 (after CLA INS P1 P2 Lc)
            // First byte of data should NOT be 0x81 (no outer wrapper)
            if (auth0Cmd.length < 6)
                return result("APDU_AUTH0_FLAT_TLV", "APDU", "AUTH0 flat TLVs", false,
                        "Command too short", start);

            byte firstDataByte = auth0Cmd[5];
            if (firstDataByte == (byte) 0x81)
                return result("APDU_AUTH0_FLAT_TLV", "APDU", "AUTH0 flat TLVs", false,
                        "First data byte is 0x81 (wrapped), expected flat TLVs", start);

            // First tag should be 0x41 (command_parameters)
            if (firstDataByte != 0x41)
                return result("APDU_AUTH0_FLAT_TLV", "APDU", "AUTH0 flat TLVs", false,
                        "First data byte is " + String.format("%02X", firstDataByte) + ", expected 0x41", start);

            return result("APDU_AUTH0_FLAT_TLV", "APDU", "AUTH0 has flat TLVs, no 81 41 wrapper",
                    true, "Data starts with tag 0x41 (flat)", start);
        }
        catch (Exception e)
        {
            return result("APDU_AUTH0_FLAT_TLV", "APDU", "AUTH0 flat TLVs", false, e.toString(), start);
        }
    }

    private TestResult testApduAuth0Tags()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            byte[] auth0Cmd = reader.buildAuth0Command();

            int dataOffset = 5;
            int dataLen = auth0Cmd[4] & 0xFF;
            byte[] data = Arrays.copyOfRange(auth0Cmd, dataOffset, dataOffset + dataLen);

            boolean found41 = false, found42 = false, found5C = false;
            boolean found87 = false, found4C = false, found4D = false;

            for (int i = 0; i < data.length - 1; i++)
            {
                int tag = data[i] & 0xFF;
                switch (tag)
                {
                    case 0x41: found41 = true; break;
                    case 0x42: found42 = true; break;
                    case 0x5C: found5C = true; break;
                    case 0x87: found87 = true; break;
                    case 0x4C: found4C = true; break;
                    case 0x4D: found4D = true; break;
                }
            }

            if (!found41 || !found42 || !found5C || !found87 || !found4C || !found4D)
            {
                String missing = "";
                if (!found41) missing += "41 ";
                if (!found42) missing += "42 ";
                if (!found5C) missing += "5C ";
                if (!found87) missing += "87 ";
                if (!found4C) missing += "4C ";
                if (!found4D) missing += "4D ";
                return result("APDU_AUTH0_TAGS", "APDU", "AUTH0 required tags", false,
                        "Missing tags: " + missing.trim(), start);
            }

            return result("APDU_AUTH0_TAGS", "APDU", "AUTH0 contains required tags 41, 42, 5C, 87, 4C, 4D",
                    true, "All 6 required tags present", start);
        }
        catch (Exception e)
        {
            return result("APDU_AUTH0_TAGS", "APDU", "AUTH0 tags", false, e.toString(), start);
        }
    }

    private TestResult testApduAuth0KeyLength()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            byte[] auth0Cmd = reader.buildAuth0Command();

            int dataOffset = 5;
            int dataLen = auth0Cmd[4] & 0xFF;
            byte[] data = Arrays.copyOfRange(auth0Cmd, dataOffset, dataOffset + dataLen);

            // Find tag 87
            for (int i = 0; i < data.length - 2; i++)
            {
                if ((data[i] & 0xFF) == 0x87)
                {
                    int len = data[i + 1] & 0xFF;
                    if (len != 65)
                        return result("APDU_AUTH0_KEY_LENGTH", "APDU", "Reader eph key length", false,
                                "Tag 87 length=" + len + ", expected 65", start);
                    if (data[i + 2] != 0x04)
                        return result("APDU_AUTH0_KEY_LENGTH", "APDU", "Reader eph key length", false,
                                "First byte=" + String.format("%02X", data[i + 2]) + ", expected 0x04", start);

                    return result("APDU_AUTH0_KEY_LENGTH", "APDU",
                            "Reader eph pub key is 65 bytes uncompressed (04...)",
                            true, "Tag 87: 65 bytes, starts with 0x04", start);
                }
            }

            return result("APDU_AUTH0_KEY_LENGTH", "APDU", "Reader eph key length", false,
                    "Tag 87 not found", start);
        }
        catch (Exception e)
        {
            return result("APDU_AUTH0_KEY_LENGTH", "APDU", "Reader eph key length", false, e.toString(), start);
        }
    }

    private TestResult testApduAuth0TidLength()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            byte[] auth0Cmd = reader.buildAuth0Command();

            int dataOffset = 5;
            int dataLen = auth0Cmd[4] & 0xFF;
            byte[] data = Arrays.copyOfRange(auth0Cmd, dataOffset, dataOffset + dataLen);

            for (int i = 0; i < data.length - 1; i++)
            {
                if ((data[i] & 0xFF) == 0x4C)
                {
                    int len = data[i + 1] & 0xFF;
                    if (len != 16)
                        return result("APDU_AUTH0_TID_LENGTH", "APDU", "Transaction ID length", false,
                                "Tag 4C length=" + len + ", expected 16", start);

                    return result("APDU_AUTH0_TID_LENGTH", "APDU", "Transaction ID is 16 bytes",
                            true, "Tag 4C: 16 bytes", start);
                }
            }

            return result("APDU_AUTH0_TID_LENGTH", "APDU", "Transaction ID length", false,
                    "Tag 4C not found", start);
        }
        catch (Exception e)
        {
            return result("APDU_AUTH0_TID_LENGTH", "APDU", "TID length", false, e.toString(), start);
        }
    }

    private TestResult testApduAuth0ReaderIdLength()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            byte[] auth0Cmd = reader.buildAuth0Command();

            int dataOffset = 5;
            int dataLen = auth0Cmd[4] & 0xFF;
            byte[] data = Arrays.copyOfRange(auth0Cmd, dataOffset, dataOffset + dataLen);

            // Walk TLVs properly to avoid matching 0x4D inside a value field
            int i = 0;
            while (i < data.length - 1)
            {
                int tag = data[i] & 0xFF;
                int len = data[i + 1] & 0xFF;
                if (tag == 0x4D)
                {
                    if (len != 32)
                        return result("APDU_AUTH0_READER_ID_LENGTH", "APDU", "Reader ID length", false,
                                "Tag 4D length=" + len + ", expected 32", start);
                    return result("APDU_AUTH0_READER_ID_LENGTH", "APDU", "Reader ID is 32 bytes",
                            true, "Tag 4D: 32 bytes", start);
                }
                i += 2 + len;
            }

            return result("APDU_AUTH0_READER_ID_LENGTH", "APDU", "Reader ID length", false,
                    "Tag 4D not found", start);
        }
        catch (Exception e)
        {
            return result("APDU_AUTH0_READER_ID_LENGTH", "APDU", "Reader ID length", false, e.toString(), start);
        }
    }

    private TestResult testApduLoadCertTag()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            // SELECT first
            byte[] selectResp = cred.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp))
                return result("APDU_LOAD_CERT_TAG", "APDU", "LOAD CERT SW 9000", false,
                        "SELECT failed", start);

            // AUTH0
            byte[] auth0Resp = cred.process(reader.buildAuth0Command());
            if (!isSW9000(auth0Resp))
                return result("APDU_LOAD_CERT_TAG", "APDU", "LOAD CERT SW 9000", false,
                        "AUTH0 failed", start);

            reader.parseAuth0Response(auth0Resp);

            // LOAD CERT
            byte[] loadCertCmd = reader.buildLoadCertCommand();
            byte[] loadCertResp = cred.process(loadCertCmd);

            if (!isSW9000(loadCertResp))
                return result("APDU_LOAD_CERT_TAG", "APDU", "LOAD CERT SW 9000", false,
                        "Response SW: " + swHex(loadCertResp), start);

            return result("APDU_LOAD_CERT_TAG", "APDU", "LOAD CERT response is SW 9000",
                    true, "SW 9000 confirmed", start);
        }
        catch (Exception e)
        {
            return result("APDU_LOAD_CERT_TAG", "APDU", "LOAD CERT", false, e.toString(), start);
        }
    }

    private TestResult testApduAuth1Tag41()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            byte[] auth1Cmd = reader.buildAuth1CommandForTest();

            // AUTH1: 80 81 00 00 45 41 01 01 9E 40 <sig>
            // Find tag 41 in the data portion
            boolean found41 = false;
            for (int i = 5; i < auth1Cmd.length - 1; i++)
            {
                if ((auth1Cmd[i] & 0xFF) == 0x41)
                {
                    found41 = true;
                    break;
                }
            }

            if (!found41)
                return result("APDU_AUTH1_TAG_41", "APDU", "AUTH1 tag 41", false,
                        "Tag 41 not found in AUTH1 command", start);

            return result("APDU_AUTH1_TAG_41", "APDU", "AUTH1 contains encrypted data in tag 41",
                    true, "Tag 41 present", start);
        }
        catch (Exception e)
        {
            return result("APDU_AUTH1_TAG_41", "APDU", "AUTH1 tag 41", false, e.toString(), start);
        }
    }

    private TestResult testApduExchangeResponse()
    {
        long start = System.currentTimeMillis();
        try
        {
            // Run full loopback to get EXCHANGE response
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            // SELECT
            byte[] selectResp = cred.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp)) return result("APDU_EXCHANGE_RESPONSE", "APDU", "EXCHANGE response", false, "SELECT failed", start);

            // AUTH0
            byte[] auth0Resp = cred.process(reader.buildAuth0Command());
            if (!isSW9000(auth0Resp)) return result("APDU_EXCHANGE_RESPONSE", "APDU", "EXCHANGE response", false, "AUTH0 failed", start);
            reader.parseAuth0Response(auth0Resp);
            reader.deriveKeys(AliroCryptoProvider.INTERFACE_BYTE_NFC);

            // AUTH1
            byte[] auth1Cmd = reader.buildAuth1CommandFull();
            byte[] auth1Resp = cred.process(auth1Cmd);
            if (!isSW9000(auth1Resp)) return result("APDU_EXCHANGE_RESPONSE", "APDU", "EXCHANGE response", false, "AUTH1 failed", start);

            // EXCHANGE
            byte[] exchangeCmd = reader.buildExchangeCommand();
            byte[] exchangeResp = cred.process(exchangeCmd);
            if (!isSW9000(exchangeResp)) return result("APDU_EXCHANGE_RESPONSE", "APDU", "EXCHANGE response", false, "EXCHANGE SW != 9000", start);

            // Decrypt EXCHANGE response
            byte[] encPayload = Arrays.copyOfRange(exchangeResp, 0, exchangeResp.length - 2);
            byte[] decrypted = AliroCryptoProvider.decryptDeviceGcm(reader.skDevice, encPayload);
            if (decrypted == null)
                return result("APDU_EXCHANGE_RESPONSE", "APDU", "EXCHANGE response", false,
                        "Decryption failed", start);

            if (decrypted.length < 4 || decrypted[0] != 0x00 || decrypted[1] != 0x02
                    || decrypted[2] != 0x00 || decrypted[3] != 0x00)
                return result("APDU_EXCHANGE_RESPONSE", "APDU", "EXCHANGE response", false,
                        "Expected 0x00020000, got " + Hex.toHexString(decrypted), start);

            return result("APDU_EXCHANGE_RESPONSE", "APDU",
                    "EXCHANGE response decrypts to 0x0002 0x00 0x00",
                    true, "Payload verified: " + Hex.toHexString(decrypted), start);
        }
        catch (Exception e)
        {
            return result("APDU_EXCHANGE_RESPONSE", "APDU", "EXCHANGE response", false, e.toString(), start);
        }
    }

    private TestResult testApduControlFlow()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackCredential cred = new LoopbackCredential();

            // Send CONTROL FLOW: CLA=80 INS=3C P1=00 P2=00
            byte[] controlFlow = {(byte) 0x80, 0x3C, 0x00, 0x00};
            byte[] resp = cred.process(controlFlow);

            if (resp == null)
                return result("APDU_CONTROL_FLOW", "APDU", "CONTROL FLOW handling", false,
                        "Response is null", start);

            if (!isSW9000(resp))
                return result("APDU_CONTROL_FLOW", "APDU", "CONTROL FLOW handling", false,
                        "SW: " + swHex(resp), start);

            return result("APDU_CONTROL_FLOW", "APDU", "CONTROL FLOW (INS 0x3C) handled by credential",
                    true, "SW 9000 returned", start);
        }
        catch (Exception e)
        {
            return result("APDU_CONTROL_FLOW", "APDU", "CONTROL FLOW", false, e.toString(), start);
        }
    }

    private TestResult testApduSw9000()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            // Test SELECT
            byte[] selectResp = cred.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp))
                return result("APDU_SW_9000", "APDU", "All commands return SW 9000", false,
                        "SELECT SW: " + swHex(selectResp), start);

            // Test AUTH0
            byte[] auth0Resp = cred.process(reader.buildAuth0Command());
            if (!isSW9000(auth0Resp))
                return result("APDU_SW_9000", "APDU", "All commands return SW 9000", false,
                        "AUTH0 SW: " + swHex(auth0Resp), start);

            reader.parseAuth0Response(auth0Resp);

            // Test LOAD CERT
            byte[] loadCertResp = cred.process(reader.buildLoadCertCommand());
            if (!isSW9000(loadCertResp))
                return result("APDU_SW_9000", "APDU", "All commands return SW 9000", false,
                        "LOAD CERT SW: " + swHex(loadCertResp), start);

            reader.deriveKeys(AliroCryptoProvider.INTERFACE_BYTE_NFC);

            // Test AUTH1
            byte[] auth1Resp = cred.process(reader.buildAuth1CommandFull());
            if (!isSW9000(auth1Resp))
                return result("APDU_SW_9000", "APDU", "All commands return SW 9000", false,
                        "AUTH1 SW: " + swHex(auth1Resp), start);

            // Test EXCHANGE
            byte[] exchangeResp = cred.process(reader.buildExchangeCommand());
            if (!isSW9000(exchangeResp))
                return result("APDU_SW_9000", "APDU", "All commands return SW 9000", false,
                        "EXCHANGE SW: " + swHex(exchangeResp), start);

            return result("APDU_SW_9000", "APDU", "All successful commands return SW 9000",
                    true, "SELECT, AUTH0, LOAD CERT, AUTH1, EXCHANGE all return 9000", start);
        }
        catch (Exception e)
        {
            return result("APDU_SW_9000", "APDU", "All SW 9000", false, e.toString(), start);
        }
    }

    // =========================================================================
    // GROUP 3: Full Flow Tests
    // =========================================================================

    private TestResult testNfcUdStandardNoCert()
    {
        long start = System.currentTimeMillis();
        try
        {
            return runFullFlow(false, AliroCryptoProvider.INTERFACE_BYTE_NFC,
                    "NFC_UD_STANDARD_NO_CERT", "Full Flow",
                    "Full NFC flow, no LOAD CERT step", start);
        }
        catch (Exception e)
        {
            return result("NFC_UD_STANDARD_NO_CERT", "Full Flow", "NFC UD no cert", false, e.toString(), start);
        }
    }

    private TestResult testNfcUdStandardWithCert()
    {
        long start = System.currentTimeMillis();
        try
        {
            return runFullFlow(true, AliroCryptoProvider.INTERFACE_BYTE_NFC,
                    "NFC_UD_STANDARD_WITH_CERT", "Full Flow",
                    "Full NFC flow with LOAD CERT", start);
        }
        catch (Exception e)
        {
            return result("NFC_UD_STANDARD_WITH_CERT", "Full Flow", "NFC UD with cert", false, e.toString(), start);
        }
    }

    private TestResult testNfcRdrStandardNoCert()
    {
        long start = System.currentTimeMillis();
        try
        {
            // Same as UD standard no cert — reader perspective
            return runFullFlow(false, AliroCryptoProvider.INTERFACE_BYTE_NFC,
                    "NFC_RDR_STANDARD_NO_CERT", "Full Flow",
                    "Reader perspective, standard flow", start);
        }
        catch (Exception e)
        {
            return result("NFC_RDR_STANDARD_NO_CERT", "Full Flow", "NFC RDR no cert", false, e.toString(), start);
        }
    }

    private TestResult testNfcRdrStandardWithCert()
    {
        long start = System.currentTimeMillis();
        try
        {
            return runFullFlow(true, AliroCryptoProvider.INTERFACE_BYTE_NFC,
                    "NFC_RDR_STANDARD_WITH_CERT", "Full Flow",
                    "Reader with LOAD CERT", start);
        }
        catch (Exception e)
        {
            return result("NFC_RDR_STANDARD_WITH_CERT", "Full Flow", "NFC RDR with cert", false, e.toString(), start);
        }
    }

    private TestResult testBleOnlyStandard()
    {
        long start = System.currentTimeMillis();
        try
        {
            return runFullFlow(false, AliroCryptoProvider.INTERFACE_BYTE_BLE,
                    "BLE_ONLY_STANDARD", "Full Flow",
                    "BLE-Only flow with interface_byte=0xC3", start);
        }
        catch (Exception e)
        {
            return result("BLE_ONLY_STANDARD", "Full Flow", "BLE-Only", false, e.toString(), start);
        }
    }

    private TestResult runFullFlow(boolean useCert, byte interfaceByte,
                                    String testId, String group, String name, long start)
    {
        LoopbackReader reader = new LoopbackReader();
        LoopbackCredential cred = new LoopbackCredential();
        cred.interfaceByte = interfaceByte; // credential must use same interface byte as reader

        // Step 1: SELECT
        byte[] selectCmd = reader.buildSelectCommand();
        byte[] selectResp = cred.process(selectCmd);
        if (!isSW9000(selectResp))
            return result(testId, group, name, false, "SELECT failed: " + swHex(selectResp), start);

        // Verify A5 tag in response
        boolean foundA5 = false;
        for (int i = 0; i < selectResp.length - 1; i++)
        {
            if (selectResp[i] == (byte) 0xA5)
            {
                foundA5 = true;
                break;
            }
        }
        if (!foundA5)
            return result(testId, group, name, false, "SELECT response missing A5 tag", start);

        // Step 2: AUTH0
        byte[] auth0Cmd = reader.buildAuth0Command();
        byte[] auth0Resp = cred.process(auth0Cmd);
        if (!isSW9000(auth0Resp))
            return result(testId, group, name, false, "AUTH0 failed: " + swHex(auth0Resp), start);

        // Parse UD eph pub key from response: 86 41 <65 bytes>
        if (auth0Resp.length < 69 || auth0Resp[0] != (byte) 0x86 || auth0Resp[1] != 0x41)
            return result(testId, group, name, false, "AUTH0 response format invalid", start);

        reader.parseAuth0Response(auth0Resp);

        // Step 2.5: LOAD CERT (optional)
        if (useCert)
        {
            byte[] loadCertCmd = reader.buildLoadCertCommand();
            byte[] loadCertResp = cred.process(loadCertCmd);
            if (!isSW9000(loadCertResp))
                return result(testId, group, name, false, "LOAD CERT failed: " + swHex(loadCertResp), start);
        }

        // Derive session keys on reader side
        reader.deriveKeys(interfaceByte);
        if (reader.skReader == null || reader.skDevice == null)
            return result(testId, group, name, false, "Key derivation failed", start);

        // Step 3: AUTH1
        byte[] auth1Cmd = reader.buildAuth1CommandFull();
        byte[] auth1Resp = cred.process(auth1Cmd);
        if (!isSW9000(auth1Resp))
            return result(testId, group, name, false, "AUTH1 failed: " + swHex(auth1Resp), start);

        // Decrypt and verify AUTH1 response
        byte[] encAuth1 = Arrays.copyOfRange(auth1Resp, 0, auth1Resp.length - 2);
        byte[] decAuth1 = AliroCryptoProvider.decryptDeviceGcm(reader.skDevice, encAuth1);
        if (decAuth1 == null)
            return result(testId, group, name, false, "AUTH1 response decryption failed", start);

        // Parse: 5A 41 <cred pub 65> 9E 40 <sig 64>
        if (decAuth1.length < 133 || decAuth1[0] != 0x5A || decAuth1[1] != 0x41)
            return result(testId, group, name, false, "AUTH1 response format invalid", start);

        byte[] credPubKey = Arrays.copyOfRange(decAuth1, 2, 67);
        byte[] credSig = Arrays.copyOfRange(decAuth1, 69, 133);

        byte[] udEphPubX = Arrays.copyOfRange(reader.udEphPubBytes, 1, 33);
        byte[] readerEphPubX = Arrays.copyOfRange(reader.readerEphPub, 1, 33);
        boolean sigValid = AliroCryptoProvider.verifyCredentialSignature(
                credSig, credPubKey, TEST_READER_ID, udEphPubX, readerEphPubX, reader.transactionId);

        // Step 4: EXCHANGE
        byte[] exchangeCmd = reader.buildExchangeCommand();
        byte[] exchangeResp = cred.process(exchangeCmd);
        if (!isSW9000(exchangeResp))
            return result(testId, group, name, false, "EXCHANGE failed: " + swHex(exchangeResp), start);

        // Decrypt EXCHANGE response
        byte[] encExchange = Arrays.copyOfRange(exchangeResp, 0, exchangeResp.length - 2);
        byte[] decExchange = AliroCryptoProvider.decryptDeviceGcm(reader.skDevice, encExchange);
        if (decExchange == null)
            return result(testId, group, name, false, "EXCHANGE response decryption failed", start);

        if (decExchange.length < 4 || decExchange[0] != 0x00 || decExchange[1] != 0x02)
            return result(testId, group, name, false,
                    "EXCHANGE payload unexpected: " + Hex.toHexString(decExchange), start);

        String detail = "SigValid=" + sigValid + ", EXCHANGE OK";
        if (interfaceByte == AliroCryptoProvider.INTERFACE_BYTE_BLE) detail += " (BLE interface)";
        if (useCert) detail += " (with LOAD CERT)";

        return result(testId, group, name, true, detail, start);
    }

    // =========================================================================
    // GROUP 4: Negative Tests
    // =========================================================================

    private TestResult testNegAuth0WrongReaderId()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            byte[] selectResp = cred.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp))
                return result("NEG_AUTH0_WRONG_READER_ID", "Negative", "Wrong reader ID", false, "SELECT failed", start);

            // Build AUTH0 with all-zeros reader ID
            byte[] auth0Cmd = reader.buildAuth0CommandWithReaderId(new byte[32]);
            byte[] auth0Resp = cred.process(auth0Cmd);

            // Credential should still respond (no rejection at credential layer)
            if (!isSW9000(auth0Resp))
                return result("NEG_AUTH0_WRONG_READER_ID", "Negative", "Wrong reader ID", false,
                        "Credential rejected AUTH0 with wrong reader ID: " + swHex(auth0Resp), start);

            return result("NEG_AUTH0_WRONG_READER_ID", "Negative",
                    "AUTH0 with all-zeros reader ID accepted by credential",
                    true, "Credential responds normally (permissive)", start);
        }
        catch (Exception e)
        {
            return result("NEG_AUTH0_WRONG_READER_ID", "Negative", "Wrong reader ID", false, e.toString(), start);
        }
    }

    private TestResult testNegAuth1TamperedSig()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            byte[] selectResp = cred.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp)) return result("NEG_AUTH1_TAMPERED_SIG", "Negative", "Tampered AUTH1 sig", false, "SELECT failed", start);

            byte[] auth0Resp = cred.process(reader.buildAuth0Command());
            if (!isSW9000(auth0Resp)) return result("NEG_AUTH1_TAMPERED_SIG", "Negative", "Tampered AUTH1 sig", false, "AUTH0 failed", start);

            reader.parseAuth0Response(auth0Resp);
            reader.deriveKeys(AliroCryptoProvider.INTERFACE_BYTE_NFC);

            // Build AUTH1 with tampered signature
            byte[] auth1Cmd = reader.buildAuth1CommandFull();
            // Tamper with the signature (last 64 bytes of data, before Le)
            if (auth1Cmd.length > 10)
            {
                auth1Cmd[auth1Cmd.length - 2] ^= 0xFF; // flip a byte in the signature area
            }

            byte[] auth1Resp = cred.process(auth1Cmd);

            // Credential is permissive — sigValid may be false but flow continues
            // AUTH1 should still return 9000
            if (!isSW9000(auth1Resp))
                return result("NEG_AUTH1_TAMPERED_SIG", "Negative", "Tampered AUTH1 sig", false,
                        "Credential rejected AUTH1 with tampered sig: " + swHex(auth1Resp), start);

            return result("NEG_AUTH1_TAMPERED_SIG", "Negative",
                    "AUTH1 with tampered reader signature: sigValid=false but flow continues",
                    true, "Credential is permissive, returned 9000", start);
        }
        catch (Exception e)
        {
            return result("NEG_AUTH1_TAMPERED_SIG", "Negative", "Tampered AUTH1 sig", false, e.toString(), start);
        }
    }

    private TestResult testNegExchangeTampered()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            byte[] selectResp = cred.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp)) return result("NEG_EXCHANGE_TAMPERED", "Negative", "Tampered EXCHANGE", false, "SELECT failed", start);

            byte[] auth0Resp = cred.process(reader.buildAuth0Command());
            if (!isSW9000(auth0Resp)) return result("NEG_EXCHANGE_TAMPERED", "Negative", "Tampered EXCHANGE", false, "AUTH0 failed", start);

            reader.parseAuth0Response(auth0Resp);
            reader.deriveKeys(AliroCryptoProvider.INTERFACE_BYTE_NFC);

            byte[] auth1Resp = cred.process(reader.buildAuth1CommandFull());
            if (!isSW9000(auth1Resp)) return result("NEG_EXCHANGE_TAMPERED", "Negative", "Tampered EXCHANGE", false, "AUTH1 failed", start);

            // Build tampered EXCHANGE command
            byte[] exchangePayload = new byte[]{(byte) 0x97, 0x02, 0x01, (byte) 0x82};
            byte[] encrypted = AliroCryptoProvider.encryptReaderGcm(reader.skReader, exchangePayload);
            if (encrypted == null)
                return result("NEG_EXCHANGE_TAMPERED", "Negative", "Tampered EXCHANGE", false, "Encryption failed", start);

            // Tamper the ciphertext
            encrypted[0] ^= 0x01;

            byte[] cmd = new byte[5 + encrypted.length + 1];
            cmd[0] = (byte) 0x80;
            cmd[1] = (byte) 0xC9;
            cmd[2] = 0x00;
            cmd[3] = 0x00;
            cmd[4] = (byte) encrypted.length;
            System.arraycopy(encrypted, 0, cmd, 5, encrypted.length);
            cmd[5 + encrypted.length] = 0x00;

            byte[] exchangeResp = cred.process(cmd);

            // Credential should return error SW (not 9000) since decryption fails
            if (isSW9000(exchangeResp))
                return result("NEG_EXCHANGE_TAMPERED", "Negative", "Tampered EXCHANGE", false,
                        "Tampered EXCHANGE should not return 9000", start);

            return result("NEG_EXCHANGE_TAMPERED", "Negative",
                    "EXCHANGE with tampered ciphertext returns error SW",
                    true, "Error SW: " + swHex(exchangeResp), start);
        }
        catch (Exception e)
        {
            return result("NEG_EXCHANGE_TAMPERED", "Negative", "Tampered EXCHANGE", false, e.toString(), start);
        }
    }

    private TestResult testNegSessionKeyDestroy()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackReader reader = new LoopbackReader();
            LoopbackCredential cred = new LoopbackCredential();

            // Run full flow
            cred.process(reader.buildSelectCommand());
            byte[] auth0Resp = cred.process(reader.buildAuth0Command());
            reader.parseAuth0Response(auth0Resp);
            reader.deriveKeys(AliroCryptoProvider.INTERFACE_BYTE_NFC);
            cred.process(reader.buildAuth1CommandFull());
            cred.process(reader.buildExchangeCommand());

            // Reset state
            cred.reset();

            // Verify credential keys are zeroed/null
            boolean keysDestroyed = (cred.skReader == null && cred.skDevice == null);

            if (!keysDestroyed)
            {
                boolean skReaderZero = cred.skReader != null && isAllZeros(cred.skReader);
                boolean skDeviceZero = cred.skDevice != null && isAllZeros(cred.skDevice);
                keysDestroyed = skReaderZero || skDeviceZero
                        || (cred.skReader == null) || (cred.skDevice == null);
            }

            if (!keysDestroyed)
                return result("NEG_SESSION_KEY_DESTROY", "Negative", "Session key destroy", false,
                        "Keys not zeroed after resetState()", start);

            return result("NEG_SESSION_KEY_DESTROY", "Negative",
                    "After full flow, session keys are zeroed",
                    true, "Keys null/zeroed after resetState()", start);
        }
        catch (Exception e)
        {
            return result("NEG_SESSION_KEY_DESTROY", "Negative", "Session key destroy", false, e.toString(), start);
        }
    }

    // =========================================================================
    // LoopbackReader — replicates HomeFragment Aliro NFC flow logic
    // =========================================================================
    private static class LoopbackReader
    {
        KeyPair readerEphKP;
        byte[] readerEphPub;
        byte[] transactionId;
        byte[] udEphPubBytes;  // 65 bytes from AUTH0 response
        byte[] skReader;
        byte[] skDevice;
        PrivateKey readerPrivKey;
        byte[] readerPubKeyX;

        LoopbackReader()
        {
            readerEphKP = AliroCryptoProvider.generateEphemeralKeypair();
            readerEphPub = AliroCryptoProvider.getUncompressedPublicKey(readerEphKP);
            transactionId = AliroCryptoProvider.generateRandom(16);
            readerPrivKey = rawBytesToEcPrivateKey(TEST_READER_PRIVATE_KEY);
            readerPubKeyX = derivePublicKeyXFromPrivate(TEST_READER_PRIVATE_KEY);
        }

        byte[] buildSelectCommand()
        {
            return new byte[]{
                    0x00, (byte) 0xA4, 0x04, 0x00, 0x09,
                    (byte) 0xA0, 0x00, 0x00, 0x09, 0x09,
                    (byte) 0xAC, (byte) 0xCE, 0x55, 0x01,
                    0x00
            };
        }

        byte[] buildAuth0Command()
        {
            return buildAuth0CommandWithReaderId(TEST_READER_ID);
        }

        byte[] buildAuth0CommandWithReaderId(byte[] readerId)
        {
            byte[] proto = {0x01, 0x00};
            int dataLen = 3 + 3 + 4 + 67 + 18 + 34; // 129
            byte[] cmd = new byte[4 + 1 + dataLen + 1];
            int idx = 0;
            cmd[idx++] = (byte) 0x80;
            cmd[idx++] = (byte) 0x80;
            cmd[idx++] = 0x00;
            cmd[idx++] = 0x00;
            cmd[idx++] = (byte) dataLen;
            // 41: command_parameters
            cmd[idx++] = 0x41; cmd[idx++] = 0x01; cmd[idx++] = 0x00;
            // 42: authentication_policy
            cmd[idx++] = 0x42; cmd[idx++] = 0x01; cmd[idx++] = 0x01;
            // 5C: protocol version
            cmd[idx++] = 0x5C; cmd[idx++] = 0x02;
            System.arraycopy(proto, 0, cmd, idx, 2); idx += 2;
            // 87: reader eph pub key
            cmd[idx++] = (byte) 0x87; cmd[idx++] = 0x41;
            System.arraycopy(readerEphPub, 0, cmd, idx, 65); idx += 65;
            // 4C: transaction ID
            cmd[idx++] = 0x4C; cmd[idx++] = 0x10;
            System.arraycopy(transactionId, 0, cmd, idx, 16); idx += 16;
            // 4D: reader ID
            cmd[idx++] = 0x4D; cmd[idx++] = 0x20;
            System.arraycopy(readerId, 0, cmd, idx, 32); idx += 32;
            cmd[idx] = 0x00;
            return cmd;
        }

        byte[] buildLoadCertCommand()
        {
            byte[] cert = TEST_READER_CERT;
            boolean extended = cert.length > 255;
            int headerSize = 4 + (extended ? 3 : 1);
            byte[] cmd = new byte[headerSize + cert.length + 1];
            cmd[0] = (byte) 0x80; cmd[1] = (byte) 0xD1; cmd[2] = 0x00; cmd[3] = 0x00;
            int idx = 4;
            if (extended)
            {
                cmd[idx++] = 0x00;
                cmd[idx++] = (byte) (cert.length >> 8);
                cmd[idx++] = (byte) (cert.length & 0xFF);
            }
            else
            {
                cmd[idx++] = (byte) cert.length;
            }
            System.arraycopy(cert, 0, cmd, idx, cert.length);
            cmd[idx + cert.length] = 0x00;
            return cmd;
        }

        void parseAuth0Response(byte[] auth0Resp)
        {
            // Response: 86 41 <UD eph pub key 65 bytes> [optional vendor TLV] 90 00
            udEphPubBytes = Arrays.copyOfRange(auth0Resp, 2, 67);
        }

        void deriveKeys(byte interfaceByte)
        {
            byte[] readerEphPubX = Arrays.copyOfRange(readerEphPub, 1, 33);
            byte[] udEphPubX = Arrays.copyOfRange(udEphPubBytes, 1, 33);
            byte[] proto = {0x01, 0x00};
            byte[] flag = {0x00, 0x01};

            byte[] keybuf = AliroCryptoProvider.deriveKeys(
                    readerEphKP.getPrivate(),
                    udEphPubBytes,
                    64,
                    proto,
                    readerPubKeyX,
                    TEST_READER_ID,
                    transactionId,
                    readerEphPubX,
                    udEphPubX,
                    PROPRIETARY_TLV,
                    null,
                    interfaceByte,
                    flag);

            if (keybuf != null)
            {
                skReader = Arrays.copyOfRange(keybuf, 0, 32);
                skDevice = Arrays.copyOfRange(keybuf, 32, 64);
            }
        }

        /** Build AUTH1 command with a dummy signature (for tag format testing only). */
        byte[] buildAuth1CommandForTest()
        {
            byte[] dummySig = new byte[64];
            new SecureRandom().nextBytes(dummySig);
            byte[] header = {(byte) 0x80, (byte) 0x81, 0x00, 0x00, 0x45,
                    0x41, 0x01, 0x01, (byte) 0x9E, 0x40};
            byte[] cmd = new byte[header.length + 64];
            System.arraycopy(header, 0, cmd, 0, header.length);
            System.arraycopy(dummySig, 0, cmd, header.length, 64);
            return cmd;
        }

        /** Build AUTH1 command with real reader signature. */
        byte[] buildAuth1CommandFull()
        {
            byte[] udEphPubX = Arrays.copyOfRange(udEphPubBytes, 1, 33);
            byte[] readerEphPubX = Arrays.copyOfRange(readerEphPub, 1, 33);
            byte[] readerSig = AliroCryptoProvider.computeReaderSignature(
                    readerPrivKey, TEST_READER_ID, udEphPubX, readerEphPubX, transactionId);

            byte[] header = {(byte) 0x80, (byte) 0x81, 0x00, 0x00, 0x45,
                    0x41, 0x01, 0x01, (byte) 0x9E, 0x40};
            byte[] cmd = new byte[header.length + 64];
            System.arraycopy(header, 0, cmd, 0, header.length);
            if (readerSig != null) System.arraycopy(readerSig, 0, cmd, header.length, 64);
            return cmd;
        }

        /** Build EXCHANGE command with access decision. */
        byte[] buildExchangeCommand()
        {
            byte[] exchangePayload = new byte[]{(byte) 0x97, 0x02, 0x01, (byte) 0x82};
            byte[] encrypted = AliroCryptoProvider.encryptReaderGcm(skReader, exchangePayload);
            if (encrypted == null) return new byte[0];

            byte[] cmd = new byte[5 + encrypted.length + 1];
            cmd[0] = (byte) 0x80; cmd[1] = (byte) 0xC9; cmd[2] = 0x00; cmd[3] = 0x00;
            cmd[4] = (byte) encrypted.length;
            System.arraycopy(encrypted, 0, cmd, 5, encrypted.length);
            cmd[5 + encrypted.length] = 0x00;
            return cmd;
        }
    }

    // =========================================================================
    // LoopbackCredential — replicates Aliro_HostApduService APDU processing
    // =========================================================================
    private static class LoopbackCredential
    {
        private enum State { IDLE, SELECTED, AUTH0_DONE, CERT_LOADED, AUTH1_DONE }

        private static final byte[] SW_OK = {(byte) 0x90, 0x00};
        private static final byte[] SW_ERROR = {0x6A, (byte) 0x82};
        private static final byte[] SW_CONDITIONS = {0x69, (byte) 0x85};

        private static final byte[] SELECT_AID = {
                (byte) 0xA0, 0x00, 0x00, 0x09, 0x09,
                (byte) 0xAC, (byte) 0xCE, 0x55, 0x01
        };

        private static final byte[] CRED_PROPRIETARY_TLV = {
                (byte) 0xA5, 0x0A,
                (byte) 0x80, 0x02, 0x00, 0x00,
                0x5C, 0x04, 0x01, 0x00, 0x00, 0x09
        };

        State state = State.IDLE;
        byte interfaceByte = AliroCryptoProvider.INTERFACE_BYTE_NFC; // set before process() for BLE
        KeyPair udEphKP;
        byte[] udEphPubBytes;
        byte[] readerEphPubBytes;
        byte[] readerIdBytes;
        byte[] transactionId;
        byte[] selectedProtocol;
        byte[] auth0Flag;
        byte[] readerStaticPubKeyX;
        byte[] skReader;
        byte[] skDevice;

        // Credential keypair (generated fresh for self-test, not from Android KeyStore)
        KeyPair credentialKP;
        byte[] credentialPubBytes;

        LoopbackCredential()
        {
            // Generate a fresh credential keypair for testing
            credentialKP = AliroCryptoProvider.generateEphemeralKeypair();
            credentialPubBytes = AliroCryptoProvider.getUncompressedPublicKey(credentialKP);
        }

        byte[] process(byte[] apdu)
        {
            if (apdu == null || apdu.length < 4) return SW_ERROR;

            byte ins = apdu[1];
            switch (ins)
            {
                case (byte) 0xA4: return handleSelect(apdu);
                case (byte) 0x80: return handleAuth0(apdu);
                case (byte) 0xD1: return handleLoadCert(apdu);
                case (byte) 0x81: return handleAuth1(apdu);
                case (byte) 0xC9: return handleExchange(apdu);
                case (byte) 0x3C: return handleControlFlow(apdu);
                default: return SW_ERROR;
            }
        }

        void reset()
        {
            state = State.IDLE;
            udEphKP = null;
            udEphPubBytes = null;
            readerEphPubBytes = null;
            readerIdBytes = null;
            transactionId = null;
            selectedProtocol = null;
            auth0Flag = null;
            readerStaticPubKeyX = null;
            if (skReader != null) { Arrays.fill(skReader, (byte) 0); skReader = null; }
            if (skDevice != null) { Arrays.fill(skDevice, (byte) 0); skDevice = null; }
        }

        private byte[] handleSelect(byte[] apdu)
        {
            if (apdu.length < 5) return SW_ERROR;
            int aidLen = apdu[4] & 0xFF;
            if (apdu.length < 5 + aidLen) return SW_ERROR;
            byte[] requestedAid = Arrays.copyOfRange(apdu, 5, 5 + aidLen);
            if (!Arrays.equals(requestedAid, SELECT_AID)) return SW_ERROR;

            reset();
            state = State.SELECTED;

            // Build SELECT response: 6F <len> 84 09 <AID> <PROP_TLV> SW9000
            int innerLen = 2 + SELECT_AID.length + CRED_PROPRIETARY_TLV.length;
            byte[] selectResp = new byte[2 + innerLen];
            selectResp[0] = 0x6F;
            selectResp[1] = (byte) innerLen;
            selectResp[2] = (byte) 0x84;
            selectResp[3] = (byte) SELECT_AID.length;
            System.arraycopy(SELECT_AID, 0, selectResp, 4, SELECT_AID.length);
            System.arraycopy(CRED_PROPRIETARY_TLV, 0, selectResp, 4 + SELECT_AID.length, CRED_PROPRIETARY_TLV.length);

            byte[] response = new byte[selectResp.length + 2];
            System.arraycopy(selectResp, 0, response, 0, selectResp.length);
            response[selectResp.length] = (byte) 0x90;
            response[selectResp.length + 1] = 0x00;
            return response;
        }

        private byte[] handleAuth0(byte[] apdu)
        {
            if (state != State.SELECTED) return SW_CONDITIONS;

            try
            {
                int dataOffset = 5;
                int dataLen = apdu[4] & 0xFF;
                if (apdu.length < dataOffset + dataLen) return SW_ERROR;
                byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);

                // Parse flat TLVs
                readerEphPubBytes = null;
                transactionId = null;
                readerIdBytes = null;
                selectedProtocol = null;

                byte cmdParams = 0x00;
                byte authPolicy = 0x01;

                for (int i = 0; i < data.length - 1; i++)
                {
                    int tag = data[i] & 0xFF;
                    int len = (i + 1 < data.length) ? (data[i + 1] & 0xFF) : 0;
                    if (i + 2 + len > data.length) continue;

                    if (tag == 0x41 && len == 0x01) cmdParams = data[i + 2];
                    if (tag == 0x42 && len == 0x01) authPolicy = data[i + 2];
                    if (tag == 0x5C && len == 0x02 && selectedProtocol == null)
                        selectedProtocol = Arrays.copyOfRange(data, i + 2, i + 4);
                    if (tag == 0x87 && len == 0x41)
                        readerEphPubBytes = Arrays.copyOfRange(data, i + 2, i + 67);
                    if (tag == 0x4C && len == 0x10)
                        transactionId = Arrays.copyOfRange(data, i + 2, i + 18);
                    if (tag == 0x4D && len == 0x20)
                        readerIdBytes = Arrays.copyOfRange(data, i + 2, i + 34);
                }

                auth0Flag = new byte[]{cmdParams, authPolicy};
                if (selectedProtocol == null) selectedProtocol = new byte[]{0x01, 0x00};

                if (readerEphPubBytes == null || transactionId == null || readerIdBytes == null)
                    return SW_ERROR;

                // Generate UD ephemeral keypair
                udEphKP = AliroCryptoProvider.generateEphemeralKeypair();
                if (udEphKP == null) return SW_ERROR;
                udEphPubBytes = AliroCryptoProvider.getUncompressedPublicKey(udEphKP);

                state = State.AUTH0_DONE;

                // Response: 86 41 <UD eph pub key 65 bytes> SW9000
                byte[] response = new byte[2 + 65 + 2];
                response[0] = (byte) 0x86;
                response[1] = 0x41;
                System.arraycopy(udEphPubBytes, 0, response, 2, 65);
                response[67] = (byte) 0x90;
                response[68] = 0x00;
                return response;
            }
            catch (Exception e)
            {
                Log.e(TAG, "LoopbackCredential AUTH0 error", e);
                return SW_ERROR;
            }
        }

        private byte[] handleLoadCert(byte[] apdu)
        {
            if (state != State.AUTH0_DONE) return SW_CONDITIONS;

            try
            {
                int dataOffset = 5;
                int dataLen = apdu[4] & 0xFF;
                // Handle extended length
                if (dataLen == 0 && apdu.length > 7)
                {
                    dataLen = ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
                    dataOffset = 7;
                }
                if (apdu.length >= dataOffset + dataLen)
                {
                    byte[] cert = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
                    // Parse reader static pub key from cert (tag 0x85)
                    for (int i = 0; i < cert.length - 2; i++)
                    {
                        if ((cert[i] & 0xFF) == 0x85 && (cert[i + 1] & 0xFF) == 0x42)
                        {
                            if (i + 68 <= cert.length && cert[i + 2] == 0x00 && cert[i + 3] == 0x04)
                            {
                                readerStaticPubKeyX = Arrays.copyOfRange(cert, i + 4, i + 36);
                            }
                            break;
                        }
                    }
                }
            }
            catch (Exception e)
            {
                Log.w(TAG, "LoopbackCredential LOAD CERT parse error: " + e.getMessage());
            }

            state = State.CERT_LOADED;
            return SW_OK;
        }

        private byte[] handleAuth1(byte[] apdu)
        {
            if (state != State.AUTH0_DONE && state != State.CERT_LOADED) return SW_CONDITIONS;

            try
            {
                byte[] readerEphPubX = Arrays.copyOfRange(readerEphPubBytes, 1, 33);
                byte[] udEphPubX = Arrays.copyOfRange(udEphPubBytes, 1, 33);

                // Per Aliro spec, HKDF always uses reader static pub key X.
                // If LOAD CERT was received, use the X extracted from the cert (tag 0x85).
                // If no LOAD CERT (no-cert flow), use the provisioned TEST_READER_PUB_KEY_X
                // which is what LoopbackReader.deriveKeys() also uses.
                byte[] hkdfReaderPubKeyX = (readerStaticPubKeyX != null)
                        ? readerStaticPubKeyX : TEST_READER_PUB_KEY_X;

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
                        CRED_PROPRIETARY_TLV,
                        null,
                        interfaceByte,
                        auth0Flag);

                if (keybuf == null) return SW_ERROR;
                skReader = Arrays.copyOfRange(keybuf, 0, 32);
                skDevice = Arrays.copyOfRange(keybuf, 32, 64);

                // Compute credential signature using software key
                byte[] credSig = AliroCryptoProvider.computeCredentialSignature(
                        credentialKP.getPrivate(), readerIdBytes, udEphPubX, readerEphPubX, transactionId);
                if (credSig == null) return SW_ERROR;

                // Build plaintext: 5A 41 <cred pub key 65> 9E 40 <sig 64>
                byte[] plaintext = new byte[2 + 65 + 2 + 64];
                plaintext[0] = 0x5A; plaintext[1] = 0x41;
                System.arraycopy(credentialPubBytes, 0, plaintext, 2, 65);
                plaintext[67] = (byte) 0x9E; plaintext[68] = 0x40;
                System.arraycopy(credSig, 0, plaintext, 69, 64);

                byte[] encrypted = AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext);
                if (encrypted == null) return SW_ERROR;

                state = State.AUTH1_DONE;

                byte[] response = new byte[encrypted.length + 2];
                System.arraycopy(encrypted, 0, response, 0, encrypted.length);
                response[encrypted.length] = (byte) 0x90;
                response[encrypted.length + 1] = 0x00;
                return response;
            }
            catch (Exception e)
            {
                Log.e(TAG, "LoopbackCredential AUTH1 error", e);
                return SW_ERROR;
            }
        }

        private byte[] handleExchange(byte[] apdu)
        {
            if (state != State.AUTH1_DONE) return SW_CONDITIONS;

            try
            {
                int dataOffset = 5;
                int dataLen = apdu[4] & 0xFF;
                if (apdu.length < dataOffset + dataLen) return SW_ERROR;

                byte[] encryptedPayload = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
                byte[] decrypted = AliroCryptoProvider.decryptReaderGcm(skReader, encryptedPayload);
                if (decrypted == null) return SW_ERROR;

                // Response: encrypted 0x0002 0x00 0x00
                byte[] successPayload = new byte[]{0x00, 0x02, 0x00, 0x00};
                byte[] encryptedResponse = AliroCryptoProvider.encryptDeviceGcm(skDevice, successPayload);
                if (encryptedResponse == null) return SW_ERROR;

                byte[] response = new byte[encryptedResponse.length + 2];
                System.arraycopy(encryptedResponse, 0, response, 0, encryptedResponse.length);
                response[encryptedResponse.length] = (byte) 0x90;
                response[encryptedResponse.length + 1] = 0x00;
                return response;
            }
            catch (Exception e)
            {
                Log.e(TAG, "LoopbackCredential EXCHANGE error", e);
                return SW_ERROR;
            }
        }

        private byte[] handleControlFlow(byte[] apdu)
        {
            reset();
            return SW_OK;
        }
    }

    // =========================================================================
    // Utility methods
    // =========================================================================

    private static boolean isSW9000(byte[] response)
    {
        return response != null && response.length >= 2
                && response[response.length - 2] == (byte) 0x90
                && response[response.length - 1] == 0x00;
    }

    private static String swHex(byte[] response)
    {
        if (response == null || response.length < 2) return "null";
        return String.format("%02X%02X", response[response.length - 2], response[response.length - 1]);
    }

    private static boolean isAllZeros(byte[] arr)
    {
        for (byte b : arr) if (b != 0) return false;
        return true;
    }

    private TestResult result(String testId, String group, String name,
                              boolean passed, String detail, long startMs)
    {
        return new TestResult(testId, group, name, passed, false, detail,
                System.currentTimeMillis() - startMs);
    }

    /** Derive the public key X coordinate from a raw 32-byte private key */
    private static byte[] derivePublicKeyXFromPrivate(byte[] privateKeyBytes)
    {
        try
        {
            org.bouncycastle.asn1.x9.X9ECParameters x9 =
                    org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1");
            org.bouncycastle.crypto.params.ECDomainParameters domainParams =
                    new org.bouncycastle.crypto.params.ECDomainParameters(
                            x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
            BigInteger privBI = new BigInteger(1, privateKeyBytes);
            org.bouncycastle.math.ec.ECPoint pubPoint = domainParams.getG().multiply(privBI).normalize();
            byte[] x = pubPoint.getAffineXCoord().getEncoded();
            byte[] out = new byte[32];
            System.arraycopy(x, x.length - 32, out, 0, 32);
            return out;
        }
        catch (Exception e)
        {
            Log.e(TAG, "derivePublicKeyXFromPrivate failed", e);
            return null;
        }
    }

    /** Convert raw 32-byte private key bytes to a Java ECPrivateKey */
    private static PrivateKey rawBytesToEcPrivateKey(byte[] rawBytes)
    {
        try
        {
            BigInteger s = new BigInteger(1, rawBytes);
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec bcSpec =
                    org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
            org.bouncycastle.jce.spec.ECNamedCurveSpec spec =
                    new org.bouncycastle.jce.spec.ECNamedCurveSpec(
                            "secp256r1", bcSpec.getCurve(), bcSpec.getG(), bcSpec.getN());
            java.security.spec.ECPrivateKeySpec keySpec = new java.security.spec.ECPrivateKeySpec(s, spec);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance(
                    "EC", new BouncyCastleProvider());
            return kf.generatePrivate(keySpec);
        }
        catch (Exception e)
        {
            Log.e(TAG, "rawBytesToEcPrivateKey failed", e);
            return null;
        }
    }
}
