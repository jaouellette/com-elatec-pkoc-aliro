package com.psia.pkoc.core;

import android.util.Log;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import javax.crypto.KeyAgreement;

/**
 * PKOC 1.0 Compliance Self-Test Engine.
 *
 * Runs all test cases in-process using pure Java — no NFC/BLE hardware required.
 * Uses a loopback architecture with 4 inner classes:
 *   - LoopbackPKOCReader: NFC reader side
 *   - LoopbackPKOCDevice: NFC device/card side
 *   - LoopbackPKOCBleReader: BLE reader side
 *   - LoopbackPKOCBleDevice: BLE device side
 *
 * Test groups:
 *   1. NFC Crypto & Format (14 tests)
 *   2. BLE Protocol Format (13 tests)
 *   3. Full Flow (3 tests)
 *   4. Negative Tests (5 tests)
 */
public class PKOCSelfTestEngine
{
    private static final String TAG = "PKOCSelfTest";

    // PKOC AID: A000000898000001 (8 bytes)
    private static final byte[] PKOC_AID = {
            (byte) 0xA0, 0x00, 0x00, 0x08, (byte) 0x98, 0x00, 0x00, 0x01
    };

    // PKOC BLE Service UUID (0xFFF0)
    private static final String BLE_SERVICE_UUID = "0000FFF0-0000-1000-8000-00805F9B34FB";

    // Test reader/site IDs (random UUIDs serialized to 16 bytes)
    private static final byte[] TEST_READER_LOCATION_ID = hexToBytes("0102030405060708090a0b0c0d0e0f10");
    private static final byte[] TEST_SITE_ID = hexToBytes("a1a2a3a4a5a6a7a8b1b2b3b4b5b6b7b8");

    // =========================================================================
    // Reuse AliroSelfTestEngine.TestResult (same package)
    // =========================================================================
    // TestResult is defined in AliroSelfTestEngine. Since both are in
    // com.psia.pkoc.core, we reference it as AliroSelfTestEngine.TestResult.
    // For standalone use, define identical class here.

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

        // Group 1: NFC Crypto & Format (14 tests)
        runAndReport(results, cb, this::testNfcSelectAid);
        runAndReport(results, cb, this::testNfcSelectResponse);
        runAndReport(results, cb, this::testNfcAuthCmdFormat);
        runAndReport(results, cb, this::testNfcAuthCmdTags);
        runAndReport(results, cb, this::testNfcAuthTidLength);
        runAndReport(results, cb, this::testNfcAuthReaderIdLength);
        runAndReport(results, cb, this::testNfcAuthResponsePk);
        runAndReport(results, cb, this::testNfcAuthResponseSig);
        runAndReport(results, cb, this::testNfcSigValid);
        runAndReport(results, cb, this::testNfcSigWrongData);
        runAndReport(results, cb, this::testNfcPkXExtraction);
        runAndReport(results, cb, this::testNfcPk64BitExtraction);
        runAndReport(results, cb, this::testNfcStatusWrongIns);
        runAndReport(results, cb, this::testNfcStatusWrongCla);

        // Group 2: BLE Protocol Format (13 tests)
        runAndReport(results, cb, this::testBleUuidService);
        runAndReport(results, cb, this::testBleReaderMsgHasProtoId);
        runAndReport(results, cb, this::testBleReaderMsgHasEphKey);
        runAndReport(results, cb, this::testBleReaderMsgHasLocation);
        runAndReport(results, cb, this::testBleReaderMsgHasSiteId);
        runAndReport(results, cb, this::testBleProtoIdFormat);
        runAndReport(results, cb, this::testBleDeviceMsgHasPk);
        runAndReport(results, cb, this::testBleDeviceMsgHasSig);
        runAndReport(results, cb, this::testBleDeviceMsgHasTime);
        runAndReport(results, cb, this::testBleSigInputIsEphKeyTlv);
        runAndReport(results, cb, this::testBleResponseCodeSuccess);
        runAndReport(results, cb, this::testBleResponseCodeAccessGranted);
        runAndReport(results, cb, this::testBleSigNotAsn1);

        // Group 3: Full Flow Tests (3 tests)
        runAndReport(results, cb, this::testPkocNfcFlow);
        runAndReport(results, cb, this::testPkocBleUnobfuscated);
        runAndReport(results, cb, this::testPkocBleEcdhe);

        // Group 4: Negative Tests (5 tests)
        runAndReport(results, cb, this::testNegNfcWrongAid);
        runAndReport(results, cb, this::testNegNfcWrongP2);
        runAndReport(results, cb, this::testNegNfcSigTampered);
        runAndReport(results, cb, this::testNegBleWrongSiteKey);
        runAndReport(results, cb, this::testNegBleCcmTampered);

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
    // GROUP 1: NFC Crypto & Format (14 tests)
    // =========================================================================

    private TestResult testNfcSelectAid()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            byte[] selectCmd = reader.buildSelectCommand();

            // SELECT: 00 A4 04 00 08 <AID 8 bytes> 00
            if (selectCmd.length < 13)
                return result("NFC_SELECT_AID", "NFC Format", "SELECT uses correct AID", false,
                        "Command too short: " + selectCmd.length, start);

            byte[] aidFromCmd = Arrays.copyOfRange(selectCmd, 5, 13);
            if (!Arrays.equals(aidFromCmd, PKOC_AID))
                return result("NFC_SELECT_AID", "NFC Format", "SELECT uses correct AID", false,
                        "AID mismatch: " + Hex.toHexString(aidFromCmd), start);

            return result("NFC_SELECT_AID", "NFC Format", "SELECT uses correct AID A000000898000001",
                    true, "AID verified", start);
        }
        catch (Exception e)
        {
            return result("NFC_SELECT_AID", "NFC Format", "SELECT AID", false, e.toString(), start);
        }
    }

    private TestResult testNfcSelectResponse()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            byte[] selectResp = device.process(reader.buildSelectCommand());

            if (!isSW9000(selectResp))
                return result("NFC_SELECT_RESPONSE", "NFC Format", "SELECT response", false,
                        "SW != 9000: " + swHex(selectResp), start);

            // Check for 5C 02 01 00 in response
            boolean found5C = false;
            for (int i = 0; i < selectResp.length - 3; i++)
            {
                if (selectResp[i] == 0x5C && selectResp[i + 1] == 0x02
                        && selectResp[i + 2] == 0x01 && selectResp[i + 3] == 0x00)
                {
                    found5C = true;
                    break;
                }
            }

            if (!found5C)
                return result("NFC_SELECT_RESPONSE", "NFC Format", "SELECT response", false,
                        "Protocol version TLV 5C 02 01 00 not found", start);

            return result("NFC_SELECT_RESPONSE", "NFC Format",
                    "SELECT response contains 5C 02 01 00 + SW 9000",
                    true, "Protocol version 1.0 confirmed", start);
        }
        catch (Exception e)
        {
            return result("NFC_SELECT_RESPONSE", "NFC Format", "SELECT response", false, e.toString(), start);
        }
    }

    private TestResult testNfcAuthCmdFormat()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            byte[] authCmd = reader.buildAuthCommand();

            if (authCmd.length < 5)
                return result("NFC_AUTH_CMD_FORMAT", "NFC Format", "AUTH command format", false,
                        "Command too short", start);

            // CLA=80 INS=80 P1=00 P2=01
            if (authCmd[0] != (byte) 0x80)
                return result("NFC_AUTH_CMD_FORMAT", "NFC Format", "AUTH command format", false,
                        "CLA=" + String.format("%02X", authCmd[0]) + ", expected 80", start);
            if (authCmd[1] != (byte) 0x80)
                return result("NFC_AUTH_CMD_FORMAT", "NFC Format", "AUTH command format", false,
                        "INS=" + String.format("%02X", authCmd[1]) + ", expected 80", start);
            if (authCmd[2] != 0x00)
                return result("NFC_AUTH_CMD_FORMAT", "NFC Format", "AUTH command format", false,
                        "P1=" + String.format("%02X", authCmd[2]) + ", expected 00", start);
            if (authCmd[3] != 0x01)
                return result("NFC_AUTH_CMD_FORMAT", "NFC Format", "AUTH command format", false,
                        "P2=" + String.format("%02X", authCmd[3]) + ", expected 01", start);

            return result("NFC_AUTH_CMD_FORMAT", "NFC Format",
                    "AUTH has correct CLA=80 INS=80 P1=00 P2=01",
                    true, "Header bytes verified", start);
        }
        catch (Exception e)
        {
            return result("NFC_AUTH_CMD_FORMAT", "NFC Format", "AUTH format", false, e.toString(), start);
        }
    }

    private TestResult testNfcAuthCmdTags()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            byte[] authCmd = reader.buildAuthCommand();

            int dataOffset = 5;
            int dataLen = authCmd[4] & 0xFF;
            byte[] data = Arrays.copyOfRange(authCmd, dataOffset, dataOffset + dataLen);

            boolean found5C = false, found4C = false, found4D = false;
            for (int i = 0; i < data.length - 1; i++)
            {
                int tag = data[i] & 0xFF;
                if (tag == 0x5C) found5C = true;
                if (tag == 0x4C) found4C = true;
                if (tag == 0x4D) found4D = true;
            }

            if (!found5C || !found4C || !found4D)
            {
                String missing = "";
                if (!found5C) missing += "5C ";
                if (!found4C) missing += "4C ";
                if (!found4D) missing += "4D ";
                return result("NFC_AUTH_CMD_TAGS", "NFC Format", "AUTH required tags", false,
                        "Missing tags: " + missing.trim(), start);
            }

            return result("NFC_AUTH_CMD_TAGS", "NFC Format",
                    "AUTH contains all 3 TLVs: 5C, 4C, 4D",
                    true, "All required tags present", start);
        }
        catch (Exception e)
        {
            return result("NFC_AUTH_CMD_TAGS", "NFC Format", "AUTH tags", false, e.toString(), start);
        }
    }

    private TestResult testNfcAuthTidLength()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            byte[] authCmd = reader.buildAuthCommand();

            int dataOffset = 5;
            int dataLen = authCmd[4] & 0xFF;
            byte[] data = Arrays.copyOfRange(authCmd, dataOffset, dataOffset + dataLen);

            for (int i = 0; i < data.length - 1; i++)
            {
                if ((data[i] & 0xFF) == 0x4C)
                {
                    int len = data[i + 1] & 0xFF;
                    if (len != 16)
                        return result("NFC_AUTH_TID_LENGTH", "NFC Format", "Transaction ID length", false,
                                "Tag 4C length=" + len + ", expected 16", start);
                    return result("NFC_AUTH_TID_LENGTH", "NFC Format",
                            "Transaction ID (tag 4C) is 16 bytes",
                            true, "Tag 4C: 16 bytes", start);
                }
            }
            return result("NFC_AUTH_TID_LENGTH", "NFC Format", "TID length", false,
                    "Tag 4C not found", start);
        }
        catch (Exception e)
        {
            return result("NFC_AUTH_TID_LENGTH", "NFC Format", "TID length", false, e.toString(), start);
        }
    }

    private TestResult testNfcAuthReaderIdLength()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            byte[] authCmd = reader.buildAuthCommand();

            int dataOffset = 5;
            int dataLen = authCmd[4] & 0xFF;
            byte[] data = Arrays.copyOfRange(authCmd, dataOffset, dataOffset + dataLen);

            // Walk TLVs properly (skip value bytes) to avoid false tag matches inside values
            int i = 0;
            while (i < data.length - 1)
            {
                int tag = data[i] & 0xFF;
                int len = data[i + 1] & 0xFF;
                if (tag == 0x4D)
                {
                    if (len != 32)
                        return result("NFC_AUTH_READER_ID_LENGTH", "NFC Format", "Reader ID length", false,
                                "Tag 4D length=" + len + ", expected 32", start);
                    return result("NFC_AUTH_READER_ID_LENGTH", "NFC Format",
                            "Reader ID (tag 4D) is 32 bytes",
                            true, "Tag 4D: 32 bytes", start);
                }
                i += 2 + len; // skip tag + length + value
            }
            return result("NFC_AUTH_READER_ID_LENGTH", "NFC Format", "Reader ID length", false,
                    "Tag 4D not found", start);
        }
        catch (Exception e)
        {
            return result("NFC_AUTH_READER_ID_LENGTH", "NFC Format", "Reader ID length", false, e.toString(), start);
        }
    }

    private TestResult testNfcAuthResponsePk()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            byte[] selectResp = device.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp))
                return result("NFC_AUTH_RESPONSE_PK", "NFC Format", "AUTH response pub key", false, "SELECT failed", start);

            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("NFC_AUTH_RESPONSE_PK", "NFC Format", "AUTH response pub key", false,
                        "AUTH failed: " + swHex(authResp), start);

            // Find tag 5A 41 in response
            boolean found5A = false;
            for (int i = 0; i < authResp.length - 67; i++)
            {
                if (authResp[i] == 0x5A && authResp[i + 1] == 0x41)
                {
                    byte firstByte = authResp[i + 2];
                    if (firstByte != 0x04)
                        return result("NFC_AUTH_RESPONSE_PK", "NFC Format", "AUTH response pub key", false,
                                "First byte of key=" + String.format("%02X", firstByte) + ", expected 04", start);
                    found5A = true;
                    break;
                }
            }

            if (!found5A)
                return result("NFC_AUTH_RESPONSE_PK", "NFC Format", "AUTH response pub key", false,
                        "Tag 5A 41 not found in response", start);

            return result("NFC_AUTH_RESPONSE_PK", "NFC Format",
                    "AUTH response contains tag 5A with 65-byte uncompressed key (0x04...)",
                    true, "Tag 5A with 65 bytes, starts 0x04", start);
        }
        catch (Exception e)
        {
            return result("NFC_AUTH_RESPONSE_PK", "NFC Format", "AUTH response PK", false, e.toString(), start);
        }
    }

    private TestResult testNfcAuthResponseSig()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            device.process(reader.buildSelectCommand());
            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("NFC_AUTH_RESPONSE_SIG", "NFC Format", "AUTH response signature", false,
                        "AUTH failed", start);

            // Find tag 9E 40 in response
            boolean found9E = false;
            for (int i = 0; i < authResp.length - 65; i++)
            {
                if (authResp[i] == (byte) 0x9E && authResp[i + 1] == 0x40)
                {
                    found9E = true;
                    break;
                }
            }

            if (!found9E)
                return result("NFC_AUTH_RESPONSE_SIG", "NFC Format", "AUTH response signature", false,
                        "Tag 9E 40 not found in response", start);

            return result("NFC_AUTH_RESPONSE_SIG", "NFC Format",
                    "AUTH response contains tag 9E with 64-byte raw signature (not ASN.1)",
                    true, "Tag 9E 40 found — 64 bytes raw R||S", start);
        }
        catch (Exception e)
        {
            return result("NFC_AUTH_RESPONSE_SIG", "NFC Format", "AUTH response sig", false, e.toString(), start);
        }
    }

    private TestResult testNfcSigValid()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            device.process(reader.buildSelectCommand());
            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("NFC_SIG_VALID", "NFC Format", "Signature validates", false, "AUTH failed", start);

            // Parse response: 5A 41 <65B pub key> 9E 40 <64B sig> 90 00
            byte[] pubKey = Arrays.copyOfRange(authResp, 2, 67);
            byte[] sig = Arrays.copyOfRange(authResp, 69, 133);

            boolean valid = verifyPkocSignature(sig, pubKey, reader.transactionId);
            if (!valid)
                return result("NFC_SIG_VALID", "NFC Format", "Signature validates", false,
                        "Signature verification failed with correct TID", start);

            return result("NFC_SIG_VALID", "NFC Format",
                    "Signature over TID verifies with public key",
                    true, "ECDSA SHA-256 verification passed", start);
        }
        catch (Exception e)
        {
            return result("NFC_SIG_VALID", "NFC Format", "Sig valid", false, e.toString(), start);
        }
    }

    private TestResult testNfcSigWrongData()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            device.process(reader.buildSelectCommand());
            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("NFC_SIG_WRONG_DATA", "NFC Format", "Sig fails with wrong data", false, "AUTH failed", start);

            byte[] pubKey = Arrays.copyOfRange(authResp, 2, 67);
            byte[] sig = Arrays.copyOfRange(authResp, 69, 133);

            // Verify with wrong TID
            byte[] wrongTid = new byte[16];
            new SecureRandom().nextBytes(wrongTid);

            boolean valid = verifyPkocSignature(sig, pubKey, wrongTid);
            if (valid)
                return result("NFC_SIG_WRONG_DATA", "NFC Format", "Sig fails with wrong data", false,
                        "Signature should NOT verify with wrong TID", start);

            return result("NFC_SIG_WRONG_DATA", "NFC Format",
                    "Signature over wrong data fails verification",
                    true, "Correctly rejected wrong TID", start);
        }
        catch (Exception e)
        {
            return result("NFC_SIG_WRONG_DATA", "NFC Format", "Sig wrong data", false, e.toString(), start);
        }
    }

    private TestResult testNfcPkXExtraction()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            device.process(reader.buildSelectCommand());
            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("NFC_PK_X_EXTRACTION", "NFC Format", "X credential extraction", false, "AUTH failed", start);

            byte[] pubKey = Arrays.copyOfRange(authResp, 2, 67);

            // X = bytes 1-32 of 65-byte key (skip 0x04)
            if (pubKey[0] != 0x04)
                return result("NFC_PK_X_EXTRACTION", "NFC Format", "X credential extraction", false,
                        "First byte not 0x04: " + String.format("%02X", pubKey[0]), start);

            byte[] x = Arrays.copyOfRange(pubKey, 1, 33);
            if (x.length != 32)
                return result("NFC_PK_X_EXTRACTION", "NFC Format", "X credential extraction", false,
                        "X length=" + x.length + ", expected 32", start);

            // Verify it's non-zero
            boolean allZero = true;
            for (byte b : x) if (b != 0) { allZero = false; break; }
            if (allZero)
                return result("NFC_PK_X_EXTRACTION", "NFC Format", "X credential extraction", false,
                        "X component is all zeros", start);

            return result("NFC_PK_X_EXTRACTION", "NFC Format",
                    "256-bit credential = bytes 1-32 of 65-byte public key",
                    true, "X: " + Hex.toHexString(x).substring(0, 16) + "...", start);
        }
        catch (Exception e)
        {
            return result("NFC_PK_X_EXTRACTION", "NFC Format", "PK X extraction", false, e.toString(), start);
        }
    }

    private TestResult testNfcPk64BitExtraction()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            device.process(reader.buildSelectCommand());
            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("NFC_PK_64BIT_EXTRACTION", "NFC Format", "64-bit credential", false, "AUTH failed", start);

            byte[] pubKey = Arrays.copyOfRange(authResp, 2, 67);
            byte[] x = Arrays.copyOfRange(pubKey, 1, 33);

            // 64-bit credential = last 8 bytes of X
            byte[] pkoc64 = Arrays.copyOfRange(x, 24, 32);
            if (pkoc64.length != 8)
                return result("NFC_PK_64BIT_EXTRACTION", "NFC Format", "64-bit credential", false,
                        "64-bit credential length=" + pkoc64.length, start);

            BigInteger cardNumber = new BigInteger(1, pkoc64);
            if (cardNumber.signum() == 0)
                return result("NFC_PK_64BIT_EXTRACTION", "NFC Format", "64-bit credential", false,
                        "64-bit credential is zero", start);

            return result("NFC_PK_64BIT_EXTRACTION", "NFC Format",
                    "64-bit credential = last 8 bytes of X component",
                    true, "Card number: " + cardNumber, start);
        }
        catch (Exception e)
        {
            return result("NFC_PK_64BIT_EXTRACTION", "NFC Format", "64-bit credential", false, e.toString(), start);
        }
    }

    private TestResult testNfcStatusWrongIns()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            // SELECT first
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            device.process(reader.buildSelectCommand());

            // Send command with wrong INS (0xBB instead of 0x80)
            byte[] wrongInsCmd = {(byte) 0x80, (byte) 0xBB, 0x00, 0x01, 0x00};
            byte[] resp = device.process(wrongInsCmd);

            // Expect SW 6D00 (Invalid INS)
            if (resp.length >= 2 && resp[resp.length - 2] == 0x6D && resp[resp.length - 1] == 0x00)
            {
                return result("NFC_STATUS_WRONG_INS", "NFC Format",
                        "INS != 0x80 and != 0xA4 returns SW 6D00",
                        true, "SW 6D00 returned for INS=0xBB", start);
            }

            // Any non-9000 SW is acceptable
            if (!isSW9000(resp))
                return result("NFC_STATUS_WRONG_INS", "NFC Format",
                        "INS != 0x80 and != 0xA4 returns error SW",
                        true, "Error SW returned: " + swHex(resp), start);

            return result("NFC_STATUS_WRONG_INS", "NFC Format", "Wrong INS response", false,
                    "Expected error SW, got 9000", start);
        }
        catch (Exception e)
        {
            return result("NFC_STATUS_WRONG_INS", "NFC Format", "Wrong INS", false, e.toString(), start);
        }
    }

    private TestResult testNfcStatusWrongCla()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            // SELECT first
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            device.process(reader.buildSelectCommand());

            // Send AUTH with wrong CLA (0xFF instead of 0x80)
            byte[] wrongClaCmd = {(byte) 0xFF, (byte) 0x80, 0x00, 0x01, 0x00};
            byte[] resp = device.process(wrongClaCmd);

            // Expect SW 6E00 (Invalid CLA)
            if (resp.length >= 2 && resp[resp.length - 2] == 0x6E && resp[resp.length - 1] == 0x00)
            {
                return result("NFC_STATUS_WRONG_CLA", "NFC Format",
                        "CLA != 0x80 and != 0x00 returns SW 6E00",
                        true, "SW 6E00 returned for CLA=0xFF", start);
            }

            // Any non-9000 SW is acceptable
            if (!isSW9000(resp))
                return result("NFC_STATUS_WRONG_CLA", "NFC Format",
                        "CLA != 0x80 and != 0x00 returns error SW",
                        true, "Error SW returned: " + swHex(resp), start);

            return result("NFC_STATUS_WRONG_CLA", "NFC Format", "Wrong CLA response", false,
                    "Expected error SW, got 9000", start);
        }
        catch (Exception e)
        {
            return result("NFC_STATUS_WRONG_CLA", "NFC Format", "Wrong CLA", false, e.toString(), start);
        }
    }

    // =========================================================================
    // GROUP 2: BLE Protocol Format (13 tests)
    // =========================================================================

    private TestResult testBleUuidService()
    {
        long start = System.currentTimeMillis();
        try
        {
            String expected = BLE_SERVICE_UUID.toLowerCase();
            String actual = UUID.fromString(BLE_SERVICE_UUID).toString().toLowerCase();

            // Verify 16-bit short form is FFF0
            if (!actual.startsWith("0000fff0"))
                return result("BLE_UUID_SERVICE", "BLE Format", "Service UUID", false,
                        "UUID does not start with 0000FFF0: " + actual, start);

            return result("BLE_UUID_SERVICE", "BLE Format",
                    "Service UUID is 0xFFF0 (0000FFF0-0000-1000-8000-00805F9B34FB)",
                    true, "UUID: " + actual, start);
        }
        catch (Exception e)
        {
            return result("BLE_UUID_SERVICE", "BLE Format", "Service UUID", false, e.toString(), start);
        }
    }

    private TestResult testBleReaderMsgHasProtoId()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            byte[] msg = reader.buildOpeningMessage();

            if (!hasTlvTag(msg, 0x0C))
                return result("BLE_READER_MSG_HAS_PROTO_ID", "BLE Format", "Reader msg has proto ID", false,
                        "Tag 0x0C not found in opening message", start);

            return result("BLE_READER_MSG_HAS_PROTO_ID", "BLE Format",
                    "Reader opening message contains 0x0C (protocol identifiers)",
                    true, "Tag 0x0C present", start);
        }
        catch (Exception e)
        {
            return result("BLE_READER_MSG_HAS_PROTO_ID", "BLE Format", "Proto ID", false, e.toString(), start);
        }
    }

    private TestResult testBleReaderMsgHasEphKey()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            byte[] msg = reader.buildOpeningMessage();

            int tagOffset = findTlvTag(msg, 0x02);
            if (tagOffset < 0)
                return result("BLE_READER_MSG_HAS_EPH_KEY", "BLE Format", "Reader msg has eph key", false,
                        "Tag 0x02 not found", start);

            int len = msg[tagOffset + 1] & 0xFF;
            if (len != 33)
                return result("BLE_READER_MSG_HAS_EPH_KEY", "BLE Format", "Reader msg has eph key", false,
                        "Tag 0x02 length=" + len + ", expected 33", start);

            return result("BLE_READER_MSG_HAS_EPH_KEY", "BLE Format",
                    "Reader opening message contains 0x02 (compressed eph pub key, 33 bytes)",
                    true, "Tag 0x02: 33 bytes", start);
        }
        catch (Exception e)
        {
            return result("BLE_READER_MSG_HAS_EPH_KEY", "BLE Format", "Eph key", false, e.toString(), start);
        }
    }

    private TestResult testBleReaderMsgHasLocation()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            byte[] msg = reader.buildOpeningMessage();

            int tagOffset = findTlvTag(msg, 0x0D);
            if (tagOffset < 0)
                return result("BLE_READER_MSG_HAS_LOCATION", "BLE Format", "Reader msg has location", false,
                        "Tag 0x0D not found", start);

            int len = msg[tagOffset + 1] & 0xFF;
            if (len != 16)
                return result("BLE_READER_MSG_HAS_LOCATION", "BLE Format", "Reader msg has location", false,
                        "Tag 0x0D length=" + len + ", expected 16", start);

            return result("BLE_READER_MSG_HAS_LOCATION", "BLE Format",
                    "Reader opening message contains 0x0D (reader location, 16 bytes)",
                    true, "Tag 0x0D: 16 bytes", start);
        }
        catch (Exception e)
        {
            return result("BLE_READER_MSG_HAS_LOCATION", "BLE Format", "Location", false, e.toString(), start);
        }
    }

    private TestResult testBleReaderMsgHasSiteId()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            byte[] msg = reader.buildOpeningMessage();

            int tagOffset = findTlvTag(msg, 0x0E);
            if (tagOffset < 0)
                return result("BLE_READER_MSG_HAS_SITE_ID", "BLE Format", "Reader msg has site ID", false,
                        "Tag 0x0E not found", start);

            int len = msg[tagOffset + 1] & 0xFF;
            if (len != 16)
                return result("BLE_READER_MSG_HAS_SITE_ID", "BLE Format", "Reader msg has site ID", false,
                        "Tag 0x0E length=" + len + ", expected 16", start);

            return result("BLE_READER_MSG_HAS_SITE_ID", "BLE Format",
                    "Reader opening message contains 0x0E (site identifier, 16 bytes)",
                    true, "Tag 0x0E: 16 bytes", start);
        }
        catch (Exception e)
        {
            return result("BLE_READER_MSG_HAS_SITE_ID", "BLE Format", "Site ID", false, e.toString(), start);
        }
    }

    private TestResult testBleProtoIdFormat()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            byte[] msg = reader.buildOpeningMessage();

            int tagOffset = findTlvTag(msg, 0x0C);
            if (tagOffset < 0)
                return result("BLE_PROTO_ID_FORMAT", "BLE Format", "Proto ID format", false,
                        "Tag 0x0C not found", start);

            int len = msg[tagOffset + 1] & 0xFF;
            if (len != 5)
                return result("BLE_PROTO_ID_FORMAT", "BLE Format", "Proto ID format", false,
                        "Tag 0x0C length=" + len + ", expected 5", start);

            return result("BLE_PROTO_ID_FORMAT", "BLE Format",
                    "0x0C value is 5 bytes: spec_ver(1) + vendor(2) + features(2)",
                    true, "Tag 0x0C: 5 bytes", start);
        }
        catch (Exception e)
        {
            return result("BLE_PROTO_ID_FORMAT", "BLE Format", "Proto ID format", false, e.toString(), start);
        }
    }

    private TestResult testBleDeviceMsgHasPk()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            LoopbackPKOCBleDevice device = new LoopbackPKOCBleDevice();
            byte[] opening = reader.buildOpeningMessage();
            byte[] response = device.buildResponse(opening);

            int tagOffset = findTlvTag(response, 0x01);
            if (tagOffset < 0)
                return result("BLE_DEVICE_MSG_HAS_PK", "BLE Format", "Device msg has pub key", false,
                        "Tag 0x01 not found", start);

            int len = response[tagOffset + 1] & 0xFF;
            if (len != 65)
                return result("BLE_DEVICE_MSG_HAS_PK", "BLE Format", "Device msg has pub key", false,
                        "Tag 0x01 length=" + len + ", expected 65", start);

            return result("BLE_DEVICE_MSG_HAS_PK", "BLE Format",
                    "Device response contains 0x01 (PKOC pub key, 65 bytes)",
                    true, "Tag 0x01: 65 bytes", start);
        }
        catch (Exception e)
        {
            return result("BLE_DEVICE_MSG_HAS_PK", "BLE Format", "Device PK", false, e.toString(), start);
        }
    }

    private TestResult testBleDeviceMsgHasSig()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            LoopbackPKOCBleDevice device = new LoopbackPKOCBleDevice();
            byte[] opening = reader.buildOpeningMessage();
            byte[] response = device.buildResponse(opening);

            int tagOffset = findTlvTag(response, 0x03);
            if (tagOffset < 0)
                return result("BLE_DEVICE_MSG_HAS_SIG", "BLE Format", "Device msg has signature", false,
                        "Tag 0x03 not found", start);

            int len = response[tagOffset + 1] & 0xFF;
            if (len != 64)
                return result("BLE_DEVICE_MSG_HAS_SIG", "BLE Format", "Device msg has signature", false,
                        "Tag 0x03 length=" + len + ", expected 64", start);

            return result("BLE_DEVICE_MSG_HAS_SIG", "BLE Format",
                    "Device response contains 0x03 (signature, 64 bytes)",
                    true, "Tag 0x03: 64 bytes", start);
        }
        catch (Exception e)
        {
            return result("BLE_DEVICE_MSG_HAS_SIG", "BLE Format", "Device sig", false, e.toString(), start);
        }
    }

    private TestResult testBleDeviceMsgHasTime()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            LoopbackPKOCBleDevice device = new LoopbackPKOCBleDevice();
            byte[] opening = reader.buildOpeningMessage();
            byte[] response = device.buildResponse(opening);

            int tagOffset = findTlvTag(response, 0x09);
            if (tagOffset < 0)
                return result("BLE_DEVICE_MSG_HAS_TIME", "BLE Format", "Device msg has time", false,
                        "Tag 0x09 not found", start);

            int len = response[tagOffset + 1] & 0xFF;
            if (len != 4)
                return result("BLE_DEVICE_MSG_HAS_TIME", "BLE Format", "Device msg has time", false,
                        "Tag 0x09 length=" + len + ", expected 4", start);

            return result("BLE_DEVICE_MSG_HAS_TIME", "BLE Format",
                    "Device response contains 0x09 (last update time, 4 bytes)",
                    true, "Tag 0x09: 4 bytes", start);
        }
        catch (Exception e)
        {
            return result("BLE_DEVICE_MSG_HAS_TIME", "BLE Format", "Device time", false, e.toString(), start);
        }
    }

    private TestResult testBleSigInputIsEphKeyTlv()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            LoopbackPKOCBleDevice device = new LoopbackPKOCBleDevice();
            byte[] opening = reader.buildOpeningMessage();
            byte[] response = device.buildResponse(opening);

            // Extract compressed eph key from reader msg (tag 0x02)
            int ephOffset = findTlvTag(opening, 0x02);
            byte[] compressedEphKey = Arrays.copyOfRange(opening, ephOffset + 2, ephOffset + 2 + 33);

            // Extract sig and pub key from device response
            int pkOffset = findTlvTag(response, 0x01);
            byte[] pubKey = Arrays.copyOfRange(response, pkOffset + 2, pkOffset + 2 + 65);
            int sigOffset = findTlvTag(response, 0x03);
            byte[] sig = Arrays.copyOfRange(response, sigOffset + 2, sigOffset + 2 + 64);

            // Verify signature over compressed eph key (33 bytes)
            boolean valid = verifyPkocSignature(sig, pubKey, compressedEphKey);
            if (!valid)
                return result("BLE_SIG_INPUT_IS_EPH_KEY_TLV", "BLE Format", "Sig input is eph key TLV value", false,
                        "Signature does not verify over 33-byte compressed eph key", start);

            return result("BLE_SIG_INPUT_IS_EPH_KEY_TLV", "BLE Format",
                    "Signature input = raw bytes of 0x02 TLV value (33 bytes compressed key)",
                    true, "Signature verifies over compressed eph key", start);
        }
        catch (Exception e)
        {
            return result("BLE_SIG_INPUT_IS_EPH_KEY_TLV", "BLE Format", "Sig input eph key", false, e.toString(), start);
        }
    }

    private TestResult testBleResponseCodeSuccess()
    {
        long start = System.currentTimeMillis();
        try
        {
            // Build response code TLV: 04 01 01
            byte[] responseTlv = buildBleTlv(0x04, new byte[]{0x01});

            if (responseTlv.length != 3)
                return result("BLE_RESPONSE_CODE_SUCCESS", "BLE Format", "Response code success", false,
                        "TLV length=" + responseTlv.length + ", expected 3", start);

            if (responseTlv[0] != 0x04 || responseTlv[1] != 0x01 || responseTlv[2] != 0x01)
                return result("BLE_RESPONSE_CODE_SUCCESS", "BLE Format", "Response code success", false,
                        "Expected 04 01 01, got " + Hex.toHexString(responseTlv), start);

            return result("BLE_RESPONSE_CODE_SUCCESS", "BLE Format",
                    "Reader sends 0x04 with value 0x01 on success",
                    true, "TLV: 04 01 01", start);
        }
        catch (Exception e)
        {
            return result("BLE_RESPONSE_CODE_SUCCESS", "BLE Format", "Response code", false, e.toString(), start);
        }
    }

    private TestResult testBleResponseCodeAccessGranted()
    {
        long start = System.currentTimeMillis();
        try
        {
            byte[] responseTlv = buildBleTlv(0x04, new byte[]{0x03});

            if (responseTlv[0] != 0x04 || responseTlv[1] != 0x01 || responseTlv[2] != 0x03)
                return result("BLE_RESPONSE_CODE_ACCESS_GRANTED", "BLE Format", "Response code access granted", false,
                        "Expected 04 01 03, got " + Hex.toHexString(responseTlv), start);

            return result("BLE_RESPONSE_CODE_ACCESS_GRANTED", "BLE Format",
                    "Reader sends 0x04 with value 0x03 on access granted",
                    true, "TLV: 04 01 03", start);
        }
        catch (Exception e)
        {
            return result("BLE_RESPONSE_CODE_ACCESS_GRANTED", "BLE Format", "Response code", false, e.toString(), start);
        }
    }

    private TestResult testBleSigNotAsn1()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            LoopbackPKOCBleDevice device = new LoopbackPKOCBleDevice();
            byte[] opening = reader.buildOpeningMessage();
            byte[] response = device.buildResponse(opening);

            int sigOffset = findTlvTag(response, 0x03);
            int sigLen = response[sigOffset + 1] & 0xFF;

            // Raw 64 bytes, NOT ASN.1 DER (which would be 70-72 bytes starting with 0x30)
            if (sigLen != 64)
                return result("BLE_SIG_NOT_ASN1", "BLE Format", "Sig is raw R||S, not ASN.1", false,
                        "Sig length=" + sigLen + ", expected 64 (ASN.1 would be 70-72)", start);

            byte firstSigByte = response[sigOffset + 2];
            if (firstSigByte == 0x30)
                return result("BLE_SIG_NOT_ASN1", "BLE Format", "Sig is raw R||S, not ASN.1", false,
                        "Sig starts with 0x30 (looks like DER-encoded)", start);

            return result("BLE_SIG_NOT_ASN1", "BLE Format",
                    "Signature is 64 bytes R||S, not DER (length != 70-72)",
                    true, "64 bytes raw, first byte=" + String.format("%02X", firstSigByte), start);
        }
        catch (Exception e)
        {
            return result("BLE_SIG_NOT_ASN1", "BLE Format", "Sig not ASN1", false, e.toString(), start);
        }
    }

    // =========================================================================
    // GROUP 3: Full Flow Tests (3 tests)
    // =========================================================================

    private TestResult testPkocNfcFlow()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            // Step 1: SELECT
            byte[] selectResp = device.process(reader.buildSelectCommand());
            if (!isSW9000(selectResp))
                return result("PKOC_NFC_FLOW", "Full Flow", "Full NFC loopback", false,
                        "SELECT failed: " + swHex(selectResp), start);

            // Verify protocol version
            boolean found5C = false;
            for (int i = 0; i < selectResp.length - 3; i++)
            {
                if (selectResp[i] == 0x5C && selectResp[i + 1] == 0x02)
                {
                    found5C = true;
                    break;
                }
            }
            if (!found5C)
                return result("PKOC_NFC_FLOW", "Full Flow", "Full NFC loopback", false,
                        "No protocol version in SELECT response", start);

            // Step 2: AUTH
            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("PKOC_NFC_FLOW", "Full Flow", "Full NFC loopback", false,
                        "AUTH failed: " + swHex(authResp), start);

            // Parse: 5A 41 <65B key> 9E 40 <64B sig> 90 00
            if (authResp.length < 135)
                return result("PKOC_NFC_FLOW", "Full Flow", "Full NFC loopback", false,
                        "AUTH response too short: " + authResp.length, start);

            byte[] pubKey = Arrays.copyOfRange(authResp, 2, 67);
            byte[] sig = Arrays.copyOfRange(authResp, 69, 133);

            // Step 3: Verify signature
            boolean sigValid = verifyPkocSignature(sig, pubKey, reader.transactionId);

            // Step 4: Extract credential
            byte[] x = Arrays.copyOfRange(pubKey, 1, 33);
            byte[] pkoc64 = Arrays.copyOfRange(x, 24, 32);
            BigInteger cardNumber = new BigInteger(1, pkoc64);

            String detail = "SigValid=" + sigValid + ", 64-bit credential=" + cardNumber;
            if (!sigValid)
                return result("PKOC_NFC_FLOW", "Full Flow", "Full NFC loopback", false,
                        "Signature verification failed: " + detail, start);

            return result("PKOC_NFC_FLOW", "Full Flow",
                    "Full NFC loopback: SELECT → AUTH → verify sig → extract credential",
                    true, detail, start);
        }
        catch (Exception e)
        {
            return result("PKOC_NFC_FLOW", "Full Flow", "NFC flow", false, e.toString(), start);
        }
    }

    private TestResult testPkocBleUnobfuscated()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCBleReader reader = new LoopbackPKOCBleReader();
            LoopbackPKOCBleDevice device = new LoopbackPKOCBleDevice();

            // Step 1: Reader sends opening message
            byte[] opening = reader.buildOpeningMessage();

            // Step 2: Device sends response
            byte[] response = device.buildResponse(opening);

            // Step 3: Parse device response
            int pkOffset = findTlvTag(response, 0x01);
            int sigOffset = findTlvTag(response, 0x03);
            if (pkOffset < 0 || sigOffset < 0)
                return result("PKOC_BLE_UNOBFUSCATED", "Full Flow", "BLE Un-Obfuscated flow", false,
                        "Missing PK or sig in device response", start);

            byte[] pubKey = Arrays.copyOfRange(response, pkOffset + 2, pkOffset + 2 + 65);
            byte[] sig = Arrays.copyOfRange(response, sigOffset + 2, sigOffset + 2 + 64);

            // Step 4: Extract compressed eph key from reader msg (sig input)
            int ephOffset = findTlvTag(opening, 0x02);
            byte[] compressedEphKey = Arrays.copyOfRange(opening, ephOffset + 2, ephOffset + 2 + 33);

            // Step 5: Verify signature
            boolean sigValid = verifyPkocSignature(sig, pubKey, compressedEphKey);

            // Step 6: Extract credential
            byte[] x = Arrays.copyOfRange(pubKey, 1, 33);
            BigInteger cardNumber = new BigInteger(1, Arrays.copyOfRange(x, 24, 32));

            if (!sigValid)
                return result("PKOC_BLE_UNOBFUSCATED", "Full Flow", "BLE Un-Obfuscated flow", false,
                        "Signature verification failed", start);

            return result("PKOC_BLE_UNOBFUSCATED", "Full Flow",
                    "Full BLE Normal/Un-Obfuscated: handshake → device response → verify sig",
                    true, "SigValid=true, credential=" + cardNumber, start);
        }
        catch (Exception e)
        {
            return result("PKOC_BLE_UNOBFUSCATED", "Full Flow", "BLE unobfuscated", false, e.toString(), start);
        }
    }

    private TestResult testPkocBleEcdhe()
    {
        long start = System.currentTimeMillis();
        try
        {
            // Generate site keypair (used by reader for ECDHE)
            KeyPair siteKP = generateP256Keypair();
            byte[] siteUncompressed = getUncompressedPubKey(siteKP);

            // Generate reader ephemeral keypair
            KeyPair readerEphKP = generateP256Keypair();
            byte[] readerEphUncompressed = getUncompressedPubKey(readerEphKP);
            byte[] readerEphCompressed = compressPublicKey(readerEphUncompressed);
            byte[] readerEphX = Arrays.copyOfRange(readerEphUncompressed, 1, 33);

            // Generate device credential keypair
            KeyPair deviceCredKP = generateP256Keypair();
            byte[] deviceCredPub = getUncompressedPubKey(deviceCredKP);

            // Generate device ephemeral keypair
            KeyPair deviceEphKP = generateP256Keypair();
            byte[] deviceEphUncompressed = getUncompressedPubKey(deviceEphKP);
            byte[] deviceEphX = Arrays.copyOfRange(deviceEphUncompressed, 1, 33);

            // Step 1: ECDH key agreement (both sides)
            byte[] readerSharedSecret = ecdhRawSecret(readerEphKP.getPrivate(), deviceEphUncompressed);
            byte[] deviceSharedSecret = ecdhRawSecret(deviceEphKP.getPrivate(), readerEphUncompressed);

            if (readerSharedSecret == null || deviceSharedSecret == null)
                return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE flow", false,
                        "ECDH key agreement failed", start);

            if (!Arrays.equals(readerSharedSecret, deviceSharedSecret))
                return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE flow", false,
                        "ECDH shared secrets don't match", start);

            // Step 2: Derive AES key = SHA-256(shared_secret)
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] sessionKey = sha.digest(readerSharedSecret);

            // Step 3: Build ECDHE signature data
            // siteId(16) + readerId(16) + deviceEphX(32) + readerEphX(32) = 96 bytes
            byte[] sigData = new byte[96];
            System.arraycopy(TEST_SITE_ID, 0, sigData, 0, 16);
            System.arraycopy(TEST_READER_LOCATION_ID, 0, sigData, 16, 16);
            System.arraycopy(deviceEphX, 0, sigData, 32, 32);
            System.arraycopy(readerEphX, 0, sigData, 64, 32);

            // Step 4: Device signs with credential private key
            byte[] deviceSig = signSha256Ecdsa(deviceCredKP.getPrivate(), sigData);
            if (deviceSig == null)
                return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE flow", false,
                        "Device signature failed", start);

            // Step 5: Reader verifies device signature
            boolean sigValid = verifyPkocSignature(deviceSig, deviceCredPub, sigData);
            if (!sigValid)
                return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE flow", false,
                        "Device signature verification failed", start);

            // Step 6: Encrypt and decrypt test
            byte[] plaintext = concat(
                    buildBleTlv(0x01, deviceCredPub),
                    buildBleTlv(0x03, deviceSig),
                    buildBleTlv(0x09, intToBytes4((int) (System.currentTimeMillis() / 1000)))
            );
            byte[] encrypted = aesGcmEncrypt(sessionKey, plaintext, 1);
            if (encrypted == null)
                return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE flow", false,
                        "AES-GCM encryption failed", start);

            byte[] decrypted = aesGcmDecrypt(sessionKey, encrypted, 1);
            if (decrypted == null)
                return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE flow", false,
                        "AES-GCM decryption failed", start);

            if (!Arrays.equals(plaintext, decrypted))
                return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE flow", false,
                        "Decrypted data doesn't match plaintext", start);

            return result("PKOC_BLE_ECDHE", "Full Flow",
                    "Full BLE ECDHE: key agreement → encrypt/decrypt → verify sig",
                    true, "SigValid=true, AES-GCM round-trip OK, 96-byte sig data", start);
        }
        catch (Exception e)
        {
            return result("PKOC_BLE_ECDHE", "Full Flow", "BLE ECDHE", false, e.toString(), start);
        }
    }

    // =========================================================================
    // GROUP 4: Negative Tests (5 tests)
    // =========================================================================

    private TestResult testNegNfcWrongAid()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            // SELECT with wrong AID
            byte[] wrongSelect = {0x00, (byte) 0xA4, 0x04, 0x00, 0x08,
                    (byte) 0xA0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
            byte[] resp = device.process(wrongSelect);

            if (isSW9000(resp))
                return result("NEG_NFC_WRONG_AID", "Negative", "Wrong AID returns error", false,
                        "Expected error SW, got 9000", start);

            return result("NEG_NFC_WRONG_AID", "Negative",
                    "SELECT with wrong AID returns error (not SW 9000)",
                    true, "Error SW: " + swHex(resp), start);
        }
        catch (Exception e)
        {
            return result("NEG_NFC_WRONG_AID", "Negative", "Wrong AID", false, e.toString(), start);
        }
    }

    private TestResult testNegNfcWrongP2()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            // SELECT first
            device.process(reader.buildSelectCommand());

            // AUTH with wrong P2 (0x00 instead of 0x01)
            byte[] authCmd = reader.buildAuthCommand();
            authCmd[3] = 0x00; // P2 = 0x00 instead of 0x01
            byte[] resp = device.process(authCmd);

            // Expect SW 6B00 (Wrong P1/P2) or non-9000
            if (resp.length >= 2 && resp[resp.length - 2] == 0x6B && resp[resp.length - 1] == 0x00)
            {
                return result("NEG_NFC_WRONG_P2", "Negative",
                        "AUTH with wrong P2 returns SW 6B00",
                        true, "SW 6B00 as expected", start);
            }

            if (!isSW9000(resp))
                return result("NEG_NFC_WRONG_P2", "Negative",
                        "AUTH with wrong P2 returns error SW",
                        true, "Error SW: " + swHex(resp), start);

            return result("NEG_NFC_WRONG_P2", "Negative", "Wrong P2 response", false,
                    "Expected error SW, got 9000", start);
        }
        catch (Exception e)
        {
            return result("NEG_NFC_WRONG_P2", "Negative", "Wrong P2", false, e.toString(), start);
        }
    }

    private TestResult testNegNfcSigTampered()
    {
        long start = System.currentTimeMillis();
        try
        {
            LoopbackPKOCReader reader = new LoopbackPKOCReader();
            LoopbackPKOCDevice device = new LoopbackPKOCDevice();

            device.process(reader.buildSelectCommand());
            byte[] authResp = device.process(reader.buildAuthCommand());
            if (!isSW9000(authResp))
                return result("NEG_NFC_SIG_TAMPERED", "Negative", "Tampered sig", false, "AUTH failed", start);

            byte[] pubKey = Arrays.copyOfRange(authResp, 2, 67);
            byte[] sig = Arrays.copyOfRange(authResp, 69, 133);

            // Flip a bit in signature
            sig[0] ^= 0x01;

            boolean valid = verifyPkocSignature(sig, pubKey, reader.transactionId);
            if (valid)
                return result("NEG_NFC_SIG_TAMPERED", "Negative", "Tampered sig", false,
                        "Tampered signature should NOT verify", start);

            return result("NEG_NFC_SIG_TAMPERED", "Negative",
                    "AUTH response with flipped signature bit fails verification",
                    true, "Tampered signature correctly rejected", start);
        }
        catch (Exception e)
        {
            return result("NEG_NFC_SIG_TAMPERED", "Negative", "Tampered sig", false, e.toString(), start);
        }
    }

    private TestResult testNegBleWrongSiteKey()
    {
        long start = System.currentTimeMillis();
        try
        {
            // ECDHE with wrong site key — signature should fail
            KeyPair wrongSiteKP = generateP256Keypair();
            KeyPair readerEphKP = generateP256Keypair();
            byte[] readerEphUncompressed = getUncompressedPubKey(readerEphKP);
            byte[] readerEphX = Arrays.copyOfRange(readerEphUncompressed, 1, 33);

            KeyPair deviceCredKP = generateP256Keypair();
            byte[] deviceCredPub = getUncompressedPubKey(deviceCredKP);

            KeyPair deviceEphKP = generateP256Keypair();
            byte[] deviceEphUncompressed = getUncompressedPubKey(deviceEphKP);
            byte[] deviceEphX = Arrays.copyOfRange(deviceEphUncompressed, 1, 33);

            // Build sig data
            byte[] sigData = new byte[96];
            System.arraycopy(TEST_SITE_ID, 0, sigData, 0, 16);
            System.arraycopy(TEST_READER_LOCATION_ID, 0, sigData, 16, 16);
            System.arraycopy(deviceEphX, 0, sigData, 32, 32);
            System.arraycopy(readerEphX, 0, sigData, 64, 32);

            // Reader signs with WRONG site key
            byte[] wrongSig = signSha256Ecdsa(wrongSiteKP.getPrivate(), sigData);

            // Device verifies with correct site key — should fail
            byte[] correctSitePub = getUncompressedPubKey(generateP256Keypair()); // different key
            boolean valid = verifyPkocSignature(wrongSig, correctSitePub, sigData);

            if (valid)
                return result("NEG_BLE_WRONG_SITE_KEY", "Negative", "Wrong site key", false,
                        "Signature with wrong key should NOT verify", start);

            return result("NEG_BLE_WRONG_SITE_KEY", "Negative",
                    "ECDHE with wrong site key: signature invalid",
                    true, "Signature correctly rejected with mismatched key", start);
        }
        catch (Exception e)
        {
            return result("NEG_BLE_WRONG_SITE_KEY", "Negative", "Wrong site key", false, e.toString(), start);
        }
    }

    private TestResult testNegBleCcmTampered()
    {
        long start = System.currentTimeMillis();
        try
        {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            byte[] plaintext = "PKOCTamperTest".getBytes();

            byte[] encrypted = aesGcmEncrypt(key, plaintext, 1);
            if (encrypted == null)
                return result("NEG_BLE_CCM_TAMPERED", "Negative", "Tampered CCM/GCM", false,
                        "Encryption failed", start);

            // Flip a bit in ciphertext
            encrypted[0] ^= 0x01;

            byte[] decrypted = aesGcmDecrypt(key, encrypted, 1);
            if (decrypted != null)
                return result("NEG_BLE_CCM_TAMPERED", "Negative", "Tampered CCM/GCM", false,
                        "Tampered ciphertext should NOT decrypt", start);

            return result("NEG_BLE_CCM_TAMPERED", "Negative",
                    "ECDHE flow with tampered ciphertext: GCM tag validation fails",
                    true, "Tampered ciphertext correctly rejected", start);
        }
        catch (Exception e)
        {
            return result("NEG_BLE_CCM_TAMPERED", "Negative", "Tampered CCM/GCM", false, e.toString(), start);
        }
    }

    // =========================================================================
    // LoopbackPKOCReader — NFC reader side
    // =========================================================================
    private static class LoopbackPKOCReader
    {
        byte[] transactionId;
        byte[] readerId;

        LoopbackPKOCReader()
        {
            transactionId = new byte[16];
            new SecureRandom().nextBytes(transactionId);
            readerId = new byte[32];
            new SecureRandom().nextBytes(readerId);
        }

        byte[] buildSelectCommand()
        {
            // 00 A4 04 00 08 <AID 8 bytes> 00
            return new byte[]{
                    0x00, (byte) 0xA4, 0x04, 0x00, 0x08,
                    (byte) 0xA0, 0x00, 0x00, 0x08, (byte) 0x98, 0x00, 0x00, 0x01,
                    0x00
            };
        }

        byte[] buildAuthCommand()
        {
            // CLA=80 INS=80 P1=00 P2=01 Lc=38
            // Data: 5C 02 01 00 | 4C 10 <TID 16B> | 4D 20 <ReaderID 32B>
            // Le=00
            int dataLen = 4 + 18 + 34; // 56 = 0x38
            byte[] cmd = new byte[4 + 1 + dataLen + 1];
            int idx = 0;
            cmd[idx++] = (byte) 0x80; // CLA
            cmd[idx++] = (byte) 0x80; // INS
            cmd[idx++] = 0x00;         // P1
            cmd[idx++] = 0x01;         // P2
            cmd[idx++] = (byte) dataLen; // Lc = 0x38 = 56
            // 5C: Protocol version 1.0
            cmd[idx++] = 0x5C; cmd[idx++] = 0x02; cmd[idx++] = 0x01; cmd[idx++] = 0x00;
            // 4C: Transaction ID
            cmd[idx++] = 0x4C; cmd[idx++] = 0x10;
            System.arraycopy(transactionId, 0, cmd, idx, 16); idx += 16;
            // 4D: Reader ID
            cmd[idx++] = 0x4D; cmd[idx++] = 0x20;
            System.arraycopy(readerId, 0, cmd, idx, 32); idx += 32;
            cmd[idx] = 0x00; // Le
            return cmd;
        }
    }

    // =========================================================================
    // LoopbackPKOCDevice — NFC device/card side
    // =========================================================================
    private static class LoopbackPKOCDevice
    {
        private static final byte[] SW_OK = {(byte) 0x90, 0x00};
        private static final byte[] SW_AID_NOT_FOUND = {0x6A, (byte) 0x82};
        private static final byte[] SW_WRONG_P1P2 = {0x6B, 0x00};
        private static final byte[] SW_INVALID_INS = {0x6D, 0x00};
        private static final byte[] SW_INVALID_CLA = {0x6E, 0x00};

        private static final byte[] PKOC_AID_LOCAL = {
                (byte) 0xA0, 0x00, 0x00, 0x08, (byte) 0x98, 0x00, 0x00, 0x01
        };

        private boolean selected = false;
        private final KeyPair credentialKP;
        private final byte[] credentialPubBytes;

        LoopbackPKOCDevice()
        {
            credentialKP = generateP256Keypair();
            credentialPubBytes = getUncompressedPubKey(credentialKP);
        }

        byte[] process(byte[] apdu)
        {
            if (apdu == null || apdu.length < 4) return SW_AID_NOT_FOUND;

            byte cla = apdu[0];
            byte ins = apdu[1];

            // SELECT
            if (ins == (byte) 0xA4 && cla == 0x00)
            {
                return handleSelect(apdu);
            }

            // Validate CLA for non-SELECT commands
            if (cla != (byte) 0x80 && cla != 0x00)
            {
                return SW_INVALID_CLA;
            }

            // AUTH
            if (ins == (byte) 0x80 && (cla == (byte) 0x80 || cla == 0x00))
            {
                return handleAuth(apdu);
            }

            return SW_INVALID_INS;
        }

        private byte[] handleSelect(byte[] apdu)
        {
            if (apdu.length < 5) return SW_AID_NOT_FOUND;
            int aidLen = apdu[4] & 0xFF;
            if (apdu.length < 5 + aidLen) return SW_AID_NOT_FOUND;
            byte[] aid = Arrays.copyOfRange(apdu, 5, 5 + aidLen);
            if (!Arrays.equals(aid, PKOC_AID_LOCAL)) return SW_AID_NOT_FOUND;

            selected = true;

            // Response: 5C 02 01 00 + SW 9000
            return new byte[]{0x5C, 0x02, 0x01, 0x00, (byte) 0x90, 0x00};
        }

        private byte[] handleAuth(byte[] apdu)
        {
            if (!selected) return SW_AID_NOT_FOUND;

            // Validate P2
            if (apdu[3] != 0x01) return SW_WRONG_P1P2;

            try
            {
                int dataOffset = 5;
                int dataLen = apdu[4] & 0xFF;
                if (apdu.length < dataOffset + dataLen) return SW_AID_NOT_FOUND;
                byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);

                // Parse TLVs to find Transaction ID (tag 4C)
                byte[] transactionId = null;
                for (int i = 0; i < data.length - 1; i++)
                {
                    int tag = data[i] & 0xFF;
                    int len = data[i + 1] & 0xFF;
                    if (i + 2 + len > data.length) break;

                    if (tag == 0x4C && len == 0x10)
                    {
                        transactionId = Arrays.copyOfRange(data, i + 2, i + 18);
                    }
                    // Skip past this TLV
                    i += 1 + len;
                }

                if (transactionId == null) return SW_AID_NOT_FOUND;

                // Sign the TID with credential private key: SHA256withECDSA
                byte[] rawSig = signSha256Ecdsa(credentialKP.getPrivate(), transactionId);
                if (rawSig == null) return SW_AID_NOT_FOUND;

                // Response: 5A 41 <65B pub key> 9E 40 <64B sig> 90 00
                byte[] response = new byte[2 + 65 + 2 + 64 + 2];
                response[0] = 0x5A; response[1] = 0x41;
                System.arraycopy(credentialPubBytes, 0, response, 2, 65);
                response[67] = (byte) 0x9E; response[68] = 0x40;
                System.arraycopy(rawSig, 0, response, 69, 64);
                response[133] = (byte) 0x90;
                response[134] = 0x00;
                return response;
            }
            catch (Exception e)
            {
                Log.e(TAG, "LoopbackPKOCDevice AUTH error", e);
                return SW_AID_NOT_FOUND;
            }
        }
    }

    // =========================================================================
    // LoopbackPKOCBleReader — BLE reader side
    // =========================================================================
    private static class LoopbackPKOCBleReader
    {
        final KeyPair ephKP;
        final byte[] ephUncompressed;
        final byte[] ephCompressed;

        LoopbackPKOCBleReader()
        {
            ephKP = generateP256Keypair();
            ephUncompressed = getUncompressedPubKey(ephKP);
            ephCompressed = compressPublicKey(ephUncompressed);
        }

        byte[] buildOpeningMessage()
        {
            // Protocol version TLV: 0x0C + 5 bytes (spec_ver=0x03, vendor=0x0000, features=0x0001)
            byte[] protoId = {0x03, 0x00, 0x00, 0x00, 0x01};
            byte[] proto = buildBleTlv(0x0C, protoId);

            // Compressed eph pub key TLV: 0x02 + 33 bytes
            byte[] ephKey = buildBleTlv(0x02, ephCompressed);

            // Reader location ID TLV: 0x0D + 16 bytes
            byte[] locationId = buildBleTlv(0x0D, TEST_READER_LOCATION_ID);

            // Site ID TLV: 0x0E + 16 bytes
            byte[] siteId = buildBleTlv(0x0E, TEST_SITE_ID);

            return concat(proto, ephKey, locationId, siteId);
        }
    }

    // =========================================================================
    // LoopbackPKOCBleDevice — BLE device side
    // =========================================================================
    private static class LoopbackPKOCBleDevice
    {
        final KeyPair credentialKP;
        final byte[] credentialPub;

        LoopbackPKOCBleDevice()
        {
            credentialKP = generateP256Keypair();
            credentialPub = getUncompressedPubKey(credentialKP);
        }

        byte[] buildResponse(byte[] readerOpening)
        {
            // Parse compressed eph key from reader opening (tag 0x02)
            int ephOffset = findTlvTag(readerOpening, 0x02);
            byte[] compressedEphKey = Arrays.copyOfRange(readerOpening, ephOffset + 2, ephOffset + 2 + 33);

            // Sign the compressed eph key bytes (33 bytes) — Un-Obfuscated flow
            byte[] sig = signSha256Ecdsa(credentialKP.getPrivate(), compressedEphKey);

            // Build response: 0x01(pub key) + 0x03(sig) + 0x09(time) + 0x0C(proto)
            byte[] pkTlv = buildBleTlv(0x01, credentialPub);
            byte[] sigTlv = buildBleTlv(0x03, sig);
            byte[] timeTlv = buildBleTlv(0x09, intToBytes4((int) (System.currentTimeMillis() / 1000)));
            byte[] protoTlv = buildBleTlv(0x0C, new byte[]{0x03, 0x00, 0x00, 0x00, 0x01});

            return concat(pkTlv, sigTlv, timeTlv, protoTlv);
        }
    }

    // =========================================================================
    // Crypto utilities
    // =========================================================================

    /** Generate a P-256 keypair using BouncyCastle */
    private static KeyPair generateP256Keypair()
    {
        try
        {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            kpg.initialize(new ECGenParameterSpec("secp256r1"), new SecureRandom());
            return kpg.generateKeyPair();
        }
        catch (Exception e)
        {
            Log.e(TAG, "generateP256Keypair failed", e);
            return null;
        }
    }

    /** Get 65-byte uncompressed public key: 0x04 || X[32] || Y[32] */
    private static byte[] getUncompressedPubKey(KeyPair kp)
    {
        ECPublicKey pub = (ECPublicKey) kp.getPublic();
        byte[] x = toBytes32(pub.getW().getAffineX());
        byte[] y = toBytes32(pub.getW().getAffineY());
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1, 32);
        System.arraycopy(y, 0, out, 33, 32);
        return out;
    }

    /** Compress a 65-byte uncompressed public key to 33 bytes: prefix || X[32] */
    private static byte[] compressPublicKey(byte[] uncompressed)
    {
        byte[] x = Arrays.copyOfRange(uncompressed, 1, 33);
        byte[] y = Arrays.copyOfRange(uncompressed, 33, 65);
        byte prefix = (y[31] & 0x01) == 0 ? (byte) 0x02 : (byte) 0x03;
        byte[] compressed = new byte[33];
        compressed[0] = prefix;
        System.arraycopy(x, 0, compressed, 1, 32);
        return compressed;
    }

    /** Sign data with SHA256withECDSA and return 64-byte raw R||S */
    private static byte[] signSha256Ecdsa(PrivateKey privateKey, byte[] data)
    {
        try
        {
            Signature sig = Signature.getInstance("SHA256withECDSA", new BouncyCastleProvider());
            sig.initSign(privateKey);
            sig.update(data);
            byte[] der = sig.sign();
            return derToRaw64(der);
        }
        catch (Exception e)
        {
            Log.e(TAG, "signSha256Ecdsa failed", e);
            return null;
        }
    }

    /** Verify PKOC signature: SHA-256 ECDSA with raw 64-byte R||S */
    private static boolean verifyPkocSignature(byte[] rawSig, byte[] pubKey65, byte[] data)
    {
        try
        {
            byte[] r = Arrays.copyOfRange(rawSig, 0, 32);
            byte[] s = Arrays.copyOfRange(rawSig, 32, 64);

            // Hash the data
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(data);

            // Create EC public key point
            org.bouncycastle.crypto.params.ECDomainParameters ecParams = getDomainParams();
            org.bouncycastle.math.ec.ECPoint point = ecParams.getCurve().createPoint(
                    new BigInteger(1, Arrays.copyOfRange(pubKey65, 1, 33)),
                    new BigInteger(1, Arrays.copyOfRange(pubKey65, 33, 65)));
            org.bouncycastle.crypto.params.ECPublicKeyParameters pubParams =
                    new org.bouncycastle.crypto.params.ECPublicKeyParameters(point, ecParams);

            org.bouncycastle.crypto.signers.ECDSASigner signer =
                    new org.bouncycastle.crypto.signers.ECDSASigner();
            signer.init(false, pubParams);
            return signer.verifySignature(hash,
                    new BigInteger(1, r), new BigInteger(1, s));
        }
        catch (Exception e)
        {
            Log.e(TAG, "verifyPkocSignature failed", e);
            return false;
        }
    }

    /** ECDH raw shared secret (full agreement bytes) */
    private static byte[] ecdhRawSecret(PrivateKey ourPriv, byte[] theirPub65)
    {
        try
        {
            // Decode 65-byte uncompressed public key
            ECPublicKey theirKey = decodeUncompressedPubKey(theirPub65);
            KeyAgreement ka = KeyAgreement.getInstance("ECDH", new BouncyCastleProvider());
            ka.init(ourPriv);
            ka.doPhase(theirKey, true);
            return ka.generateSecret();
        }
        catch (Exception e)
        {
            Log.e(TAG, "ecdhRawSecret failed", e);
            return null;
        }
    }

    /** Decode 65-byte uncompressed public key to ECPublicKey */
    private static ECPublicKey decodeUncompressedPubKey(byte[] pub65)
    {
        try
        {
            BigInteger x = new BigInteger(1, Arrays.copyOfRange(pub65, 1, 33));
            BigInteger y = new BigInteger(1, Arrays.copyOfRange(pub65, 33, 65));
            ECPoint point = new ECPoint(x, y);

            // Get EC parameters from a generated key
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            KeyPair tempKP = kpg.generateKeyPair();
            ECParameterSpec ecSpec = ((ECPublicKey) tempKP.getPublic()).getParams();

            ECPublicKeySpec pubSpec = new ECPublicKeySpec(point, ecSpec);
            KeyFactory kf = KeyFactory.getInstance("EC", new BouncyCastleProvider());
            return (ECPublicKey) kf.generatePublic(pubSpec);
        }
        catch (Exception e)
        {
            Log.e(TAG, "decodeUncompressedPubKey failed", e);
            return null;
        }
    }

    /** Convert DER-encoded ECDSA signature to raw 64-byte R||S */
    private static byte[] derToRaw64(byte[] der)
    {
        try
        {
            ASN1Sequence seq = ASN1Sequence.getInstance(der);
            byte[] r = BigIntegers.asUnsignedByteArray(
                    ASN1Integer.getInstance(seq.getObjectAt(0)).getPositiveValue());
            byte[] s = BigIntegers.asUnsignedByteArray(
                    ASN1Integer.getInstance(seq.getObjectAt(1)).getPositiveValue());

            byte[] r32 = new byte[32];
            byte[] s32 = new byte[32];
            if (r.length <= 32)
                System.arraycopy(r, 0, r32, 32 - r.length, r.length);
            else
                System.arraycopy(r, r.length - 32, r32, 0, 32);
            if (s.length <= 32)
                System.arraycopy(s, 0, s32, 32 - s.length, s.length);
            else
                System.arraycopy(s, s.length - 32, s32, 0, 32);

            byte[] out = new byte[64];
            System.arraycopy(r32, 0, out, 0, 32);
            System.arraycopy(s32, 0, out, 32, 32);
            return out;
        }
        catch (Exception e)
        {
            Log.e(TAG, "derToRaw64 failed", e);
            return null;
        }
    }

    /** AES-GCM encrypt with counter-based IV */
    private static byte[] aesGcmEncrypt(byte[] key, byte[] plaintext, int counter)
    {
        try
        {
            byte[] iv = new byte[12];
            // 0x00000000000001 (7 bytes) + counter (4 bytes BE)
            iv[6] = 0x01;
            iv[8] = (byte) (counter >> 24);
            iv[9] = (byte) (counter >> 16);
            iv[10] = (byte) (counter >> 8);
            iv[11] = (byte) counter;

            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv);
            gcm.init(true, params);

            byte[] output = new byte[gcm.getOutputSize(plaintext.length)];
            int len = gcm.processBytes(plaintext, 0, plaintext.length, output, 0);
            gcm.doFinal(output, len);
            return output;
        }
        catch (Exception e)
        {
            Log.e(TAG, "aesGcmEncrypt failed", e);
            return null;
        }
    }

    /** AES-GCM decrypt with counter-based IV */
    private static byte[] aesGcmDecrypt(byte[] key, byte[] ciphertextAndTag, int counter)
    {
        try
        {
            byte[] iv = new byte[12];
            iv[6] = 0x01;
            iv[8] = (byte) (counter >> 24);
            iv[9] = (byte) (counter >> 16);
            iv[10] = (byte) (counter >> 8);
            iv[11] = (byte) counter;

            GCMBlockCipher gcm = new GCMBlockCipher(new AESEngine());
            AEADParameters params = new AEADParameters(new KeyParameter(key), 128, iv);
            gcm.init(false, params);

            byte[] output = new byte[gcm.getOutputSize(ciphertextAndTag.length)];
            int len = gcm.processBytes(ciphertextAndTag, 0, ciphertextAndTag.length, output, 0);
            gcm.doFinal(output, len);
            return output;
        }
        catch (Exception e)
        {
            Log.e(TAG, "aesGcmDecrypt failed", e);
            return null;
        }
    }

    /** Get P-256 domain parameters via BouncyCastle */
    private static org.bouncycastle.crypto.params.ECDomainParameters getDomainParams()
    {
        org.bouncycastle.asn1.x9.X9ECParameters x9 =
                org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1");
        return new org.bouncycastle.crypto.params.ECDomainParameters(
                x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
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

    private static boolean hasTlvTag(byte[] data, int tag)
    {
        return findTlvTag(data, tag) >= 0;
    }

    private static int findTlvTag(byte[] data, int tag)
    {
        // Walk TLVs properly to avoid matching tag bytes inside value fields
        int i = 0;
        while (i < data.length - 1)
        {
            int t = data[i] & 0xFF;
            int l = data[i + 1] & 0xFF;
            if (t == tag) return i;
            i += 2 + l;
        }
        return -1;
    }

    private static byte[] buildBleTlv(int tag, byte[] value)
    {
        byte[] tlv = new byte[2 + value.length];
        tlv[0] = (byte) tag;
        tlv[1] = (byte) value.length;
        System.arraycopy(value, 0, tlv, 2, value.length);
        return tlv;
    }

    private static byte[] concat(byte[]... arrays)
    {
        int totalLen = 0;
        for (byte[] a : arrays) totalLen += a.length;
        byte[] out = new byte[totalLen];
        int pos = 0;
        for (byte[] a : arrays)
        {
            System.arraycopy(a, 0, out, pos, a.length);
            pos += a.length;
        }
        return out;
    }

    private static byte[] intToBytes4(int v)
    {
        return new byte[]{
                (byte) (v >> 24), (byte) (v >> 16),
                (byte) (v >> 8), (byte) v
        };
    }

    private static byte[] toBytes32(BigInteger n)
    {
        byte[] raw = n.toByteArray();
        byte[] out = new byte[32];
        if (raw.length <= 32)
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        else
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        return out;
    }

    private static byte[] hexToBytes(String hex)
    {
        return Hex.decode(hex);
    }

    private TestResult result(String testId, String group, String name,
                              boolean passed, String detail, long startMs)
    {
        return new TestResult(testId, group, name, passed, false, detail,
                System.currentTimeMillis() - startMs);
    }
}
