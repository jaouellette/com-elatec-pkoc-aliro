package com.pkoc.readersimulator;

import android.annotation.SuppressLint;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothServerSocket;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelUuid;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import com.psia.pkoc.core.AliroBleMessage;
import com.psia.pkoc.core.AliroCryptoProvider;
import com.psia.pkoc.core.AliroMailbox;

import com.upokecenter.cbor.CBORObject;

import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.UUID;

/**
 * Aliro BLE Reader Service — runs the full Aliro 1.0 BLE-Only L2CAP CoC flow.
 *
 * Startup sequence:
 *   1. Open L2CAP server socket → get dynamic SPSM
 *   2. Start GATT server with Aliro FFF2 service (SPSM read + device version write chars)
 *   3. Start BLE advertising with FFF2 service data
 *   4. Accept L2CAP connection on background thread
 *   5. Run BLE-Only access protocol flow over L2CAP
 *   6. Broadcast result
 */
@RequiresApi(api = Build.VERSION_CODES.Q)
public class AliroBleReaderService extends Service
{
    private static final String TAG = "AliroBleReader";

    // Aliro BLE Service UUID (16-bit 0xFFF2 in full 128-bit form)
    static final UUID SERVICE_UUID = UUID.fromString("0000FFF2-0000-1000-8000-00805F9B34FB");

    // GATT characteristics
    static final UUID CHAR_SPSM_UUID = UUID.fromString("D3B5A130-9E23-4B3A-8BE4-6B1EE5F980A3");
    static final UUID CHAR_DEV_VERSION_UUID = UUID.fromString("BD4B9502-3F54-11EC-B919-0242AC120005");

    // Broadcast action for result
    public static final String ACTION_BLE_RESULT = "com.pkoc.readersimulator.ALIRO_BLE_RESULT";
    public static final String EXTRA_ACCESS_GRANTED      = "accessGranted";
    public static final String EXTRA_STATUS_MESSAGE      = "statusMessage";
    public static final String EXTRA_CREDENTIAL_PUB_KEY  = "credentialPubKey";
    public static final String EXTRA_SIG_VALID           = "sigValid";
    public static final String EXTRA_DEVICE_RESPONSE     = "deviceResponse";
    public static final String EXTRA_STEP_UP_ELEMENT_ID  = "stepUpElementId";
    public static final String EXTRA_MAILBOX_RESULT      = "mailboxResult";

    // Proprietary TLV from SELECT response (used in key derivation)
    private static final byte[] PROPRIETARY_TLV = {
        (byte)0xA5, 0x0A,
        (byte)0x80, 0x02, 0x00, 0x00,
        0x5C, 0x04, 0x01, 0x00, 0x00, 0x09
    };

    // Service binding
    private final IBinder binder = new LocalBinder();

    public class LocalBinder extends Binder
    {
        public AliroBleReaderService getService() { return AliroBleReaderService.this; }
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent)
    {
        return binder;
    }

    // State
    private BluetoothManager bluetoothManager;
    private BluetoothAdapter bluetoothAdapter;
    private BluetoothLeAdvertiser advertiser;
    private BluetoothGattServer gattServer;
    private BluetoothServerSocket l2capServerSocket;
    private int spsm;
    private volatile boolean running = false;
    private Thread acceptThread;

    // Credential-written selected version (default: version 1.0 + features 0x00)
    private volatile byte[] selectedVersion = { 0x01, 0x00 };
    private volatile byte[] selectedFeatures = { 0x00 };

    @Override
    public void onCreate()
    {
        super.onCreate();
        bluetoothManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        bluetoothAdapter = bluetoothManager.getAdapter();
    }

    @Override
    public void onDestroy()
    {
        stopAliroBle();
        super.onDestroy();
    }

    // -------------------------------------------------------------------------
    // Public API — called from HomeFragment via Binder
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    public void startAliroBle()
    {
        // If a previous accept thread is still alive and blocking on accept(),
        // the L2CAP infrastructure is already listening — nothing to do.
        if (running && acceptThread != null && acceptThread.isAlive())
        {
            Log.d(TAG, "Already running — accept thread alive");
            return;
        }

        // Previous accept thread died (server socket consumed / IO error) or
        // was never started.  Re-create the L2CAP server socket so a fresh
        // accept() can succeed, but keep GATT + advertising up.
        running = true;

        try
        {
            // Step 1: (Re-)open L2CAP server socket.
            // Android may consume the server socket after the first accepted
            // connection, so we must create a new one each time the accept
            // thread needs to be restarted.
            if (l2capServerSocket != null)
            {
                try { l2capServerSocket.close(); } catch (Exception ignored) {}
            }
            l2capServerSocket = bluetoothAdapter.listenUsingInsecureL2capChannel();
            spsm = l2capServerSocket.getPsm();
            Log.d(TAG, "L2CAP server socket opened, SPSM=" + spsm);

            // Step 2: Start GATT server (only once — keeps SPSM characteristic value stable)
            if (gattServer == null)
            {
                startGattServer();
            }
            else
            {
                // GATT server already running — update the SPSM characteristic
                // value in case the new server socket got a different PSM.
                updateSpsmCharacteristic();
            }

            // Step 3: Start advertising (only once)
            if (advertiser == null)
            {
                startAdvertising();
            }

            // Step 4: Accept L2CAP connections on background thread
            acceptThread = new Thread(() ->
            {
                while (running)
                {
                    try
                    {
                        Log.d(TAG, "Waiting for L2CAP connection...");
                        BluetoothSocket socket = l2capServerSocket.accept();
                        Log.d(TAG, "L2CAP connection accepted from " + socket.getRemoteDevice().getAddress());
                        runBleOnlyFlow(socket);
                    }
                    catch (IOException e)
                    {
                        if (running)
                        {
                            Log.e(TAG, "L2CAP accept error", e);
                        }
                        break;
                    }
                }
                Log.d(TAG, "Accept thread exiting");
            }, "AliroBleAccept");
            acceptThread.start();
        }
        catch (IOException e)
        {
            Log.e(TAG, "Failed to start L2CAP server", e);
            running = false;
            broadcastResult(false, "Failed to start L2CAP: " + e.getMessage());
        }
    }

    @SuppressLint("MissingPermission")
    public void stopAliroBle()
    {
        running = false;

        if (advertiser != null)
        {
            try { advertiser.stopAdvertising(advertiseCallback); }
            catch (Exception ignored) {}
            advertiser = null;
        }

        if (gattServer != null)
        {
            try { gattServer.clearServices(); gattServer.close(); }
            catch (Exception ignored) {}
            gattServer = null;
        }

        if (l2capServerSocket != null)
        {
            try { l2capServerSocket.close(); }
            catch (Exception ignored) {}
            l2capServerSocket = null;
        }

        if (acceptThread != null)
        {
            acceptThread.interrupt();
            acceptThread = null;
        }

        Log.d(TAG, "Aliro BLE stopped");
    }

    public boolean isRunning()
    {
        return running;
    }

    // -------------------------------------------------------------------------
    // GATT Server
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    private void startGattServer()
    {
        gattServer = bluetoothManager.openGattServer(this, gattCallback);
        if (gattServer == null)
        {
            Log.e(TAG, "Failed to open GATT server");
            return;
        }

        BluetoothGattService service = new BluetoothGattService(
                SERVICE_UUID, BluetoothGattService.SERVICE_TYPE_PRIMARY);

        // SPSM characteristic (READ)
        BluetoothGattCharacteristic spsmChar = new BluetoothGattCharacteristic(
                CHAR_SPSM_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ);

        // Build SPSM value: SPSM(2 BE) | SupportedVersionsLen(1) | Version(2) | FeaturesLen(1) | Features(1)
        byte[] spsmVal = new byte[] {
            (byte)((spsm >> 8) & 0xFF), (byte)(spsm & 0xFF),
            0x02,                // supported versions length = 2 bytes (one version)
            0x01, 0x00,          // version 1.0
            0x01,                // features supported length = 1
            0x00                 // features = 0
        };
        spsmChar.setValue(spsmVal);
        service.addCharacteristic(spsmChar);

        // Device version characteristic (WRITE)
        BluetoothGattCharacteristic devVersionChar = new BluetoothGattCharacteristic(
                CHAR_DEV_VERSION_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE);
        service.addCharacteristic(devVersionChar);

        gattServer.addService(service);
        Log.d(TAG, "GATT server started with Aliro FFF2 service");
    }

    /**
     * Update the SPSM value in the already-running GATT service.
     * Called when the L2CAP server socket is re-created (new PSM) but the
     * GATT server is kept alive between connections.
     */
    @SuppressLint("MissingPermission")
    private void updateSpsmCharacteristic()
    {
        if (gattServer == null) return;
        BluetoothGattService service = gattServer.getService(SERVICE_UUID);
        if (service == null) return;
        BluetoothGattCharacteristic spsmChar = service.getCharacteristic(CHAR_SPSM_UUID);
        if (spsmChar == null) return;

        byte[] spsmVal = new byte[] {
            (byte)((spsm >> 8) & 0xFF), (byte)(spsm & 0xFF),
            0x02,
            0x01, 0x00,
            0x01,
            0x00
        };
        spsmChar.setValue(spsmVal);
        Log.d(TAG, "Updated SPSM characteristic to " + spsm
                + " (" + org.bouncycastle.util.encoders.Hex.toHexString(spsmVal) + ")");
    }

    private final BluetoothGattServerCallback gattCallback = new BluetoothGattServerCallback()
    {
        @SuppressLint("MissingPermission")
        @Override
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState)
        {
            Log.d(TAG, "GATT connection state: " + newState + " device=" + device.getAddress());
        }

        @SuppressLint("MissingPermission")
        @Override
        public void onCharacteristicReadRequest(BluetoothDevice device, int requestId,
                int offset, BluetoothGattCharacteristic characteristic)
        {
            if (CHAR_SPSM_UUID.equals(characteristic.getUuid()))
            {
                byte[] value = characteristic.getValue();
                Log.d(TAG, "SPSM read request, returning " + Hex.toHexString(value));
                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
            }
            else
            {
                gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
            }
        }

        @SuppressLint("MissingPermission")
        @Override
        public void onCharacteristicWriteRequest(BluetoothDevice device, int requestId,
                BluetoothGattCharacteristic characteristic, boolean preparedWrite,
                boolean responseNeeded, int offset, byte[] value)
        {
            if (CHAR_DEV_VERSION_UUID.equals(characteristic.getUuid()))
            {
                Log.d(TAG, "Device version write: " + Hex.toHexString(value));
                // Parse: selectedVersion(2) | featuresLen(1) | features(variable)
                if (value != null && value.length >= 2)
                {
                    selectedVersion = Arrays.copyOfRange(value, 0, 2);
                    if (value.length >= 4)
                    {
                        int featLen = value[2] & 0xFF;
                        if (value.length >= 3 + featLen)
                        {
                            selectedFeatures = Arrays.copyOfRange(value, 3, 3 + featLen);
                        }
                    }
                }
                if (responseNeeded)
                {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
                }
            }
            else
            {
                if (responseNeeded)
                {
                    gattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                }
            }
        }
    };

    // -------------------------------------------------------------------------
    // BLE Advertising
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    private void startAdvertising()
    {
        advertiser = bluetoothAdapter.getBluetoothLeAdvertiser();
        if (advertiser == null)
        {
            Log.e(TAG, "BLE advertiser not available");
            return;
        }

        SharedPreferences prefs = getSharedPreferences("MainActivity", Context.MODE_PRIVATE);
        String readerIdHex = prefs.getString(AliroPreferences.READER_ID, "");

        // Build service data (bytes 7-30 of the ADV payload per Table 11-2)
        // byte 7 = flags, byte 8 = tx power, bytes 9-16 = truncated reader group id,
        // bytes 17-18 = sub id, bytes 19-22 = dynamic tag expiry, byte 23 = RFU, bytes 24-30 = dynamic tag
        byte[] serviceData = new byte[24]; // bytes 7 through 30 inclusive
        serviceData[0] = 0x40;   // BLE-Only supported (bit 6), version 0
        serviceData[1] = 0x00;   // TX power

        // Truncated reader group identifier = first 8 bytes of reader_identifier
        if (!readerIdHex.isEmpty())
        {
            byte[] readerIdBytes = Hex.decode(readerIdHex);
            int copyLen = Math.min(8, readerIdBytes.length);
            System.arraycopy(readerIdBytes, 0, serviceData, 2, copyLen);
        }
        // bytes 10-11 (relative): truncated sub-identifier = 0x00, 0x00
        serviceData[10] = 0x00;
        serviceData[11] = 0x00;
        // Dynamic Tag Expiry = 0xFFFFFFFF (unavailable)
        serviceData[12] = (byte)0xFF;
        serviceData[13] = (byte)0xFF;
        serviceData[14] = (byte)0xFF;
        serviceData[15] = (byte)0xFF;
        // RFU
        serviceData[16] = 0x00;
        // Dynamic tag (7 bytes) — random for simulator
        byte[] dynTag = AliroCryptoProvider.generateRandom(7);
        System.arraycopy(dynTag, 0, serviceData, 17, 7);

        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .build();

        // Set device name so credential app can display it in the reader list
        bluetoothAdapter.setName("ELATEC Aliro");

        ParcelUuid aliroUuid = ParcelUuid.fromString("0000FFF2-0000-1000-8000-00805F9B34FB");

        // Primary ADV packet: service UUID only (needed for ScanFilter.setServiceUuid() to match)
        AdvertiseData advertiseData = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(aliroUuid)
                .build();

        // Scan response: device name + structured Aliro service data payload (Table 11-2)
        // "ELATEC Aliro" = 14 bytes (2 overhead = 16), service data = 3+24 = 27 — too big together.
        // Use name only; Aliro spec service data is informational, SPSM comes from GATT.
        AdvertiseData scanResponse = new AdvertiseData.Builder()
                .setIncludeDeviceName(true)
                .build();

        advertiser.startAdvertising(settings, advertiseData, scanResponse, advertiseCallback);
        Log.d(TAG, "Aliro BLE advertising started");
    }

    private final AdvertiseCallback advertiseCallback = new AdvertiseCallback()
    {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect)
        {
            Log.i(TAG, "Aliro BLE advertising started successfully");
        }

        @Override
        public void onStartFailure(int errorCode)
        {
            Log.e(TAG, "Aliro BLE advertising failed: " + errorCode);
        }
    };

    // -------------------------------------------------------------------------
    // BLE-Only Access Protocol Flow (§11.1.2)
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    private void runBleOnlyFlow(BluetoothSocket socket)
    {
        InputStream in = null;
        OutputStream out = null;
        byte[] skReader = null;
        byte[] skDevice = null;
        byte[] bleSK = null;
        byte[] stepUpSK = null;
        int readerCounter = 1;
        int deviceCounter = 1;
        byte[] finalDeviceResponse  = null;  // populated if ENVELOPE succeeds
        String finalStepUpElementId = null;  // element ID requested
        String finalMailboxResult   = null;  // populated if mailbox read/write/set succeeds

        try
        {
            in = socket.getInputStream();
            out = socket.getOutputStream();

            // ------------------------------------------------------------------
            // Load reader config
            // ------------------------------------------------------------------
            // AliroConfigFragment saves via requireActivity().getPreferences() which writes
            // to "<ActivityClassName>.xml" — use that same file here.
            SharedPreferences prefs = getSharedPreferences("MainActivity", Context.MODE_PRIVATE);
            String privateKeyHex = prefs.getString(AliroPreferences.READER_PRIVATE_KEY, "");
            String readerIdHex   = prefs.getString(AliroPreferences.READER_ID, "");
            String issuerKeyHex  = prefs.getString(AliroPreferences.READER_ISSUER_PUBLIC_KEY, "");
            String certHex       = prefs.getString(AliroPreferences.READER_CERTIFICATE, "");

            if (privateKeyHex.isEmpty() || readerIdHex.isEmpty())
            {
                Log.e(TAG, "Aliro reader config not set");
                broadcastResult(false, "Aliro not configured");
                return;
            }

            byte[] readerPrivKeyBytes = Hex.decode(privateKeyHex);
            byte[] readerIdBytes      = Hex.decode(readerIdHex);
            byte[] certBytes          = certHex.isEmpty() ? null : Hex.decode(certHex);
            boolean useCert           = (certBytes != null && !issuerKeyHex.isEmpty());

            PrivateKey readerPrivKey = rawBytesToEcPrivateKey(readerPrivKeyBytes);
            if (readerPrivKey == null)
            {
                broadcastResult(false, "Failed to load reader private key");
                return;
            }

            byte[] readerPubKeyX = derivePublicKeyXFromPrivate(readerPrivKeyBytes);
            if (readerPubKeyX == null)
            {
                broadcastResult(false, "Failed to derive reader public key");
                return;
            }

            // ------------------------------------------------------------------
            // Step 1: Read "Initiate Access Protocol RKE" from credential
            // Expect: Protocol=2 (Notification), MsgID=6 (Initiate AP RKE)
            // ------------------------------------------------------------------
            byte[] initMsg = readAliroMessage(in);
            int[] initHeader = AliroBleMessage.parseHeader(initMsg);
            if (initHeader == null ||
                initHeader[0] != AliroBleMessage.PROTOCOL_NOTIFICATION ||
                initHeader[1] != AliroBleMessage.NOTIF_INITIATE_AP_RKE)
            {
                Log.e(TAG, "Expected Initiate AP RKE, got: " +
                        (initHeader != null ? initHeader[0] + "/" + initHeader[1] : "null"));
                broadcastResult(false, "Unexpected first message");
                return;
            }
            byte[] initPayload = AliroBleMessage.extractPayload(initMsg);
            Log.d(TAG, "Received Initiate AP RKE, payload: " + Hex.toHexString(initPayload));

            // ------------------------------------------------------------------
            // Step 2: Generate ephemeral keypair, transaction ID, build AUTH0
            // ------------------------------------------------------------------
            KeyPair readerEphKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (readerEphKP == null)
            {
                broadcastResult(false, "Ephemeral keygen failed");
                return;
            }
            byte[] readerEphPub  = AliroCryptoProvider.getUncompressedPublicKey(readerEphKP);
            byte[] readerEphPubX = Arrays.copyOfRange(readerEphPub, 1, 33);
            byte[] transactionId = AliroCryptoProvider.generateRandom(16);

            // Protocol version: use 01 00 (version 1.0)
            byte[] protocolVersion = { 0x01, 0x00 };

            byte[] auth0Apdu = buildAuth0Command(protocolVersion, readerEphPub, transactionId, readerIdBytes);
            byte[] auth0Msg = AliroBleMessage.build(AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RQ, auth0Apdu);
            out.write(auth0Msg);
            out.flush();
            Log.d(TAG, "Sent AUTH0 AP_RQ");

            // ------------------------------------------------------------------
            // Step 3: Read AUTH0 response (AP_RS)
            // ------------------------------------------------------------------
            byte[] auth0RspMsg = readAliroMessage(in);
            int[] auth0RspHeader = AliroBleMessage.parseHeader(auth0RspMsg);
            if (auth0RspHeader == null ||
                auth0RspHeader[0] != AliroBleMessage.PROTOCOL_AP ||
                auth0RspHeader[1] != AliroBleMessage.AP_RS)
            {
                broadcastResult(false, "Expected AUTH0 AP_RS");
                return;
            }
            byte[] auth0RspApdu = AliroBleMessage.extractPayload(auth0RspMsg);
            Log.d(TAG, "AUTH0 response: " + Hex.toHexString(auth0RspApdu));

            // Parse: 86 41 <UD eph pub key 65 bytes> 90 00
            if (auth0RspApdu.length < 69 ||
                auth0RspApdu[0] != (byte)0x86 || auth0RspApdu[1] != 0x41)
            {
                broadcastResult(false, "AUTH0 response format invalid");
                return;
            }
            byte[] udEphPub  = Arrays.copyOfRange(auth0RspApdu, 2, 67);
            byte[] udEphPubX = Arrays.copyOfRange(udEphPub, 1, 33);
            Log.d(TAG, "UD eph pub key: " + Hex.toHexString(udEphPub));

            // ------------------------------------------------------------------
            // Compute reader signature + derive session keys (128 bytes for BleSK)
            // ------------------------------------------------------------------
            byte[] readerSig = AliroCryptoProvider.computeReaderSignature(
                    readerPrivKey, readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            if (readerSig == null)
            {
                broadcastResult(false, "Reader signature failed");
                return;
            }

            byte[] auth0Flag = { 0x00, 0x01 };

            byte[] keybuf = AliroCryptoProvider.deriveKeys(
                    readerEphKP.getPrivate(),
                    udEphPub,
                    128,  // 128 bytes to include BleSK
                    protocolVersion,
                    readerPubKeyX,
                    readerIdBytes,
                    transactionId,
                    readerEphPubX,
                    udEphPubX,
                    PROPRIETARY_TLV,
                    null,                                    // auth0CmdVendorTLV
                    null,                                    // auth0RspVendorTLV
                    AliroCryptoProvider.INTERFACE_BYTE_BLE,
                    auth0Flag);

            if (keybuf == null)
            {
                broadcastResult(false, "Key derivation failed");
                return;
            }
            skReader  = Arrays.copyOfRange(keybuf, 0, 32);
            skDevice  = Arrays.copyOfRange(keybuf, 32, 64);
            stepUpSK  = Arrays.copyOfRange(keybuf, 64, 96);
            bleSK     = Arrays.copyOfRange(keybuf, 96, 128);

            // ------------------------------------------------------------------
            // Step 4 (optional): LOAD CERT
            // ------------------------------------------------------------------
            if (useCert)
            {
                byte[] loadCertApdu = buildLoadCertCommand(certBytes);
                byte[] loadCertMsg = AliroBleMessage.build(AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RQ, loadCertApdu);
                out.write(loadCertMsg);
                out.flush();
                Log.d(TAG, "Sent LOAD CERT AP_RQ");

                byte[] certRspMsg = readAliroMessage(in);
                byte[] certRspApdu = AliroBleMessage.extractPayload(certRspMsg);
                Log.d(TAG, "LOAD CERT response: " + Hex.toHexString(certRspApdu));
            }

            // ------------------------------------------------------------------
            // Step 5: Send AUTH1
            // ------------------------------------------------------------------
            byte[] auth1Apdu = buildAuth1Command(readerSig);
            byte[] auth1Msg = AliroBleMessage.build(AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RQ, auth1Apdu);
            out.write(auth1Msg);
            out.flush();
            Log.d(TAG, "Sent AUTH1 AP_RQ");

            // ------------------------------------------------------------------
            // Step 6: Read AUTH1 response
            // ------------------------------------------------------------------
            byte[] auth1RspMsg = readAliroMessage(in);
            byte[] auth1RspApdu = AliroBleMessage.extractPayload(auth1RspMsg);
            Log.d(TAG, "AUTH1 response: " + Hex.toHexString(auth1RspApdu));

            // Strip SW bytes if present (last 2 bytes = 90 00)
            byte[] encPayload = auth1RspApdu;
            if (auth1RspApdu.length >= 2 &&
                auth1RspApdu[auth1RspApdu.length - 2] == (byte)0x90 &&
                auth1RspApdu[auth1RspApdu.length - 1] == 0x00)
            {
                encPayload = Arrays.copyOfRange(auth1RspApdu, 0, auth1RspApdu.length - 2);
            }
            byte[] decrypted = AliroCryptoProvider.decryptDeviceGcm(skDevice, encPayload, deviceCounter++);
            if (decrypted == null)
            {
                broadcastResult(false, "AUTH1 decryption failed");
                return;
            }
            Log.d(TAG, "AUTH1 decrypted: " + Hex.toHexString(decrypted));

            // Parse signaling_bitmap (tag 0x5E 0x02) from AUTH1 response
            int signalingBits = 0;
            for (int si = 0; si < decrypted.length - 3; si++)
            {
                if ((decrypted[si] & 0xFF) == 0x5E && (decrypted[si + 1] & 0xFF) == 0x02)
                {
                    signalingBits = ((decrypted[si + 2] & 0xFF) << 8) | (decrypted[si + 3] & 0xFF);
                    Log.d(TAG, "signaling_bitmap=0x" + Integer.toHexString(signalingBits));
                    break;
                }
            }
            // CRITICAL: Over BLE, Bit2 MUST be ignored per spec Table 8-11
            boolean stepUpRequested = (signalingBits & 0x0001) != 0; // Bit0=Access Document available

            // Parse: 5A 41 <cred pub key 65> 9E 40 <sig 64> [5E 02 <hi> <lo>]
            if (decrypted.length < 131 || decrypted[0] != 0x5A || decrypted[1] != 0x41)
            {
                broadcastResult(false, "AUTH1 response format invalid");
                return;
            }
            byte[] credentialPubKey = Arrays.copyOfRange(decrypted, 2, 67);
            byte[] credentialSig    = Arrays.copyOfRange(decrypted, 69, 133);
            Log.d(TAG, "Credential pub key: " + Hex.toHexString(credentialPubKey));

            boolean sigValid = AliroCryptoProvider.verifyCredentialSignature(
                    credentialSig, credentialPubKey,
                    readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            Log.d(TAG, "Credential signature valid: " + sigValid);
            final byte[] finalCredPubKey = credentialPubKey;
            final boolean finalSigValid  = sigValid;

            // ------------------------------------------------------------------
            // Step 7: Send EXCHANGE with optional mailbox operations
            // Per CI-8: On BLE success, 0x97 is ABSENT; on failure, include 0x97 after 0xBA
            // Per Table 8-15 / CI-7: 0xBA comes BEFORE 0x97
            // ------------------------------------------------------------------
            boolean mailboxEnabled = prefs.getBoolean(AliroPreferences.MAILBOX_ENABLED, false);
            String mailboxOp = null;
            int mailboxReadLen = 0;
            byte[] mailboxBA = null;

            if (mailboxEnabled)
            {
                mailboxOp = prefs.getString(AliroPreferences.MAILBOX_OPERATION, "read");
                int mOffset = Integer.parseInt(prefs.getString(AliroPreferences.MAILBOX_OFFSET, "0"));
                int mLength = Integer.parseInt(prefs.getString(AliroPreferences.MAILBOX_LENGTH, "16"));
                boolean atomic = prefs.getBoolean(AliroPreferences.MAILBOX_ATOMIC, false);

                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

                // 0x8C is MANDATORY inside 0xBA (Table 8-16)
                if (atomic)
                {
                    baos.write(new byte[]{ (byte)0x8C, 0x01, 0x01 }, 0, 3);
                }
                else
                {
                    baos.write(new byte[]{ (byte)0x8C, 0x01, 0x00 }, 0, 3);
                }

                if ("read".equals(mailboxOp))
                {
                    baos.write(new byte[]{
                        (byte)0x87, 0x04,
                        (byte)((mOffset >> 8) & 0xFF), (byte)(mOffset & 0xFF),
                        (byte)((mLength >> 8) & 0xFF), (byte)(mLength & 0xFF)
                    }, 0, 6);
                    mailboxReadLen = mLength;
                }
                else if ("write".equals(mailboxOp))
                {
                    String dataHex = prefs.getString(AliroPreferences.MAILBOX_DATA, "");
                    byte[] writeData = dataHex.isEmpty() ? new byte[0] : Hex.decode(dataHex);
                    int writeLen = 2 + writeData.length;
                    baos.write(new byte[]{
                        (byte)0x8A, (byte)(writeLen & 0xFF),
                        (byte)((mOffset >> 8) & 0xFF), (byte)(mOffset & 0xFF)
                    }, 0, 4);
                    baos.write(writeData, 0, writeData.length);
                }
                else if ("set".equals(mailboxOp))
                {
                    String setValHex = prefs.getString(AliroPreferences.MAILBOX_SET_VALUE, "00");
                    byte setVal = (byte)(Integer.parseInt(setValHex, 16) & 0xFF);
                    baos.write(new byte[]{
                        (byte)0x95, 0x05,
                        (byte)((mOffset >> 8) & 0xFF), (byte)(mOffset & 0xFF),
                        (byte)((mLength >> 8) & 0xFF), (byte)(mLength & 0xFF),
                        setVal
                    }, 0, 7);
                }

                if (atomic)
                {
                    baos.write(new byte[]{ (byte)0x8C, 0x01, 0x00 }, 0, 3);
                }

                byte[] innerTlvs = baos.toByteArray();
                mailboxBA = new byte[2 + innerTlvs.length];
                mailboxBA[0] = (byte)0xBA;
                mailboxBA[1] = (byte)(innerTlvs.length & 0xFF);
                System.arraycopy(innerTlvs, 0, mailboxBA, 2, innerTlvs.length);

                Log.d(TAG, "Mailbox BA TLV: " + Hex.toHexString(mailboxBA));
            }

            // Build EXCHANGE plaintext per CI-8:
            // BLE success: [0xBA mailbox] only (NO 0x97)
            // BLE failure: [0xBA mailbox] + 0x97
            byte[] exchangePayload;
            if (sigValid)
            {
                // CI-8: success over BLE omits 0x97
                if (mailboxBA != null)
                {
                    exchangePayload = mailboxBA;
                }
                else
                {
                    // CI-8: BLE success with no mailbox — empty plaintext (no 0x97)
                    exchangePayload = new byte[0];
                }
            }
            else
            {
                // Failure: include 0x97 after 0xBA
                byte[] statusTlv = new byte[]{ (byte)0x97, 0x02, 0x00, (byte)0x82 };
                if (mailboxBA != null)
                {
                    exchangePayload = new byte[mailboxBA.length + statusTlv.length];
                    System.arraycopy(mailboxBA, 0, exchangePayload, 0, mailboxBA.length);
                    System.arraycopy(statusTlv, 0, exchangePayload, mailboxBA.length, statusTlv.length);
                }
                else
                {
                    exchangePayload = statusTlv;
                }
            }

            byte[] encExchange = AliroCryptoProvider.encryptReaderGcm(skReader, exchangePayload, readerCounter++);
            if (encExchange != null)
            {
                byte[] exchangeApdu = buildExchangeCommand(encExchange);
                byte[] exchangeMsg = AliroBleMessage.build(AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RQ, exchangeApdu);
                out.write(exchangeMsg);
                out.flush();
                Log.d(TAG, "Sent EXCHANGE AP_RQ");

                byte[] exchangeRspMsg = readAliroMessage(in);
                byte[] exchangeRspApdu = AliroBleMessage.extractPayload(exchangeRspMsg);
                Log.d(TAG, "EXCHANGE response: " + Hex.toHexString(exchangeRspApdu));

                // Decrypt EXCHANGE response with counter
                byte[] encExchangeRsp = exchangeRspApdu;
                if (exchangeRspApdu.length >= 2 &&
                    exchangeRspApdu[exchangeRspApdu.length - 2] == (byte)0x90 &&
                    exchangeRspApdu[exchangeRspApdu.length - 1] == 0x00)
                {
                    encExchangeRsp = Arrays.copyOfRange(exchangeRspApdu, 0, exchangeRspApdu.length - 2);
                }
                byte[] decExchangeRsp = AliroCryptoProvider.decryptDeviceGcm(skDevice, encExchangeRsp, deviceCounter++);

            if (decExchangeRsp != null && mailboxEnabled
                    && ("write".equals(mailboxOp) || "set".equals(mailboxOp)))
            {
                finalMailboxResult = mailboxOp.toUpperCase() + " OK";
                Log.d(TAG, "Mailbox " + mailboxOp + " accepted by credential");
            }
                if (decExchangeRsp != null)
                {
                    Log.d(TAG, "EXCHANGE response decrypted: " + Hex.toHexString(decExchangeRsp));

                    // Mailbox read data comes BEFORE status bytes
                    if (mailboxEnabled && "read".equals(mailboxOp) && mailboxReadLen > 0)
                    {
                        if (decExchangeRsp.length > 4)
                        {
                            int readDataLen = decExchangeRsp.length - 4;
                            if (readDataLen > 0)
                            {
                                byte[] mailboxReadData = Arrays.copyOfRange(decExchangeRsp, 0, readDataLen);
                                // Parse mailbox using the shared §18 TLV parser for
                                // human-readable display (same as NFC path)
                                if (mailboxReadData.length > 0 && (mailboxReadData[0] & 0xFF) == 0x60)
                                    finalMailboxResult = AliroMailbox.parseMailboxToString(mailboxReadData, readDataLen);
                                else
                                    finalMailboxResult = "Read " + readDataLen + "B: " + Hex.toHexString(mailboxReadData);
                                Log.d(TAG, "Mailbox READ response (" + readDataLen + " bytes): "
                                        + Hex.toHexString(mailboxReadData));
                            }
                            else
                            {
                                finalMailboxResult = "Read — empty (mailbox may not be initialized)";
                            }
                        }
                        else
                        {
                            finalMailboxResult = "Read — empty (mailbox may not be initialized)";
                            Log.d(TAG, "Mailbox READ: no data returned");
                        }
                    }
                }
            }

            // ------------------------------------------------------------------
            // Step 7b: ENVELOPE (Step-Up) if credential signaled Access Document
            // ------------------------------------------------------------------
            if (stepUpRequested && stepUpSK != null)
            {
                String stepUpElementId = prefs.getString(AliroPreferences.STEP_UP_ELEMENT_ID, "");
                if (!stepUpElementId.isEmpty())
                {
                    byte[] suKeys = AliroCryptoProvider.deriveStepUpSessionKeys(stepUpSK);
                    if (suKeys != null)
                    {
                        byte[] suSKDevice = Arrays.copyOfRange(suKeys, 0, 32);
                        byte[] suSKReader = Arrays.copyOfRange(suKeys, 32, 64);

                        // Build DeviceRequest CBOR (Table 8-21).
                        // The Step-Up Element Identifier preference accepts a
                        // single value or a comma-separated list to request
                        // multiple elements per Aliro 1.0 §7.3 / §8.4.2.
                        CBORObject nameSpaces = CBORObject.NewMap();
                        CBORObject elemMap = CBORObject.NewMap();
                        for (String tok : stepUpElementId.split(","))
                        {
                            String eid = tok.trim();
                            if (!eid.isEmpty())
                                elemMap.Add(eid, CBORObject.True);
                        }
                        if (elemMap.size() == 0)
                            elemMap.Add(stepUpElementId, CBORObject.True);
                        nameSpaces.Add("aliro-a", elemMap);

                        CBORObject itemsReq = CBORObject.NewMap();
                        itemsReq.Add("1", nameSpaces);   // key "1" = nameSpaces
                        itemsReq.Add("5", "aliro-a");    // key "5" = docType

                        CBORObject docReq = CBORObject.NewMap();
                        docReq.Add("1", itemsReq);       // key "1" = itemsRequest

                        CBORObject docRequests = CBORObject.NewArray();
                        docRequests.Add(docReq);

                        CBORObject deviceRequest = CBORObject.NewMap();
                        deviceRequest.Add("2", docRequests); // key "2" = docRequests

                        byte[] deviceRequestBytes = deviceRequest.EncodeToBytes();

                        // Encrypt DeviceRequest with suSKReader (counter=1)
                        byte[] encDeviceRequest = AliroCryptoProvider.encryptReaderGcm(suSKReader, deviceRequestBytes, 1);

                        // Wrap in SessionData CBOR: {"data": bstr(ciphertext)}
                        CBORObject sessionData = CBORObject.NewMap();
                        sessionData.Add("data", encDeviceRequest);
                        byte[] envelopeData = sessionData.EncodeToBytes();

                        // Build ENVELOPE APDU (INS=0xC3)
                        byte[] envelopeApdu = buildEnvelopeCommand(envelopeData);
                        byte[] envelopeMsg = AliroBleMessage.build(
                                AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RQ, envelopeApdu);
                        out.write(envelopeMsg);
                        out.flush();
                        Log.d(TAG, "Sent ENVELOPE AP_RQ (DeviceRequest)");

                        // Read ENVELOPE response
                        byte[] envelopeRspMsg = readAliroMessage(in);
                        byte[] envelopeRspApdu = AliroBleMessage.extractPayload(envelopeRspMsg);
                        Log.d(TAG, "ENVELOPE response: " + Hex.toHexString(envelopeRspApdu));

                        // Strip SW if present
                        if (envelopeRspApdu.length >= 2 &&
                            envelopeRspApdu[envelopeRspApdu.length - 2] == (byte)0x90 &&
                            envelopeRspApdu[envelopeRspApdu.length - 1] == 0x00)
                        {
                            envelopeRspApdu = Arrays.copyOfRange(envelopeRspApdu, 0, envelopeRspApdu.length - 2);
                        }

                        // Parse SessionData CBOR, decrypt DeviceResponse
                        CBORObject rspSessionData = CBORObject.DecodeFromBytes(envelopeRspApdu);
                        byte[] encDeviceResponse = rspSessionData.get("data").GetByteString();
                        byte[] deviceResponse = AliroCryptoProvider.decryptDeviceGcm(suSKDevice, encDeviceResponse, 1);
                        if (deviceResponse != null)
                        {
                            Log.d(TAG, "DeviceResponse received (" + deviceResponse.length + " bytes): "
                                    + Hex.toHexString(deviceResponse));
                            finalDeviceResponse  = deviceResponse;
                            finalStepUpElementId = stepUpElementId;
                        }

                        // Zero step-up keys
                        Arrays.fill(suSKDevice, (byte)0);
                        Arrays.fill(suSKReader, (byte)0);
                        Arrays.fill(suKeys, (byte)0);
                    }
                }
            }

            // ------------------------------------------------------------------
            // Step 8: Derive BleSKReader / BleSKDevice (§11.8.1)
            // ------------------------------------------------------------------
            byte[] readerSupportedVersions = { 0x01, 0x00 };
            byte[] hkdfSalt = new byte[readerSupportedVersions.length + selectedVersion.length];
            System.arraycopy(readerSupportedVersions, 0, hkdfSalt, 0, readerSupportedVersions.length);
            System.arraycopy(selectedVersion, 0, hkdfSalt, readerSupportedVersions.length, selectedVersion.length);

            byte[] bleSKReader = AliroCryptoProvider.hkdfDeriveKey(bleSK, "BleSKReader", hkdfSalt, 32);
            byte[] bleSKDevice = AliroCryptoProvider.hkdfDeriveKey(bleSK, "BleSKDevice", hkdfSalt, 32);
            if (bleSKReader == null || bleSKDevice == null)
            {
                broadcastResult(false, "BleSK derivation failed");
                return;
            }

            // ------------------------------------------------------------------
            // Step 9: Send Reader Status Access Protocol Completed (encrypted with BleSKReader)
            // ------------------------------------------------------------------
            byte[] statusPlain = AliroBleMessage.buildAttribute(0x00, new byte[]{ 0x20, 0x01 });
            byte[] statusAad = AliroCryptoProvider.buildBleAad(
                    AliroBleMessage.PROTOCOL_NOTIFICATION,
                    AliroBleMessage.NOTIF_READER_STATUS_COMPLETED,
                    statusPlain.length);
            byte[] statusEncrypted = AliroCryptoProvider.encryptBleGcm(bleSKReader, statusPlain, statusAad, 1);
            if (statusEncrypted == null)
            {
                broadcastResult(false, "BLE status encryption failed");
                return;
            }
            byte[] statusMsg = AliroBleMessage.build(
                    AliroBleMessage.PROTOCOL_NOTIFICATION,
                    AliroBleMessage.NOTIF_READER_STATUS_COMPLETED,
                    statusEncrypted);
            out.write(statusMsg);
            out.flush();
            Log.d(TAG, "Sent Reader Status Completed");

            // ------------------------------------------------------------------
            // Step 10: Read RKE Request (encrypted with BleSKDevice)
            // ------------------------------------------------------------------
            byte[] rkeMsg = readAliroMessage(in);
            int[] rkeHeader = AliroBleMessage.parseHeader(rkeMsg);
            if (rkeHeader != null &&
                rkeHeader[0] == AliroBleMessage.PROTOCOL_NOTIFICATION &&
                rkeHeader[1] == AliroBleMessage.NOTIF_RKE_REQUEST)
            {
                byte[] rkeEncPayload = AliroBleMessage.extractPayload(rkeMsg);
                // Reconstruct AAD: we need the original plaintext length, but we don't know it
                // until we decrypt. For RKE, plain is AttrID(1)+AttrLen(1)+Action(1) = 3 bytes.
                byte[] rkeAad = AliroCryptoProvider.buildBleAad(
                        AliroBleMessage.PROTOCOL_NOTIFICATION,
                        AliroBleMessage.NOTIF_RKE_REQUEST,
                        3);  // RKE action attribute is 3 bytes
                byte[] rkePlain = AliroCryptoProvider.decryptBleGcm(bleSKDevice, rkeEncPayload, rkeAad, 1);
                if (rkePlain != null)
                {
                    Log.d(TAG, "RKE Request decrypted: " + Hex.toHexString(rkePlain));
                    // Parse: AttrID=0x00, AttrLen=0x01, Action (0=secure, 1=unsecure/unlock)
                    if (rkePlain.length >= 3)
                    {
                        int action = rkePlain[2] & 0xFF;
                        Log.d(TAG, "RKE action: " + action + " (0=secure, 1=unsecure)");
                    }
                    broadcastResult(true, "BLE Access Granted", finalCredPubKey, finalSigValid,
                            finalDeviceResponse, finalStepUpElementId, finalMailboxResult);
                }
                else
                {
                    Log.e(TAG, "RKE Request decryption failed");
                    broadcastResult(false, "RKE decryption failed");
                }
            }
            else
            {
                Log.w(TAG, "Did not receive expected RKE Request");
                broadcastResult(sigValid, sigValid ? "BLE Access Granted (no RKE)" : "BLE Signature Invalid");
            }
        }
        catch (IOException e)
        {
            Log.e(TAG, "BLE flow IO error", e);
            broadcastResult(false, "BLE IO error: " + e.getMessage());
        }
        catch (Exception e)
        {
            Log.e(TAG, "BLE flow error", e);
            broadcastResult(false, "BLE error: " + e.getMessage());
        }
        finally
        {
            // Zero session keys
            if (skReader != null)  Arrays.fill(skReader, (byte)0);
            if (skDevice != null)  Arrays.fill(skDevice, (byte)0);
            if (bleSK != null)     Arrays.fill(bleSK, (byte)0);
            if (stepUpSK != null)  Arrays.fill(stepUpSK, (byte)0);

            try { socket.close(); }
            catch (Exception ignored) {}
        }
    }

    // -------------------------------------------------------------------------
    // L2CAP message I/O
    // -------------------------------------------------------------------------

    /**
     * Read a complete Aliro BLE message from the L2CAP stream.
     * Reads 4-byte header, then payload of declared length.
     */
    private byte[] readAliroMessage(InputStream in) throws IOException
    {
        byte[] header = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = in.read(header, read, 4 - read);
            if (n < 0) throw new IOException("EOF reading header");
            read += n;
        }
        int payloadLen = ((header[2] & 0xFF) << 8) | (header[3] & 0xFF);
        byte[] msg = new byte[4 + payloadLen];
        System.arraycopy(header, 0, msg, 0, 4);
        read = 0;
        while (read < payloadLen)
        {
            int n = in.read(msg, 4 + read, payloadLen - read);
            if (n < 0) throw new IOException("EOF reading payload");
            read += n;
        }
        Log.d(TAG, "Read Aliro message: proto=" + (header[0] & 0xFF) +
                " msgId=" + (header[1] & 0xFF) + " len=" + payloadLen);
        return msg;
    }

    // -------------------------------------------------------------------------
    // APDU builders (same as HomeFragment NFC flow)
    // -------------------------------------------------------------------------

    private byte[] buildAuth0Command(byte[] protocolVersion, byte[] readerEphPub,
                                     byte[] transactionId, byte[] readerId)
    {
        int dataLen = 3 + 3 + 4 + 67 + 18 + 34; // 41+42+5C+87+4C+4D with tag+len
        byte[] cmd = new byte[4 + 1 + dataLen + 1];
        int idx = 0;
        cmd[idx++] = (byte)0x80; cmd[idx++] = (byte)0x80; cmd[idx++] = 0x00; cmd[idx++] = 0x00;
        cmd[idx++] = (byte) dataLen;
        cmd[idx++] = 0x41; cmd[idx++] = 0x01; cmd[idx++] = 0x00;
        cmd[idx++] = 0x42; cmd[idx++] = 0x01; cmd[idx++] = 0x01;
        cmd[idx++] = 0x5C; cmd[idx++] = 0x02;
        System.arraycopy(protocolVersion, 0, cmd, idx, 2); idx += 2;
        cmd[idx++] = (byte)0x87; cmd[idx++] = 0x41;
        System.arraycopy(readerEphPub, 0, cmd, idx, 65); idx += 65;
        cmd[idx++] = 0x4C; cmd[idx++] = 0x10;
        System.arraycopy(transactionId, 0, cmd, idx, 16); idx += 16;
        cmd[idx++] = 0x4D; cmd[idx++] = 0x20;
        System.arraycopy(readerId, 0, cmd, idx, 32); idx += 32;
        cmd[idx] = 0x00;
        return cmd;
    }

    private byte[] buildLoadCertCommand(byte[] cert)
    {
        boolean extended = cert.length > 255;
        int headerSize = 4 + (extended ? 3 : 1);
        byte[] cmd = new byte[headerSize + cert.length + 1];
        cmd[0] = (byte)0x80; cmd[1] = (byte)0xD1; cmd[2] = 0x00; cmd[3] = 0x00;
        int idx = 4;
        if (extended)
        {
            cmd[idx++] = 0x00;
            cmd[idx++] = (byte)(cert.length >> 8);
            cmd[idx++] = (byte)(cert.length & 0xFF);
        }
        else
        {
            cmd[idx++] = (byte) cert.length;
        }
        System.arraycopy(cert, 0, cmd, idx, cert.length);
        cmd[idx + cert.length] = 0x00;
        return cmd;
    }

    private byte[] buildAuth1Command(byte[] signature)
    {
        byte[] header = { (byte)0x80, (byte)0x81, 0x00, 0x00, 0x45,
                          0x41, 0x01, 0x01, (byte)0x9E, 0x40 };
        byte[] cmd = new byte[header.length + 64];
        System.arraycopy(header, 0, cmd, 0, header.length);
        System.arraycopy(signature, 0, cmd, header.length, 64);
        return cmd;
    }

    private byte[] buildExchangeCommand(byte[] encryptedPayload)
    {
        byte[] cmd = new byte[5 + encryptedPayload.length + 1];
        cmd[0] = (byte)0x80; cmd[1] = (byte)0xC9; cmd[2] = 0x00; cmd[3] = 0x00;
        cmd[4] = (byte) encryptedPayload.length;
        System.arraycopy(encryptedPayload, 0, cmd, 5, encryptedPayload.length);
        cmd[5 + encryptedPayload.length] = 0x00;
        return cmd;
    }

    private byte[] buildEnvelopeCommand(byte[] data)
    {
        // INS=0xC3, extended length if data > 255
        boolean extended = data.length > 255;
        int headerSize = 4 + (extended ? 3 : 1);
        byte[] cmd = new byte[headerSize + data.length + (extended ? 2 : 1)];
        cmd[0] = (byte)0x80; cmd[1] = (byte)0xC3; cmd[2] = 0x00; cmd[3] = 0x00;
        int idx = 4;
        if (extended)
        {
            cmd[idx++] = 0x00;
            cmd[idx++] = (byte)(data.length >> 8);
            cmd[idx++] = (byte)(data.length & 0xFF);
        }
        else
        {
            cmd[idx++] = (byte) data.length;
        }
        System.arraycopy(data, 0, cmd, idx, data.length);
        // Le
        cmd[idx + data.length] = 0x00;
        if (extended) cmd[idx + data.length + 1] = 0x00;
        return cmd;
    }

    // -------------------------------------------------------------------------
    // EC key helpers (same as HomeFragment)
    // -------------------------------------------------------------------------

    private PrivateKey rawBytesToEcPrivateKey(byte[] rawBytes)
    {
        try
        {
            java.math.BigInteger s = new java.math.BigInteger(1, rawBytes);
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec bcSpec =
                    org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
            org.bouncycastle.jce.spec.ECNamedCurveSpec spec =
                    new org.bouncycastle.jce.spec.ECNamedCurveSpec(
                            "secp256r1", bcSpec.getCurve(), bcSpec.getG(), bcSpec.getN());
            java.security.spec.ECPrivateKeySpec keySpec = new java.security.spec.ECPrivateKeySpec(s, spec);
            java.security.KeyFactory kf = java.security.KeyFactory.getInstance(
                    "EC", new org.bouncycastle.jce.provider.BouncyCastleProvider());
            return kf.generatePrivate(keySpec);
        }
        catch (Exception e)
        {
            Log.e(TAG, "rawBytesToEcPrivateKey failed", e);
            return null;
        }
    }

    private byte[] derivePublicKeyXFromPrivate(byte[] privateKeyBytes)
    {
        try
        {
            org.bouncycastle.asn1.x9.X9ECParameters x9 =
                    org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1");
            org.bouncycastle.crypto.params.ECDomainParameters domainParams =
                    new org.bouncycastle.crypto.params.ECDomainParameters(
                            x9.getCurve(), x9.getG(), x9.getN(), x9.getH());
            java.math.BigInteger privBI = new java.math.BigInteger(1, privateKeyBytes);
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

    // -------------------------------------------------------------------------
    // Broadcast
    // -------------------------------------------------------------------------

    private void broadcastResult(boolean accessGranted, String message)
    {
        broadcastResult(accessGranted, message, null, false);
    }

    private void broadcastResult(boolean accessGranted, String message,
                                  byte[] credentialPubKey, boolean sigValid)
    {
        broadcastResult(accessGranted, message, credentialPubKey, sigValid, null, null, null);
    }

    private void broadcastResult(boolean accessGranted, String message,
                                  byte[] credentialPubKey, boolean sigValid,
                                  byte[] deviceResponse, String stepUpElementId,
                                  String mailboxResult)
    {
        Intent intent = new Intent(ACTION_BLE_RESULT);
        intent.setPackage(getPackageName());
        intent.putExtra(EXTRA_ACCESS_GRANTED, accessGranted);
        intent.putExtra(EXTRA_STATUS_MESSAGE, message);
        intent.putExtra(EXTRA_SIG_VALID, sigValid);
        if (credentialPubKey != null)
        {
            intent.putExtra(EXTRA_CREDENTIAL_PUB_KEY,
                    org.bouncycastle.util.encoders.Hex.toHexString(credentialPubKey));
        }
        if (deviceResponse != null)
        {
            intent.putExtra(EXTRA_DEVICE_RESPONSE, deviceResponse);
        }
        if (stepUpElementId != null)
        {
            intent.putExtra(EXTRA_STEP_UP_ELEMENT_ID, stepUpElementId);
        }
        if (mailboxResult != null)
        {
            intent.putExtra(EXTRA_MAILBOX_RESULT, mailboxResult);
        }
        sendBroadcast(intent);
        Log.d(TAG, "Broadcast: accessGranted=" + accessGranted + " msg=" + message
                + (deviceResponse != null ? " deviceResponse=" + deviceResponse.length + "B" : ""));
    }
}
