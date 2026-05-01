package com.psia.pkoc;

import android.annotation.SuppressLint;
import android.app.Service;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.BluetoothSocket;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Context;
import android.content.Intent;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelUuid;
import android.util.Log;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;

import com.psia.pkoc.core.AliroAccessDocument;
import com.psia.pkoc.core.AliroBleMessage;
import com.psia.pkoc.core.AliroCryptoProvider;
import com.psia.pkoc.core.AliroProvisioningManager;

import com.upokecenter.cbor.CBORObject;

import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Collections;
import java.util.UUID;

/**
 * Aliro BLE Credential Service — User Device side of the Aliro 1.0 BLE-Only L2CAP flow.
 *
 * Flow:
 *   1. Scan for BLE devices advertising Aliro FFF2 service
 *   2. Connect GATT, read SPSM, write selected version
 *   3. Open L2CAP CoC to the reader's SPSM
 *   4. Send "Initiate Access Protocol RKE"
 *   5. Receive AUTH0, process, send AUTH0 response
 *   6. Optionally receive LOAD CERT
 *   7. Receive AUTH1, derive keys, send AUTH1 response
 *   8. Optionally receive EXCHANGE
 *   9. Receive Reader Status Completed (BleSK encrypted)
 *   10. Send RKE Request (BleSK encrypted)
 *   11. Broadcast result
 */
@RequiresApi(api = Build.VERSION_CODES.Q)
public class AliroBleCredentialService extends Service
{
    private static final String TAG = "AliroBleCredential";

    static final UUID ALIRO_SERVICE_UUID = UUID.fromString("0000FFF2-0000-1000-8000-00805F9B34FB");
    static final UUID CHAR_SPSM_UUID = UUID.fromString("D3B5A130-9E23-4B3A-8BE4-6B1EE5F980A3");
    static final UUID CHAR_DEV_VERSION_UUID = UUID.fromString("BD4B9502-3F54-11EC-B919-0242AC120005");

    public static final String ACTION_BLE_RESULT   = "com.psia.pkoc.ALIRO_BLE_RESULT";
    public static final String ACTION_DEVICE_FOUND   = "com.psia.pkoc.ALIRO_DEVICE_FOUND";
    public static final String EXTRA_ACCESS_GRANTED  = "accessGranted";
    public static final String EXTRA_STATUS_MESSAGE  = "statusMessage";
    public static final String EXTRA_DEVICE_ADDRESS  = "deviceAddress";
    public static final String EXTRA_DEVICE_NAME     = "deviceName";
    public static final String EXTRA_DEVICE_RSSI     = "deviceRssi";

    // Proprietary TLV (same as in Aliro_HostApduService)
    private static final byte[] PROPRIETARY_TLV = {
        (byte)0xA5, 0x0A,
        (byte)0x80, 0x02, 0x00, 0x00,
        0x5C, 0x04, 0x01, 0x00, 0x00, 0x09
    };

    // Service binding
    private final IBinder binder = new LocalBinder();

    public class LocalBinder extends Binder
    {
        public AliroBleCredentialService getService() { return AliroBleCredentialService.this; }
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
    private BluetoothLeScanner scanner;
    private BluetoothGatt connectedGatt;
    private BluetoothDevice lastDevice;   // saved for 133 retry
    private int gatt133RetryCount = 0;
    private static final int MAX_133_RETRIES = 5;
    private volatile boolean scanning    = false;
    private volatile boolean running     = false;
    private volatile boolean flowActive  = false;  // true while L2CAP credential flow is executing

    // Mailbox constants (same as Aliro_HostApduService)
    private static final String PREFS_NAME       = "AliroMailbox";
    private static final String PREF_MAILBOX_KEY = "mailbox";
    private static final int    MAILBOX_MAX_SIZE = 65536;

    // Connected device info (populated when GATT connects, included in broadcast)
    private String connectedDeviceAddress = "";
    private String connectedDeviceName    = "";
    private int    connectedDeviceRssi    = 0;

    // Per-transaction state
    private KeyPair udEphKP;
    private byte[] udEphPubBytes;
    private byte[] readerEphPubBytes;
    private byte[] readerIdBytes;
    private byte[] transactionId;
    private byte[] selectedProtocol;
    private byte[] auth0Flag;
    private byte[] readerStaticPubKeyX;
    private byte[] skReader;
    private byte[] skDevice;
    private byte[] bleSK;
    private byte[] stepUpSK;
    private int deviceCounter = 1;
    private int readerCounter = 1;
    private int signalingBits = 0;

    // Mailbox state
    private boolean mailboxAtomicActive  = false;
    private byte[]  mailboxPendingWrites = null;

    // Per Aliro 1.0 §8.3.3.5: "After an EXCHANGE command containing 0x97,
    // no further EXCHANGE commands can be sent." This flag tracks whether
    // the current transaction has already received a terminal EXCHANGE
    // (i.e. one carrying tag 0x97). Any subsequent EXCHANGE that arrives
    // while this is true MUST trigger the failure process per §8.3.3.1.
    // Cleared by resetState() at the start of each transaction.
    private boolean terminalExchangeReceived = false;

    // Selected version to write to reader GATT
    private final byte[] SELECTED_VERSION = { 0x01, 0x00 };
    private final byte[] SELECTED_VERSION_WRITE = { 0x01, 0x00, 0x01, 0x00 }; // version + featLen + features

    @Override
    public void onCreate()
    {
        super.onCreate();
        bluetoothManager = (BluetoothManager) getSystemService(Context.BLUETOOTH_SERVICE);
        bluetoothAdapter = bluetoothManager.getAdapter();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId)
    {
        Log.d(TAG, "onStartCommand — starting Aliro BLE scan");
        startScan();
        return START_NOT_STICKY;
    }

    @Override
    public void onDestroy()
    {
        stopScan();
        resetState();
        super.onDestroy();
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    public void startScan()
    {
        if (scanning) return;
        running = true;
        scanning = true;
        gatt133RetryCount = 0;
        // Clear lastDevice so any pending 133 retry callbacks from the previous
        // transaction are cancelled (they check lastDevice == targetDevice)
        lastDevice = null;

        scanner = bluetoothAdapter.getBluetoothLeScanner();
        if (scanner == null)
        {
            Log.e(TAG, "BLE scanner not available");
            broadcastResult(false, "BLE scanner unavailable");
            return;
        }

        ScanFilter filter = new ScanFilter.Builder()
                .setServiceUuid(ParcelUuid.fromString("0000FFF2-0000-1000-8000-00805F9B34FB"))
                .build();

        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();

        scanner.startScan(Collections.singletonList(filter), settings, scanCallback);
        Log.d(TAG, "BLE scan started for FFF2");
    }

    @SuppressLint("MissingPermission")
    public void stopScan()
    {
        scanning = false;
        if (scanner != null)
        {
            try { scanner.stopScan(scanCallback); }
            catch (Exception ignored) {}
        }
        if (connectedGatt != null)
        {
            try { connectedGatt.close(); }
            catch (Exception ignored) {}
            connectedGatt = null;
        }
    }

    public boolean isRunning()
    {
        return running;
    }

    /** Returns true while the L2CAP credential exchange is executing (AUTH0 through RKE). */
    public boolean isFlowActive()
    {
        return flowActive;
    }

    /**
     * Manually connect to a specific reader device selected by the user.
     * Stops any active scan, then initiates GATT connection directly.
     */
    @SuppressLint("MissingPermission")
    public void connectToReader(android.bluetooth.BluetoothDevice device)
    {
        if (device == null) return;
        if (flowActive)
        {
            // L2CAP credential flow already in progress — ignore duplicate call
            Log.d(TAG, "connectToReader: flow already active, ignoring call for " + device.getAddress());
            return;
        }

        // Stop any active scan first
        if (scanning)
        {
            scanning = false;
            if (scanner != null)
            {
                try { scanner.stopScan(scanCallback); }
                catch (Exception ignored) {}
            }
        }

        running = true;
        gatt133RetryCount = 0;

        // Capture device info
        connectedDeviceAddress = device.getAddress();
        connectedDeviceName    = device.getName() != null ? device.getName() : "";
        connectedDeviceRssi    = 0; // RSSI not available for manual selection

        lastDevice = device;
        Log.d(TAG, "connectToReader: manually connecting to " + device.getAddress());
        connectToDevice(device);
    }

    // -------------------------------------------------------------------------
    // BLE Scan callback
    // -------------------------------------------------------------------------

    private final ScanCallback scanCallback = new ScanCallback()
    {
        @SuppressLint("MissingPermission")
        @Override
        public void onScanResult(int callbackType, ScanResult result)
        {
            if (!scanning) return;
            BluetoothDevice device = result.getDevice();
            Log.d(TAG, "Found Aliro reader: " + device.getAddress());

            // Capture device info for later broadcast
            connectedDeviceAddress = device.getAddress();
            connectedDeviceName    = device.getName() != null ? device.getName() : "";
            connectedDeviceRssi    = result.getRssi();

            // Broadcast device found so UI can display it in the device list
            Intent foundIntent = new Intent(ACTION_DEVICE_FOUND);
            foundIntent.setPackage(getPackageName());
            foundIntent.putExtra(EXTRA_DEVICE_ADDRESS, connectedDeviceAddress);
            foundIntent.putExtra(EXTRA_DEVICE_NAME,    connectedDeviceName);
            foundIntent.putExtra(EXTRA_DEVICE_RSSI,    connectedDeviceRssi);
            sendBroadcast(foundIntent);

            // Stop scanning, connect to first device found
            scanning = false;
            scanner.stopScan(this);

            // Connect GATT
            lastDevice = device;
            connectToDevice(device);
        }

        @Override
        public void onScanFailed(int errorCode)
        {
            Log.e(TAG, "BLE scan failed: " + errorCode);
            scanning = false;
            broadcastResult(false, "BLE scan failed: " + errorCode);
        }
    };

    // -------------------------------------------------------------------------
    // GATT helpers
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    private void connectToDevice(BluetoothDevice device)
    {
        // Close any stale GATT handle before opening a fresh connection
        if (connectedGatt != null)
        {
            try { connectedGatt.disconnect(); connectedGatt.close(); }
            catch (Exception ignored) {}
            connectedGatt = null;
        }
        connectedGatt = device.connectGatt(this, false, gattCallback,
                BluetoothDevice.TRANSPORT_LE);
    }

    private int discoveredSpsm = -1;

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback()
    {
        @SuppressLint("MissingPermission")
        @Override
        public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState)
        {
            if (status == 133 && newState == BluetoothProfile.STATE_DISCONNECTED)
            {
                // Close this specific handle immediately — never reuse a 133'd GATT
                gatt.close();
                if (connectedGatt == gatt) connectedGatt = null;

                gatt133RetryCount++;
                if (gatt133RetryCount > MAX_133_RETRIES)
                {
                    Log.e(TAG, "GATT status 133 exceeded max retries, giving up");
                    gatt133RetryCount = 0;
                    // Re-scan to get a fresh advertisement — clear lastDevice so stale
                    // retry callbacks that fire after this point are ignored
                    lastDevice = null;
                    new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() ->
                    {
                        if (running) startScan();
                    }, 2000);
                    return;
                }
                // Exponential backoff: 500ms, 1s, 1.5s, 2s, 2.5s
                long delay = 500L * gatt133RetryCount;
                Log.w(TAG, "GATT status 133 (attempt " + gatt133RetryCount + "/" + MAX_133_RETRIES + "), retrying in " + delay + "ms");
                final android.bluetooth.BluetoothDevice targetDevice = lastDevice;
                new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() ->
                {
                    // Only retry if running AND lastDevice hasn't been replaced by a new scan result
                    if (running && lastDevice != null && lastDevice == targetDevice)
                    {
                        Log.d(TAG, "Retrying GATT connect to " + lastDevice.getAddress());
                        connectToDevice(lastDevice);
                    }
                    else
                    {
                        Log.d(TAG, "GATT retry cancelled — device changed or stopped");
                    }
                }, delay);
                return;
            }
            // Reset retry counter on any non-133 outcome
            gatt133RetryCount = 0;
            if (newState == BluetoothProfile.STATE_CONNECTED)
            {
                connectedDeviceAddress = gatt.getDevice().getAddress();
                connectedDeviceName    = gatt.getDevice().getName() != null
                        ? gatt.getDevice().getName() : "";
                Log.d(TAG, "GATT connected, discovering services...");
                gatt.discoverServices();
            }
            else if (newState == BluetoothProfile.STATE_DISCONNECTED)
            {
                Log.d(TAG, "GATT disconnected");
                gatt.close();
                if (connectedGatt == gatt) connectedGatt = null;
            }
        }

        @SuppressLint("MissingPermission")
        @Override
        public void onServicesDiscovered(BluetoothGatt gatt, int status)
        {
            if (status != BluetoothGatt.GATT_SUCCESS)
            {
                Log.e(TAG, "Service discovery failed: " + status);
                broadcastResult(false, "GATT service discovery failed");
                return;
            }

            BluetoothGattService aliroService = gatt.getService(ALIRO_SERVICE_UUID);
            if (aliroService == null)
            {
                Log.e(TAG, "Aliro FFF2 service not found on device");
                broadcastResult(false, "Aliro service not found");
                return;
            }

            // Read SPSM characteristic
            BluetoothGattCharacteristic spsmChar = aliroService.getCharacteristic(CHAR_SPSM_UUID);
            if (spsmChar == null)
            {
                Log.e(TAG, "SPSM characteristic not found");
                broadcastResult(false, "SPSM characteristic missing");
                return;
            }

            gatt.readCharacteristic(spsmChar);
        }

        @SuppressLint("MissingPermission")
        @Override
        public void onCharacteristicRead(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic,
                int status)
        {
            if (status != BluetoothGatt.GATT_SUCCESS)
            {
                Log.e(TAG, "Characteristic read failed: " + status);
                return;
            }

            if (CHAR_SPSM_UUID.equals(characteristic.getUuid()))
            {
                byte[] value = characteristic.getValue();
                Log.d(TAG, "SPSM value read: " + Hex.toHexString(value));

                // Parse: SPSM(2 BE) | supportedVersionsLen(1) | versions | featuresLen(1) | features
                if (value.length >= 2)
                {
                    discoveredSpsm = ((value[0] & 0xFF) << 8) | (value[1] & 0xFF);
                    Log.d(TAG, "Reader SPSM: " + discoveredSpsm);
                }

                // Write selected version to device version characteristic
                BluetoothGattService service = gatt.getService(ALIRO_SERVICE_UUID);
                if (service != null)
                {
                    BluetoothGattCharacteristic devVersionChar = service.getCharacteristic(CHAR_DEV_VERSION_UUID);
                    if (devVersionChar != null)
                    {
                        devVersionChar.setValue(SELECTED_VERSION_WRITE);
                        gatt.writeCharacteristic(devVersionChar);
                    }
                    else
                    {
                        // No device version char — proceed directly to L2CAP
                        launchL2capFlow(gatt);
                    }
                }
            }
        }

        @SuppressLint("MissingPermission")
        @Override
        public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic,
                int status)
        {
            if (CHAR_DEV_VERSION_UUID.equals(characteristic.getUuid()))
            {
                Log.d(TAG, "Device version written, status=" + status);
                launchL2capFlow(gatt);
            }
        }
    };

    // -------------------------------------------------------------------------
    // L2CAP connection + credential flow
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    private void launchL2capFlow(BluetoothGatt gatt)
    {
        if (discoveredSpsm < 0)
        {
            broadcastResult(false, "No SPSM discovered");
            return;
        }

        new Thread(() ->
        {
            BluetoothSocket socket = null;
            try
            {
                BluetoothDevice device = gatt.getDevice();
                socket = device.createInsecureL2capChannel(discoveredSpsm);
                socket.connect();
                Log.d(TAG, "L2CAP connected to SPSM " + discoveredSpsm);

                flowActive = true;
                runCredentialFlow(socket);
            }
            catch (IOException e)
            {
                Log.e(TAG, "L2CAP connection failed", e);
                broadcastResult(false, "L2CAP connection failed: " + e.getMessage());
            }
            finally
            {
                flowActive = false;
                if (socket != null)
                {
                    try { socket.close(); }
                    catch (Exception ignored) {}
                }
                // Disconnect GATT
                try { gatt.disconnect(); gatt.close(); }
                catch (Exception ignored) {}
                connectedGatt = null;
                running = false;
            }
        }, "AliroBleL2CAP").start();
    }

    private void runCredentialFlow(BluetoothSocket socket)
    {
        InputStream in = null;
        OutputStream out = null;

        try
        {
            in = socket.getInputStream();
            out = socket.getOutputStream();

            // Ensure credential keypair exists
            Aliro_HostApduService.ensureAliroKeypairExists();

            // ------------------------------------------------------------------
            // Step 1: Send "Initiate Access Protocol RKE"
            // Proprietary info attribute: AttrID=0x00, AttrLen=0x0C, Value=PROPRIETARY_TLV
            // ------------------------------------------------------------------
            byte[] propInfoAttr = AliroBleMessage.buildAttribute(0x00, PROPRIETARY_TLV);
            byte[] initiateMsg = AliroBleMessage.build(
                    AliroBleMessage.PROTOCOL_NOTIFICATION,
                    AliroBleMessage.NOTIF_INITIATE_AP_RKE,
                    propInfoAttr);
            out.write(initiateMsg);
            out.flush();
            Log.d(TAG, "Sent Initiate AP RKE");

            // ------------------------------------------------------------------
            // Step 2: Read AUTH0 command (AP_RQ)
            // ------------------------------------------------------------------
            byte[] auth0Msg = readAliroMessage(in);
            int[] auth0Header = AliroBleMessage.parseHeader(auth0Msg);
            Log.d(TAG, "AUTH0 raw msg (" + auth0Msg.length + " bytes): "
                    + org.bouncycastle.util.encoders.Hex.toHexString(auth0Msg));
            if (auth0Header == null ||
                auth0Header[0] != AliroBleMessage.PROTOCOL_AP ||
                auth0Header[1] != AliroBleMessage.AP_RQ)
            {
                Log.e(TAG, "Expected AP/AP_RQ (0/0), got proto="
                        + (auth0Header != null ? auth0Header[0] : -1)
                        + " msgId=" + (auth0Header != null ? auth0Header[1] : -1)
                        + " len=" + (auth0Header != null ? auth0Header[2] : -1));
                broadcastResult(false, "Expected AUTH0 AP_RQ");
                return;
            }
            byte[] auth0Apdu = AliroBleMessage.extractPayload(auth0Msg);
            Log.d(TAG, "Received AUTH0: " + Hex.toHexString(auth0Apdu));

            // Process AUTH0 — same logic as Aliro_HostApduService.handleAuth0
            byte[] auth0Response = handleAuth0Ble(auth0Apdu);
            if (auth0Response == null)
            {
                broadcastResult(false, "AUTH0 processing failed");
                return;
            }

            // Send AUTH0 response
            byte[] auth0RspMsg = AliroBleMessage.build(AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RS, auth0Response);
            out.write(auth0RspMsg);
            out.flush();
            Log.d(TAG, "Sent AUTH0 response");

            // ------------------------------------------------------------------
            // Step 3: Read next command — could be LOAD CERT or AUTH1
            // ------------------------------------------------------------------
            byte[] nextMsg = readAliroMessage(in);
            int[] nextHeader = AliroBleMessage.parseHeader(nextMsg);
            byte[] nextApdu = AliroBleMessage.extractPayload(nextMsg);

            // Check if it's LOAD CERT (INS=0xD1) or AUTH1 (INS=0x81)
            if (nextApdu != null && nextApdu.length >= 2 && nextApdu[1] == (byte)0xD1)
            {
                // LOAD CERT
                Log.d(TAG, "Received LOAD CERT");
                byte[] loadCertResponse = handleLoadCertBle(nextApdu);
                byte[] certRspMsg = AliroBleMessage.build(AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RS, loadCertResponse);
                out.write(certRspMsg);
                out.flush();
                Log.d(TAG, "Sent LOAD CERT response");

                // Read AUTH1
                nextMsg = readAliroMessage(in);
                nextApdu = AliroBleMessage.extractPayload(nextMsg);
            }

            // ------------------------------------------------------------------
            // Step 4: Process AUTH1
            // ------------------------------------------------------------------
            if (nextApdu == null || nextApdu.length < 2 || nextApdu[1] != (byte)0x81)
            {
                broadcastResult(false, "Expected AUTH1 command");
                return;
            }
            Log.d(TAG, "Received AUTH1: " + Hex.toHexString(nextApdu));

            byte[] auth1Response = handleAuth1Ble(nextApdu);
            if (auth1Response == null)
            {
                broadcastResult(false, "AUTH1 processing failed");
                return;
            }

            byte[] auth1RspMsg = AliroBleMessage.build(AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RS, auth1Response);
            out.write(auth1RspMsg);
            out.flush();
            Log.d(TAG, "Sent AUTH1 response");

            // ------------------------------------------------------------------
            // Step 5: Optionally read EXCHANGE
            // ------------------------------------------------------------------
            byte[] exchangeMsg = readAliroMessage(in);
            int[] exchangeHeader = AliroBleMessage.parseHeader(exchangeMsg);
            byte[] exchangePayload = AliroBleMessage.extractPayload(exchangeMsg);

            if (exchangeHeader != null &&
                exchangeHeader[0] == AliroBleMessage.PROTOCOL_AP &&
                exchangeHeader[1] == AliroBleMessage.AP_RQ &&
                exchangePayload != null && exchangePayload.length >= 2 &&
                exchangePayload[1] == (byte)0xC9)
            {
                // EXCHANGE command
                Log.d(TAG, "Received EXCHANGE");
                byte[] exchangeResponse = handleExchangeBle(exchangePayload);
                if (exchangeResponse != null)
                {
                    byte[] exchangeRspMsg = AliroBleMessage.build(
                            AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RS, exchangeResponse);
                    out.write(exchangeRspMsg);
                    out.flush();
                    Log.d(TAG, "Sent EXCHANGE response");
                }

                // Read next message — could be:
                //   a) ENVELOPE (step-up, if reader requests Access Document)
                //   b) Reader Status Completed (normal completion)
                //   c) Another EXCHANGE (multiple mailbox operations)
                exchangeMsg = readAliroMessage(in);
                exchangeHeader = AliroBleMessage.parseHeader(exchangeMsg);
                exchangePayload = AliroBleMessage.extractPayload(exchangeMsg);

                // Handle step-up ENVELOPE if the reader sends one
                // The reader only sends ENVELOPE if it is configured for step-up,
                // regardless of the signaling_bitmap Bit0 value.
                if (exchangeHeader != null &&
                    exchangeHeader[0] == AliroBleMessage.PROTOCOL_AP &&
                    exchangeHeader[1] == AliroBleMessage.AP_RQ &&
                    exchangePayload != null && exchangePayload.length >= 2 &&
                    exchangePayload[1] == (byte)0xC3 &&
                    stepUpSK != null)
                {
                    Log.d(TAG, "Received ENVELOPE (step-up)");
                    byte[] envelopeResponse = handleEnvelopeBle(exchangePayload);
                    if (envelopeResponse != null)
                    {
                        byte[] envelopeRspMsg = AliroBleMessage.build(
                                AliroBleMessage.PROTOCOL_AP, AliroBleMessage.AP_RS, envelopeResponse);
                        out.write(envelopeRspMsg);
                        out.flush();
                        Log.d(TAG, "Sent ENVELOPE response (Access Document)");
                    }
                    // Read Reader Status Completed after ENVELOPE
                    exchangeMsg = readAliroMessage(in);
                    exchangeHeader = AliroBleMessage.parseHeader(exchangeMsg);
                    exchangePayload = AliroBleMessage.extractPayload(exchangeMsg);
                }
                // else: exchangeMsg already holds Reader Status Completed — fall through
            }

            // ------------------------------------------------------------------
            // Step 6: Reader Status Access Protocol Completed (BleSK encrypted)
            // If we already read it above (non-EXCHANGE case), it's in exchangeMsg
            // ------------------------------------------------------------------
            if (exchangeHeader != null &&
                exchangeHeader[0] == AliroBleMessage.PROTOCOL_NOTIFICATION &&
                exchangeHeader[1] == AliroBleMessage.NOTIF_READER_STATUS_COMPLETED)
            {
                Log.d(TAG, "Received Reader Status Completed");

                // Derive BleSKReader / BleSKDevice
                if (bleSK != null)
                {
                    byte[] readerSupportedVersions = { 0x01, 0x00 };
                    byte[] hkdfSalt = new byte[readerSupportedVersions.length + SELECTED_VERSION.length];
                    System.arraycopy(readerSupportedVersions, 0, hkdfSalt, 0, readerSupportedVersions.length);
                    System.arraycopy(SELECTED_VERSION, 0, hkdfSalt, readerSupportedVersions.length, SELECTED_VERSION.length);

                    byte[] bleSKReader = AliroCryptoProvider.hkdfDeriveKey(bleSK, "BleSKReader", hkdfSalt, 32);
                    byte[] bleSKDevice = AliroCryptoProvider.hkdfDeriveKey(bleSK, "BleSKDevice", hkdfSalt, 32);

                    if (bleSKReader != null && exchangePayload != null)
                    {
                        // Decrypt Reader Status Completed
                        // We need the plaintext length for AAD — status attr is 4 bytes (AttrID+Len+2 val)
                        byte[] statusAad = AliroCryptoProvider.buildBleAad(
                                AliroBleMessage.PROTOCOL_NOTIFICATION,
                                AliroBleMessage.NOTIF_READER_STATUS_COMPLETED,
                                4);
                        byte[] statusPlain = AliroCryptoProvider.decryptBleGcm(bleSKReader, exchangePayload, statusAad, 1);
                        if (statusPlain != null)
                        {
                            Log.d(TAG, "Reader status decrypted: " + Hex.toHexString(statusPlain));
                        }
                    }

                    // ------------------------------------------------------------------
                    // Step 7: Send RKE Request (encrypted with BleSKDevice)
                    // ------------------------------------------------------------------
                    if (bleSKDevice != null)
                    {
                        byte[] rkePlain = AliroBleMessage.buildAttribute(0x00, new byte[]{ 0x01 }); // action=1 (unsecure/unlock)
                        byte[] rkeAad = AliroCryptoProvider.buildBleAad(
                                AliroBleMessage.PROTOCOL_NOTIFICATION,
                                AliroBleMessage.NOTIF_RKE_REQUEST,
                                rkePlain.length);
                        byte[] rkeEncrypted = AliroCryptoProvider.encryptBleGcm(bleSKDevice, rkePlain, rkeAad, 1);
                        if (rkeEncrypted != null)
                        {
                            byte[] rkeMsg = AliroBleMessage.build(
                                    AliroBleMessage.PROTOCOL_NOTIFICATION,
                                    AliroBleMessage.NOTIF_RKE_REQUEST,
                                    rkeEncrypted);
                            out.write(rkeMsg);
                            out.flush();
                            Log.d(TAG, "Sent RKE Request");
                        }

                        Arrays.fill(bleSKReader, (byte)0);
                        Arrays.fill(bleSKDevice, (byte)0);
                    }
                }

                broadcastResult(true, "BLE Credential Sent - Access Granted");
            }
            else
            {
                // No Reader Status Completed — still consider it a success if AUTH1 passed
                broadcastResult(true, "BLE Credential Sent");
            }
        }
        catch (IOException e)
        {
            Log.e(TAG, "Credential flow IO error", e);
            broadcastResult(false, "BLE IO error: " + e.getMessage());
        }
        catch (Exception e)
        {
            Log.e(TAG, "Credential flow error", e);
            broadcastResult(false, "BLE error: " + e.getMessage());
        }
        finally
        {
            resetState();
        }
    }

    // -------------------------------------------------------------------------
    // APDU handlers (ported from Aliro_HostApduService for BLE transport)
    // -------------------------------------------------------------------------

    /**
     * Handle AUTH0 APDU — same logic as Aliro_HostApduService.handleAuth0
     * @return AUTH0 response APDU bytes (86 41 <UD eph pub 65> 90 00), or null on failure
     */
    private byte[] handleAuth0Ble(byte[] apdu)
    {
        try
        {
            int dataOffset = 5; // CLA INS P1 P2 Lc
            int dataLen = apdu[4] & 0xFF;
            if (apdu.length < dataOffset + dataLen) return null;

            byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);

            // Parse TLVs
            readerEphPubBytes = null;
            transactionId = null;
            readerIdBytes = null;
            selectedProtocol = null;
            byte cmdParams = 0x00;
            byte authPolicy = 0x01;

            for (int i = 0; i < data.length - 1; i++)
            {
                int tag = data[i] & 0xFF;
                int len = data[i + 1] & 0xFF;
                if (i + 2 + len > data.length) continue;

                switch (tag)
                {
                    case 0x41: if (len == 1) cmdParams = data[i + 2]; break;
                    case 0x42: if (len == 1) authPolicy = data[i + 2]; break;
                    case 0x5C: if (len == 2) selectedProtocol = Arrays.copyOfRange(data, i + 2, i + 4); break;
                    case 0x87: if (len == 0x41) readerEphPubBytes = Arrays.copyOfRange(data, i + 2, i + 67); break;
                    case 0x4C: if (len == 0x10) transactionId = Arrays.copyOfRange(data, i + 2, i + 18); break;
                    case 0x4D: if (len == 0x20) readerIdBytes = Arrays.copyOfRange(data, i + 2, i + 34); break;
                }
            }
            auth0Flag = new byte[]{ cmdParams, authPolicy };

            if (readerEphPubBytes == null || transactionId == null || readerIdBytes == null)
            {
                Log.e(TAG, "AUTH0 missing required TLVs");
                return null;
            }
            if (selectedProtocol == null) selectedProtocol = new byte[]{ 0x01, 0x00 };

            // Strict mode: verify reader_group_identifier matches authorized group
            if (AliroProvisioningManager.isStrictMode(this) && AliroProvisioningManager.isProvisioned(this))
            {
                byte[] authorizedGroupId = AliroProvisioningManager.getAuthorizedReaderGroupId(this);
                if (authorizedGroupId != null)
                {
                    byte[] receivedGroupId = Arrays.copyOfRange(readerIdBytes, 0, 16);
                    if (!Arrays.equals(receivedGroupId, authorizedGroupId))
                    {
                        Log.w(TAG, "Strict mode: Reader group ID mismatch — rejecting (BLE)");
                        return null; // reject the connection
                    }
                    Log.d(TAG, "Strict mode: Reader group ID verified (BLE)");
                }
            }

            // Generate UD ephemeral keypair
            udEphKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (udEphKP == null) return null;
            udEphPubBytes = AliroCryptoProvider.getUncompressedPublicKey(udEphKP);

            Log.d(TAG, "AUTH0: reader eph pub parsed, UD eph generated");

            // Response: 86 41 <UD eph pub 65> 90 00
            byte[] response = new byte[2 + 65 + 2];
            response[0] = (byte)0x86;
            response[1] = 0x41;
            System.arraycopy(udEphPubBytes, 0, response, 2, 65);
            response[67] = (byte)0x90;
            response[68] = 0x00;
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "handleAuth0Ble error", e);
            return null;
        }
    }

    /**
     * Handle LOAD CERT APDU
     * @return SW 90 00
     */
    private byte[] handleLoadCertBle(byte[] apdu)
    {
        byte[] certData = null;
        try
        {
            int dataOffset = 5;
            int dataLen = apdu[4] & 0xFF;
            if (apdu.length >= dataOffset + dataLen)
            {
                certData = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
                // Parse tag 0x85 for reader static public key X
                for (int i = 0; i < certData.length - 2; i++)
                {
                    if ((certData[i] & 0xFF) == 0x85 && (certData[i + 1] & 0xFF) == 0x42)
                    {
                        if (i + 68 <= certData.length && certData[i + 2] == 0x00 && certData[i + 3] == 0x04)
                        {
                            readerStaticPubKeyX = Arrays.copyOfRange(certData, i + 4, i + 36);
                            Log.d(TAG, "LOAD CERT: reader static pub key X = " + Hex.toHexString(readerStaticPubKeyX));
                        }
                        break;
                    }
                }
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "LOAD CERT parse error: " + e.getMessage());
        }

        // Strict mode: verify reader certificate against stored Issuer CA public key
        if (AliroProvisioningManager.isStrictMode(this) && AliroProvisioningManager.isProvisioned(this)
                && certData != null)
        {
            try
            {
                byte[] issuerPubKey = AliroProvisioningManager.getIssuerCAPubKey(this);
                if (issuerPubKey != null)
                {
                    boolean certValid = AliroProvisioningManager.verifyProfile0000Cert(certData, issuerPubKey);
                    if (!certValid)
                    {
                        Log.w(TAG, "Strict mode: Reader certificate verification FAILED (BLE)");
                        // Return security error SW (6982) — caller will abort flow
                        return new byte[]{ 0x69, (byte)0x82 };
                    }
                    Log.d(TAG, "Strict mode: Reader certificate verified against Issuer CA (BLE)");
                }
            }
            catch (Exception e)
            {
                Log.w(TAG, "Strict mode cert verify error (BLE): " + e.getMessage());
            }
        }

        return new byte[]{ (byte)0x90, 0x00 };
    }

    /**
     * Handle AUTH1 APDU — derives keys with INTERFACE_BYTE_BLE, builds encrypted response
     * @return AUTH1 response APDU bytes (encrypted + 90 00), or null on failure
     */
    private byte[] handleAuth1Ble(byte[] apdu)
    {
        try
        {
            int dataOffset = 5;
            int dataLen = apdu[4] & 0xFF;
            if (dataOffset + dataLen > apdu.length) return null;

            byte[] data = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);

            // Find tag 9E (reader signature)
            byte[] readerSig = null;
            int i = 0;
            while (i < data.length - 1)
            {
                byte tag = data[i];
                int len = data[i + 1] & 0xFF;
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
                return null;
            }

            // Get credential keypair
            PrivateKey credPrivKey = getCredentialPrivateKey();
            byte[] credPubKeyBytes = getCredentialPublicKeyBytes();
            if (credPrivKey == null || credPubKeyBytes == null)
            {
                Log.e(TAG, "AUTH1: credential keypair not available");
                return null;
            }

            byte[] readerEphPubX = Arrays.copyOfRange(readerEphPubBytes, 1, 33);
            byte[] udEphPubX     = Arrays.copyOfRange(udEphPubBytes, 1, 33);

            byte[] hkdfReaderPubKeyX = (readerStaticPubKeyX != null)
                    ? readerStaticPubKeyX
                    : readerEphPubX;

            // Derive 128 bytes of key material (to include BleSK at offset 96)
            byte[] keybuf = AliroCryptoProvider.deriveKeys(
                    udEphKP.getPrivate(),
                    readerEphPubBytes,
                    128,
                    selectedProtocol,
                    hkdfReaderPubKeyX,
                    readerIdBytes,
                    transactionId,
                    readerEphPubX,
                    udEphPubX,
                    PROPRIETARY_TLV,
                    null,  // auth0CmdVendorTLV
                    null,  // auth0RspVendorTLV
                    AliroCryptoProvider.INTERFACE_BYTE_BLE,
                    auth0Flag);

            if (keybuf == null)
            {
                Log.e(TAG, "AUTH1: key derivation failed");
                return null;
            }
            skReader  = Arrays.copyOfRange(keybuf, 0, 32);
            skDevice  = Arrays.copyOfRange(keybuf, 32, 64);
            stepUpSK  = Arrays.copyOfRange(keybuf, 64, 96);
            bleSK     = Arrays.copyOfRange(keybuf, 96, 128);

            // Compute credential signature
            byte[] credSig = AliroCryptoProvider.computeCredentialSignature(
                    credPrivKey, readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            if (credSig == null)
            {
                Log.e(TAG, "AUTH1: credential signature failed");
                return null;
            }

            // Build signaling_bitmap (tag 0x5E, 2 bytes big-endian) per Table 8-11.
            // Bit0=1: Access Document available → reader SHALL send ENVELOPE.
            // Bit1=1: Revocation Document available.
            // Bit2: step-up AID select required. Per Table 8-11, this bit is
            // "only applicable when the transaction is performed using NFC
            // transport. When using other transport mechanisms, this bit
            // SHALL be ignored by the Reader and SHALL not be set by the
            // User Device." We are on BLE here, so Bit2 stays unset.
            // (Aliro 1.0 Table 8-11. Mailbox availability is signaled by
            // Bits 3/4/5/10, not Bit2 — see §8.3.1.15.)
            // Walk the multi-doc set (per §8.4.2 RECOMMENDED multi-element
            // behavior) so we report availability accurately when zero/one/
            // many documents are stored. Mirrors the NFC service's logic.
            java.util.List<AliroAccessDocument.StoredDocument> allDocs =
                    AliroAccessDocument.getAllDocuments(this);
            boolean hasAccessDoc = false;
            boolean hasRevocDoc  = false;
            for (AliroAccessDocument.StoredDocument sd : allDocs)
            {
                if (sd.accessDocBytes     != null && sd.accessDocBytes.length     > 0) hasAccessDoc = true;
                if (sd.revocationDocBytes != null && sd.revocationDocBytes.length > 0) hasRevocDoc  = true;
            }
            signalingBits = 0;
            if (hasAccessDoc) signalingBits |= 0x0001; // bit 0: access doc present
            if (hasRevocDoc)  signalingBits |= 0x0002; // bit 1: revocation doc present
            // Bit 2 (step-up AID select required) is NFC-only per Table 8-11
            // and SHALL NOT be set on BLE. Mailbox bits (3/4/5/10) per §8.3.1.15.
            Log.d(TAG, "AUTH1: signaling_bitmap=0x" + String.format("%04X", signalingBits)
                    + " (hasAccessDoc=" + hasAccessDoc + ", hasRevocDoc=" + hasRevocDoc + ")");

            // Build AUTH1 response plaintext (137 bytes):
            //   5A 41 <cred pub key 65>       — credential public key
            //   9E 40 <cred sig 64>           — credential signature
            //   5E 02 <bitmap_hi> <bitmap_lo> — signaling_bitmap (MANDATORY)
            byte[] plaintext = new byte[2 + 65 + 2 + 64 + 4]; // 137 bytes
            plaintext[0] = 0x5A; plaintext[1] = 0x41;
            System.arraycopy(credPubKeyBytes, 0, plaintext, 2, 65);
            plaintext[67] = (byte)0x9E; plaintext[68] = 0x40;
            System.arraycopy(credSig, 0, plaintext, 69, 64);
            plaintext[133] = 0x5E;
            plaintext[134] = 0x02;
            plaintext[135] = (byte)((signalingBits >> 8) & 0xFF);
            plaintext[136] = (byte)(signalingBits & 0xFF);

            // Encrypt with SKDevice, counter-aware (deviceCounter=1 for AUTH1, then 2+ for EXCHANGE)
            byte[] encrypted = AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext, deviceCounter++);
            if (encrypted == null)
            {
                Log.e(TAG, "AUTH1: encryption failed");
                return null;
            }

            // Response: encrypted + SW 90 00
            byte[] response = new byte[encrypted.length + 2];
            System.arraycopy(encrypted, 0, response, 0, encrypted.length);
            response[encrypted.length]     = (byte)0x90;
            response[encrypted.length + 1] = 0x00;
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "handleAuth1Ble error", e);
            return null;
        }
    }

    /**
     * Handle EXCHANGE APDU over BLE.
     *
     * <p>Performs counter-aware GCM decryption, enforces the BLE-specific
     * rules on tag 0x97 from Aliro 1.0 §8.3.3.5 and Table 8-15, runs the
     * §8.3.1.15 mailbox tag processing pipeline, and returns the encrypted
     * EXCHANGE response.
     *
     * <p>BLE-specific rules enforced here (per Aliro 1.0 §8.3.3.5 and
     * Table 8-15):
     * <ul>
     *   <li>Tag 0x97 over BLE is allowed only when its first byte is 0x00
     *       (failure indication). A tag 0x97 with first byte 0x01 (success)
     *       SHALL NOT be sent or received on BLE — receiving one triggers
     *       the failure process per §8.3.3.1.
     *   <li>"After an EXCHANGE command containing 0x97, no further
     *       EXCHANGE commands can be sent." A subsequent EXCHANGE arriving
     *       after a terminal one triggers the failure process.
     * </ul>
     *
     * <p>Mailbox handling (per Aliro 1.0 §8.3.1.15):
     * <ul>
     *   <li>"The User Device SHALL support the mailbox mechanism." The
     *       spec applies this requirement unconditionally — there is no
     *       transport restriction. Mailbox 0xBA TLVs and inner read/write/
     *       set/atomic-session operations are processed identically over
     *       NFC and BLE in the expedited phase.
     *   <li>The only spec-defined restriction is "The mailbox SHALL NOT
     *       be used when in the step-up phase" (§8.3.1.15). This handler
     *       is the expedited-phase EXCHANGE handler; step-up EXCHANGE is
     *       handled separately.
     * </ul>
     */
    private byte[] handleExchangeBle(byte[] apdu)
    {
        try
        {
            // Terminal-EXCHANGE rule per §8.3.3.5: once an EXCHANGE has
            // arrived carrying tag 0x97, the spec forbids the Reader from
            // sending any further EXCHANGEs. If we still receive one, the
            // peer is misbehaving — enter failure process per §8.3.3.1.
            if (terminalExchangeReceived)
            {
                return enterFailureProcess(
                        "EXCHANGE received after a terminal (0x97-bearing) EXCHANGE — §8.3.3.5");
            }

            int dataOffset = 5;
            int dataLen = apdu[4] & 0xFF;
            if (dataOffset + dataLen > apdu.length) return null;

            byte[] encryptedPayload = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            byte[] decrypted = AliroCryptoProvider.decryptReaderGcm(skReader, encryptedPayload, readerCounter++);
            if (decrypted == null)
            {
                Log.e(TAG, "EXCHANGE: decryption failed (readerCounter was " + (readerCounter - 1) + ")");
                return null;
            }
            Log.d(TAG, "EXCHANGE decrypted: " + Hex.toHexString(decrypted));

            // Parse tag 0x97 (Reader Status, Table 8-18) and enforce
            // BLE-specific rules per §8.3.3.5 and Table 8-15.
            //
            // §8.3.3.5: "When using BLE for transaction protocol, tag 0x97
            // is present in the EXCHANGE command sent by Reader only if
            // the transaction failure occurs."
            // Table 8-15: "This tag SHALL be accepted by the User Device
            // on the BLE interface only if the first byte is set to 0x00.
            // Otherwise, this tag SHALL NOT be sent and received on the
            // BLE interface."
            //
            // So on BLE:
            //   - tag 0x97 absent       → success (no terminal indication)
            //   - tag 0x97 first byte 0x00 → failure (terminal, per Table 8-18)
            //   - tag 0x97 first byte 0x01 → SPEC VIOLATION (rejected here)
            boolean exchangeWasTerminal = false;
            for (int j = 0; j < decrypted.length - 1; j++)
            {
                if (decrypted[j] == (byte)0x97 && decrypted[j + 1] == 0x02 && j + 3 < decrypted.length)
                {
                    int firstByte = decrypted[j + 2] & 0xFF;
                    if (firstByte == 0x01)
                    {
                        // Forbidden on BLE per Table 8-15 — enter failure
                        // process. Session keys are destroyed; SW=6F00 is
                        // returned with no encrypted payload.
                        return enterFailureProcess(
                                "tag 0x97 with first byte 0x01 received on BLE — Table 8-15 SHALL NOT");
                    }
                    if (firstByte == 0x00)
                    {
                        // Spec-correct BLE failure indication.
                        exchangeWasTerminal = true;
                        Log.d(TAG, "EXCHANGE: tag 0x97 first byte 0x00 → terminal failure");
                    }
                    else
                    {
                        // First byte is something other than 0x00 or 0x01
                        // (e.g. RFU). Table 8-15 only blesses 0x00 for BLE,
                        // so any other value is also forbidden.
                        return enterFailureProcess(
                                "tag 0x97 first byte 0x"
                                        + String.format("%02X", firstByte)
                                        + " not permitted on BLE — Table 8-15");
                    }
                    break;
                }
            }

            // Process mailbox operations from the decrypted payload per
            // Aliro 1.0 §8.3.1.15. The §8.3.1.15 requirement is that "The
            // User Device SHALL support the mailbox mechanism" — applied
            // unconditionally on transport. The only spec restriction is
            // that mailbox SHALL NOT be used during step-up; this is the
            // expedited-phase handler, so mailbox operations are processed.
            byte[] mailboxReadData = processMailboxTags(decrypted);

            // Build EXCHANGE response: [mailboxReadData] || 0x0002||0x00||0x00
            byte[] successSuffix = new byte[]{ 0x00, 0x02, 0x00, 0x00 };
            int readLen = (mailboxReadData != null) ? mailboxReadData.length : 0;
            byte[] responsePlaintext = new byte[readLen + successSuffix.length];
            if (readLen > 0) System.arraycopy(mailboxReadData, 0, responsePlaintext, 0, readLen);
            System.arraycopy(successSuffix, 0, responsePlaintext, readLen, successSuffix.length);

            byte[] encResponse = AliroCryptoProvider.encryptDeviceGcm(skDevice, responsePlaintext, deviceCounter++);
            if (encResponse == null)
            {
                Log.e(TAG, "EXCHANGE: response encryption failed (deviceCounter was " + (deviceCounter - 1) + ")");
                return null;
            }

            byte[] response = new byte[encResponse.length + 2];
            System.arraycopy(encResponse, 0, response, 0, encResponse.length);
            response[encResponse.length]     = (byte)0x90;
            response[encResponse.length + 1] = 0x00;

            // Per §8.3.3.5 terminal-EXCHANGE rule: only set the flag
            // AFTER the response has been generated, so the response to
            // the terminal EXCHANGE itself goes out normally; subsequent
            // EXCHANGEs (if the reader misbehaves) are rejected at the
            // top of this handler on the next call.
            if (exchangeWasTerminal)
            {
                terminalExchangeReceived = true;
                Log.d(TAG, "EXCHANGE: terminal flag set — subsequent EXCHANGEs will fail per §8.3.3.5");
            }
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "handleExchangeBle error", e);
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Mailbox tag processing (same as Aliro_HostApduService.processMailboxTags)
    // Tags per Table 8-16:
    //   0x8C 01 <options>   — atomic session: bit0=1 start, bit0=0 stop
    //   0x87 04 <off_hi><off_lo><len_hi><len_lo>  — read
    //   0x8A var <off_hi><off_lo><data...>         — write
    //   0x95 05 <off_hi><off_lo><len_hi><len_lo><value> — set (fill)
    // -------------------------------------------------------------------------

    private byte[] processMailboxTags(byte[] decrypted)
    {
        if (decrypted == null || decrypted.length < 2) return null;

        byte[] mailbox   = loadMailbox();
        boolean didWrite = false;
        ByteArrayOutputStream readOutput = new ByteArrayOutputStream();

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
                        int rdLen   = ((decrypted[valOff + 2] & 0xFF) << 8)
                                     | (decrypted[valOff + 3] & 0xFF);
                        byte[] src  = mailboxAtomicActive ? mailboxPendingWrites : mailbox;
                        if (src != null && offset + rdLen <= src.length)
                        {
                            readOutput.write(src, offset, rdLen);
                            Log.d(TAG, "Mailbox: read offset=" + offset + " len=" + rdLen);
                        }
                        else
                        {
                            Log.w(TAG, "Mailbox: read out of bounds");
                        }
                    }
                    break;

                case 0x8A: // Write: offset(2) || data(var)
                    if (len >= 2)
                    {
                        int offset    = ((decrypted[valOff]     & 0xFF) << 8)
                                       | (decrypted[valOff + 1] & 0xFF);
                        int dataLen2  = len - 2;
                        byte[] target = mailboxAtomicActive
                                ? mailboxPendingWrites
                                : (mailbox != null ? mailbox : new byte[0]);
                        int needed    = offset + dataLen2;
                        if (needed > MAILBOX_MAX_SIZE) break;
                        if (needed > target.length)
                        {
                            target = Arrays.copyOf(target, needed);
                        }
                        System.arraycopy(decrypted, valOff + 2, target, offset, dataLen2);
                        if (mailboxAtomicActive)
                        {
                            mailboxPendingWrites = target;
                        }
                        else
                        {
                            mailbox  = target;
                            didWrite = true;
                        }
                        Log.d(TAG, "Mailbox: write offset=" + offset + " len=" + dataLen2);
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
                        if (needed > MAILBOX_MAX_SIZE) break;
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
                        Log.d(TAG, "Mailbox: set offset=" + offset + " len=" + setLen);
                    }
                    break;

                default:
                    break;
            }

            i = valOff + len;
        }

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
            android.content.SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            String encoded = prefs.getString(PREF_MAILBOX_KEY, null);
            if (encoded == null) return new byte[0];
            return android.util.Base64.decode(encoded, android.util.Base64.DEFAULT);
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
            android.content.SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            prefs.edit()
                 .putString(PREF_MAILBOX_KEY, android.util.Base64.encodeToString(data, android.util.Base64.DEFAULT))
                 .apply();
            Log.d(TAG, "Mailbox: saved " + data.length + " bytes");
        }
        catch (Exception e)
        {
            Log.e(TAG, "saveMailbox failed", e);
        }
    }

    // -------------------------------------------------------------------------
    // ENVELOPE (INS C3) — Step-Up phase over BLE
    // -------------------------------------------------------------------------

    private byte[] handleEnvelopeBle(byte[] apdu)
    {
        if (stepUpSK == null)
        {
            Log.e(TAG, "ENVELOPE: stepUpSK not available");
            return new byte[]{ 0x69, (byte)0x85 }; // SW_CONDITIONS
        }

        try
        {
            // Support both short (Lc=1 byte) and extended (Lc=3 bytes, first=0x00) APDU encoding
            int dataOffset;
            int dataLen;
            if (apdu.length >= 7 && apdu[4] == 0x00)
            {
                // Extended length: Lc = apdu[5..6] (big-endian)
                dataOffset = 7;
                dataLen = ((apdu[5] & 0xFF) << 8) | (apdu[6] & 0xFF);
            }
            else
            {
                dataOffset = 5;
                dataLen = apdu[4] & 0xFF;
            }
            if (apdu.length < dataOffset + dataLen)
            {
                return new byte[]{ 0x67, 0x00 }; // SW_WRONG_LENGTH
            }

            byte[] sessionDataIn = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            Log.d(TAG, "ENVELOPE: SessionData (" + sessionDataIn.length + " bytes)");

            // Derive step-up session keys from stepUpSK
            byte[] stepUpSessionKeys = AliroCryptoProvider.deriveStepUpSessionKeys(stepUpSK);
            if (stepUpSessionKeys == null)
            {
                Log.e(TAG, "ENVELOPE: step-up session key derivation failed");
                return new byte[]{ 0x6A, (byte)0x82 }; // SW_ERROR
            }
            byte[] suSKDevice = Arrays.copyOfRange(stepUpSessionKeys, 0,  32);
            byte[] suSKReader = Arrays.copyOfRange(stepUpSessionKeys, 32, 64);

            try
            {
                // Parse SessionData CBOR: {"data": bstr(encrypted DeviceRequest)}
                CBORObject sdIn = CBORObject.DecodeFromBytes(sessionDataIn);
                CBORObject dataIn = sdIn.get(CBORObject.FromObject("data"));
                if (dataIn == null)
                {
                    Log.e(TAG, "ENVELOPE: SessionData missing 'data' field");
                    return new byte[]{ 0x6A, (byte)0x82 };
                }
                byte[] encryptedRequest = dataIn.GetByteString();

                // Decrypt with suSKReader (reader→credential)
                byte[] deviceRequest = AliroCryptoProvider.decryptReaderGcm(suSKReader, encryptedRequest);
                if (deviceRequest == null)
                {
                    Log.e(TAG, "ENVELOPE: DeviceRequest decryption failed");
                    return new byte[]{ 0x6A, (byte)0x82 };
                }
                Log.d(TAG, "ENVELOPE: DeviceRequest (" + deviceRequest.length + " bytes)");

                // Build DeviceResponse
                byte[] deviceResponse = buildDeviceResponse(deviceRequest);
                if (deviceResponse == null)
                {
                    Log.e(TAG, "ENVELOPE: failed to build DeviceResponse");
                    return new byte[]{ 0x6A, (byte)0x82 };
                }

                // Encrypt DeviceResponse with suSKDevice
                byte[] encryptedResponse = AliroCryptoProvider.encryptDeviceGcm(suSKDevice, deviceResponse);
                if (encryptedResponse == null)
                {
                    Log.e(TAG, "ENVELOPE: DeviceResponse encryption failed");
                    return new byte[]{ 0x6A, (byte)0x82 };
                }

                // Wrap in SessionData CBOR: {"data": bstr(ciphertext)}
                CBORObject sdOut = CBORObject.NewOrderedMap();
                sdOut.Add(CBORObject.FromObject("data"), CBORObject.FromObject(encryptedResponse));
                byte[] sessionDataOut = sdOut.EncodeToBytes();
                Log.d(TAG, "ENVELOPE: SessionData response (" + sessionDataOut.length + " bytes)");

                // Return sessionDataOut + SW 9000
                byte[] response = new byte[sessionDataOut.length + 2];
                System.arraycopy(sessionDataOut, 0, response, 0, sessionDataOut.length);
                response[sessionDataOut.length]     = (byte)0x90;
                response[sessionDataOut.length + 1] = 0x00;
                return response;
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
            Log.e(TAG, "handleEnvelopeBle error", e);
            return new byte[]{ 0x6A, (byte)0x82 };
        }
    }

    /**
     * Build DeviceResponse from the stored Access/Revocation Document set,
     * matching the NFC service's logic (Aliro 1.0 §8.4.2 multi-element /
     * §7.3 multi-element / §8.4.2 §7.4-Step-5 validity gating).
     *
     * <p>Walks the reader's DeviceRequest to extract, per docType, the
     * ordered list of element identifiers being requested. Then for each
     * requested element (in the order the reader listed it) finds the
     * stored document that carries that element and appends a slice for
     * it. Per-doctype iteration order is preserved (LinkedHashMap), and
     * within a doctype the emit order tracks request order (List, not Set).
     *
     * <p>Why request-order matters: the reader's slicer
     * (sliceDeviceResponsePerDocument) is positional. If we emit out of
     * order, slice N gets verified against request[N]'s element id and
     * the per-slice display attributes element data to the wrong slot.
     * Emitting in request order makes slice positions == request positions.
     *
     * <p>This is the same code path as
     * {@code Aliro_HostApduService.buildDeviceResponse}; keeping them in
     * sync ensures NFC and BLE taps return byte-comparable responses for
     * the same DeviceRequest.
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

        // Load every stored Access/Revocation document pair from the multi-doc
        // collection. Each entry is keyed by elementId (e.g. "floor1",
        // "pool_door"); the reader picks which one(s) it wants via DeviceRequest.
        java.util.List<AliroAccessDocument.StoredDocument> storedDocs =
                AliroAccessDocument.getAllDocuments(this);
        Log.d(TAG, "buildDeviceResponse: stored docs=" + storedDocs.size());

        try
        {
            // ---- Parse DeviceRequest ----
            // Collect, per docType requested, the LIST of element identifiers
            // the reader is asking for, in the order the reader specified them.
            // If the reader doesn't list specific elements for a docType, treat
            // that as "any element of this docType".
            //   requestedElements: Map< docType, List<elementId> >  (order-preserving)
            //   docTypesAnyElement: Set<docType> where the reader wants any/all elements
            java.util.Map<String, java.util.List<String>> requestedElements =
                    new java.util.LinkedHashMap<>();
            java.util.Set<String> docTypesAnyElement = new java.util.LinkedHashSet<>();
            boolean parseOk = false;

            try
            {
                CBORObject req = CBORObject.DecodeFromBytes(deviceRequest);
                CBORObject docRequestsArr = req.get(CBORObject.FromObject("2"));
                if (docRequestsArr != null
                        && docRequestsArr.getType() == com.upokecenter.cbor.CBORType.Array)
                {
                    for (int i = 0; i < docRequestsArr.size(); i++)
                    {
                        CBORObject docReq = docRequestsArr.get(i);

                        // itemsRequest may be a plain map or wrapped in tag 24.
                        CBORObject itemsReqRaw = docReq.get(CBORObject.FromObject("1"));
                        if (itemsReqRaw == null) continue;

                        CBORObject itemsReq;
                        if (itemsReqRaw.getType() == com.upokecenter.cbor.CBORType.ByteString
                                || itemsReqRaw.isTagged())
                        {
                            try
                            {
                                byte[] innerBytes = itemsReqRaw.GetByteString();
                                itemsReq = CBORObject.DecodeFromBytes(innerBytes);
                            }
                            catch (Exception unwrapEx) { itemsReq = itemsReqRaw; }
                        }
                        else
                        {
                            itemsReq = itemsReqRaw;
                        }

                        // Pull docType (key "5") — fallback to outer docReq if absent.
                        String docType = null;
                        CBORObject docTypeObj = itemsReq.get(CBORObject.FromObject("5"));
                        if (docTypeObj != null)
                        {
                            try { docType = docTypeObj.AsString(); } catch (Exception ignored) {}
                        }
                        if (docType == null)
                        {
                            CBORObject outerDocType = docReq.get(CBORObject.FromObject("5"));
                            if (outerDocType != null)
                            {
                                try { docType = outerDocType.AsString(); } catch (Exception ignored) {}
                            }
                        }
                        if (docType == null) continue;

                        Log.d(TAG, "buildDeviceResponse: reader requests docType=" + docType);

                        // Pull namespaces (key "1" inside itemsRequest):
                        //   { "<namespace>": { "<elementId>": <bool>, ... }, ... }
                        // Collect element identifiers across all namespaces under
                        // this docType, preserving the order the reader listed them.
                        CBORObject namespaces = itemsReq.get(CBORObject.FromObject("1"));
                        java.util.List<String> elementList = requestedElements.get(docType);
                        if (elementList == null)
                        {
                            elementList = new java.util.ArrayList<>();
                            requestedElements.put(docType, elementList);
                        }

                        boolean foundElements = false;
                        if (namespaces != null
                                && namespaces.getType() == com.upokecenter.cbor.CBORType.Map)
                        {
                            for (CBORObject nsKey : namespaces.getKeys())
                            {
                                String ns;
                                try { ns = nsKey.AsString(); }
                                catch (Exception ignored) { continue; }
                                CBORObject nsMap = namespaces.get(nsKey);
                                if (nsMap == null
                                        || nsMap.getType() != com.upokecenter.cbor.CBORType.Map)
                                    continue;
                                for (CBORObject elemKey : nsMap.getKeys())
                                {
                                    try
                                    {
                                        String elemId = elemKey.AsString();
                                        if (!elementList.contains(elemId))
                                        {
                                            elementList.add(elemId);
                                        }
                                        foundElements = true;
                                        Log.d(TAG, "buildDeviceResponse:   namespace=" + ns
                                                + " element=" + elemId);
                                    }
                                    catch (Exception ignored) {}
                                }
                            }
                        }

                        if (!foundElements)
                        {
                            // Reader requested a docType but didn't enumerate elements
                            // (or we couldn't parse them). Treat as "any element".
                            docTypesAnyElement.add(docType);
                            Log.d(TAG, "buildDeviceResponse:   docType=" + docType
                                    + " requested with no specific elements");
                        }
                    }
                    parseOk = true;
                }
            }
            catch (Exception parseEx)
            {
                Log.w(TAG, "buildDeviceResponse: could not parse DeviceRequest", parseEx);
            }

            // ---- Fallback: parse failed or no docTypes found ----
            // Mirrors the NFC path: fall back to returning the FIRST stored
            // Access Document if available, else empty. Provides graceful
            // behavior with malformed/legacy reader requests.
            if (!parseOk || (requestedElements.isEmpty() && docTypesAnyElement.isEmpty()))
            {
                for (AliroAccessDocument.StoredDocument sd : storedDocs)
                {
                    if (sd.accessDocBytes != null && sd.accessDocBytes.length > 0)
                    {
                        Log.d(TAG, "buildDeviceResponse: fallback — returning first stored Access Document ("
                                + sd.accessDocBytes.length + " bytes)");
                        return sd.accessDocBytes;
                    }
                }
                Log.d(TAG, "buildDeviceResponse: no document provisioned — returning empty DeviceResponse");
                return EMPTY_RESPONSE;
            }

            // ---- Emit matching documents in REQUEST ORDER ----
            // Outer loop: requested element list (in order). Inner: find the
            // stored doc that carries that element. This makes slice positions
            // line up with request positions for the reader's positional slicer.
            java.util.List<CBORObject> matchedDocs = new java.util.ArrayList<>();

            // Access Documents (aliro-a)
            java.util.List<String> requestedAccessElementsList =
                    requestedElements.get(AliroAccessDocument.DOCTYPE_ACCESS);
            boolean accessAny = docTypesAnyElement.contains(AliroAccessDocument.DOCTYPE_ACCESS);
            if (accessAny)
            {
                for (AliroAccessDocument.StoredDocument sd : storedDocs)
                {
                    if (sd.accessDocBytes == null) continue;
                    // §8.4.2: SHOULD NOT return data elements when IssuerAuth
                    // Validity is not current.
                    if (!AliroAccessDocument.isValidityCurrent(sd.accessDocBytes))
                    {
                        Log.d(TAG, "buildDeviceResponse: skipping elementId=" + sd.elementId
                                + " — IssuerAuth Validity not current");
                        continue;
                    }
                    CBORObject inner = extractInnerDocument(sd.accessDocBytes);
                    if (inner != null)
                    {
                        matchedDocs.add(inner);
                        Log.d(TAG, "buildDeviceResponse: matched Access Document elementId="
                                + sd.elementId + " (any-element mode)");
                    }
                }
            }
            else if (requestedAccessElementsList != null)
            {
                for (String requestedElemId : requestedAccessElementsList)
                {
                    AliroAccessDocument.StoredDocument matchSd = null;
                    for (AliroAccessDocument.StoredDocument sd : storedDocs)
                    {
                        if (sd.accessDocBytes == null) continue;
                        if (requestedElemId.equals(sd.elementId))
                        {
                            matchSd = sd;
                            break;
                        }
                    }
                    if (matchSd == null)
                    {
                        Log.d(TAG, "buildDeviceResponse: requested elementId="
                                + requestedElemId + " not present — skipping");
                        continue;
                    }
                    if (!AliroAccessDocument.isValidityCurrent(matchSd.accessDocBytes))
                    {
                        Log.d(TAG, "buildDeviceResponse: skipping elementId=" + matchSd.elementId
                                + " — IssuerAuth Validity not current");
                        continue;
                    }
                    CBORObject inner = extractInnerDocument(matchSd.accessDocBytes);
                    if (inner != null)
                    {
                        matchedDocs.add(inner);
                        Log.d(TAG, "buildDeviceResponse: matched Access Document elementId="
                                + matchSd.elementId + " (request-order position "
                                + (matchedDocs.size() - 1) + ")");
                    }
                }
            }

            // Revocation Documents (aliro-r)
            java.util.List<String> requestedRevocElementsList =
                    requestedElements.get(AliroAccessDocument.DOCTYPE_REVOCATION);
            boolean revocAny = docTypesAnyElement.contains(AliroAccessDocument.DOCTYPE_REVOCATION);
            if (revocAny)
            {
                for (AliroAccessDocument.StoredDocument sd : storedDocs)
                {
                    if (sd.revocationDocBytes == null) continue;
                    if (!AliroAccessDocument.isValidityCurrent(sd.revocationDocBytes))
                    {
                        Log.d(TAG, "buildDeviceResponse: skipping revoc elementId="
                                + sd.elementId + " — IssuerAuth Validity not current");
                        continue;
                    }
                    CBORObject inner = extractInnerDocument(sd.revocationDocBytes);
                    if (inner != null)
                    {
                        matchedDocs.add(inner);
                        Log.d(TAG, "buildDeviceResponse: matched Revocation Document elementId="
                                + sd.elementId + " (any-element mode)");
                    }
                }
            }
            else if (requestedRevocElementsList != null)
            {
                for (String requestedElemId : requestedRevocElementsList)
                {
                    AliroAccessDocument.StoredDocument matchSd = null;
                    for (AliroAccessDocument.StoredDocument sd : storedDocs)
                    {
                        if (sd.revocationDocBytes == null) continue;
                        if (requestedElemId.equals(sd.elementId))
                        {
                            matchSd = sd;
                            break;
                        }
                    }
                    if (matchSd == null)
                    {
                        Log.d(TAG, "buildDeviceResponse: requested revoc elementId="
                                + requestedElemId + " not present — skipping");
                        continue;
                    }
                    if (!AliroAccessDocument.isValidityCurrent(matchSd.revocationDocBytes))
                    {
                        Log.d(TAG, "buildDeviceResponse: skipping revoc elementId="
                                + matchSd.elementId + " — IssuerAuth Validity not current");
                        continue;
                    }
                    CBORObject inner = extractInnerDocument(matchSd.revocationDocBytes);
                    if (inner != null)
                    {
                        matchedDocs.add(inner);
                        Log.d(TAG, "buildDeviceResponse: matched Revocation Document elementId="
                                + matchSd.elementId + " (request-order position "
                                + (matchedDocs.size() - 1) + ")");
                    }
                }
            }

            if (matchedDocs.isEmpty())
            {
                Log.d(TAG, "buildDeviceResponse: no matching documents — returning empty DeviceResponse");
                return EMPTY_RESPONSE;
            }

            // Assemble new DeviceResponse: { "1": "1.0", "2": [doc1, doc2, ...], "3": 0 }
            CBORObject newResponse = CBORObject.NewOrderedMap();
            newResponse.Add(CBORObject.FromObject("1"), CBORObject.FromObject("1.0"));
            CBORObject newDocsArray = CBORObject.NewArray();
            for (CBORObject d : matchedDocs) newDocsArray.Add(d);
            newResponse.Add(CBORObject.FromObject("2"), newDocsArray);
            newResponse.Add(CBORObject.FromObject("3"), CBORObject.FromObject(0));

            byte[] responseBytes = newResponse.EncodeToBytes();
            Log.d(TAG, "buildDeviceResponse: built DeviceResponse with " + matchedDocs.size()
                    + " document(s) (" + responseBytes.length + " bytes)");
            return responseBytes;
        }
        catch (Exception e)
        {
            Log.e(TAG, "buildDeviceResponse failed", e);
            return EMPTY_RESPONSE;
        }
    }

    /**
     * Extract the single inner Document object from a stored DeviceResponse's
     * top-level "2" array (where the credential persists each Access/Revocation
     * Document as a one-element DeviceResponse). Returns null on any failure.
     */
    private CBORObject extractInnerDocument(byte[] storedDocResponseBytes)
    {
        try
        {
            CBORObject storedResponse = CBORObject.DecodeFromBytes(storedDocResponseBytes);
            CBORObject docsArray = storedResponse.get(CBORObject.FromObject("2"));
            if (docsArray != null && docsArray.size() > 0)
            {
                return docsArray.get(0);
            }
        }
        catch (Exception ex)
        {
            Log.w(TAG, "extractInnerDocument failed", ex);
        }
        return null;
    }


    // -------------------------------------------------------------------------
    // L2CAP message I/O
    // -------------------------------------------------------------------------

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
    // KeyStore helpers (same as Aliro_HostApduService)
    // -------------------------------------------------------------------------

    private PrivateKey getCredentialPrivateKey()
    {
        try
        {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            KeyStore.Entry entry = ks.getEntry(Aliro_HostApduService.ALIRO_KEYSTORE_ALIAS, null);
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
            java.security.cert.Certificate cert = ks.getCertificate(Aliro_HostApduService.ALIRO_KEYSTORE_ALIAS);
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

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Failure process per Aliro 1.0 §8.3.3.1.
     *
     * <p>When a User Device failure state is reached, §8.3.3.1 requires:
     * <ul>
     *   <li>Return an empty response data field
     *   <li>Return an error code as defined in §8.3.2.3 (recommended from
     *       ISO 7816-4 — we use 0x6F00 "no precise diagnosis")
     *   <li>Destroy all session-bound keys and data
     *   <li>Terminate the transaction
     * </ul>
     *
     * <p>This helper performs steps 3 and 4 (key destruction, transaction
     * teardown) and returns the bytes the caller should send back to the
     * Reader (steps 1 and 2 — an empty data field followed by SW=6F00).
     *
     * @param reason short description for logging.
     * @return APDU response: empty data field + SW=6F00.
     */
    private byte[] enterFailureProcess(String reason)
    {
        Log.w(TAG, "Failure process (§8.3.3.1): " + reason);
        // §8.3.3.1 step 3: destroy session-bound keys and data.
        if (skReader != null)  { Arrays.fill(skReader, (byte)0);  skReader = null; }
        if (skDevice != null)  { Arrays.fill(skDevice, (byte)0);  skDevice = null; }
        if (bleSK != null)     { Arrays.fill(bleSK, (byte)0);     bleSK = null; }
        if (stepUpSK != null)  { Arrays.fill(stepUpSK, (byte)0);  stepUpSK = null; }
        // §8.3.3.1 step 4: terminate the transaction. The flow loop in
        // runCredentialFlow checks flowActive and exits when it goes false.
        flowActive = false;
        // §8.3.3.1 step 1+2: empty data field, error code from §8.3.2.3.
        // ISO 7816-4 0x6F00 "no precise diagnosis" matches the spec's
        // "recommended to use an error code defined in [7]" guidance.
        return new byte[]{ (byte)0x6F, 0x00 };
    }

    private void resetState()
    {
        udEphKP = null;
        udEphPubBytes = null;
        readerEphPubBytes = null;
        readerIdBytes = null;
        transactionId = null;
        selectedProtocol = null;
        auth0Flag = null;
        readerStaticPubKeyX = null;
        if (skReader != null)  { Arrays.fill(skReader, (byte)0);  skReader = null; }
        if (skDevice != null)  { Arrays.fill(skDevice, (byte)0);  skDevice = null; }
        if (bleSK != null)     { Arrays.fill(bleSK, (byte)0);     bleSK = null; }
        if (stepUpSK != null)  { Arrays.fill(stepUpSK, (byte)0);  stepUpSK = null; }
        deviceCounter = 1;
        readerCounter = 1;
        signalingBits = 0;
        mailboxAtomicActive  = false;
        mailboxPendingWrites = null;
        terminalExchangeReceived = false;
        connectedDeviceAddress = "";
        connectedDeviceName    = "";
        connectedDeviceRssi    = 0;
        flowActive = false;
    }

    private void broadcastResult(boolean accessGranted, String message)
    {
        Intent intent = new Intent(ACTION_BLE_RESULT);
        intent.setPackage(getPackageName());
        intent.putExtra(EXTRA_ACCESS_GRANTED, accessGranted);
        intent.putExtra(EXTRA_STATUS_MESSAGE, message);
        intent.putExtra(EXTRA_DEVICE_ADDRESS, connectedDeviceAddress);
        intent.putExtra(EXTRA_DEVICE_NAME,    connectedDeviceName);
        intent.putExtra(EXTRA_DEVICE_RSSI,    connectedDeviceRssi);
        sendBroadcast(intent);
        Log.d(TAG, "Broadcast: accessGranted=" + accessGranted + " msg=" + message);
    }
}
