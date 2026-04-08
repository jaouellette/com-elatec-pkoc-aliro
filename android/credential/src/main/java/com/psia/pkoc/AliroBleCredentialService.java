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

import com.psia.pkoc.core.AliroBleMessage;
import com.psia.pkoc.core.AliroCryptoProvider;

import org.bouncycastle.util.encoders.Hex;

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

    public static final String ACTION_BLE_RESULT    = "com.psia.pkoc.ALIRO_BLE_RESULT";
    public static final String ACTION_DEVICE_FOUND   = "com.psia.pkoc.ALIRO_BLE_DEVICE_FOUND";
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
    private volatile boolean scanning = false;
    private volatile boolean running = false;

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
            String address = device.getAddress();
            String name = device.getName();
            if (name == null || name.isEmpty()) name = "Unknown Aliro Reader";
            int rssi = result.getRssi();
            Log.d(TAG, "Found Aliro reader: " + address + " rssi=" + rssi);

            // Broadcast to fragment so it can populate the device list
            // Keep scanning so multiple readers can be discovered
            Intent found = new Intent(ACTION_DEVICE_FOUND);
            found.setPackage(getPackageName());
            found.putExtra(EXTRA_DEVICE_ADDRESS, address);
            found.putExtra(EXTRA_DEVICE_NAME, name);
            found.putExtra(EXTRA_DEVICE_RSSI, rssi);
            sendBroadcast(found);
        }

        @Override
        public void onScanFailed(int errorCode)
        {
            Log.e(TAG, "BLE scan failed: " + errorCode);
            scanning = false;
            broadcastResult(false, "BLE scan failed: " + errorCode);
        }
    };

    /**
     * Called by the fragment when the user taps a device in the list.
     * Stops scanning and runs the full Aliro BLE-Only flow to that device.
     */
    @SuppressLint("MissingPermission")
    public void connectToReader(BluetoothDevice device)
    {
        Log.d(TAG, "connectToReader: " + device.getAddress());
        stopScan();
        lastDevice = device;
        gatt133RetryCount = 0;
        connectToDevice(device);
    }

    // -------------------------------------------------------------------------
    // GATT helpers
    // -------------------------------------------------------------------------

    @SuppressLint("MissingPermission")
    private void connectToDevice(BluetoothDevice device)
    {
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
                gatt.close();
                gatt133RetryCount++;
                if (gatt133RetryCount > MAX_133_RETRIES)
                {
                    Log.e(TAG, "GATT status 133 exceeded max retries, giving up");
                    gatt133RetryCount = 0;
                    // Re-scan to get a fresh advertisement and retry the whole flow
                    new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() ->
                    {
                        if (running) startScan();
                    }, 2000);
                    return;
                }
                // Exponential backoff: 500ms, 1s, 1.5s, 2s, 2.5s
                long delay = 500L * gatt133RetryCount;
                Log.w(TAG, "GATT status 133 (attempt " + gatt133RetryCount + "/" + MAX_133_RETRIES + "), retrying in " + delay + "ms");
                new android.os.Handler(android.os.Looper.getMainLooper()).postDelayed(() ->
                {
                    if (running && lastDevice != null)
                    {
                        Log.d(TAG, "Retrying GATT connect to " + lastDevice.getAddress());
                        connectToDevice(lastDevice);
                    }
                }, delay);
                return;
            }
            // Reset retry counter on any non-133 callback
            gatt133RetryCount = 0;
            if (newState == BluetoothProfile.STATE_CONNECTED)
            {
                Log.d(TAG, "GATT connected, discovering services...");
                gatt.discoverServices();
            }
            else if (newState == BluetoothProfile.STATE_DISCONNECTED)
            {
                Log.d(TAG, "GATT disconnected");
                gatt.close();
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

                runCredentialFlow(socket);
            }
            catch (IOException e)
            {
                Log.e(TAG, "L2CAP connection failed", e);
                broadcastResult(false, "L2CAP connection failed: " + e.getMessage());
            }
            finally
            {
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

                // Read Reader Status Completed
                exchangeMsg = readAliroMessage(in);
                exchangeHeader = AliroBleMessage.parseHeader(exchangeMsg);
                exchangePayload = AliroBleMessage.extractPayload(exchangeMsg);
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
        try
        {
            int dataOffset = 5;
            int dataLen = apdu[4] & 0xFF;
            if (apdu.length >= dataOffset + dataLen)
            {
                byte[] cert = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
                // Parse tag 0x85 for reader static public key X
                for (int i = 0; i < cert.length - 2; i++)
                {
                    if ((cert[i] & 0xFF) == 0x85 && (cert[i + 1] & 0xFF) == 0x42)
                    {
                        if (i + 68 <= cert.length && cert[i + 2] == 0x00 && cert[i + 3] == 0x04)
                        {
                            readerStaticPubKeyX = Arrays.copyOfRange(cert, i + 4, i + 36);
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
                    null,
                    AliroCryptoProvider.INTERFACE_BYTE_BLE,
                    auth0Flag);

            if (keybuf == null)
            {
                Log.e(TAG, "AUTH1: key derivation failed");
                return null;
            }
            skReader = Arrays.copyOfRange(keybuf, 0, 32);
            skDevice = Arrays.copyOfRange(keybuf, 32, 64);
            bleSK    = Arrays.copyOfRange(keybuf, 96, 128);

            // Compute credential signature
            byte[] credSig = AliroCryptoProvider.computeCredentialSignature(
                    credPrivKey, readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            if (credSig == null)
            {
                Log.e(TAG, "AUTH1: credential signature failed");
                return null;
            }

            // Build AUTH1 response plaintext: 5A 41 <cred pub key 65> 9E 40 <sig 64>
            byte[] plaintext = new byte[2 + 65 + 2 + 64];
            plaintext[0] = 0x5A; plaintext[1] = 0x41;
            System.arraycopy(credPubKeyBytes, 0, plaintext, 2, 65);
            plaintext[67] = (byte)0x9E; plaintext[68] = 0x40;
            System.arraycopy(credSig, 0, plaintext, 69, 64);

            // Encrypt with SKDevice
            byte[] encrypted = AliroCryptoProvider.encryptDeviceGcm(skDevice, plaintext);
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
     * Handle EXCHANGE APDU
     */
    private byte[] handleExchangeBle(byte[] apdu)
    {
        try
        {
            int dataOffset = 5;
            int dataLen = apdu[4] & 0xFF;
            if (dataOffset + dataLen > apdu.length) return null;

            byte[] encryptedPayload = Arrays.copyOfRange(apdu, dataOffset, dataOffset + dataLen);
            byte[] decrypted = AliroCryptoProvider.decryptReaderGcm(skReader, encryptedPayload);
            if (decrypted == null)
            {
                Log.e(TAG, "EXCHANGE: decryption failed");
                return null;
            }
            Log.d(TAG, "EXCHANGE decrypted: " + Hex.toHexString(decrypted));

            // Parse tag 97 for access decision
            for (int j = 0; j < decrypted.length - 1; j++)
            {
                if (decrypted[j] == (byte)0x97 && decrypted[j + 1] == 0x02 && j + 3 < decrypted.length)
                {
                    boolean granted = (decrypted[j + 2] == 0x01);
                    Log.d(TAG, "EXCHANGE: access granted=" + granted);
                    break;
                }
            }

            // Response: encrypted 0x0002||0x00||0x00
            byte[] successPayload = { 0x00, 0x02, 0x00, 0x00 };
            byte[] encResponse = AliroCryptoProvider.encryptDeviceGcm(skDevice, successPayload);
            if (encResponse == null) return null;

            byte[] response = new byte[encResponse.length + 2];
            System.arraycopy(encResponse, 0, response, 0, encResponse.length);
            response[encResponse.length]     = (byte)0x90;
            response[encResponse.length + 1] = 0x00;
            return response;
        }
        catch (Exception e)
        {
            Log.e(TAG, "handleExchangeBle error", e);
            return null;
        }
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
        if (skReader != null) { Arrays.fill(skReader, (byte)0); skReader = null; }
        if (skDevice != null) { Arrays.fill(skDevice, (byte)0); skDevice = null; }
        if (bleSK != null)    { Arrays.fill(bleSK, (byte)0);    bleSK = null; }
    }

    private void broadcastResult(boolean accessGranted, String message)
    {
        Intent intent = new Intent(ACTION_BLE_RESULT);
        intent.setPackage(getPackageName());
        intent.putExtra(EXTRA_ACCESS_GRANTED, accessGranted);
        intent.putExtra(EXTRA_STATUS_MESSAGE, message);
        sendBroadcast(intent);
        Log.d(TAG, "Broadcast: accessGranted=" + accessGranted + " msg=" + message);
    }
}
