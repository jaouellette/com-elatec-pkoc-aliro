package com.psia.pkoc;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothProfile;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;
import android.util.Log;
import android.widget.Toast;

import com.psia.pkoc.core.BLE_PacketType;
import com.psia.pkoc.core.BleFragmenter;
import com.psia.pkoc.core.Constants;
import com.psia.pkoc.core.PKOC_ConnectionType;
import com.psia.pkoc.core.ReaderDto;
import com.psia.pkoc.core.SiteDto;
import com.psia.pkoc.core.TLVProvider;
import com.psia.pkoc.core.interfaces.Transaction;
import com.psia.pkoc.core.transactions.BleEcdheFlowTransaction;
import com.psia.pkoc.core.transactions.BleNormalFlowTransaction;
import com.psia.pkoc.PKOC_Application;
import com.psia.pkoc.SiteModel;
import com.psia.pkoc.ReaderModel;

import java.util.ArrayList;
import java.util.LinkedList;
import java.util.Queue;


/**
 * Bluetooth Gatt Callback for PKOC
 */
public class PKOC_BluetoothCallbackGatt extends BluetoothGattCallback
{
    private final Activity mainActivity;
    private Handler bHandler;
    private final Handler uiHandler;
    private Transaction transaction;

    BluetoothGattService requiredService;
    BluetoothGattCharacteristic writeCharacteristic;
    BluetoothGattCharacteristic readCharacteristic;

    // BLE Transport Profile 2.0.1 §5.5: application-layer fragmentation state.
    private int negotiatedMtu = 23;
    private final BleFragmenter.Reassembler incomingReassembler = new BleFragmenter.Reassembler();
    private final Queue<byte[]> outgoingFragments = new LinkedList<>();
    private volatile boolean writeInProgress = false;
    private volatile boolean disconnectAfterWrite = false;

    private BluetoothGattService tryGetService(BluetoothGatt gatt)
    {
        BluetoothGattService requiredService = gatt.getService(Constants.ServiceUUID);

        if (requiredService == null)
        {
            requiredService = gatt.getService(Constants.ServiceLegacyUUID);
        }

        return requiredService;
    }

    /**
     * Constructor
     * @param parent Activity
     * @param toUse Enumeration for PKOC flow option
     * @param updateUIHandler Handler to receive UI updates
     * @param siteDtos list of known sites
     * @param readerDtos list of known readers
     */
    public PKOC_BluetoothCallbackGatt (Activity parent, PKOC_ConnectionType toUse, Handler updateUIHandler, ArrayList<SiteDto> siteDtos, ArrayList<ReaderDto> readerDtos)
    {
        mainActivity = parent;

        if (toUse == PKOC_ConnectionType.Uncompressed)
        {
            transaction = new BleNormalFlowTransaction(true, mainActivity);
        }
        else if (toUse == PKOC_ConnectionType.ECHDE_Full)
        {
            // Read the site/reader lists fresh from the DB at transaction-build time,
            // so a key scanned after this callback was created is still picked up.
            ArrayList<SiteDto> freshSites = (ArrayList<SiteDto>) PKOC_Application.getDb()
                    .siteDao().list().stream().map(SiteModel::toDto)
                    .collect(java.util.stream.Collectors.toList());
            ArrayList<ReaderDto> freshReaders = (ArrayList<ReaderDto>) PKOC_Application.getDb()
                    .readerDao().list().stream().map(ReaderModel::toDto)
                    .collect(java.util.stream.Collectors.toList());
            transaction = new BleEcdheFlowTransaction(true, freshSites, freshReaders, mainActivity);
        }

        uiHandler = updateUIHandler;

        HandlerThread hThread = new HandlerThread("PKOC_GATT");
        if (!hThread.isAlive())
        {
            hThread.start();
            bHandler = new Handler(hThread.getLooper());
        }
    }

    /**
     * On connection state change
     * @param gatt Bluetooth GATT
     * @param status Status
     * @param newState new State
     */
    @Override
    @SuppressLint("MissingPermission")
    public void onConnectionStateChange (BluetoothGatt gatt, int status, int newState)
    {
        super.onConnectionStateChange(gatt, status, newState);

        bHandler.post(() ->
        {
            if (status != 0x0000 || newState == BluetoothProfile.STATE_DISCONNECTED)
            {
                gatt.close();
            }

            if (newState == BluetoothProfile.STATE_CONNECTED)
            {
                gatt.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH);

                try
                {
                    Thread.sleep(2);
                }
                catch (InterruptedException e)
                {
                    throw new RuntimeException(e);
                }

                gatt.discoverServices();
            }
        });

    }

    /**
     * on Services Discovered
     * @param gatt Bluetooth GATT
     * @param status Status
     */
    @SuppressLint("MissingPermission")
    @Override
    public void onServicesDiscovered (BluetoothGatt gatt, int status)
    {
        super.onServicesDiscovered(gatt, status);

        bHandler.post(() ->
        {
            requiredService = tryGetService(gatt);

            gatt.requestMtu(512);
        });
    }

    /**
     * on MTU Changed
     * @param gatt Bluetooth GATT
     * @param mtu Maximum transmission unit in bytes
     * @param status status integer
     */
    @Override
    public void onMtuChanged(BluetoothGatt gatt, int mtu, int status)
    {
        super.onMtuChanged(gatt, mtu, status);

        negotiatedMtu = (status == BluetoothGatt.GATT_SUCCESS) ? mtu : 23;

        bHandler.post(() -> characteristicRegistration(gatt));
    }

    /**
     * characteristic Registration
     * @param gatt Bluetooth GATT
     */
    @SuppressLint("MissingPermission")
    public void characteristicRegistration(BluetoothGatt gatt)
    {
        requiredService = tryGetService(gatt);

        if (requiredService == null)
        {
            gatt.disconnect();
            return;
        }

        readCharacteristic = requiredService.getCharacteristic(Constants.ReadUUID);
        writeCharacteristic = requiredService.getCharacteristic(Constants.WriteUUID);

        if(readCharacteristic == null || writeCharacteristic == null)
        {
            gatt.disconnect();
            return;
        }

        gatt.setCharacteristicNotification(readCharacteristic, true);

        BluetoothGattDescriptor descriptor = readCharacteristic.getDescriptor(Constants.ConfigUUID);

        if (descriptor == null)
        {
            Log.d("Failed", "No Notification Support From Reader");
            uiHandler.post(() -> Toast.makeText(mainActivity, "Reader does not support notifications", Toast.LENGTH_SHORT).show());
            gatt.disconnect();
            return;
        }

        descriptor.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
        gatt.writeDescriptor(descriptor);
    }

    /**
     * on Characteristic Changed
     * @param gatt Bluetooth GATT
     * @param characteristic Characteristic
     */
    @SuppressLint("MissingPermission")
    @Override
    public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic)
    {
        super.onCharacteristicChanged(gatt, characteristic);

        bHandler.post(() ->
        {
            final byte[] value = characteristic.getValue();
            if (value == null)
            {
                return;
            }

            byte[] complete = incomingReassembler.onFragment(value);
            if (complete == null)
            {
                return; // still reassembling
            }

            var validationResult = transaction.processNewData(complete);
            if(validationResult.isValid)
            {
                var toWrite = transaction.toWrite();
                if (toWrite != null)
                {
                    sendFragmented(gatt, toWrite, false);
                }
                else
                {
                    Message message = new Message();
                    message.what = transaction.getReaderUnlockStatus().ordinal();
                    uiHandler.sendMessage(message);
                }
            }
            else if (validationResult.cancelTransaction)
            {
                byte[] errorTlv = TLVProvider.GetBleTLV(BLE_PacketType.Error, new byte[]{ validationResult.errorCode });
                sendFragmented(gatt, errorTlv, true);
            }
        });
    }

    /**
     * on Characteristic Write
     * @param gatt Bluetooth GATT
     * @param characteristic Characteristic
     * @param status Status
     */
    @Override
    public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status)
    {
        super.onCharacteristicWrite(gatt, characteristic, status);

        bHandler.post(() -> pumpNextWrite(gatt));
    }

    /**
     * Fragment a payload (PKOC BLE Transport Profile 2.0.1 §5.5) and enqueue it for sending.
     * @param gatt Bluetooth GATT
     * @param payload full message to send
     * @param disconnectAfter disconnect once every queued fragment has been written
     */
    private void sendFragmented(BluetoothGatt gatt, byte[] payload, boolean disconnectAfter)
    {
        outgoingFragments.addAll(BleFragmenter.fragment(payload, negotiatedMtu));
        disconnectAfterWrite |= disconnectAfter;

        if (!writeInProgress)
        {
            pumpNextWrite(gatt);
        }
    }

    /**
     * Send the next queued fragment, or disconnect if the queue is empty and a
     * disconnect was requested once the write completed.
     * @param gatt Bluetooth GATT
     */
    @SuppressLint("MissingPermission")
    private void pumpNextWrite(BluetoothGatt gatt)
    {
        byte[] fragment = outgoingFragments.poll();
        if (fragment == null)
        {
            writeInProgress = false;
            if (disconnectAfterWrite)
            {
                disconnectAfterWrite = false;
                gatt.disconnect();
            }
            return;
        }

        writeInProgress = true;
        writeCharacteristic.setValue(fragment);
        gatt.writeCharacteristic(writeCharacteristic);
    }
}
