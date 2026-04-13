package com.psia.pkoc;

import static android.os.Looper.getMainLooper;

import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanRecord;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.content.res.Configuration;
import android.graphics.BlendMode;
import android.graphics.BlendModeColorFilter;
import android.graphics.Color;
import android.graphics.PorterDuff;
import android.graphics.drawable.Drawable;
import android.location.LocationManager;
import android.nfc.NfcAdapter;
import android.nfc.NfcManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelUuid;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.provider.Settings;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.RelativeLayout;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.core.view.MenuHost;
import androidx.core.view.MenuProvider;
import androidx.fragment.app.Fragment;
import androidx.navigation.NavController;
import androidx.navigation.Navigation;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import com.psia.pkoc.core.Constants;
import com.psia.pkoc.core.CryptoProvider;
import com.psia.pkoc.core.PKOC_ConnectionType;
import com.psia.pkoc.core.PKOC_Preferences;
import com.psia.pkoc.core.PKOC_TransmissionType;
import com.psia.pkoc.core.ReaderDto;
import com.psia.pkoc.core.SiteDto;
import com.psia.pkoc.databinding.FragmentSendCredentialBinding;

/**
 * Send credential fragment
 */
public class SendCredentialFragment extends Fragment
{
    private FragmentSendCredentialBinding binding;
    private MenuProvider menuProvider;
    private BluetoothAdapter mBTAdapter;
    private ListModelAdapter mBTArrayAdapter;
    private ListModel chosenDevice;
    private BluetoothGatt connectedGatt;

    private boolean IsConnecting = false;
    private boolean _IsScanning = false;

    private static Handler updateUIHandler;
    private static Handler timeoutHandler;

    /**
     * Broadcast receiver used to handle intents sent by the NFC APDU service
     * indicating that the emulated smart card has successfully generated
     * an authentication command to be sent to a connected reader
     */
    // Broadcast receiver for Aliro BLE result from AliroBleCredentialService
    private final BroadcastReceiver aliroBleReceiver = new BroadcastReceiver()
    {
        @Override
        public void onReceive(Context context, Intent intent)
        {
            if (!isAdded()) return;
            boolean granted = intent.getBooleanExtra(AliroBleCredentialService.EXTRA_ACCESS_GRANTED, false);
            new Handler(getMainLooper()).post(() ->
            {
                if (!isAdded()) return;
                binding.readerIcon.setImageResource(granted
                        ? R.drawable.ic_reader_success
                        : R.drawable.ic_reader_error);
                binding.statusText.setText(granted ? "Aliro BLE: Credential Sent" : "Aliro BLE: Send Failed");
                binding.statusText.setVisibility(View.VISIBLE);
                binding.readerIcon.postDelayed(() ->
                {
                    if (!isAdded()) return;
                    binding.readerIcon.setImageResource(R.drawable.ic_reader_idle);
                    binding.statusText.setVisibility(View.INVISIBLE);
                    restoreButtonUI();
                    if (binding.btnAliroBle != null)
                    {
                        binding.btnAliroBle.setText("Aliro BLE");
                        binding.btnAliroBle.setOnClickListener(v -> startAliroBle());
                    }
                    // Clear the entire list (Aliro + any stale PKOC entries) and
                    // restart PKOC scan if AutoDiscover is on, so the user starts fresh
                    if (_IsScanning) setIsScanning(false);
                    if (mBTArrayAdapter != null) { mBTArrayAdapter.clear(); mBTArrayAdapter.notifyDataSetChanged(); }
                    aliroDeviceAddresses.clear();
                    android.content.SharedPreferences prefs2 = requireActivity().getPreferences(android.content.Context.MODE_PRIVATE);
                    if (prefs2.getBoolean(PKOC_Preferences.AutoDiscoverDevices, false) && isAdded())
                        setIsScanning(true);
                }, 3000);
            });
        }
    };
    private boolean aliroBleReceiverRegistered = false;
    private boolean aliroBleDeviceReceiverRegistered = false;
    private AliroBleCredentialService aliroBleCredentialService;
    private boolean aliroBleServiceBound = false;
    // Tracks which list entries are Aliro BLE (vs PKOC BLE) so the click listener can route correctly
    private final java.util.Set<String> aliroDeviceAddresses = new java.util.HashSet<>();

    private final android.content.ServiceConnection aliroBleConnection = new android.content.ServiceConnection()
    {
        @Override
        public void onServiceConnected(android.content.ComponentName name, android.os.IBinder service)
        {
            aliroBleCredentialService = ((AliroBleCredentialService.LocalBinder) service).getService();
            aliroBleServiceBound = true;
        }
        @Override
        public void onServiceDisconnected(android.content.ComponentName name)
        {
            aliroBleCredentialService = null;
            aliroBleServiceBound = false;
        }
    };

    private final BroadcastReceiver aliroBleDeviceReceiver = new BroadcastReceiver()
    {
        @Override
        public void onReceive(Context context, Intent intent)
        {
            if (!isAdded()) return;
            String address = intent.getStringExtra(AliroBleCredentialService.EXTRA_DEVICE_ADDRESS);
            String name    = intent.getStringExtra(AliroBleCredentialService.EXTRA_DEVICE_NAME);
            int    rssi    = intent.getIntExtra(AliroBleCredentialService.EXTRA_DEVICE_RSSI, 0);
            if (address == null) return;

            new Handler(getMainLooper()).post(() ->
            {
                if (!isAdded() || mBTArrayAdapter == null) return;

                aliroDeviceAddresses.add(address);

                // Update existing entry or add new one
                for (int i = 0; i < mBTArrayAdapter.getCount(); i++)
                {
                    ListModel m = (ListModel) mBTArrayAdapter.getItem(i);
                    if (m.getAddress().equals(address))
                    {
                        m.setRssi(rssi);
                        m.setLastSeen(new java.util.Date());
                        mBTArrayAdapter.notifyDataSetChanged();
                        return;
                    }
                }
                ListModel entry = new ListModel();
                entry.setAddress(address);
                entry.setName("[Aliro] " + name);
                entry.setRssi(rssi);
                entry.setIcon(R.drawable.baseline_lock_24);
                entry.setLastSeen(new java.util.Date());
                mBTArrayAdapter.add(entry);
                mBTArrayAdapter.notifyDataSetChanged();
            });
        }
    };

    private final BroadcastReceiver nfcReceiver = new BroadcastReceiver()
    {
        @Override
        public void onReceive(Context context, Intent intent)
        {
            if (!isAdded())
            {
                return;
            }

            binding.readerIcon.setImageResource(R.drawable.ic_reader_success);
            // Determine protocol from the broadcast action
            String action = intent.getAction();
            String transport;
            if ("com.psia.pkoc.ALIRO_CREDENTIAL_SENT".equals(action))
                transport = "Aliro NFC";
            else
                transport = "PKOC NFC";
            binding.statusText.setText(transport + ": " + getString(R.string.credential_sent));
            binding.statusText.setVisibility(View.VISIBLE);

            binding.readerIcon.postDelayed(() ->
            {
                if (!isAdded())
                {
                    return;
                }

                binding.readerIcon.setImageResource(R.drawable.ic_reader_idle);
                binding.statusText.setVisibility(View.INVISIBLE);
            }, 2000);
        }
    };

    /**
     * Get device from address
     *
     * @param address MAC address of the BLE device
     * @return Matched device from address
     */
    private ListModel getModelFromAddress(String address)
    {
        for (int a = 0; a < mBTArrayAdapter.getCount(); a++)
        {
            if (((ListModel) mBTArrayAdapter.getItem(a)).getAddress().equals(address))
            {
                return (ListModel) mBTArrayAdapter.getItem(a);
            }
        }
        return null;
    }

    /**
     * Helper function to set button background color
     * @param btn Button
     * @param color New color as integer
     */
    private void setButtonColor(Button btn, Integer color)
    {
        if (Build.VERSION.SDK_INT >= 29)
            btn.getBackground().setColorFilter(new BlendModeColorFilter(color, BlendMode.MULTIPLY));
        else
            btn.getBackground().setColorFilter(color, PorterDuff.Mode.MULTIPLY);
    }

    /**
     * Setter for _IsScanning private variable
     * @param value New value
     */
    private void setIsScanning(boolean value)
    {
        if (_IsScanning == value)
        {
            return;
        }

        _IsScanning = value;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        {
            if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED)
                return;
        }
        else
        {
            if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED)
                return;
        }

        if (value)
        {
            // Starting a new scan — tear down any stale GATT connection and reset state
            // so the new scan starts clean (mirrors Aliro BLE connectToDevice guard)
            IsConnecting = false;
            if (connectedGatt != null)
            {
                try { connectedGatt.disconnect(); connectedGatt.close(); }
                catch (Exception ignored) {}
                connectedGatt = null;
            }
        }

        if (_IsScanning)
        {
            if (mBTAdapter != null)
            {
                if (!mBTAdapter.isEnabled())
                {
                    Toast.makeText(getContext(), getString(R.string.BTnotOn), Toast.LENGTH_SHORT).show();
                    return;
                }
            }

            LocationManager lm = (LocationManager)requireContext().getSystemService(Context.LOCATION_SERVICE);
            boolean gps_enabled = false;
            boolean network_enabled = false;

            try
            {
                gps_enabled = lm.isProviderEnabled(LocationManager.GPS_PROVIDER);
            }
            catch (Exception ignored) {}

            try
            {
                network_enabled = lm.isProviderEnabled(LocationManager.NETWORK_PROVIDER);
            }
            catch (Exception ignored) {}

            if (!gps_enabled && !network_enabled)
            {
                Toast.makeText(getContext(), getString(R.string.LocationNotOn), Toast.LENGTH_LONG).show();
                return;
            }

            mBTArrayAdapter.clear();
            mBTArrayAdapter.notifyDataSetChanged();

            List<ScanFilter> filters = new ArrayList<>();
            ScanFilter.Builder serviceFilter = new ScanFilter.Builder().setServiceUuid(new ParcelUuid(Constants.ServiceUUID));
            ScanFilter.Builder serviceLegacyFilter = new ScanFilter.Builder().setServiceUuid(new ParcelUuid(Constants.ServiceLegacyUUID));
            filters.add(serviceFilter.build());
            filters.add(serviceLegacyFilter.build());

            ScanSettings settings = new ScanSettings.Builder()
                    .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                    .build();

            mBTAdapter.getBluetoothLeScanner().startScan(filters, settings, mLeScanCallback);

            Toast.makeText(getContext(), getString(R.string.DisStart), Toast.LENGTH_SHORT).show();

            binding.discover.setText(R.string.stop_discovery);
            setButtonColor(binding.discover, Color.RED);
        }
        else
        {
            mBTAdapter.getBluetoothLeScanner().stopScan(mLeScanCallback);
            binding.discover.setText(R.string.discover_new_devices);
            setButtonColor(binding.discover, requireContext().getColor(R.color.colorAccent));
        }
    }

    /**
     * Helper function to increase readability of permission check
     * @param permission Permission to check
     * @return Boolean if the permission is granted
     */
    private Boolean hasPermission(String permission)
    {
        return ContextCompat.checkSelfPermission(this.requireContext(), permission) == PackageManager.PERMISSION_GRANTED;
    }

    /***
     * Request NFC permissions
     */
    private void requestNfcPermissions()
    {
        NfcManager nfcManager = (NfcManager) requireContext().getSystemService(Context.NFC_SERVICE);
        NfcAdapter nfcAdapter = nfcManager != null ? nfcManager.getDefaultAdapter() : null;

        if (nfcAdapter == null)
        {
            return;
        }

        if (!nfcAdapter.isEnabled())
        {
            new AlertDialog.Builder(requireContext())
                    .setTitle(R.string.enable_nfc)
                    .setMessage(R.string.nfc_is_disabled_please_enable_it_if_you_intend_to_use_nfc_to_transmit_credentials)
                    .setPositiveButton(R.string.go_to_settings, (dialog, which) ->
                    {
                        Intent intent = new Intent(Settings.ACTION_NFC_SETTINGS);
                        startActivity(intent);
                    })
                    .setNegativeButton(R.string.cancel, null)
                    .show();
        }
    }

    /***
     * Request Bluetooth permissions
     */
    private void requestBluetoothPermissions()
    {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        {
            if (!hasPermission(Manifest.permission.ACCESS_FINE_LOCATION) || !hasPermission(Manifest.permission.BLUETOOTH_CONNECT) || !hasPermission(Manifest.permission.BLUETOOTH_SCAN))
            {
                String[] permissionsForNewerPhones = new String[]
                        {
                                Manifest.permission.ACCESS_FINE_LOCATION,
                                Manifest.permission.BLUETOOTH_CONNECT,
                                Manifest.permission.BLUETOOTH_SCAN
                        };

                ActivityCompat.requestPermissions(this.requireActivity(), permissionsForNewerPhones, 1);
            }
        }
        else
        {
            if (!hasPermission(Manifest.permission.ACCESS_FINE_LOCATION) || !hasPermission(Manifest.permission.BLUETOOTH_ADMIN))
            {
                String[] permissionsForOlderPhones = new String[]
                        {
                                Manifest.permission.ACCESS_FINE_LOCATION,
                                Manifest.permission.BLUETOOTH_ADMIN
                        };

                ActivityCompat.requestPermissions(this.requireActivity(), permissionsForOlderPhones, 1);
            }
        }
    }

    /**
     * Initialize Fragment for NFC usage
     */
    private void initializeFragmentForNfc()
    {
        binding.discover.setVisibility(View.GONE);
        binding.devicesListView.setVisibility(View.GONE);
        binding.readerContainer.setVisibility(View.VISIBLE); // show the reader icon + instruction
        if (binding.btnAliroBle != null) binding.btnAliroBle.setVisibility(View.GONE);

        requestNfcPermissions();

        IntentFilter filter = new IntentFilter("com.psia.pkoc.CREDENTIAL_SENT");
        filter.addAction("com.psia.pkoc.ALIRO_CREDENTIAL_SENT");
        ContextCompat.registerReceiver(requireActivity(), nfcReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);
    }

    /**
     * Teardown/cleanup of NFC usage
     */
    private void teardownFragmentForNfc()
    {
        requireActivity().unregisterReceiver(nfcReceiver);
    }

    private void teardownAliroBle()
    {
        if (aliroBleReceiverRegistered)
        {
            try { requireActivity().unregisterReceiver(aliroBleReceiver); }
            catch (Exception ignored) {}
            aliroBleReceiverRegistered = false;
        }
        if (aliroBleDeviceReceiverRegistered)
        {
            try { requireActivity().unregisterReceiver(aliroBleDeviceReceiver); }
            catch (Exception ignored) {}
            aliroBleDeviceReceiverRegistered = false;
        }
        if (aliroBleServiceBound)
        {
            try { requireContext().unbindService(aliroBleConnection); }
            catch (Exception ignored) {}
            aliroBleServiceBound = false;
            aliroBleCredentialService = null;
        }
    }

    private void startAliroBle()
    {
        Log.i("SendCredentialFragment", "Starting Aliro BLE scan");

        // Stop PKOC scanning if running
        if (_IsScanning) setIsScanning(false);

        // Close any active PKOC GATT connection
        if (connectedGatt != null)
        {
            try { connectedGatt.disconnect(); connectedGatt.close(); }
            catch (Exception ignored) {}
            connectedGatt = null;
            IsConnecting = false;
        }

        // Clear previous Aliro entries from list and address set
        aliroDeviceAddresses.clear();
        if (mBTArrayAdapter != null)
        {
            for (int i = mBTArrayAdapter.getCount() - 1; i >= 0; i--)
            {
                ListModel m = (ListModel) mBTArrayAdapter.getItem(i);
                if (aliroDeviceAddresses.contains(m.getAddress()))
                    mBTArrayAdapter.remove(m);
            }
            // Since we just cleared aliroDeviceAddresses above, clear all and let PKOC rescan
            // Actually just clear everything — user tapped Aliro BLE so PKOC list is stale
            mBTArrayAdapter.clear();
            mBTArrayAdapter.notifyDataSetChanged();
        }

        // Show the device list so user can pick a reader
        binding.readerContainer.setVisibility(View.GONE);
        binding.discover.setVisibility(View.VISIBLE);
        binding.devicesListView.setVisibility(View.VISIBLE);
        if (binding.btnAliroBle != null) binding.btnAliroBle.setVisibility(View.VISIBLE);
        binding.btnAliroBle.setText("Stop Aliro Scan");
        binding.btnAliroBle.setOnClickListener(v -> stopAliroBle());

        // Register device-found receiver
        if (!aliroBleDeviceReceiverRegistered)
        {
            IntentFilter deviceFilter = new IntentFilter(AliroBleCredentialService.ACTION_DEVICE_FOUND);
            ContextCompat.registerReceiver(requireActivity(), aliroBleDeviceReceiver, deviceFilter,
                    ContextCompat.RECEIVER_NOT_EXPORTED);
            aliroBleDeviceReceiverRegistered = true;
        }

        // Register result receiver
        if (!aliroBleReceiverRegistered)
        {
            IntentFilter resultFilter = new IntentFilter(AliroBleCredentialService.ACTION_BLE_RESULT);
            ContextCompat.registerReceiver(requireActivity(), aliroBleReceiver, resultFilter,
                    ContextCompat.RECEIVER_NOT_EXPORTED);
            aliroBleReceiverRegistered = true;
        }

        // Start + bind service
        Intent intent = new Intent(requireContext(), AliroBleCredentialService.class);
        requireContext().startService(intent);
        requireContext().bindService(intent, aliroBleConnection, Context.BIND_AUTO_CREATE);
    }

    /** Restore the scan button UI and ensure no button retains focus. */
    private void restoreButtonUI()
    {
        binding.readerContainer.setVisibility(View.GONE);
        binding.discover.setVisibility(View.VISIBLE);
        binding.devicesListView.setVisibility(View.VISIBLE);
        if (binding.btnAliroBle != null) binding.btnAliroBle.setVisibility(View.VISIBLE);
        // Explicitly clear focus so no button gets the highlight ring
        binding.discover.clearFocus();
        if (binding.btnAliroBle != null) binding.btnAliroBle.clearFocus();
        if (binding.getRoot() != null) binding.getRoot().requestFocus();
    }

    private void stopAliroBle()
    {
        if (aliroBleCredentialService != null) aliroBleCredentialService.stopScan();
        if (binding.btnAliroBle != null)
        {
            binding.btnAliroBle.setText("Aliro BLE");
            binding.btnAliroBle.setOnClickListener(v -> startAliroBle());
        }
    }

    /**
     * Initialize fragment for BLE usage
     */
    private void initializeFragmentForBle()
    {
        binding.discover.setVisibility(View.VISIBLE);
        binding.devicesListView.setVisibility(View.VISIBLE);
        binding.readerContainer.setVisibility(View.GONE); // hide reader icon in BLE mode

        // Aliro BLE button — starts AliroBleCredentialService
        if (binding.btnAliroBle != null)
        {
            binding.btnAliroBle.setVisibility(View.VISIBLE);
            binding.btnAliroBle.setOnClickListener(v ->
            {
                v.clearFocus();
                if (binding.getRoot() != null) binding.getRoot().requestFocus();
                startAliroBle();
            });
        }

        mBTArrayAdapter = new ListModelAdapter(requireActivity());
        Log.i("SendCredentialFragment", "mBTArrayAdapter is not null");
        binding.discover.setOnClickListener(v ->
        {
            v.clearFocus();
            if (binding.getRoot() != null) binding.getRoot().requestFocus();
            setIsScanning(!_IsScanning);
        });

        mBTAdapter = BluetoothAdapter.getDefaultAdapter();

        binding.devicesListView.setAdapter(mBTArrayAdapter);
        binding.devicesListView.setOnItemClickListener(mDeviceClickListener);

        Log.i("SendCredentialFragment", "Begin check permissions");
        requestBluetoothPermissions();
        LoadUserPreferences();

        updateUIHandler = new Handler(getMainLooper())
        {
            @Override
            public void handleMessage (@NonNull Message msg)
            {
                super.handleMessage(msg);
                Log.i("SendCredentialFragment", "handleMessage");

                IsConnecting = false;

                String deviceAddress = chosenDevice.getAddress();
                chosenDevice = getModelFromAddress(deviceAddress);

                if (chosenDevice == null || !isAdded())
                {
                    return;
                }

                chosenDevice.setIsBusy(false);
                mBTArrayAdapter.notifyDataSetChanged();

                // Determine result type
                boolean pkocGranted  = msg.what == ReaderUnlockStatus.AccessGranted.ordinal();
                boolean pkocUnknown  = msg.what == ReaderUnlockStatus.CompletedTransaction.ordinal();
                boolean pkocDenied   = msg.what == ReaderUnlockStatus.AccessDenied.ordinal()
                                    || msg.what == ReaderUnlockStatus.Unrecognized.ordinal()
                                    || msg.what == ReaderUnlockStatus.Unknown.ordinal();

                // Vibrate feedback
                Vibrator vibrator = requireContext().getSystemService(Vibrator.class);
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                {
                    if (pkocGranted || pkocUnknown)
                        vibrator.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_DOUBLE_CLICK));
                    else
                        vibrator.vibrate(VibrationEffect.createPredefined(VibrationEffect.EFFECT_HEAVY_CLICK));
                }

                // Show reader display UI — same as Aliro
                binding.discover.setVisibility(View.GONE);
                binding.devicesListView.setVisibility(View.GONE);
                if (binding.btnAliroBle != null) binding.btnAliroBle.setVisibility(View.GONE);
                binding.readerContainer.setVisibility(View.VISIBLE);

                if (pkocGranted)
                {
                    binding.readerIcon.setImageResource(R.drawable.ic_reader_success);
                    binding.statusText.setText("PKOC BLE: " + getString(R.string.credential_sent));
                }
                else if (pkocUnknown)
                {
                    binding.readerIcon.setImageResource(R.drawable.ic_reader_success);
                    binding.statusText.setText("PKOC BLE: " + getString(R.string.credential_sent));
                }
                else
                {
                    binding.readerIcon.setImageResource(R.drawable.ic_reader_error);
                    binding.statusText.setText("PKOC BLE: Access Denied");
                }
                binding.statusText.setVisibility(View.VISIBLE);

                // Restore list after 3 seconds — clear list first, then restart scan if AutoDiscover
                // (mirrors Aliro BLE behaviour: list is always empty when buttons reappear)
                binding.readerIcon.postDelayed(() ->
                {
                    if (!isAdded()) return;
                    binding.readerIcon.setImageResource(R.drawable.ic_reader_idle);
                    binding.statusText.setVisibility(View.INVISIBLE);

                    // Stop scanning and wipe the list before making it visible
                    if (_IsScanning) setIsScanning(false);
                    if (mBTArrayAdapter != null) { mBTArrayAdapter.clear(); mBTArrayAdapter.notifyDataSetChanged(); }

                    restoreButtonUI();

                    SharedPreferences sharedPref2 = requireActivity().getPreferences(Context.MODE_PRIVATE);
                    boolean AutoDiscover = sharedPref2.getBoolean(PKOC_Preferences.AutoDiscoverDevices, false);
                    if (AutoDiscover && isAdded())
                        setIsScanning(true);  // setIsScanning(true) also clears the adapter before scanning
                }, 3000);

                if (msg.what == ReaderUnlockStatus.Unrecognized.ordinal())
                    Log.i("SendCredentialFragment", "Reader is not recognized in this mode");

                if (msg.what == ReaderUnlockStatus.Unknown.ordinal())
                    Log.i("SendCredentialFragment", "Lost connection with reader");
            }
        };
    }

    private void teardownFragmentForBle()
    {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        {
            if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }
        else
        {
            if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }

        if (mBTAdapter != null)
        {
            if (mBTAdapter.isEnabled())
            {
                if (_IsScanning)
                {
                    setIsScanning(false);
                }

                if (IsConnecting && connectedGatt != null)
                {
                    connectedGatt.disconnect();
                }
            }
        }
    }

    private void initializeFragment()
    {
        int orientation = getResources().getConfiguration().orientation;
        if (orientation == Configuration.ORIENTATION_LANDSCAPE)
        {
            binding.imageView.setVisibility(View.GONE);
        }
        else
        {
            binding.imageView.setVisibility(View.VISIBLE);
        }

        SharedPreferences sharedPref = requireActivity().getPreferences(Context.MODE_PRIVATE);
        int transmissionTypeInt = sharedPref.getInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.BLE.ordinal());
        PKOC_TransmissionType transmissionType = PKOC_TransmissionType.values()[transmissionTypeInt];

        if (transmissionType == PKOC_TransmissionType.NFC)
        {
            initializeFragmentForNfc();
        }
        else
        {
            initializeFragmentForBle();
        }
    }

    private void teardownFragment()
    {
        SharedPreferences sharedPref = requireActivity().getPreferences(Context.MODE_PRIVATE);
        int transmissionTypeInt = sharedPref.getInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.BLE.ordinal());
        PKOC_TransmissionType transmissionType = PKOC_TransmissionType.values()[transmissionTypeInt];

        if (transmissionType == PKOC_TransmissionType.NFC)
        {
            teardownFragmentForNfc();
        }
        else
        {
            teardownFragmentForBle();
        }
    }

    @Override
    public View onCreateView (@NonNull LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState)
    {
        Log.i("SendCredentialFragment", "onCreateView");
        binding = FragmentSendCredentialBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    public void LoadUserPreferences ()
    {
        Log.i("SendCredentialFragment", "LoadUserPreferences");

        SharedPreferences sharedPref = requireActivity().getPreferences(Context.MODE_PRIVATE);
        boolean AutoDiscover = sharedPref.getBoolean(PKOC_Preferences.AutoDiscoverDevices, false);

        Log.i("SendCredentialFragment", "AutoDiscover: " + AutoDiscover);
        if (AutoDiscover)
        {
            Log.d("SendCredentialFragment", "AutoDiscover is true");
            binding.discover.setVisibility(View.GONE);

            RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) binding.devicesListView.getLayoutParams();
            params.addRule(RelativeLayout.ALIGN_PARENT_TOP);
            binding.devicesListView.setLayoutParams(params);

            setIsScanning(true);
        }
        else
        {
            Log.d("SendCredentialFragment", "AutoDiscover is false");
            binding.discover.setVisibility(View.VISIBLE);

            RelativeLayout.LayoutParams params = (RelativeLayout.LayoutParams) binding.devicesListView.getLayoutParams();
            params.removeRule(RelativeLayout.ALIGN_PARENT_TOP);
            binding.devicesListView.setLayoutParams(params);

            if (_IsScanning)
            {
                setIsScanning(false);
            }
        }
    }

    public void onViewCreated (@NonNull View view, Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        MenuHost host = requireActivity();
        host.addMenuProvider(menuProvider = new MenuProvider()
        {
            @Override
            public void onCreateMenu (@NonNull Menu menu, @NonNull MenuInflater menuInflater)
            {
                requireActivity().getMenuInflater().inflate(R.menu.menu_main, menu);
            }

            @Override
            public boolean onMenuItemSelected (@NonNull MenuItem menuItem)
            {
                if (menuItem.getItemId() == R.id.action_settings)
                {
                    NavController navController = Navigation.findNavController(requireActivity(), R.id.nav_host_fragment_content_main);
                    navController.navigate(R.id.settingsFragment);
                    return true;
                }

                if (menuItem.getItemId() == R.id.action_about)
                {
                    NavController navController = Navigation.findNavController(requireActivity(), R.id.nav_host_fragment_content_main);
                    navController.navigate(R.id.aboutFragment);
                    return true;
                }

                if (menuItem.getItemId() == R.id.action_DisplayPK)
                {
                    NavController navController = Navigation.findNavController(requireActivity(), R.id.nav_host_fragment_content_main);
                    navController.navigate(R.id.action_sendCredentialFragment_to_DisplayPKFragment);
                    return true;
                }

                if (menuItem.getItemId() == R.id.action_data_management)
                {
                    NavController navController = Navigation.findNavController(requireActivity(), R.id.nav_host_fragment_content_main);
                    navController.navigate(R.id.action_sendCredentialFragment_to_dataManagementFragment);
                    return true;
                }

                if (menuItem.getItemId() == R.id.action_scan_reader_qr)
                {
                    NavController navController = Navigation.findNavController(requireActivity(), R.id.nav_host_fragment_content_main);
                    navController.navigate(R.id.action_sendCredentialFragment_to_scanReaderQrFragment);
                    return true;
                }

                if (menuItem.getItemId() == R.id.action_aliro_config)
                {
                    NavController navController = Navigation.findNavController(requireActivity(), R.id.nav_host_fragment_content_main);
                    navController.navigate(R.id.action_sendCredentialFragment_to_credentialAliroConfigFragment);
                    return true;
                }

                return false;
            }
        });

        CryptoProvider.initializeCredentials(requireActivity());
        initializeFragment();
    }

    @Override
    public void onDestroyView ()
    {
        if (menuProvider != null)
        {
            MenuHost host = requireActivity();
            host.removeMenuProvider(menuProvider);
        }

        teardownFragment();
        teardownAliroBle();
        super.onDestroyView();
        binding = null;
    }

    private final ScanCallback mLeScanCallback = new ScanCallback()
    {
        @Override
        public void onScanResult(int callbackType, ScanResult result)
        {
            super.onScanResult(callbackType, result);

            if (!isAdded()) {
                return;
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED)
                    return;
            } else {
                if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED)
                    return;
            }

            ScanRecord scanRecord = result.getScanRecord();
            if (scanRecord == null || scanRecord.getServiceUuids() == null) return;

            List<ParcelUuid> uuids = scanRecord.getServiceUuids();
            boolean hasTargetUUID = false;

            for (ParcelUuid uuid : uuids) {
                UUID currentUUID = uuid.getUuid();
                if (currentUUID.equals(UUID.fromString("0000FFF0-0000-1000-8000-00805F9B34FB")) ||
                        currentUUID.equals(UUID.fromString("41fb60a1-d4d0-4ae9-8cbb-b62b5ae81810"))) {
                    hasTargetUUID = true;
                    break;
                }
            }
            if (!hasTargetUUID) return;

            if (IsConnecting)
                return;

            for (int i = 0; i < mBTArrayAdapter.getCount(); i++) {
                ListModel toCheck = (ListModel) mBTArrayAdapter.getItem(i);
                if ((new Date()).getTime() - toCheck.getLastSeen().getTime() > 15 * 1000)
                    mBTArrayAdapter.remove(toCheck);
            }

            ListModel ToUpdate = new ListModel();
            ToUpdate.setIcon(R.drawable.baseline_lock_24);
            String Address = result.getDevice().getAddress();
            ToUpdate.setAddress(Address);
            ToUpdate.setLastSeen(new Date());

            String Name = result.getDevice().getName();
            if (Name == null || Name.isEmpty())
            {
                byte[] scanRecordBytes = scanRecord.getBytes();
                Name = parseDeviceName(scanRecordBytes);
            }
            if (Name == null || Name.isEmpty())
            {
                Name = "Unknown Reader";
            }
            // Prefix PKOC so user can distinguish from Aliro readers in the list
            if (!Name.startsWith("[PKOC]"))
            {
                Name = "[PKOC] " + Name;
            }
            ToUpdate.setName(Name);
            ToUpdate.setRssi(result.getRssi());

            SharedPreferences sharedPref = requireActivity().getPreferences(Context.MODE_PRIVATE);
            boolean rangingEnabled = sharedPref.getBoolean(PKOC_Preferences.EnableRanging, false);

            if (rangingEnabled) {
                Log.i("SendCredentialFragment", "Ranging enabled");
                int range = sharedPref.getInt(PKOC_Preferences.RangeValue, 0);
                range *= -5;
                range -= 35;

                if (ToUpdate.getRssi() >= range) {
                    Log.i("SendCredentialFragment", "Ranging success");
                    IsConnecting = true;
                    updateUIHandler.postDelayed(() -> connectDevice(ToUpdate), 100);
                }
            }

            for (int a = 0; a < mBTArrayAdapter.getCount(); a++) {
                ListModel thisModel = (ListModel) mBTArrayAdapter.getItem(a);
                if (thisModel.getAddress().equals(Address)) {
                    thisModel.setRssi(ToUpdate.getRssi());
                    thisModel.setLastSeen(new Date());
                    mBTArrayAdapter.notifyDataSetChanged();
                    return;
                }
            }

            mBTArrayAdapter.add(ToUpdate);
            mBTArrayAdapter.notifyDataSetChanged();
        }

        @Override
        public void onBatchScanResults (List<ScanResult> results)
        {
            super.onBatchScanResults(results);
        }

        @Override
        public void onScanFailed (int errorCode)
        {
            super.onScanFailed(errorCode);
        }
    };

    public void connectDevice(ListModel lm)
    {
        Log.i("SendCredentialFragment", "connectDevice");
        if (mBTAdapter != null)
        {
            Log.i("SendCredentialFragment", "mBTAdapter is not null");
            if (!mBTAdapter.isEnabled())
            {
                Log.i("SendCredentialFragment", "BT not on");
                Toast.makeText(getContext(), getString(R.string.BTnotOn), Toast.LENGTH_SHORT).show();
                return;
            }
        }

        if (_IsScanning)
        {
            Log.i("SendCredentialFragment", "Stopping scanning");
            setIsScanning(false);
        }

        Log.i("SendCredentialFragment", "Sending Credential");
        Toast.makeText(getContext(), "Sending Credential", Toast.LENGTH_SHORT).show();

        chosenDevice = lm;
        chosenDevice.setIsBusy(true);
        mBTArrayAdapter.notifyDataSetChanged();

        final String address = lm.getAddress();

        Log.i("SendCredentialFragment", "lm.getAddress address: " + address);
        SharedPreferences sharedPref = requireActivity().getPreferences(Context.MODE_PRIVATE);
        int ToFlow_int = sharedPref.getInt(PKOC_Preferences.PKOC_TransmissionFlow, PKOC_ConnectionType.Uncompressed.ordinal());

        PKOC_ConnectionType finalToFlow = PKOC_ConnectionType.values()[ToFlow_int];
        Log.i("SendCredentialFragment", "finalToFlow: " + finalToFlow);
        new Thread(() -> {
            // Close any previous GATT client before opening a new one.
            // Without this, the old client holds the connection open and the
            // new connectGatt() call gets routed to the stale callback.
            if (connectedGatt != null)
            {
                Log.i("SendCredentialFragment", "Closing previous GATT client");
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                {
                    if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED)
                        connectedGatt.close();
                }
                else
                {
                    connectedGatt.close();
                }
                connectedGatt = null;
            }

            BluetoothDevice device = mBTAdapter.getRemoteDevice(address);

            Log.i("SendCredentialFragment", "device: " + device);

            ArrayList<SiteDto> siteDtos = (ArrayList<SiteDto>) PKOC_Application.getDb().siteDao().list().stream().map(SiteModel::toDto).collect(Collectors.toList());
            ArrayList<ReaderDto> readerDtos = (ArrayList<ReaderDto>) PKOC_Application.getDb().readerDao().list().stream().map(ReaderModel::toDto).collect(Collectors.toList());

            PKOC_BluetoothCallbackGatt callback = new PKOC_BluetoothCallbackGatt(requireActivity(), finalToFlow, updateUIHandler, siteDtos, readerDtos);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            {
                Log.i("SendCredentialFragment", "Checking for bluetooth connect permission");
                if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED)
                    return;
            }
            else
            {
                if (ActivityCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED)
                    return;
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
            {
                Log.i("SendCredentialFragment", "Connecting to device");
                connectedGatt = device.connectGatt(getContext(),
                        false,
                        callback,
                        BluetoothDevice.TRANSPORT_LE,
                        ScanSettings.PHY_LE_ALL_SUPPORTED);
            }
            else
            {
                Log.i("SendCredentialFragment", "Connecting to device else");
                connectedGatt = device.connectGatt(getContext(),
                        false,
                        callback);
            }

            if (timeoutHandler != null)
            {
                Log.w("SendCredentialFragment", "Cancelling timeout handler");
                timeoutHandler.removeCallbacksAndMessages(null);
            }

            timeoutHandler = new Handler(getMainLooper());
            timeoutHandler.postDelayed(() ->
            {
                if (IsConnecting)
                {
                    Log.w("SendCredentialFragment", "Timeout handler");
                    if (connectedGatt != null)
                    {
                        Log.w("SendCredentialFragment", "Disconnecting");
                        connectedGatt.disconnect();
                        connectedGatt.close();
                        connectedGatt = null;
                    }

                    IsConnecting = false;
                    chosenDevice.setIsBusy(false);
                    chosenDevice.setIcon(R.drawable.baseline_lock_24);
                    mBTArrayAdapter.notifyDataSetChanged();

                    Log.w("SendCredentialFragment", "Interaction with the reader has timed out");
                    Toast.makeText(getContext(), "Interaction with the reader has timed out", Toast.LENGTH_SHORT).show();

                    SharedPreferences sharedPref1 = requireActivity().getPreferences(Context.MODE_PRIVATE);
                    boolean AutoDiscover = sharedPref1.getBoolean(PKOC_Preferences.AutoDiscoverDevices, false);

                    if (AutoDiscover)
                    {
                        setIsScanning(true);
                    }
                }
            }, 6000);

        }).start();
    }

    private final AdapterView.OnItemClickListener mDeviceClickListener = new AdapterView.OnItemClickListener()
    {
        @Override
        public void onItemClick(AdapterView<?> parent, View view, int position, long id)
        {
            ListModel lm = (ListModel) mBTArrayAdapter.getItem(position);

            if (aliroDeviceAddresses.contains(lm.getAddress()))
            {
                // Aliro BLE device — route to AliroBleCredentialService
                stopAliroBle(); // stop scanning
                if (aliroBleCredentialService != null)
                {
                    android.bluetooth.BluetoothAdapter btAdapter = android.bluetooth.BluetoothAdapter.getDefaultAdapter();
                    android.bluetooth.BluetoothDevice device = btAdapter.getRemoteDevice(lm.getAddress());

                    // Show waiting UI
                    binding.discover.setVisibility(View.GONE);
                    binding.devicesListView.setVisibility(View.GONE);
                    if (binding.btnAliroBle != null) binding.btnAliroBle.setVisibility(View.GONE);
                    binding.readerContainer.setVisibility(View.VISIBLE);
                    binding.readerIcon.setImageResource(R.drawable.ic_reader_idle);
                    binding.statusText.setText("Connecting to " + lm.getName() + "...");
                    binding.statusText.setVisibility(View.VISIBLE);

                    aliroBleCredentialService.connectToReader(device);
                }
                else
                {
                    Toast.makeText(requireContext(), "Aliro service not ready, try again", Toast.LENGTH_SHORT).show();
                }
            }
            else if (!IsConnecting)
            {
                // PKOC BLE device — existing flow
                IsConnecting = true;
                connectDevice(lm);
            }
        }
    };

    private String parseDeviceName(byte[] scanRecord)
    {
        int index = 0;
        while (index < scanRecord.length) {
            int length = scanRecord[index++];
            if (length == 0) break;

            int type = scanRecord[index];
            if (type == 0x09) {
                return new String(Arrays.copyOfRange(scanRecord, index + 1, index + length));
            }
            index += length;
        }
        return null;
    }
}