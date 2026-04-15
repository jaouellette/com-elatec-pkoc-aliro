package com.pkoc.readersimulator;

import static java.lang.System.arraycopy;

import android.annotation.SuppressLint;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattServer;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.media.AudioManager;
import android.media.ToneGenerator;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Spannable;
import android.text.style.BackgroundColorSpan;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AlphaAnimation;
import android.view.animation.Animation;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.TextView;
import android.widget.Toast;
import android.widget.LinearLayout;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.Fragment;
import android.text.SpannableStringBuilder;
import android.text.SpannableString;
import android.text.style.AbsoluteSizeSpan;
import android.text.style.ForegroundColorSpan;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.text.Html;
import android.text.Spanned;
import android.text.style.StyleSpan;
import android.graphics.Typeface;
import android.Manifest;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattServerCallback;
import android.bluetooth.BluetoothProfile;
import android.bluetooth.le.AdvertiseCallback;
import android.bluetooth.le.AdvertiseData;
import android.bluetooth.le.AdvertiseSettings;
import android.bluetooth.le.BluetoothLeAdvertiser;
import android.bluetooth.BluetoothGattDescriptor;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.ParcelUuid;

import androidx.core.content.ContextCompat;

import com.psia.pkoc.core.BLE_Packet;
import com.psia.pkoc.core.BLE_PacketType;
import com.psia.pkoc.core.Constants;
import com.psia.pkoc.core.CryptoProvider;
import com.psia.pkoc.core.PKOC_ConnectionType;
import com.psia.pkoc.core.PKOC_Preferences;
import com.psia.pkoc.core.ReaderUnlockStatus;
import com.psia.pkoc.core.TLVProvider;
import com.psia.pkoc.core.UuidConverters;
import com.psia.pkoc.core.transactions.NfcNormalFlowTransaction;
import com.psia.pkoc.core.AliroCryptoProvider;
import com.psia.pkoc.core.AliroMailbox;
import com.psia.pkoc.core.LeafVerifiedManager;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;

import android.content.BroadcastReceiver;
import android.content.ComponentName;
import android.content.IntentFilter;
import android.content.ServiceConnection;
import android.os.IBinder;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;


public class HomeFragment extends Fragment implements NfcAdapter.ReaderCallback
{

    private static final String TAG = "HomeFragment";

    // Reader protocol mode
    public static final String PREF_READER_MODE  = "reader_protocol_mode";
    public static final int    MODE_PKOC = 0;
    public static final int    MODE_ALIRO = 1;
    public static final int    MODE_AUTO  = 2; // tries Aliro SELECT first, falls back to PKOC
    public static final int    MODE_LEAF  = 3; // LEAF Verified Open ID only

    private int readerMode = MODE_AUTO; // default: auto-detect
    private Button rdrButton;
    private TextView textView;
    private TextView readerLocationUUIDView;
    private TextView readerSiteUUIDView;
    private TextView sitePublicKeyView;
    private TextView nfcAdvertisingStatusView;
    private TextView bleAdvertisingStatusView;
    private String bleStatusValue;
    private String scanReaderUUIDValue;
    private String siteUUIDValue;
    private String sitePublicKeyValue;
    private String nfcAdvertisingStatusValue;
    private String bleAdvertisingStatusValue;

    private UUID readerUUID;
    private UUID siteUUID;

    private NfcAdapter nfcAdapter;

    private BluetoothManager mBluetoothManager;
    private BluetoothLeAdvertiser mBluetoothLeAdvertiser;
    private BluetoothGattServer mBluetoothGattServer;
    private final List<FlowModel> _connectedDevices = new CopyOnWriteArrayList<>();

    private ActivityResultLauncher<String[]> requestPermissionLauncher;

    private ImageView readerImageView;
    private LinearLayout keypadLayout;
    private boolean keypadPositioned = false;

    private TextView pinDisplay;
    private boolean isDisplayingResult = false;

    // Cached Aliro reader private key — loaded once when config changes to avoid
    // rebuilding the ECPrivateKey on every NFC tap (which takes ~400ms).
    private java.security.PrivateKey cachedAliroReaderPrivKey = null;
    private String cachedAliroPrivKeyHex = null;

    // --- Aliro BLE L2CAP service ---
    private AliroBleReaderService aliroBleService;
    private boolean aliroBleServiceBound = false;

    private final ServiceConnection aliroBleConnection = new ServiceConnection()
    {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service)
        {
            aliroBleService = ((AliroBleReaderService.LocalBinder) service).getService();
            aliroBleServiceBound = true;
            Log.d(TAG, "AliroBleReaderService bound — auto-starting BLE");
            // Auto-start immediately — no button needed
            if (!aliroBleService.isRunning())
                aliroBleService.startAliroBle();
        }
        @Override
        public void onServiceDisconnected(ComponentName name)
        {
            aliroBleService = null;
            aliroBleServiceBound = false;
        }
    };

    private final BroadcastReceiver aliroBleReceiver = new BroadcastReceiver()
    {
        @Override
        public void onReceive(android.content.Context context, Intent intent)
        {
            boolean granted       = intent.getBooleanExtra(AliroBleReaderService.EXTRA_ACCESS_GRANTED, false);
            boolean sigValid      = intent.getBooleanExtra(AliroBleReaderService.EXTRA_SIG_VALID, false);
            String credPubKeyHex  = intent.getStringExtra(AliroBleReaderService.EXTRA_CREDENTIAL_PUB_KEY);
            byte[] deviceResponse = intent.getByteArrayExtra(AliroBleReaderService.EXTRA_DEVICE_RESPONSE);
            String stepUpElemId   = intent.getStringExtra(AliroBleReaderService.EXTRA_STEP_UP_ELEMENT_ID);
            String mailboxResult  = intent.getStringExtra(AliroBleReaderService.EXTRA_MAILBOX_RESULT);
            Log.d(TAG, "Aliro BLE result: granted=" + granted + " sigValid=" + sigValid
                    + " stepUp=" + (deviceResponse != null ? deviceResponse.length + "B" : "none")
                    + " mailbox=" + (mailboxResult != null ? mailboxResult : "none"));
            requireActivity().runOnUiThread(() ->
            {
                if (!isAdded()) return;
                if (granted && credPubKeyHex != null)
                {
                    // Stop accepting new connections while result is displayed
                    if (aliroBleService != null) aliroBleService.stopAliroBle();

                    // Build connection type string — formatted via shared helper
                    // (initial value will be overwritten by formatAliroConnectionType below)
                    String connectionType = "";

                    // Parse step-up result from device response bytes
                    String bleStepUpResult = null;
                    if (deviceResponse != null)
                    {
                        bleStepUpResult = parseBleStepUpResult(deviceResponse, stepUpElemId);
                        if (bleStepUpResult == null)
                            bleStepUpResult = "Access Document received";
                    }

                    // Parse mailbox: if it looks like raw hex (not already parsed), decode it
                    String bleMailboxParsed = null;
                    if (mailboxResult != null)
                    {
                        if (mailboxResult.matches("[0-9A-Fa-f]+") && mailboxResult.length() >= 4)
                        {
                            try
                            {
                                byte[] mailboxBytes = org.bouncycastle.util.encoders.Hex.decode(mailboxResult);
                                if (mailboxBytes.length > 0 && (mailboxBytes[0] & 0xFF) == 0x60)
                                    bleMailboxParsed = AliroMailbox.parseMailboxToString(mailboxBytes, mailboxBytes.length);
                                else
                                    bleMailboxParsed = mailboxResult;
                            }
                            catch (Exception ignored)
                            {
                                bleMailboxParsed = mailboxResult;
                            }
                        }
                        else
                        {
                            bleMailboxParsed = mailboxResult;
                        }
                    }

                    connectionType = formatAliroConnectionType("BLE", sigValid, bleStepUpResult, bleMailboxParsed);

                    // Show the credential result screen — same as Aliro NFC
                    readerImageView.setVisibility(View.GONE);
                    keypadLayout.setVisibility(View.GONE);
                    displayPublicKeyInfo(credPubKeyHex, connectionType);

                    ToneGenerator toneGen = new ToneGenerator(AudioManager.STREAM_RING, 100);
                    toneGen.startTone(sigValid
                            ? ToneGenerator.TONE_SUP_DIAL
                            : ToneGenerator.TONE_CDMA_ABBR_ALERT, 150);
                }
                else if (!granted)
                {
                    Toast.makeText(requireContext(),
                            "Aliro BLE: " + intent.getStringExtra(AliroBleReaderService.EXTRA_STATUS_MESSAGE),
                            Toast.LENGTH_LONG).show();
                }
            });
        }
    };

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState)
    {
        return inflater.inflate(R.layout.fragment_home, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        requireActivity().invalidateOptionsMenu();
        // Set up the reader details button
        rdrButton = view.findViewById(R.id.rdrButton);
        rdrButton.setVisibility(View.VISIBLE);
        rdrButton.setOnClickListener(v -> showRdrDetails());

        // Protocol mode toggle
        android.widget.RadioGroup modeGroup = view.findViewById(R.id.protocolModeGroup);
        readerMode = requireActivity().getPreferences(Context.MODE_PRIVATE)
                .getInt(PREF_READER_MODE, MODE_AUTO);
        switch (readerMode)
        {
            case MODE_PKOC:  modeGroup.check(R.id.modePkoc);  break;
            case MODE_ALIRO: modeGroup.check(R.id.modeAliro); break;
            case MODE_LEAF:  modeGroup.check(R.id.modeLeaf);  break;
            default:         modeGroup.check(R.id.modeAuto);  break;
        }
        updateModeLabel();
        updateRdrButtonVisibility();
        modeGroup.setOnCheckedChangeListener((group, checkedId) ->
        {
            if      (checkedId == R.id.modePkoc)  readerMode = MODE_PKOC;
            else if (checkedId == R.id.modeAliro) readerMode = MODE_ALIRO;
            else if (checkedId == R.id.modeLeaf)  readerMode = MODE_LEAF;
            else                                  readerMode = MODE_AUTO;
            requireActivity().getPreferences(Context.MODE_PRIVATE)
                    .edit().putInt(PREF_READER_MODE, readerMode).apply();
            updateModeLabel();
            updateRdrButtonVisibility();
            Log.d(TAG, "Reader mode set to: " + readerMode);
        });


        textView = view.findViewById(R.id.textView);
        readerLocationUUIDView = view.findViewById(R.id.readerLocationUUID);
        readerSiteUUIDView = view.findViewById(R.id.readerSiteUUID);
        sitePublicKeyView = view.findViewById(R.id.sitePublicKey);
        nfcAdvertisingStatusView = view.findViewById(R.id.nfcadvertisingStatus);
        bleAdvertisingStatusView = view.findViewById(R.id.bleadvertisingStatus);// Dynamically position keypad below LED area of reader image
        View readerImage = view.findViewById(R.id.readerImageView);

        readerImageView = view.findViewById(R.id.readerImageView);
        keypadLayout = view.findViewById(R.id.keypadLayout);
        keypadPositioned = false;

        // Position the keypad overlay once the reader image has been measured.
        // Using OnGlobalLayoutListener instead of post() guarantees the image
        // has valid dimensions — post() can fire before layout is complete
        // when the fragment view is recreated after navigating back.
        readerImage.getViewTreeObserver().addOnGlobalLayoutListener(
                new android.view.ViewTreeObserver.OnGlobalLayoutListener() {
                    @Override
                    public void onGlobalLayout() {
                        positionKeypad(readerImage, view);
                        // Remove after first successful positioning to avoid
                        // re-running on every subsequent layout pass.
                        readerImage.getViewTreeObserver()
                                .removeOnGlobalLayoutListener(this);
                    }
                });

        // Set up keypad PIN display and click listeners
        pinDisplay = view.findViewById(R.id.pinDisplay);
        pinDisplay.setText("");  // explicitly clear on start

        int[] keyIds = {
            R.id.key1, R.id.key2, R.id.key3,
            R.id.key4, R.id.key5, R.id.key6,
            R.id.key7, R.id.key8, R.id.key9,
            R.id.keyStar, R.id.key0, R.id.keyHash
        };
        String[] keyVals = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "*", "0", "#"};

        for (int i = 0; i < keyIds.length; i++) {
            final String val = keyVals[i];
            view.findViewById(keyIds[i]).setOnClickListener(v -> {
                CharSequence current = pinDisplay.getText();
                if (current.length() == 0) {
                    pinDisplay.setText(val);
                } else {
                    pinDisplay.setText(current + val);
                }
            });
        }

        CryptoProvider.initializeCredentials(requireActivity());
        initializeReaderAndSiteUUID();

        // Initialize with some values
        scanReaderUUIDValue = "<b>Reader Location UUID:</b>";
        siteUUIDValue = "<b>Reader Site UUID:</b>";
        sitePublicKeyValue = "<b>Site Public Key:</b>";
        nfcAdvertisingStatusValue = "<b>NFC Advertising Status:</b>";
        bleAdvertisingStatusValue = "<b>BLE Advertising Status:</b>";

        displayValues();

        // Set initial text with bold headers
        String initialText = "<b>Scan a PKOC NFC or BLE Credential</b>";
        textView.setText(Html.fromHtml(initialText, Html.FROM_HTML_MODE_LEGACY));

        String readerLocationUUIDText = "<b>Reader Location UUID:</b> " + PKOC_Preferences.ReaderUUID;
        String readerSiteUUIDText = "<b>Reader Site UUID:</b> " + PKOC_Preferences.SiteUUID;
        String sitePublicKeyText = "<b>Site Public Key:</b> " + getSitePublicKey();
        String nfcAdvertisingStatusText = "<b>NFC Advertising Status:</b> " + getAdvertisingStatus();
        String bleAdvertisingStatusText = "<b>BLE Advertising Status:</b> Pending";


        readerLocationUUIDView.setText(Html.fromHtml(readerLocationUUIDText, Html.FROM_HTML_MODE_LEGACY));
        readerSiteUUIDView.setText(Html.fromHtml(readerSiteUUIDText, Html.FROM_HTML_MODE_LEGACY));
        sitePublicKeyView.setText(Html.fromHtml(sitePublicKeyText, Html.FROM_HTML_MODE_LEGACY));
        nfcAdvertisingStatusView.setText(Html.fromHtml(nfcAdvertisingStatusText, Html.FROM_HTML_MODE_LEGACY));
        bleAdvertisingStatusView.setText(Html.fromHtml(bleAdvertisingStatusText, Html.FROM_HTML_MODE_LEGACY));

        requestPermissionLauncher =
                registerForActivityResult(new ActivityResultContracts.RequestMultiplePermissions(), isGranted -> {
                    if (isGranted.containsValue(false)) {
                        Log.d("onCreate", "Bluetooth permissions have not been granted.");
                    } else {
                        initializeBluetooth();
                    }
                });
    }

    @Override
    public void onResume()
    {
        super.onResume();
        // Clear any stale keypad input when returning from another fragment
        if (pinDisplay != null) pinDisplay.setText("");

        // Refresh mode label in case LEAF mode was toggled in LEAF Config
        updateModeLabel();

        // Re-position keypad if it hasn't been positioned yet (can happen
        // when returning from another fragment and the OnGlobalLayoutListener
        // from onViewCreated already fired before layout was ready).
        // Also handles rotation / config changes.
        if (!keypadPositioned && readerImageView != null && getView() != null) {
            readerImageView.post(() -> positionKeypad(readerImageView, getView()));
        }

        nfcAdapter = NfcAdapter.getDefaultAdapter(requireContext());
        if (nfcAdapter == null)
        {
            textView.setText(R.string.nfc_is_not_available_on_this_device);
        }
        else
        {
            nfcAdapter.enableReaderMode(requireActivity(), this, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
        }

        // Warm up the Aliro reader private key cache in the background so the
        // first NFC tap doesn't pay the ~400ms EC key construction cost.
        new Thread(() ->
        {
            SharedPreferences prefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
            String pkHex = prefs.getString(AliroPreferences.READER_PRIVATE_KEY, "");
            if (!pkHex.isEmpty() && !pkHex.equals(cachedAliroPrivKeyHex))
            {
                cachedAliroReaderPrivKey = rawBytesToEcPrivateKey(org.bouncycastle.util.encoders.Hex.decode(pkHex));
                cachedAliroPrivKeyHex = pkHex;
                Log.d(TAG, "Aliro reader private key cached");
            }
        }).start();

        // Bind Aliro BLE service and register receiver
        Intent bleServiceIntent = new Intent(requireContext(), AliroBleReaderService.class);
        requireContext().bindService(bleServiceIntent, aliroBleConnection, Context.BIND_AUTO_CREATE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU)
        {
            requireContext().registerReceiver(aliroBleReceiver,
                    new IntentFilter(AliroBleReaderService.ACTION_BLE_RESULT),
                    Context.RECEIVER_NOT_EXPORTED);
        }
        else
        {
            requireContext().registerReceiver(aliroBleReceiver,
                    new IntentFilter(AliroBleReaderService.ACTION_BLE_RESULT));
        }

        // Check for Bluetooth and location permissions
        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED
                || ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED)
        {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            {
                requestPermissionLauncher.launch(
                        new String[]
                                {
                                        Manifest.permission.ACCESS_FINE_LOCATION,
                                        Manifest.permission.BLUETOOTH,
                                        Manifest.permission.BLUETOOTH_ADVERTISE,
                                        Manifest.permission.BLUETOOTH_ADMIN,
                                        Manifest.permission.BLUETOOTH_CONNECT,
                                        Manifest.permission.BLUETOOTH_SCAN,
                                });
            } else
            {
                requestPermissionLauncher.launch(
                        new String[]
                                {
                                        Manifest.permission.ACCESS_FINE_LOCATION,
                                        Manifest.permission.BLUETOOTH,
                                        Manifest.permission.BLUETOOTH_ADMIN,
                                });
            }
        }
        else
        {
            initializeBluetooth();
        }
    }

    @Override
    public void onPause()
    {
        super.onPause();
        if (nfcAdapter != null)
        {
            nfcAdapter.disableReaderMode(requireActivity());
        }
        teardownBluetooth();

        // Unregister Aliro BLE receiver and unbind service
        try { requireContext().unregisterReceiver(aliroBleReceiver); }
        catch (Exception ignored) {}
        if (aliroBleServiceBound)
        {
            requireContext().unbindService(aliroBleConnection);
            aliroBleServiceBound = false;
        }
    }

    private void initializeReaderAndSiteUUID()
    {
        SharedPreferences prefs = requireActivity().getPreferences(Context.MODE_PRIVATE);

        String existingReader = prefs.getString(PKOC_Preferences.ReaderUUID, null);
        String existingSite = prefs.getString(PKOC_Preferences.SiteUUID, null);

        SharedPreferences.Editor editor = prefs.edit();

        if (existingReader == null || existingReader.isEmpty())
        {
            editor = prefs.edit();
            UUID newUuid = UUID.randomUUID();
            existingReader = newUuid.toString();
            editor.putString(PKOC_Preferences.ReaderUUID, existingReader);
        }

        if (existingSite == null || existingSite.isEmpty())
        {
            editor = (editor == null) ? prefs.edit() : editor;
            UUID newUuid = UUID.randomUUID();
            existingSite = newUuid.toString();
            editor.putString(PKOC_Preferences.SiteUUID, existingSite);
        }

        if (editor != null)
        {
            editor.apply();
        }

        readerUUID = UUID.fromString(existingReader);
        siteUUID = UUID.fromString(existingSite);
    }

    @SuppressLint("MissingPermission")
    private void initializeBluetooth()
    {
        // Initialize Bluetooth
        Log.d("onCreate", "Initializing Bluetooth");
        mBluetoothManager = (BluetoothManager) requireContext().getSystemService(Context.BLUETOOTH_SERVICE);
        BluetoothAdapter mBluetoothAdapter = mBluetoothManager.getAdapter();
        mBluetoothAdapter.setName("PSIA PKOC Reader Simulator");

        if (!checkBluetoothSupport(mBluetoothAdapter))
        {
            Log.d("onCreate", "Bluetooth not supported");
            requireActivity().finish();
        }

        // Start BLE advertising and server
        Log.d("onCreate", "Starting BLE advertising and server");
        startAdvertising();
        startServer();
    }

    private void teardownBluetooth()
    {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        {
            if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }
        else
        {
            if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }

        if (mBluetoothLeAdvertiser != null)
        {
            mBluetoothLeAdvertiser.stopAdvertising(mAdvertiseCallback);
            mBluetoothLeAdvertiser = null;
        }

        if (mBluetoothGattServer != null)
        {
            mBluetoothGattServer.clearServices();
            mBluetoothGattServer.close();
            mBluetoothGattServer = null;
        }
    }

    private void displayValues()
    {
        readerLocationUUIDView.setText(scanReaderUUIDValue);
        readerSiteUUIDView.setText(siteUUIDValue);
        sitePublicKeyView.setText(sitePublicKeyValue);
        nfcAdvertisingStatusView.setText(nfcAdvertisingStatusValue);
        bleAdvertisingStatusView.setText(bleAdvertisingStatusValue);
    }

    private String getSitePublicKey()
    {
        // Retrieve or generate the Site Public Key
        byte[] sitePubKey = CryptoProvider.getUncompressedPublicKeyBytes();
        return Hex.toHexString(sitePubKey);
    }

    private String getAdvertisingStatus()
    {
        // Retrieve or generate the Advertising Status
        return "Not applicable for NFC"; // NFC does not have an advertising status like BLE
    }

    @Override
    public void onTagDiscovered(Tag tag)
    {
        Log.d("NFC", "Tag discovered");
        IsoDep isoDep = IsoDep.get(tag);
        if (isoDep == null) return;

        try
        {
            isoDep.connect();
            isoDep.setTimeout(5000); // 5 second timeout for crypto-heavy Aliro flow

            Log.d("NFC", "Tag discovered, reader mode: " + readerMode);

            if (readerMode == MODE_PKOC)
            {
                // ---------------------------------------------------------------
                // PKOC-only mode — go straight to PKOC, skip Aliro SELECT
                // ---------------------------------------------------------------
                Log.d("NFC", "PKOC mode — running PKOC flow directly");
                runPkocNfcFlow(isoDep);
            }
            else if (readerMode == MODE_ALIRO)
            {
                // ---------------------------------------------------------------
                // Aliro-only mode — send Aliro SELECT, fail if not supported
                // ---------------------------------------------------------------
                byte[] aliroSelect = buildAliroSelectCommand();
                Log.d("NFC", "Aliro mode — sending SELECT: " + Hex.toHexString(aliroSelect));
                byte[] selectResponse = isoDep.transceive(aliroSelect);
                Log.d("NFC", "SELECT response: " + Hex.toHexString(selectResponse));

                if (isSW9000(selectResponse))
                {
                    performAliroNfcTransaction(isoDep, selectResponse);
                }
                else
                {
                    Log.e("NFC", "Aliro mode: credential does not support Aliro AID");
                    sendControlFlow(isoDep);
                    showAliroError("This credential does not support Aliro.");
                }
            }
            else if (readerMode == MODE_LEAF)
            {
                // ---------------------------------------------------------------
                // LEAF-only mode — try LEAF SELECT, fail if not supported
                // ---------------------------------------------------------------
                Log.d("NFC", "LEAF mode — running LEAF Open ID flow");
                performLeafNfcTransaction(isoDep);
            }
            else
            {
                // ---------------------------------------------------------------
                // Auto mode — try Aliro first, then LEAF (if Root CA configured),
                // then fall back to PKOC
                // ---------------------------------------------------------------

                // 1. Try Aliro
                byte[] aliroSelect = buildAliroSelectCommand();
                Log.d("NFC", "Auto mode — trying Aliro SELECT: " + Hex.toHexString(aliroSelect));
                byte[] selectResponse = isoDep.transceive(aliroSelect);
                Log.d("NFC", "SELECT response: " + Hex.toHexString(selectResponse));

                if (isSW9000(selectResponse))
                {
                    Log.d("NFC", "Aliro AID selected — running Aliro flow");
                    performAliroNfcTransaction(isoDep, selectResponse);
                }
                else
                {
                    // 2. Try LEAF if a Root CA has been imported
                    boolean leafEnabled = requireActivity().getPreferences(Context.MODE_PRIVATE)
                            .getBoolean(LeafVerifiedManager.READER_PREF_LEAF_MODE, false);
                    byte[] rootCAPub = LeafVerifiedManager.getReaderRootCAPubKey(requireContext());

                    if (leafEnabled && rootCAPub != null)
                    {
                        Log.d("NFC", "Not Aliro — trying LEAF flow");
                        boolean leafHandled = performLeafNfcTransaction(isoDep);
                        if (!leafHandled)
                        {
                            Log.d("NFC", "LEAF failed — falling back to PKOC");
                            runPkocNfcFlow(isoDep);
                        }
                    }
                    else
                    {
                        Log.d("NFC", "Not Aliro (SW=" + swHex(selectResponse) + ") — falling back to PKOC");
                        runPkocNfcFlow(isoDep);
                    }
                }
            }

            isoDep.close();
        }
        catch (IOException e)
        {
            Log.e("NFC", "Error communicating with NFC tag", e);
        }
    }

    /** Show 'Show Reader Details' only in PKOC or Auto mode — not relevant for Aliro-only. */
    private void updateRdrButtonVisibility()
    {
        if (rdrButton == null) return;
        rdrButton.setVisibility((readerMode == MODE_ALIRO || readerMode == MODE_LEAF) ? View.GONE : View.VISIBLE);
    }

    /** Update the main title text to reflect the current reader mode. */
    private boolean isLeafModeEnabled()
    {
        return requireActivity().getPreferences(Context.MODE_PRIVATE)
                .getBoolean(LeafVerifiedManager.READER_PREF_LEAF_MODE, false);
    }

    private void updateModeLabel()
    {
        if (textView == null) return;
        boolean leafOn = isLeafModeEnabled();

        switch (readerMode)
        {
            case MODE_PKOC:
                textView.setText("Scan a PKOC NFC or BLE Credential");
                break;
            case MODE_ALIRO:
                textView.setText("Scan a Aliro NFC Credential");
                break;
            case MODE_LEAF:
                textView.setText("Scan a LEAF Verified NFC Credential");
                break;
            default: // Auto
                textView.setText(leafOn
                        ? "Scan an Aliro, LEAF Verified, or PKOC Credential"
                        : "Scan a PKOC or Aliro Credential");
                break;
        }
    }

    // Define the formatText method
    private SpannableString formatText(String text)
    {
        SpannableString spannableString = new SpannableString(text);
        spannableString.setSpan(new AbsoluteSizeSpan(14, true), 0, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        spannableString.setSpan(new ForegroundColorSpan(Color.BLACK), 0, text.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return spannableString;
    }

    // Method to send email
    private void sendEmail()
    {
        String emailBody = textView.getText().toString(); // Get the displayed text

        Intent emailIntent = new Intent(Intent.ACTION_SEND);
        emailIntent.setType("message/rfc822");
        emailIntent.putExtra(Intent.EXTRA_SUBJECT, "Key and Bit Information");
        emailIntent.putExtra(Intent.EXTRA_TEXT, emailBody);

        try
        {
            startActivity(Intent.createChooser(emailIntent, "Send email using..."));
        }
        catch (android.content.ActivityNotFoundException ex)
        {
            Toast.makeText(requireContext(), "No email clients installed.", Toast.LENGTH_SHORT).show();
        }
    }

    private void resetToScanScreen()
    {
        requireActivity().runOnUiThread(() ->
        {
            String initialText = "<b>Scan a PKOC BLE or NFC Credential</b>";
            textView.setText(Html.fromHtml(initialText, Html.FROM_HTML_MODE_LEGACY));

            ConstraintLayout mainLayout = requireView().findViewById(R.id.mainLayout);
            //mainLayout.setBackgroundResource(0);
            //mainLayout.setBackgroundResource(R.drawable.reader_background);
            // Hide the email button
            Button emailButton = requireView().findViewById(R.id.emailButton);
            emailButton.setVisibility(View.GONE);

            // Hide the scan button
            Button scanButton = requireView().findViewById(R.id.scanButton);
            scanButton.setVisibility(View.GONE);

            // Show the reader button and mode toggle
            Button rdrButton = requireView().findViewById(R.id.rdrButton);
            rdrButton.setVisibility(View.VISIBLE);
            requireView().findViewById(R.id.protocolModeGroup).setVisibility(View.VISIBLE);
            updateModeLabel();
            updateRdrButtonVisibility();

            // Restart Aliro BLE in background — ready for the next tap
            if (aliroBleService != null && !aliroBleService.isRunning())
                aliroBleService.startAliroBle();

            // Check if the button text is "Show Reader Details"
            if (rdrButton.getText().toString().equals("Show Reader Details"))
            {
                // Hide the additional fields
                readerLocationUUIDView.setVisibility(View.GONE);
                readerSiteUUIDView.setVisibility(View.GONE);
                sitePublicKeyView.setVisibility(View.GONE);
                nfcAdvertisingStatusView.setVisibility(View.GONE);
                bleAdvertisingStatusView.setVisibility(View.GONE);
            }
            else
            {
                // Restore initial values
                scanReaderUUIDValue = "Initial Scan Reader UUID";
                siteUUIDValue = "Initial Site UUID";
                sitePublicKeyValue = "Initial Site Public Key";
                nfcAdvertisingStatusValue = "<b>NFC Advertising Status:</b>";
                bleAdvertisingStatusValue = "<b>BLE Advertising status:</b>";

                displayValues();

                String readerLocationUUIDText = "<b>Reader Location UUID:</b> " + PKOC_Preferences.ReaderUUID;
                String readerSiteUUIDText = "<b>Reader Site UUID:</b> " + PKOC_Preferences.SiteUUID;
                String sitePublicKeyText = "<b>Site Public Key:</b> " + getSitePublicKey();
                String nfcAdvertisingStatusText = "<b>Advertising Status:</b> " + getAdvertisingStatus();
                String bleAdvertisingStatusText = "<b>BLE Advertising status:</b> " + bleStatusValue;

                readerLocationUUIDView.setText(Html.fromHtml(readerLocationUUIDText, Html.FROM_HTML_MODE_LEGACY));
                readerSiteUUIDView.setText(Html.fromHtml(readerSiteUUIDText, Html.FROM_HTML_MODE_LEGACY));
                sitePublicKeyView.setText(Html.fromHtml(sitePublicKeyText, Html.FROM_HTML_MODE_LEGACY));
                nfcAdvertisingStatusView.setText(Html.fromHtml(nfcAdvertisingStatusText, Html.FROM_HTML_MODE_LEGACY));
                bleAdvertisingStatusView.setText(Html.fromHtml(bleAdvertisingStatusText, Html.FROM_HTML_MODE_LEGACY));

                // Show other fields
                readerLocationUUIDView.setVisibility(View.VISIBLE);
                readerSiteUUIDView.setVisibility(View.VISIBLE);
                sitePublicKeyView.setVisibility(View.VISIBLE);
                nfcAdvertisingStatusView.setVisibility(View.VISIBLE);
                bleAdvertisingStatusView.setVisibility(View.VISIBLE);
            }
            readerImageView.setVisibility(View.VISIBLE);
            keypadLayout.setVisibility(View.VISIBLE);
            pinDisplay.setText("");
            isDisplayingResult = false;
        });
    }

    private void showRdrDetails()
    {
        readerImageView.setVisibility(View.GONE);
        keypadLayout.setVisibility(View.GONE);
        readerLocationUUIDView.setVisibility(View.VISIBLE);
        readerSiteUUIDView.setVisibility(View.VISIBLE);
        sitePublicKeyView.setVisibility(View.VISIBLE);
        nfcAdvertisingStatusView.setVisibility(View.VISIBLE);
        bleAdvertisingStatusView.setVisibility(View.VISIBLE);
        rdrButton.setText(R.string.hide_reader_details);
        rdrButton.setOnClickListener(v -> hideRdrDetails());
    }

    private void hideRdrDetails()
    {
        readerLocationUUIDView.setVisibility(View.GONE);
        readerSiteUUIDView.setVisibility(View.GONE);
        sitePublicKeyView.setVisibility(View.GONE);
        nfcAdvertisingStatusView.setVisibility(View.GONE);
        bleAdvertisingStatusView.setVisibility(View.GONE);
        readerImageView.setVisibility(View.VISIBLE);
        keypadLayout.setVisibility(View.VISIBLE);
        rdrButton.setText(R.string.show_reader_details);
        rdrButton.setOnClickListener(v -> showRdrDetails());
    }

    /**
     * Position the keypad overlay to align with the reader image.
     * Computes absolute top/bottom margins from the image's measured
     * dimensions so the keypad sits over the physical keypad area of
     * the reader graphic.  Safe to call multiple times — skips the
     * work when the image has not been laid out yet (height == 0).
     */
    private void positionKeypad(View readerImage, View rootView) {
        if (readerImage == null || keypadLayout == null || rootView == null) return;

        int imageTop = readerImage.getTop();
        int imageHeight = readerImage.getHeight();
        int screenHeight = rootView.getHeight();

        // Guard: if layout hasn't happened yet, don't set bogus margins
        if (imageHeight == 0 || screenHeight == 0) return;

        // LED indicators sit at ~18% down the reader image
        // Keypad starts just below them at ~36% into the image
        float keypadTopFraction = 0.36f;
        float keypadBottomFraction = 0.94f;

        int keypadTop = imageTop + (int)(imageHeight * keypadTopFraction);
        int keypadBottom = imageTop + (int)(imageHeight * keypadBottomFraction);

        androidx.constraintlayout.widget.ConstraintLayout.LayoutParams params =
                (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                        keypadLayout.getLayoutParams();

        params.topToTop = androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.PARENT_ID;
        params.bottomToBottom = androidx.constraintlayout.widget.ConstraintLayout.LayoutParams.PARENT_ID;
        params.topMargin = keypadTop;
        params.bottomMargin = screenHeight - keypadBottom;
        params.height = 0; // stretch between margins

        keypadLayout.setLayoutParams(params);
        keypadPositioned = true;
    }

    // Helper method to apply background, text color, font size, and bold attribute to a specific range of text
    private SpannableStringBuilder applyColorAndSize(String text, int end, int bgColor, int textColor, boolean isBold)
    {
        SpannableStringBuilder spannable = new SpannableStringBuilder(text);
        spannable.setSpan(new BackgroundColorSpan(bgColor), 0, end, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        spannable.setSpan(new ForegroundColorSpan(textColor), 0, end, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        spannable.setSpan(new AbsoluteSizeSpan(14, true), 0, end, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);

        if (isBold)
        {
            spannable.setSpan(new StyleSpan(Typeface.BOLD), 0, end, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
        }

        return spannable;
    }

    private boolean checkBluetoothSupport(BluetoothAdapter mBluetoothAdapter)
    {
        if (mBluetoothAdapter == null)
        {
            Log.w(TAG, "Bluetooth is not supported");
            return false;
        }
        if (!requireActivity().getPackageManager().hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE))
        {
            Log.w(TAG, "Bluetooth LE is not supported");
            return false;
        }
        return true;
    }

    private final AdvertiseCallback mAdvertiseCallback = new AdvertiseCallback()
    {
        @Override
        public void onStartSuccess(AdvertiseSettings settingsInEffect)
        {
            Log.i(TAG, "Advertising started successfully");
        }

        @Override
        public void onStartFailure(int errorCode)
        {
            Log.e(TAG, "Advertising failed with error code: " + errorCode);
            // Only retry on transient failures — not data-too-large or already-started
            if (errorCode != AdvertiseCallback.ADVERTISE_FAILED_ALREADY_STARTED
                    && errorCode != AdvertiseCallback.ADVERTISE_FAILED_DATA_TOO_LARGE)
            {
                startAdvertising();
            }
        }
    };

    @SuppressLint("MissingPermission")
    private void startAdvertising()
    {
        BluetoothAdapter mBluetoothAdapter = mBluetoothManager.getAdapter();
        mBluetoothAdapter.setName("ELATEC PKOC"); // device name shown in scan results
        Log.d(TAG, "Starting BLE Advertising");
        mBluetoothLeAdvertiser = mBluetoothAdapter.getBluetoothLeAdvertiser();
        if (mBluetoothLeAdvertiser == null)
        {
            Log.w(TAG, "Failed to create advertiser");
            bleStatusValue = "Failed to create advertiser";
            return;
        }
        AdvertiseSettings settings = new AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setConnectable(true)
                .setTimeout(0)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .build();
        AdvertiseData advertiseData = new AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(new ParcelUuid(UUID.fromString("0000FFF0-0000-1000-8000-00805F9B34FB")))
                .build();
        // Scan response: device name + second UUID
        // 128-bit UUID = 18 bytes, "ELATEC PKOC" = 13 bytes (2 overhead) = 15 bytes, total = 33 — too big.
        // Use name only in scan response, drop the second UUID there.
        AdvertiseData scanResponseData = new AdvertiseData.Builder()
                .setIncludeDeviceName(true)
                .build();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        {
            if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH_ADVERTISE) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }
        else
        {
            if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH_ADMIN) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }
        mBluetoothLeAdvertiser.startAdvertising(settings, advertiseData, scanResponseData, mAdvertiseCallback);
        Log.i(TAG, "BLE Advertising status: Successful.");
        bleAdvertisingStatusView.setText(Html.fromHtml("<b>BLE Advertising status:</b> Successful", Html.FROM_HTML_MODE_LEGACY));
        bleStatusValue = "Successful";
    }

    private void startServer()
    {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        {
            if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }
        else
        {
            if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH) != PackageManager.PERMISSION_GRANTED)
            {
                return;
            }
        }

        mBluetoothGattServer = mBluetoothManager.openGattServer(requireContext(), mGattServerCallback);

        if (mBluetoothGattServer == null)
        {
            Log.w(TAG, "Unable to create GATT server");
            return;
        }

        mBluetoothGattServer.addService(ReaderProfile.createReaderService());
    }

    private final BluetoothGattServerCallback mGattServerCallback = new BluetoothGattServerCallback()
    {

        @Override
        public void onConnectionStateChange(BluetoothDevice device, int status, int newState)
        {
            Log.d(TAG, ">>> onConnectionStateChange: device=" + device.getAddress() + " status=" + status + " newState=" + newState);
            if (newState == BluetoothProfile.STATE_CONNECTED)
            {
                // Remove any stale entry for this device address before adding fresh one
                for (int a = _connectedDevices.size() - 1; a >= 0; a--)
                {
                    if (device.getAddress().equals(_connectedDevices.get(a).connectedDevice.getAddress()))
                    {
                        _connectedDevices.remove(a);
                    }
                }
                FlowModel newDevice = new FlowModel();
                newDevice.connectedDevice = device;
                _connectedDevices.add(newDevice);

                Log.d(TAG, "Device connected: " + device.getAddress());
            }
            else if (newState == BluetoothProfile.STATE_DISCONNECTED)
            {
                timeoutHandler.removeCallbacks(timeoutRunnable);
                int toRemove = -1;

                for (int a = 0; a < _connectedDevices.size(); a++)
                {
                    if (device.getAddress().equals(_connectedDevices.get(a).connectedDevice.getAddress()))
                    {
                        toRemove = a;
                        break;
                    }
                }

                if (toRemove != -1)
                {
                    _connectedDevices.remove(toRemove);
                }
                // Reset GATT operation queue so next connection starts clean
                gattOperationQueue.clear();
                isGattOperationInProgress = false;
                Log.d(TAG, "Device disconnected: " + device.getAddress());
                //layoutPost("Device disconnected", device.getAddress());
            }
        }

        public void InitiatePkocFlow(BluetoothDevice device)
        {
            Log.d(TAG, ">>> InitiatePkocFlow called for " + device.getAddress());
            FlowModel deviceModel = getDeviceCredentialModel(device);

            if (deviceModel == null)
            {
                Log.e(TAG, ">>> InitiatePkocFlow: deviceModel is NULL — device not in _connectedDevices!");
                return;
            }

            // Reset state for each new transaction (device may reconnect without full disconnect)
            deviceModel.transientKeyPair = null;
            deviceModel.receivedTransientPublicKey = null;
            deviceModel.signature = null;
            deviceModel.publicKey = null;
            deviceModel.sharedSecret = null;
            deviceModel.counter = 0;
            deviceModel.connectionType = null;

            {
                deviceModel.transientKeyPair = CryptoProvider.CreateTransientKeyPair();
                byte[] encodedPublicKey = Objects.requireNonNull(deviceModel.transientKeyPair).getPublic().getEncoded();
                byte[] uncompressedTransientPublicKey = CryptoProvider.getUncompressedPublicKeyBytes(encodedPublicKey);
                Log.i(TAG, "Uncompressed Transient Public Key: " + Arrays.toString(uncompressedTransientPublicKey));

                byte[] x = new byte[32];
                arraycopy(uncompressedTransientPublicKey, 1, x, 0, 32);
                Log.i(TAG, "X portion of public key: " + Arrays.toString(x));  //Initial communication and X portion to be used for key signature

                byte[] y = new byte[32];
                arraycopy(uncompressedTransientPublicKey, 33, y, 0, 32);
                Log.i(TAG, "Y portion of public key: " + Arrays.toString(y));

                byte[] compressedTransientPublicKey = CryptoProvider.getCompressedPublicKeyBytes(encodedPublicKey);

//                byte[] version = new byte[]{(byte) 0x0C, (byte) 0x03, (short) 0x0000, (short) 0x0001};
                // Dhruv: This is hard set to AES CCM and has 5 bytes of length
                byte[] version = new byte[]
                        {
                                (byte) 0x03, (short) 0x00, (short) 0x00, (short) 0x00, (short) 0x01
                        };
                Log.i(TAG, "Version: " + Arrays.toString(version));
                byte[] readerId = UuidConverters.fromUuid(readerUUID);
                byte[] siteId = UuidConverters.fromUuid(siteUUID);

                byte[] versionTLV = TLVProvider.GetBleTLV(BLE_PacketType.ProtocolVersion, version);
                byte[] transientPublicKeyTLV = TLVProvider.GetBleTLV(BLE_PacketType.CompressedTransientPublicKey, compressedTransientPublicKey);
                byte[] readerTLV = TLVProvider.GetBleTLV(BLE_PacketType.ReaderLocationIdentifier, readerId);
                byte[] siteTLV = TLVProvider.GetBleTLV(BLE_PacketType.SiteIdentifier, siteId);
                byte[] toSend = org.bouncycastle.util.Arrays.concatenate(versionTLV, transientPublicKeyTLV, readerTLV, siteTLV);
                Log.d(TAG, "Check if we can connect");
                boolean canConnect = false;
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                {
                    if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED)
                    {
                        canConnect = true;
                    }
                }
                else
                {
                    if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH) == PackageManager.PERMISSION_GRANTED)
                    {
                        canConnect = true;
                    }
                }
                Log.d(TAG, "canConnect: " + canConnect);
                if (canConnect)
                {
                    Log.i(TAG, "Message sent in response for request to read PKOC read characteristic");
                    Log.d(TAG, ">>> Sending reader opening message, length=" + toSend.length);
                    // Start the timeout timer
                    timeoutHandler.postDelayed(timeoutRunnable, 10000); //change this back to 1000 when done troubleshooting
                    writeToReadCharacteristic(device, toSend, false);
                }
                else
                {
                    Log.w(TAG, "Not able to connect, nothing has been sent");
                }
            }
        }

        @Override
        public void onDescriptorWriteRequest(BluetoothDevice device,
                                             int requestId,
                                             BluetoothGattDescriptor descriptor,
                                             boolean preparedWrite,
                                             boolean responseNeeded,
                                             int offset,
                                             byte[] value)
        {
            Log.d(TAG, ">>> onDescriptorWriteRequest from " + device.getAddress() + ", uuid=" + descriptor.getUuid());
            if (Constants.ConfigUUID.equals(descriptor.getUuid()))
            {
                if (responseNeeded)
                {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                    {
                        if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED)
                        {
                            return;
                        }
                    }
                    else
                    {
                        if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH) != PackageManager.PERMISSION_GRANTED)
                        {
                            return;
                        }
                    }

                    boolean success = mBluetoothGattServer.sendResponse(device,
                            requestId,
                            BluetoothGatt.GATT_SUCCESS,
                            0,
                            null);

                    if (success)
                    {
                        InitiatePkocFlow(device);
                    }
                }
            }
            else
            {
                Log.w(TAG, "Unknown descriptor write request");
                if (responseNeeded)
                {
                    mBluetoothGattServer.sendResponse(device,
                            requestId,
                            BluetoothGatt.GATT_FAILURE,
                            0,
                            null);
                }
            }
        }

        @SuppressLint("MissingPermission")
        @Override
        public void onCharacteristicWriteRequest(BluetoothDevice device, int requestId, BluetoothGattCharacteristic characteristic, boolean preparedWrite, boolean responseNeeded, int offset, byte[] value)
        {
            enqueueGattOperation(() ->
            {
                Log.d(TAG, "Characteristic Write Request: " + characteristic.getUuid());
                Log.d(TAG, "Received value: " + Arrays.toString(value));
                Log.d(TAG, "Received value size: " + value.length);
                FlowModel deviceModel = getDeviceCredentialModel(device);
                if (deviceModel == null)
                {
                    Log.w(TAG, "Device model not found for device: " + device.getAddress());
                    if (responseNeeded)
                    {
                        mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                    }
                    return;
                }

                // If the previous transaction completed (publicKey+signature set) and the
                // credential app is sending again without disconnecting/re-subscribing,
                // re-initiate the flow now so we send a fresh reader opening message first.
                if (deviceModel.publicKey != null && deviceModel.signature != null && deviceModel.transientKeyPair != null)
                {
                    Log.d(TAG, ">>> Stale completed transaction detected on write — re-initiating flow");
                    InitiatePkocFlow(device);
                    // Send GATT response and let the credential app retry after receiving the new reader key
                    if (responseNeeded)
                    {
                        mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
                    }
                    onGattOperationCompleted();
                    return;
                }

                // Check if the data is encrypted
                ArrayList<BLE_Packet> packetsFromMessage = TLVProvider.GetBleValues(value);
                if (deviceModel.connectionType == PKOC_ConnectionType.ECHDE_Full)
                {
                    ArrayList<BLE_Packet> packetsFromEncryptedBlock = new ArrayList<>();

                    for (BLE_Packet blePacket : packetsFromMessage)
                    {
                        if (blePacket.PacketType.getType() == BLE_PacketType.EncryptedDataFollows.getType())
                        {
                            Log.d(TAG, "Encrypted data: " + Hex.toHexString(blePacket.Data));
                            byte[] unencryptedData = CryptoProvider.getFromAES256(deviceModel.sharedSecret, blePacket.Data, deviceModel.counter);
                            if (unencryptedData == null)
                            {
                                requireActivity().runOnUiThread(() -> Toast.makeText(requireContext(), "Error: Failed to decrypt message.", Toast.LENGTH_LONG).show());
                                mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                                timeoutHandler.removeCallbacks(timeoutRunnable);
                                onGattOperationCompleted();
                                return;
                            }
                            deviceModel.counter++;
                            Log.d(TAG, "Decrypted data: " + Hex.toHexString(unencryptedData));
                            packetsFromEncryptedBlock.addAll(TLVProvider.GetBleValues(unencryptedData));
                        }
                    }

                    packetsFromMessage.addAll(packetsFromEncryptedBlock);
                }

                // Use processedValue for TLVProvider.GetValues
                for (BLE_Packet packet : packetsFromMessage)
                {
                    if (packet != null)
                    {
                        switch (packet.PacketType)
                        {
                            case PublicKey:
                                // Since we are parsing the encrypted packets here, the public key will be processed for both flows
                                // This will happen after the PKOC flow is determined, so if the value has been upgraded in security,
                                // we wish to convey they that through the UI still.
                                if (deviceModel.connectionType != PKOC_ConnectionType.ECHDE_Full)
                                {
                                    deviceModel.connectionType = PKOC_ConnectionType.Uncompressed;
                                }
                                deviceModel.publicKey = packet.Data;
                                Log.d(TAG, "Determined PKOC flow: Normal flow");
                                Log.d(TAG, "THIS IS THE ONE Public key: " + Hex.toHexString(packet.Data));
                                break;
                            case DigitalSignature:
                                deviceModel.signature = packet.Data;
                                Log.d(TAG, "Signature: " + Hex.toHexString(packet.Data)); //signed by the private key of the device
                                break;
                            case UncompressedTransientPublicKey:
                                Log.d(TAG, "Uncompressed transient public key: " + Hex.toHexString(packet.Data));
                                deviceModel.receivedTransientPublicKey = packet.Data;
                                break;
                            case LastUpdateTime:
                                deviceModel.creationTime = new BigInteger(packet.Data).intValue();
                                Log.d(TAG, "Creation time: " + deviceModel.creationTime);
                                break;
                            case ProtocolVersion:
                                // Dhruv changed this to support 5 byte protocol version
                                deviceModel.protocolVersion = new byte[]
                                        {
                                                (byte) 0x03, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
                                        };
                                Log.d(TAG, "Protocol Version is:" + Arrays.toString(deviceModel.protocolVersion));
                            default:
                                break;
                        }
                    }
                }

                //check to validate if we can do the normal flow or need the more secure.  This will happen if the credential is sent in ECDHE Flow (Perfect Security)
                if (deviceModel.publicKey == null && deviceModel.signature == null)
                {
                    if (deviceModel.receivedTransientPublicKey != null)
                    {
                        // Get the raw ECDH shared secret
                        byte[] rawSharedSecret = CryptoProvider.getSharedSecret(
                                deviceModel.transientKeyPair.getPrivate(),
                                deviceModel.receivedTransientPublicKey);
                        Log.i("ECDHE rawSharedSecrent", Arrays.toString(rawSharedSecret));

                        // Derive the AES-CCM key by hashing the shared secret with SHA-256
                        deviceModel.sharedSecret = CryptoProvider.deriveAesKeyFromSharedSecretSimple(rawSharedSecret);

                        if (deviceModel.sharedSecret == null)
                        {
                            requireActivity().runOnUiThread(() -> Toast.makeText(requireContext(), "Error: Failed to establish secure channel.", Toast.LENGTH_LONG).show());
                            mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                            timeoutHandler.removeCallbacks(timeoutRunnable);
                            onGattOperationCompleted();
                            return;
                        }

                        deviceModel.connectionType = PKOC_ConnectionType.ECHDE_Full;
                        Log.d(TAG, "Determined PKOC flow: ECDHE Perfect Secrecy");
                        Log.d(TAG, "Shared Secret: " + Hex.toHexString(deviceModel.sharedSecret));
                    }

                    if (deviceModel.receivedTransientPublicKey != null && deviceModel.publicKey == null)
                    {
                        byte[] toSign = generateSignaturePackage(deviceModel);

                        byte[] signatureASN = CryptoProvider.GetSignedMessage(toSign);
                        if (signatureASN == null)
                        {
                            requireActivity().runOnUiThread(() -> Toast.makeText(requireContext(), "Error: Failed to sign message.", Toast.LENGTH_LONG).show());
                            mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, offset, null);
                            timeoutHandler.removeCallbacks(timeoutRunnable);
                            onGattOperationCompleted();
                            return;
                        }

                        Log.d(TAG, "Signature with ASN header: " + Hex.toHexString(signatureASN));

                        byte[] signature = CryptoProvider.RemoveASNHeaderFromSignature(signatureASN);
                        Log.d(TAG, "Signature generated: " + Hex.toHexString(signature));

                        byte[] signatureTLV = TLVProvider.GetBleTLV(BLE_PacketType.DigitalSignature, signature);
                        Log.d(TAG, "Message sent to connected device: " + Hex.toHexString(signatureTLV));
                        writeToReadCharacteristic(device, signatureTLV, false);
                    }
                }
// Check for standard flow
                boolean completedFullFlow = false;
                if (deviceModel.transientKeyPair != null
                        && deviceModel.publicKey != null
                        && deviceModel.signature != null)
                {
                    completedFullFlow = true;
                    timeoutHandler.removeCallbacks(timeoutRunnable);
                    byte[] pubKey = deviceModel.publicKey;
                    byte[] signature = deviceModel.signature;

                    byte[] x = new byte[32];
                    System.arraycopy(pubKey, 1, x, 0, 32);
                    Log.d(TAG, "X portion of public key (the credential): " + Hex.toHexString(x));  // This is the credential

                    byte[] y = new byte[32];
                    System.arraycopy(pubKey, 33, y, 0, 32);
                    Log.d(TAG, "Y portion of public key: " + Hex.toHexString(y));

                    byte[] pkoc = new byte[8];
                    System.arraycopy(x, x.length - 8, pkoc, 0, 8);
                    Log.d(TAG, "Last eight bytes of the X portion of the public key: " + Hex.toHexString(pkoc));

                    BigInteger cardNumber64 = new BigInteger(1, pkoc);
                    Log.d(TAG, "64 bit PKOC Credential: " + cardNumber64);

                    byte[] r = new byte[32];
                    System.arraycopy(signature, 0, r, 0, 32);
                    Log.d(TAG, "R portion of signature: " + Hex.toHexString(r));

                    byte[] s = new byte[32];
                    System.arraycopy(signature, 32, s, 0, 32);
                    Log.d(TAG, "S portion of signature: " + Hex.toHexString(s));


// Parse the public key on the main thread
                    new Handler(Looper.getMainLooper()).post(() ->
                    {
                        // Hide reader image and keypad when showing BLE scan results
                        readerImageView.setVisibility(View.GONE);
                        keypadLayout.setVisibility(View.GONE);

                        String publicKeyHex = Hex.toHexString(pubKey).toUpperCase();
                        String connectionTypeText;
                        if (deviceModel.connectionType == PKOC_ConnectionType.ECHDE_Full)
                        {
                            connectionTypeText = "PKOC BLE — ECDHE Perfect Secrecy";
                        }
                        else if (deviceModel.connectionType == PKOC_ConnectionType.Uncompressed)
                        {
                            connectionTypeText = "PKOC BLE — Normal Flow";
                        }
                        else
                        {
                            connectionTypeText = "PKOC BLE — Unknown Flow";
                        }
                        displayPublicKeyInfo(publicKeyHex, connectionTypeText);
                    });
                    boolean sigValid = false;

                    BigInteger xi = new BigInteger(1, x);
                    BigInteger yi = new BigInteger(1, y);
                    BigInteger ri = new BigInteger(1, r);
                    BigInteger si = new BigInteger(1, s);

                    try
                    {
                        ECDomainParameters ecParams = CryptoProvider.getDomainParameters();

                        ECPoint ecPoint = ecParams.getCurve().createPoint(xi, yi);
                        ECPublicKeyParameters pubKeyParams = new ECPublicKeyParameters(ecPoint, ecParams);

                        ECDSASigner ecSign = new ECDSASigner();
                        ecSign.init(false, pubKeyParams);

                        byte[] signatureMessage = generateSignaturePackage(deviceModel);
                        final byte[] hash = CryptoProvider.getSHA256(signatureMessage);
                        if (hash == null)
                        {
                            requireActivity().runOnUiThread(() -> Toast.makeText(requireContext(), "Error: Failed to prepare data for verification.", Toast.LENGTH_LONG).show());
                        }
                        else
                        {
                            sigValid = ecSign.verifySignature(hash, ri, si);
                        }
                    }
                    catch (Exception e)
                    {
                        requireActivity().runOnUiThread(() -> Toast.makeText(requireContext(), "Error: Signature verification failed.", Toast.LENGTH_LONG).show());
                        Log.d(TAG, e.toString());
                    }

                    byte response = 0x00;

                    boolean cardReadSuccess = Math.abs(cardNumber64.longValue()) > 0;

                    Log.i("CardReadSuccess", String.valueOf(cardReadSuccess));
                    Log.i("SigValid", String.valueOf(sigValid));

                    if (cardReadSuccess && sigValid)
                    {
                        response = BigInteger.valueOf(ReaderUnlockStatus.AccessGranted.ordinal())
                                .byteValue();
                    }
                    else if (cardReadSuccess)
                    {
                        response = BigInteger.valueOf(ReaderUnlockStatus.SignatureInvalid.ordinal())
                                .byteValue();
                    }

                    byte[] responseTLV = TLVProvider.GetBleTLV(BLE_PacketType.Response, new byte[]
                            {
                                    response
                            });
                    // Send GATT response FIRST so the credential app is ready to receive
                    // the notification. Ordering matters: ACK the write, then notify.
                    if (responseNeeded)
                    {
                        mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
                    }

                    Log.d(TAG, "Message sent to connected device: " + Hex.toHexString(responseTLV));
                    writeToReadCharacteristic(device, responseTLV, true);
                    boolean finalSigValid = sigValid;
                    new Handler(Looper.getMainLooper()).post(() ->
                    {
                        readerImageView.setVisibility(View.GONE);
                        keypadLayout.setVisibility(View.GONE);

                        if (finalSigValid)
                        {
                            ToneGenerator toneGen1 = new ToneGenerator(AudioManager.STREAM_RING, 100);
                            toneGen1.startTone(ToneGenerator.TONE_SUP_DIAL, 150);
                        }
                        else
                        {
                            ToneGenerator toneGen1 = new ToneGenerator(AudioManager.ERROR, 100);
                            toneGen1.startTone(ToneGenerator.TONE_CDMA_ABBR_ALERT, 150);
                        }
                    });
                }

                Log.d(TAG, "Calling onGattOperationCompleted from onCharacteristicWriteRequest");
                onGattOperationCompleted();

                // For intermediate ECDHE writes (not the final full flow), send the response here
                if (responseNeeded && !completedFullFlow)
                {
                    mBluetoothGattServer.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, value);
                }
            });
        }

        private FlowModel getDeviceCredentialModel(BluetoothDevice device)
        {
            for (FlowModel connectedDevice : _connectedDevices)
            {
                if (connectedDevice.connectedDevice.getAddress().equals((device.getAddress())))
                {
                    return connectedDevice;
                }
            }

            return null;
        }

        private void writeToReadCharacteristic(BluetoothDevice device, byte[] toWrite, boolean cancelConnectionAfterCompleted)
        {
            boolean canConnect = false;

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
            {
                if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED)
                {
                    canConnect = true;
                }
            }
            else
            {
                if (requireContext().checkSelfPermission(Manifest.permission.BLUETOOTH) == PackageManager.PERMISSION_GRANTED)
                {
                    canConnect = true;
                }
            }

            if (canConnect)
            {
                BluetoothGattCharacteristic readCharacteristic = null;

                // Try to get the characteristic from the primary service
                BluetoothGattService primaryService = mBluetoothGattServer.getService(Constants.ServiceUUID);
                if (primaryService != null)
                {
                    readCharacteristic = primaryService.getCharacteristic(Constants.ReadUUID);
                }

                // If not found, try to get the characteristic from the legacy service
                if (readCharacteristic == null)
                {
                    BluetoothGattService legacyService = mBluetoothGattServer.getService(Constants.ServiceLegacyUUID);
                    if (legacyService != null)
                    {
                        readCharacteristic = legacyService.getCharacteristic(Constants.ReadUUID);
                    }
                }

                if (readCharacteristic != null)
                {
                    readCharacteristic.setValue(toWrite);

                    boolean notified = mBluetoothGattServer.notifyCharacteristicChanged(device, readCharacteristic, false);

                    Log.d(TAG, ">>> notifyCharacteristicChanged returned: " + notified + ", dataLen=" + toWrite.length);
                    if (!notified)
                    {
                        Log.e(TAG, ">>> NOTIFICATION FAILED — device may not be subscribed or a notification is already pending");
                    }
                    //layoutPost("Notify characteristic changed", String.valueOf(notified));

                    // Do not cancel connection — credential app disconnects itself,
                    // and cancelConnection() prevents the device from reconnecting.
                }
                else
                {
                    // Handle the case where neither characteristic is found
                    // For example, log an error or notify the user
                    Log.d(TAG, "Neither characteristic was found!");
                }
            }
        }

        /*
        The generateSignaturePackage method aligns with the ECDHE Perfect Forward Secrecy Flow specification.
        It correctly retrieves and concatenates the required data (site identifier, reader identifier, device ephemeral public key X component, and reader ephemeral public key X component)
        before returning the concatenated byte array for signing
         */
        private byte[] generateSignaturePackage(FlowModel deviceModel)
        {
            if (deviceModel.connectionType == PKOC_ConnectionType.ECHDE_Full)
            {

                Log.d("GenerateSignaturePackage", "Went into ECDHEFULL signature generation");
                byte[] siteIdentifier = UuidConverters.fromUuid(siteUUID);
                Log.d("NFC", "Site identifier: " + Hex.toHexString(siteIdentifier));

                byte[] readerIdentifier = UuidConverters.fromUuid((readerUUID));
                Log.d("NFC", "Reader identifier: " + Hex.toHexString(readerIdentifier));

                byte[] deviceEphemeralPublicKey = deviceModel.receivedTransientPublicKey;
                Log.d("NFC", "Device ephemeral public key: " + Hex.toHexString(deviceEphemeralPublicKey));

                byte[] deviceX = new byte[32];
                arraycopy(deviceEphemeralPublicKey, 1, deviceX, 0, 32);
                Log.d("NFC", "Device ephemeral public key x component: " + Hex.toHexString(deviceX));

                byte[] readerPk = deviceModel.transientKeyPair.getPublic().getEncoded();
                Log.d("NFC", "Reader ephemeral public key: " + Hex.toHexString(readerPk));

                byte[] readerX = CryptoProvider.getPublicKeyComponentX(readerPk);
                Log.d("NFC", "Reader ephemeral public key x component: " + Hex.toHexString(readerX));

                byte[] toSign = org.bouncycastle.util.Arrays.concatenate(siteIdentifier, readerIdentifier, deviceX, readerX);
                Log.d("NFC", "ECDHE Flow Message to sign: " + Hex.toHexString(toSign));

                return toSign;
            }

            byte[] toSignNormalFlow = CryptoProvider.getCompressedPublicKeyBytes(deviceModel.transientKeyPair.getPublic().getEncoded());
            Log.d("NFC", "Normal Flow Message to sign: " + Hex.toHexString(toSignNormalFlow));
            //layoutPost("Message to sign", Hex.toHexString(toSignNormalFlow));

            return toSignNormalFlow;
        }
    };

    private void displayPublicKeyInfo(String publicKeyHex, String connectionTypeText)
    {
        if (publicKeyHex.length() == 130)
        {
            String header = publicKeyHex.substring(0, 2);
            String xPortion = publicKeyHex.substring(2, 66);
            String yPortion = publicKeyHex.substring(66, 130);

            // Extract 64 Bit and 128 Bit Credentials from X Portion
            String credential64Bit = xPortion.substring(xPortion.length() - 16);
            String credential128Bit = xPortion.substring(xPortion.length() - 32);
            String credential200Bit = xPortion.substring(xPortion.length() - 50); // 50 hex chars = 200 bits

            // Convert Hex to Decimal
            String credential64BitDecimal = new BigInteger(credential64Bit, 16).toString(10);
            String credential128BitDecimal = new BigInteger(credential128Bit, 16).toString(10);
            String credential200BitDecimal = new BigInteger(credential200Bit, 16).toString(10);
            String credential256BitDecimal = new BigInteger(xPortion, 16).toString(10);

            // Use SpannableStringBuilder to build the final text
            SpannableStringBuilder formattedText = new SpannableStringBuilder();

            // Render connectionTypeText with smart formatting:
            // - If it contains Aliro section headers (ALL-CAPS lines like "ACCESS DOCUMENT"),
            //   apply bold+large only to the first line (transport + sig status), bold to
            //   section headers, and normal weight to data lines.
            // - For all other cases (PKOC), render as a single bold block (legacy behaviour).
            boolean hasAliroSections = connectionTypeText.contains("\nACCESS DOCUMENT")
                    || connectionTypeText.contains("\nMAILBOX");
            boolean isLeafResult = connectionTypeText.contains("\nOPEN ID");
            boolean hasSections = hasAliroSections || isLeafResult;

            // -----------------------------------------------------------------
            // Smart formatting for Aliro / LEAF section-based results
            // -----------------------------------------------------------------
            if (hasSections)
            {
                String[] ctLines = connectionTypeText.split("\n", -1);
                SpannableStringBuilder ctSb = new SpannableStringBuilder();

                for (int li = 0; li < ctLines.length; li++)
                {
                    String line = ctLines[li];
                    String lineWithNl = (li < ctLines.length - 1) ? line + "\n" : line;

                    boolean isFirstLine  = (li == 0);
                    String trimmed = line.trim();
                    boolean isSectionHdr = !trimmed.isEmpty()
                            && !line.startsWith(" ")
                            && Character.isUpperCase(trimmed.charAt(0))
                            && trimmed.length() > 1
                            && !isFirstLine
                            && trimmed.split("[^A-Za-z]")[0].equals(
                                    trimmed.split("[^A-Za-z]")[0].toUpperCase());

                    SpannableString ls = new SpannableString(lineWithNl);
                    int len = lineWithNl.length();

                    if (isFirstLine)
                    {
                        ls.setSpan(new StyleSpan(Typeface.BOLD), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                        ls.setSpan(new AbsoluteSizeSpan(16, true), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                        ls.setSpan(new ForegroundColorSpan(Color.BLACK), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                    }
                    else if (isSectionHdr)
                    {
                        ls.setSpan(new StyleSpan(Typeface.BOLD), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                        ls.setSpan(new AbsoluteSizeSpan(13, true), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                        ls.setSpan(new ForegroundColorSpan(Color.BLACK), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                    }
                    else
                    {
                        ls.setSpan(new StyleSpan(Typeface.NORMAL), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                        ls.setSpan(new AbsoluteSizeSpan(13, true), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                        ls.setSpan(new ForegroundColorSpan(Color.BLACK), 0, len,
                                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                    }
                    ctSb.append(ls);
                }
                ctSb.append("\n\n");
                formattedText.append(ctSb);

                // Both LEAF and Aliro: formatted section headers are appended above.
                // Fall through to the full public key + bit-length breakdown below.
                // The credential public key is the same ECC P-256 format (04||X||Y)
                // across all three protocols and can be used by any reader/panel.
            }
            else
            {
                // -----------------------------------------------------------------
                // Plain PKOC: bold connection type as one block
                // -----------------------------------------------------------------
                SpannableString connectionTypeSpannable = new SpannableString(connectionTypeText + "\n\n");
                connectionTypeSpannable.setSpan(new StyleSpan(Typeface.BOLD), 0, connectionTypeText.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                connectionTypeSpannable.setSpan(new ForegroundColorSpan(Color.BLACK), 0, connectionTypeText.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                connectionTypeSpannable.setSpan(new AbsoluteSizeSpan(16, true), 0, connectionTypeText.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
                formattedText.append(connectionTypeSpannable);
            }

            // Apply bold style to the "Public Key:" text with black color and size 14
            SpannableString publicKeyHeader = new SpannableString("Public Key: \n");
            publicKeyHeader.setSpan(new StyleSpan(Typeface.BOLD), 0, publicKeyHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeyHeader.setSpan(new ForegroundColorSpan(Color.BLACK), 0, publicKeyHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeyHeader.setSpan(new AbsoluteSizeSpan(14, true), 0, publicKeyHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(publicKeyHeader);

            // Apply colors and font size to the Public Key
            SpannableStringBuilder publicKeySpannable = new SpannableStringBuilder(publicKeyHex);
            publicKeySpannable.setSpan(new BackgroundColorSpan(Color.WHITE), 0, 130, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeySpannable.setSpan(new ForegroundColorSpan(Color.parseColor("#707173")), 0, 2, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeySpannable.setSpan(new AbsoluteSizeSpan(14, true), 0, 130, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            // 256 bit - xPortion
            publicKeySpannable.setSpan(new StyleSpan(Typeface.BOLD), 2, 66, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeySpannable.setSpan(new BackgroundColorSpan(Color.parseColor("#9CC3C9")), 2, 66, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeySpannable.setSpan(new ForegroundColorSpan(Color.parseColor("BLACK")), 2, 66, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            // 200 bit
            publicKeySpannable.setSpan(new StyleSpan(Typeface.BOLD), 17, 66, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeySpannable.setSpan(new ForegroundColorSpan(Color.parseColor("RED")), 17, 66, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE); // RED
            // 128 bit
            publicKeySpannable.setSpan(new StyleSpan(Typeface.ITALIC), 34, 66, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            publicKeySpannable.setSpan(new ForegroundColorSpan(Color.parseColor("BLUE")), 34, 50, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE); // Light blue

            // 64 bit
            publicKeySpannable.setSpan(new ForegroundColorSpan(Color.parseColor("YELLOW")), 50, 66, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);

            // y portion
            publicKeySpannable.setSpan(new ForegroundColorSpan(Color.parseColor("#707173")), 66, 130, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);

            formattedText.append(publicKeySpannable);

            // Append the rest of the text with specified colors and font size for Headers and values
            // This is ***AFTER THE PUBLIC KEY DISPLAY***

            SpannableString headerHeader = new SpannableString("\n\nHeader: (Not Used)\n".toUpperCase());
            headerHeader.setSpan(new StyleSpan(Typeface.BOLD), 0, headerHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            headerHeader.setSpan(new ForegroundColorSpan(Color.BLACK), 0, headerHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            headerHeader.setSpan(new AbsoluteSizeSpan(14, true), 0, headerHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(headerHeader);

            formattedText.append(applyColorAndSize(header.toUpperCase(), header.length(), Color.WHITE, Color.parseColor("#707173"), false));

            // x-Portion of the public key
            SpannableString xPortionHeader = new SpannableString("\n\nX Portion 256 Bit HEX: \n".toUpperCase());
            xPortionHeader.setSpan(new StyleSpan(Typeface.BOLD), 0, xPortionHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            xPortionHeader.setSpan(new ForegroundColorSpan(Color.BLACK), 0, xPortionHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            xPortionHeader.setSpan(new AbsoluteSizeSpan(14, true), 0, xPortionHeader.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(xPortionHeader);

            formattedText.append(applyColorAndSize(xPortion.toUpperCase(), xPortion.length(), Color.parseColor("#9CC3C9"), Color.parseColor("BLACK"), true));

            // 256 bit decimal of the public key
            SpannableString decimalTFSb = new SpannableString("\n\n256 Bit Decimal: \n".toUpperCase());
            decimalTFSb.setSpan(new StyleSpan(Typeface.BOLD), 0, decimalTFSb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimalTFSb.setSpan(new ForegroundColorSpan(Color.BLACK), 0, decimalTFSb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimalTFSb.setSpan(new AbsoluteSizeSpan(14, true), 0, decimalTFSb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(decimalTFSb);

            formattedText.append(applyColorAndSize(credential256BitDecimal, credential256BitDecimal.length(), Color.parseColor("#9CC3C9"), Color.parseColor("BLACK"), true));

            // 200 bit hex of the public key
            SpannableString hex2TEb = new SpannableString("\n\n200 Bit HEX: \n".toUpperCase());
            hex2TEb.setSpan(new StyleSpan(Typeface.BOLD), 0, hex2TEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            hex2TEb.setSpan(new ForegroundColorSpan(Color.BLACK), 0, hex2TEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            hex2TEb.setSpan(new AbsoluteSizeSpan(14, true), 0, hex2TEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(hex2TEb);

            formattedText.append(applyColorAndSize(credential200Bit.toUpperCase(), credential200Bit.length(), Color.parseColor("#9CC3C9"), Color.parseColor("RED"), true));

            // 200 bit decimal of the public key
            SpannableString decimal2TEb = new SpannableString("\n\n200 Bit Decimal: \n".toUpperCase());
            decimal2TEb.setSpan(new StyleSpan(Typeface.BOLD), 0, decimal2TEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimal2TEb.setSpan(new ForegroundColorSpan(Color.BLACK), 0, decimal2TEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimal2TEb.setSpan(new AbsoluteSizeSpan(14, true), 0, decimal2TEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(decimal2TEb);

            formattedText.append(applyColorAndSize(credential200BitDecimal, credential200BitDecimal.length(), Color.parseColor("#9CC3C9"), Color.parseColor("RED"), true));


            // 128 bit hex of the public key
            SpannableString hexOTEb = new SpannableString("\n\n128 Bit HEX: \n".toUpperCase());
            hexOTEb.setSpan(new StyleSpan(Typeface.BOLD), 0, hexOTEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            hexOTEb.setSpan(new ForegroundColorSpan(Color.BLACK), 0, hexOTEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            hexOTEb.setSpan(new AbsoluteSizeSpan(14, true), 0, hexOTEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(hexOTEb);

            formattedText.append(applyColorAndSize(credential128Bit.toUpperCase(), credential128Bit.length(), Color.parseColor("#9CC3C9"), Color.parseColor("BLUE"), true));

            // 128 bit decimal of the public key
            SpannableString decimalOTEb = new SpannableString("\n\n128 Bit Decimal: \n".toUpperCase());
            decimalOTEb.setSpan(new StyleSpan(Typeface.BOLD), 0, decimalOTEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimalOTEb.setSpan(new ForegroundColorSpan(Color.BLACK), 0, decimalOTEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimalOTEb.setSpan(new AbsoluteSizeSpan(14, true), 0, decimalOTEb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(decimalOTEb);

            formattedText.append(applyColorAndSize(credential128BitDecimal, credential128BitDecimal.length(), Color.parseColor("#9CC3C9"), Color.parseColor("BLUE"), true));

            // 64 bit hex of the public key
            SpannableString hexSFb = new SpannableString("\n\n64 Bit Hex: \n".toUpperCase());
            hexSFb.setSpan(new StyleSpan(Typeface.BOLD), 0, hexSFb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            hexSFb.setSpan(new ForegroundColorSpan(Color.BLACK), 0, hexSFb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            hexSFb.setSpan(new AbsoluteSizeSpan(14, true), 0, hexSFb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(hexSFb);

            formattedText.append(applyColorAndSize(credential64Bit.toUpperCase(), credential64Bit.length(), Color.parseColor("#9CC3C9"), Color.parseColor("YELLOW"), true));

            // 64 bit decimal of the public key
            SpannableString decimalSFb = new SpannableString("\n\n64 Bit Decimal: \n".toUpperCase());
            decimalSFb.setSpan(new StyleSpan(Typeface.BOLD), 0, decimalSFb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimalSFb.setSpan(new ForegroundColorSpan(Color.BLACK), 0, decimalSFb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            decimalSFb.setSpan(new AbsoluteSizeSpan(14, true), 0, decimalSFb.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(decimalSFb);

            formattedText.append(applyColorAndSize(credential64BitDecimal, credential64BitDecimal.length(), Color.parseColor("#9CC3C9"), Color.parseColor("YELLOW"), true));

            // Y-Portion of the public key
            SpannableString portionYKey = new SpannableString("\n\nY Portion HEX (Not Used): \n".toUpperCase());
            portionYKey.setSpan(new StyleSpan(Typeface.BOLD), 0, portionYKey.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            portionYKey.setSpan(new ForegroundColorSpan(Color.BLACK), 0, portionYKey.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            portionYKey.setSpan(new AbsoluteSizeSpan(14, true), 0, portionYKey.length(), Spannable.SPAN_EXCLUSIVE_EXCLUSIVE);
            formattedText.append(portionYKey);

            formattedText.append(applyColorAndSize(yPortion.toUpperCase(), yPortion.length(), Color.WHITE, Color.parseColor("#707173"), false));

            ConstraintLayout mainLayout = requireView().findViewById(R.id.mainLayout);
            mainLayout.setBackgroundColor(getResources().getColor(android.R.color.white, requireActivity().getTheme()));

            // Update the screen with the public key read data
            // Set the formatted text to the TextView
            textView.setText(formattedText);
            // Hide reader detail button and mode toggle
            Button rdrButton = requireView().findViewById(R.id.rdrButton);
            rdrButton.setVisibility(View.GONE);
            requireView().findViewById(R.id.protocolModeGroup).setVisibility(View.GONE);

            // Set up the email button
            Button emailButton = requireView().findViewById(R.id.emailButton);
            emailButton.setVisibility(View.VISIBLE);
            emailButton.setOnClickListener(v -> sendEmail());

            // Set up the scan button
            Button scanButton = requireView().findViewById(R.id.scanButton);
            scanButton.setVisibility(View.VISIBLE);
            scanButton.setOnClickListener(v -> resetToScanScreen());

            // Hide other fields
            readerLocationUUIDView.setVisibility(View.GONE);
            readerSiteUUIDView.setVisibility(View.GONE);
            sitePublicKeyView.setVisibility(View.GONE);
            nfcAdvertisingStatusView.setVisibility(View.GONE);
            bleAdvertisingStatusView.setVisibility(View.GONE);
        }
        else
        {
            // Set the formatted public key if parsing is not applicable
            SpannableString formattedText = formatText("Public Key: " + publicKeyHex);
            textView.setText(formattedText);
        }
    }


    private final Queue<Runnable> gattOperationQueue = new LinkedList<>();
    private boolean isGattOperationInProgress = false;

    private void enqueueGattOperation(Runnable operation)
    {
        Log.d(TAG, "Enqueuing GATT operation");
        gattOperationQueue.add(operation);
        if (!isGattOperationInProgress)
        {
            executeNextGattOperation();
        }
    }

    private void executeNextGattOperation()
    {
        if (gattOperationQueue.isEmpty())
        {
            Log.d(TAG, "No more GATT operations to execute");
            isGattOperationInProgress = false;
            return;
        }
        Log.d(TAG, "Executing next GATT operation");
        isGattOperationInProgress = true;
        Runnable operation = gattOperationQueue.poll();
        if (operation != null)
        {
            operation.run();
        }
    }

    private void onGattOperationCompleted()
    {
        Log.d(TAG, "Gatt operation completed");
        isGattOperationInProgress = false;
        executeNextGattOperation();
    }

    private void handlePkocTimeout()
    {
        Log.e(TAG, "PKOC transaction failed due to timeout");
        // Notify higher layers or take appropriate action
        // For example, you might want to close the connection or retry the transaction
        // You can also update the UI or log the error as needed
    }

    private final Handler timeoutHandler = new Handler(Looper.getMainLooper());
    private final Runnable timeoutRunnable = () ->
    {
        Log.e(TAG, "PKOC transaction timed out");
        // Handle the timeout (e.g., notify higher layers, close connection)
        handlePkocTimeout();
    };

    private void showInvalidKeyDialog()
    {
        requireActivity().runOnUiThread(() -> new AlertDialog.Builder(requireContext())
                .setTitle("Invalid Key Validation")
                .setMessage("The public key is invalid. Please try again.")
                .setPositiveButton(android.R.string.ok, (dialog, which) ->
                {
                    // Dismiss the dialog
                })
                .setIcon(android.R.drawable.ic_dialog_alert)
                .show());
    }

    // =========================================================================
    // PKOC NFC Reader Flow
    // =========================================================================

    private void runPkocNfcFlow(IsoDep isoDep)
    {
        try
        {
            var transaction = new NfcNormalFlowTransaction(false);
            byte[] commandToSend = transaction.getCommandToWrite();
            while (commandToSend != null)
            {
                Log.d("NFC", "PKOC command: " + Hex.toHexString(commandToSend));
                byte[] response = isoDep.transceive(commandToSend);
                Log.d("NFC", "PKOC response: " + Hex.toHexString(response));
                transaction.processReaderResponse(response);
                commandToSend = transaction.getCommandToWrite();
            }

            if (transaction.isTransactionSuccessful())
            {
                byte[] publicKey = transaction.getPublicKey();
                if (publicKey != null)
                {
                    requireActivity().runOnUiThread(() ->
                    {
                        readerImageView.setVisibility(View.GONE);
                        keypadLayout.setVisibility(View.GONE);
                        String pk = Hex.toHexString(publicKey);
                        Log.d("NFC", "PKOC Public Key: " + pk);
                        displayPublicKeyInfo(pk, "PKOC NFC — Normal Flow");
                    });
                }
                else
                {
                    Log.e(TAG, "PKOC public key was null");
                    showInvalidKeyDialog();
                }
            }
            else
            {
                Log.e(TAG, "PKOC transaction was not successful");
                showInvalidKeyDialog();
            }
        }
        catch (java.io.IOException e)
        {
            Log.e(TAG, "PKOC NFC IO error", e);
        }
    }

    // =========================================================================
    // LEAF Verified NFC Reader Flow (Open ID — Path 1)
    // =========================================================================

    /**
     * Perform the LEAF Verified Open ID (Path 1) NFC transaction.
     *
     * Protocol:
     *   1. SELECT LEAF Open App AID
     *   2. SELECT certificate EF (file 0x0001)
     *   3. READ BINARY in 224-byte chunks — collect full X.509 DER certificate
     *   4. Verify certificate against stored Root CA public key
     *   5. Generate 32-byte random challenge
     *   6. INTERNAL AUTHENTICATE with challenge
     *   7. Verify ECDSA signature (DER) from response against credential public key from cert
     *   8. Extract 12-digit Open ID from cert subject CN
     *   9. Display result on UI
     *
     * @param isoDep  Connected IsoDep tag
     * @return true if LEAF credential was detected and authenticated (even if cert/sig fails),
     *         false if the tag did not respond to LEAF SELECT (not a LEAF credential)
     */
    private boolean performLeafNfcTransaction(android.nfc.tech.IsoDep isoDep)
    {
        try
        {
            // ------------------------------------------------------------------
            // Step 1: SELECT LEAF Open App AID
            // ------------------------------------------------------------------
            byte[] leafAid  = LeafVerifiedManager.LEAF_OPEN_APP_AID;
            byte[] selectCmd = new byte[5 + leafAid.length + 1];
            selectCmd[0] = 0x00;  // CLA
            selectCmd[1] = (byte)0xA4; // INS = SELECT
            selectCmd[2] = 0x04;  // P1 = select by AID
            selectCmd[3] = 0x00;  // P2
            selectCmd[4] = (byte)leafAid.length; // Lc
            System.arraycopy(leafAid, 0, selectCmd, 5, leafAid.length);
            selectCmd[5 + leafAid.length] = 0x00; // Le

            Log.d(TAG, "LEAF SELECT AID: " + Hex.toHexString(selectCmd));
            byte[] selectResp = isoDep.transceive(selectCmd);
            Log.d(TAG, "LEAF SELECT response: " + Hex.toHexString(selectResp));

            if (!isSW9000(selectResp))
            {
                Log.d(TAG, "LEAF: AID not supported, SW=" + swHex(selectResp));
                return false;  // not a LEAF credential
            }

            // ------------------------------------------------------------------
            // Step 2: SELECT certificate EF (file ID 0x0001)
            // ------------------------------------------------------------------
            byte[] fileId   = LeafVerifiedManager.LEAF_CERT_FILE_ID;
            byte[] selectEF = { 0x00, (byte)0xA4, 0x02, 0x00, 0x02, fileId[0], fileId[1] };
            Log.d(TAG, "LEAF SELECT EF: " + Hex.toHexString(selectEF));
            byte[] selectEFResp = isoDep.transceive(selectEF);
            Log.d(TAG, "LEAF SELECT EF response: " + Hex.toHexString(selectEFResp));

            if (!isSW9000(selectEFResp))
            {
                Log.e(TAG, "LEAF: SELECT EF failed, SW=" + swHex(selectEFResp));
                showLeafError("LEAF SELECT EF failed: " + swHex(selectEFResp));
                return true;
            }

            // ------------------------------------------------------------------
            // Step 3: READ BINARY in 224-byte chunks
            // ------------------------------------------------------------------
            final int CHUNK = 224;
            java.io.ByteArrayOutputStream certAcc = new java.io.ByteArrayOutputStream();
            int offset = 0;
            boolean done = false;

            while (!done)
            {
                int p1 = (offset >> 8) & 0x7F;
                int p2 = offset & 0xFF;
                byte[] readCmd = { 0x00, (byte)0xB0, (byte)p1, (byte)p2, (byte)CHUNK };
                Log.d(TAG, "LEAF READ BINARY offset=" + offset + " len=" + CHUNK);
                byte[] readResp = isoDep.transceive(readCmd);

                if (readResp == null || readResp.length < 2)
                {
                    Log.e(TAG, "LEAF READ BINARY: empty response at offset=" + offset);
                    break;
                }

                byte sw1 = readResp[readResp.length - 2];
                byte sw2 = readResp[readResp.length - 1];
                int dataLen = readResp.length - 2;

                if (dataLen > 0)
                    certAcc.write(readResp, 0, dataLen);

                if (sw1 == (byte)0x90 && sw2 == 0x00)
                {
                    // More data may follow — continue reading
                    offset += dataLen;
                    if (dataLen < CHUNK)
                        done = true; // received less than requested = end of file
                }
                else if (sw1 == (byte)0x62 && sw2 == (byte)0x82)
                {
                    // End of file
                    Log.d(TAG, "LEAF READ BINARY: end of file at offset=" + offset);
                    done = true;
                }
                else
                {
                    Log.e(TAG, "LEAF READ BINARY: unexpected SW " + String.format("%02X%02X", sw1, sw2));
                    showLeafError("LEAF READ BINARY failed: " + String.format("%02X%02X", sw1, sw2));
                    return true;
                }
            }

            byte[] certDER = certAcc.toByteArray();
            Log.d(TAG, "LEAF: certificate read complete, " + certDER.length + " bytes");

            if (certDER.length == 0)
            {
                showLeafError("LEAF: empty certificate received.");
                return true;
            }

            // ------------------------------------------------------------------
            // Step 4: Verify certificate against Root CA public key
            // ------------------------------------------------------------------
            byte[] rootCAPub = LeafVerifiedManager.getReaderRootCAPubKey(requireContext());
            if (rootCAPub == null)
            {
                Log.e(TAG, "LEAF: no Root CA public key configured — aborting");
                showLeafError("LEAF: Root CA not configured. Import via LEAF Config.");
                return true;
            }

            boolean certVerified = LeafVerifiedManager.verifyCertificate(certDER, rootCAPub);
            String certVerifyMsg = certVerified ? "Verified \u2713" : "FAILED \u2717";
            Log.d(TAG, "LEAF: cert verify=" + certVerified);

            if (!certVerified)
            {
                Log.e(TAG, "LEAF: certificate failed Root CA verification — aborting");
                showLeafError("LEAF: certificate verification failed.");
                return true;
            }

            // Spec Step 4: Only upon successful validation, extract Open ID
            byte[] credPubKey = LeafVerifiedManager.extractPublicKeyFromCert(certDER);
            String openId     = LeafVerifiedManager.extractOpenIDFromCert(certDER);

            if (credPubKey == null)
            {
                showLeafError("LEAF: failed to extract credential public key from cert.");
                return true;
            }

            // Validate Open ID is exactly 12-digit numeric per spec
            if (openId == null || !openId.matches("\\d{12}"))
            {
                showLeafError("LEAF: Open ID is not a valid 12-digit numeric value.");
                return true;
            }

            // ------------------------------------------------------------------
            // Step 5: Generate 32-byte random challenge
            // ------------------------------------------------------------------
            byte[] challenge = new byte[32];
            new java.security.SecureRandom().nextBytes(challenge);
            Log.d(TAG, "LEAF challenge: " + Hex.toHexString(challenge));

            // ------------------------------------------------------------------
            // Step 6: INTERNAL AUTHENTICATE (INS=0x88)
            // ------------------------------------------------------------------
            byte[] authCmd = new byte[5 + challenge.length];
            authCmd[0] = 0x00;            // CLA
            authCmd[1] = (byte)0x88;      // INS = INTERNAL AUTHENTICATE
            authCmd[2] = 0x00;            // P1
            authCmd[3] = 0x00;            // P2
            authCmd[4] = (byte)challenge.length; // Lc
            System.arraycopy(challenge, 0, authCmd, 5, challenge.length);

            Log.d(TAG, "LEAF INTERNAL AUTHENTICATE: " + Hex.toHexString(authCmd));
            byte[] authResp = isoDep.transceive(authCmd);
            Log.d(TAG, "LEAF INTERNAL AUTHENTICATE response: " + Hex.toHexString(authResp));

            if (!isSW9000(authResp) || authResp.length < 4)
            {
                showLeafError("LEAF INTERNAL AUTHENTICATE failed: " + swHex(authResp));
                return true;
            }

            // DER signature is everything before the trailing 9000
            byte[] sigDER = java.util.Arrays.copyOfRange(authResp, 0, authResp.length - 2);

            // ------------------------------------------------------------------
            // Step 7: Verify ECDSA signature against credential's public key
            // ------------------------------------------------------------------
            boolean sigVerified = LeafVerifiedManager.verifyChallenge(challenge, sigDER, credPubKey);
            Log.d(TAG, "LEAF: sig verify=" + sigVerified);

            // ------------------------------------------------------------------
            // Step 8: Extract Open ID and build display string
            // ------------------------------------------------------------------
            final String finalOpenId      = openId;
            final boolean finalCertVerified = certVerified;
            final boolean finalSigVerified  = sigVerified;
            final String finalCertMsg      = certVerifyMsg;
            final String finalPubKeyHex    = Hex.toHexString(credPubKey).toUpperCase();

            // ------------------------------------------------------------------
            // Step 9: Display result on UI thread
            // ------------------------------------------------------------------
            requireActivity().runOnUiThread(() ->
            {
                if (!isAdded()) return;
                readerImageView.setVisibility(View.GONE);
                keypadLayout.setVisibility(View.GONE);

                // Build the connectionType string in the same style as Aliro results.
                // The first line becomes the bold title; section headers are ALL-CAPS.
                StringBuilder sb = new StringBuilder();
                // Compute 40-bit Wiegand output per LEAF spec
                String wiegandDisplay = LeafVerifiedManager.formatWiegand40Display(finalOpenId);

                sb.append("LEAF NFC \u2014 Open ID ").append(finalSigVerified ? "Verified" : "FAILED");
                sb.append("\n\nOPEN ID APPLICATION\n");
                sb.append("  ID:             ").append(finalOpenId).append("\n");
                sb.append("  Format:         12-digit unique ID\n");
                sb.append("  Certificate:    X.509 PKI (ECC P-256)\n");
                sb.append("  Auth:           Unilateral (reader verifies credential)\n");
                sb.append("\nVERIFICATION\n");
                sb.append("  Subject:        CN=LEAF-").append(finalOpenId).append("\n");
                sb.append("  Issuer:         LEAF Root CA\n");
                sb.append("  Cert Verify:    ").append(finalCertMsg).append("\n");
                sb.append("  Challenge:      ").append(finalSigVerified ? "Verified \u2713" : "FAILED \u2717");
                sb.append("\n\nREADER OUTPUT\n");
                sb.append("  Format:         40-bit (38 data + 2 parity)\n");
                sb.append("  Wiegand:        ").append(wiegandDisplay != null ? wiegandDisplay : "error");

                String connectionTypeStr = sb.toString();
                displayPublicKeyInfo(finalPubKeyHex, connectionTypeStr);

                // Audible feedback
                android.media.ToneGenerator toneGen =
                        new android.media.ToneGenerator(android.media.AudioManager.STREAM_RING, 100);
                toneGen.startTone(finalSigVerified
                        ? android.media.ToneGenerator.TONE_SUP_DIAL
                        : android.media.ToneGenerator.TONE_CDMA_ABBR_ALERT, 150);
            });

            return true;
        }
        catch (java.io.IOException e)
        {
            Log.e(TAG, "LEAF NFC IO error", e);
            return false;
        }
    }

    /** Show a toast error for LEAF failures */
    private void showLeafError(String message)
    {
        Log.e(TAG, "LEAF error: " + message);
        requireActivity().runOnUiThread(() ->
                Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show());
    }

    /** Build the Aliro expedited-phase SELECT APDU (Table 10-1, AID from Table 10-3). */
    private byte[] buildAliroSelectCommand()
    {
        return new byte[]{
            0x00, (byte)0xA4, 0x04, 0x00, 0x09,
            (byte)0xA0, 0x00, 0x00, 0x09, 0x09,
            (byte)0xAC, (byte)0xCE, 0x55, 0x01,
            0x00  // Le
        };
    }

    // =========================================================================
    // Aliro NFC Reader Flow
    // =========================================================================

    /**
     * Perform the full Aliro Expedited Standard NFC transaction.
     * Called after a successful SELECT with the Aliro AID.
     *
     * @param isoDep         Connected IsoDep tag
     * @param selectResponse Full SELECT response (including SW bytes)
     */
    private void performAliroNfcTransaction(IsoDep isoDep, byte[] selectResponse)
    {
        try
        {
            // ------------------------------------------------------------------
            // Load reader config from SharedPreferences
            // ------------------------------------------------------------------
            SharedPreferences prefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
            String privateKeyHex = prefs.getString(AliroPreferences.READER_PRIVATE_KEY, "");
            String readerIdHex   = prefs.getString(AliroPreferences.READER_ID, "");
            String issuerKeyHex  = prefs.getString(AliroPreferences.READER_ISSUER_PUBLIC_KEY, "");
            String certHex       = prefs.getString(AliroPreferences.READER_CERTIFICATE, "");

            if (privateKeyHex.isEmpty() || readerIdHex.isEmpty())
            {
                Log.e(TAG, "Aliro config not set — open Aliro Config from the menu");
                requireActivity().runOnUiThread(() ->
                        Toast.makeText(requireContext(),
                                "Aliro not configured. Use menu → Aliro Config.",
                                Toast.LENGTH_LONG).show());
                return;
            }

            byte[] readerPrivKeyBytes = Hex.decode(privateKeyHex);
            byte[] readerIdBytes      = Hex.decode(readerIdHex);
            byte[] issuerKeyBytes     = issuerKeyHex.isEmpty() ? null : Hex.decode(issuerKeyHex);
            byte[] certBytes          = certHex.isEmpty() ? null : Hex.decode(certHex);
            boolean useCert           = (certBytes != null && issuerKeyBytes != null);

            // ------------------------------------------------------------------
            // Parse SELECT response
            // Minimum structure: 6F <len> 84 09 <AID 9 bytes> A5 <len> <proprietary TLV>
            // We need:
            //   - The full Proprietary Information TLV (tag A5 + length + value)
            //     for use in HKDF key derivation
            //   - The supported protocol versions (tag 5C)
            // ------------------------------------------------------------------
            byte[] selectProprietaryTLV = parseSelectProprietaryTLV(selectResponse);
            byte[] protocolVersion      = parseProtocolVersion(selectResponse);

            if (selectProprietaryTLV == null || protocolVersion == null)
            {
                Log.e(TAG, "Aliro SELECT response parse failed");
                sendControlFlow(isoDep);
                showAliroError("Aliro SELECT response invalid.");
                return;
            }
            Log.d(TAG, "Aliro protocol version: " + Hex.toHexString(protocolVersion));
            Log.d(TAG, "Aliro proprietary TLV: " + Hex.toHexString(selectProprietaryTLV));

            // ------------------------------------------------------------------
            // Generate ephemeral key pair and transaction ID
            // ------------------------------------------------------------------
            KeyPair readerEphKP = AliroCryptoProvider.generateEphemeralKeypair();
            if (readerEphKP == null)
            {
                showAliroError("Failed to generate ephemeral key pair.");
                return;
            }
            byte[] readerEphPub    = AliroCryptoProvider.getUncompressedPublicKey(readerEphKP);
            byte[] readerEphPubX   = Arrays.copyOfRange(readerEphPub, 1, 33);
            byte[] transactionId   = AliroCryptoProvider.generateRandom(16);

            // ------------------------------------------------------------------
            // Derive reader public key (or issuer key X for key derivation)
            // We need the reader's static public key X for HKDF.
            // Re-derive it from private key bytes using BouncyCastle.
            // ------------------------------------------------------------------
            byte[] readerPubKeyX = derivePublicKeyXFromPrivate(readerPrivKeyBytes);
            if (readerPubKeyX == null)
            {
                showAliroError("Failed to derive reader public key.");
                return;
            }
            // HKDF reader_group_identifier_key.x = reader's own static public key X
            // per section 8.3.1.13. Derived from the configured reader private key.
            // The credential extracts the same value from tag 0x85 in LOAD CERT.
            // These MUST match — if not, AUTH1 decryption will fail with GCM tag mismatch.
            byte[] hkdfReaderPubKeyX = readerPubKeyX;

            // ------------------------------------------------------------------
            // Get reader private key — use cached instance if the key hex hasn't
            // changed, otherwise rebuild and cache it. This avoids ~400ms of EC
            // key construction on every tap.
            // ------------------------------------------------------------------
            if (!privateKeyHex.equals(cachedAliroPrivKeyHex) || cachedAliroReaderPrivKey == null)
            {
                cachedAliroReaderPrivKey = rawBytesToEcPrivateKey(readerPrivKeyBytes);
                cachedAliroPrivKeyHex = privateKeyHex;
            }
            java.security.PrivateKey readerPrivKey = cachedAliroReaderPrivKey;
            if (readerPrivKey == null)
            {
                showAliroError("Failed to load reader private key.");
                return;
            }

            // ------------------------------------------------------------------
            // Build and send AUTH0
            // Header: 80 80 00 00 <Lc> 81 41 01 00 42 01 01
            //   5C 02 <protocol version>
            //   87 41 <reader eph public key 65 bytes>
            //   4C 10 <transaction ID 16 bytes>
            //   4D 20 <reader ID 32 bytes>
            //   00 (Le)
            // ------------------------------------------------------------------
            byte[] auth0 = buildAuth0Command(protocolVersion, readerEphPub, transactionId, readerIdBytes);
            Log.d(TAG, "AUTH0 command: " + Hex.toHexString(auth0));
            byte[] auth0Response = isoDep.transceive(auth0);
            Log.d(TAG, "AUTH0 response: " + Hex.toHexString(auth0Response));

            if (!isSW9000(auth0Response))
            {
                sendControlFlow(isoDep);
                showAliroError("AUTH0 failed: SW=" + swHex(auth0Response));
                return;
            }

            // Parse AUTH0 response — expect 86 41 <UD eph pub key 65 bytes>
            if (auth0Response.length < 69 || auth0Response[0] != (byte)0x86 || auth0Response[1] != 0x41)
            {
                sendControlFlow(isoDep);
                showAliroError("AUTH0 response format invalid.");
                return;
            }
            byte[] udEphPub  = Arrays.copyOfRange(auth0Response, 2, 67);
            byte[] udEphPubX = Arrays.copyOfRange(udEphPub, 1, 33);
            Log.d(TAG, "UD ephemeral public key: " + Hex.toHexString(udEphPub));

            // Parse optional vendor extension TLV (tag B2) from AUTH0 response
            byte[] auth0RspVendorTLV = parseVendorExtensionTLV(auth0Response, 67);

            // ------------------------------------------------------------------
            // Compute reader signature and derive session keys immediately after
            // AUTH0 — before LOAD CERT — so AUTH1 is ready to fire with no delay.
            // keybuf[0..31]  = ExpeditedSKReader (encrypt EXCHANGE)
            // keybuf[32..63] = ExpeditedSKDevice (decrypt AUTH1 response)
            // keybuf[64..95] = StepUpSK (for ENVELOPE session encryption)
            // ------------------------------------------------------------------
            byte[] readerSig = AliroCryptoProvider.computeReaderSignature(
                    readerPrivKey, readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            if (readerSig == null)
            {
                showAliroError("Failed to compute reader signature.");
                return;
            }

            // flag = command_parameters || authentication_policy per Table 8-4
            // command_parameters = 0x00 (Bit0=0 = expedited-standard)
            // authentication_policy = 0x01 (user device setting)
            byte[] auth0Flag = new byte[]{ 0x00, 0x01 };

            byte[] keybuf = AliroCryptoProvider.deriveKeys(
                    readerEphKP.getPrivate(),
                    udEphPub,
                    96,
                    protocolVersion,
                    hkdfReaderPubKeyX,
                    readerIdBytes,
                    transactionId,
                    readerEphPubX,
                    udEphPubX,
                    selectProprietaryTLV,
                    auth0RspVendorTLV,
                    AliroCryptoProvider.INTERFACE_BYTE_NFC,
                    auth0Flag);

            if (keybuf == null)
            {
                showAliroError("Key derivation failed.");
                return;
            }
            byte[] skReader  = Arrays.copyOfRange(keybuf, 0,  32);
            byte[] skDevice  = Arrays.copyOfRange(keybuf, 32, 64);
            byte[] stepUpSK  = Arrays.copyOfRange(keybuf, 64, 96);

            // ------------------------------------------------------------------
            // LOAD CERT (optional) — sent after crypto is pre-computed so AUTH1
            // follows immediately with no processing delay.
            // ------------------------------------------------------------------
            if (useCert)
            {
                byte[] loadCert = buildLoadCertCommand(certBytes);
                Log.d(TAG, "LOAD CERT command length: " + loadCert.length);
                byte[] loadCertResponse = isoDep.transceive(loadCert);
                Log.d(TAG, "LOAD CERT response: " + Hex.toHexString(loadCertResponse));
                if (!isSW9000(loadCertResponse))
                {
                    sendControlFlow(isoDep);
                    showAliroError("LOAD CERT failed: SW=" + swHex(loadCertResponse));
                    return;
                }
            }

            // ------------------------------------------------------------------
            // Build and send AUTH1
            // Header: 80 81 00 00 45 41 01 01 9E 40 <signature 64 bytes>
            // ------------------------------------------------------------------
            byte[] auth1 = buildAuth1Command(readerSig);
            Log.d(TAG, "AUTH1 command: " + Hex.toHexString(auth1));
            byte[] auth1Response = isoDep.transceive(auth1);
            Log.d(TAG, "AUTH1 response: " + Hex.toHexString(auth1Response));

            if (!isSW9000(auth1Response))
            {
                String sw = swHex(auth1Response);
                if ("6400".equalsIgnoreCase(sw) || "6982".equalsIgnoreCase(sw) || "6985".equalsIgnoreCase(sw))
                {
                    // Credential rejected the reader's certificate/signature
                    showAliroCredentialRejectDialog(sw);
                }
                else
                {
                    showAliroError("AUTH1 failed: SW=" + sw);
                }
                return;
            }

            // ------------------------------------------------------------------
            // Per-message GCM counters (§8.3.1.6 / §8.3.1.8).
            // device_counter: credential response counter, starts at 1 (AUTH1 uses 1).
            // reader_counter: reader command counter, starts at 1 (first EXCHANGE uses 1).
            // Both increment by 1 per message. Declared here so they are in scope
            // for the EXCHANGE block below and any future multi-EXCHANGE extensions.
            // ------------------------------------------------------------------
            int deviceCounter = 1; // AUTH1 response was encrypted with device_counter=1
            int readerCounter = 1; // First EXCHANGE command will use reader_counter=1

            // ------------------------------------------------------------------
            // Decrypt AUTH1 response with SKDevice, device_counter=1 (§8.3.1.7)
            // Encrypted payload = auth1Response minus final 2 SW bytes
            // ------------------------------------------------------------------
            byte[] encryptedPayload = Arrays.copyOfRange(auth1Response, 0, auth1Response.length - 2);
            byte[] decrypted = AliroCryptoProvider.decryptDeviceGcm(skDevice, encryptedPayload, deviceCounter++);
            if (decrypted == null)
            {
                showAliroError("AUTH1 decryption failed.");
                return;
            }
            Log.d(TAG, "AUTH1 decrypted: " + Hex.toHexString(decrypted));

            // Parse: 5A 41 <credential pub key 65 bytes> 9E 40 <signature 64 bytes>
            if (decrypted.length < 131 || decrypted[0] != 0x5A || decrypted[1] != 0x41)
            {
                showAliroError("AUTH1 response format invalid.");
                return;
            }
            byte[] credentialPubKey = Arrays.copyOfRange(decrypted, 2, 67);
            if (decrypted[67] != (byte)0x9E || decrypted[68] != 0x40)
            {
                showAliroError("AUTH1 missing credential signature.");
                return;
            }
            byte[] credentialSig = Arrays.copyOfRange(decrypted, 69, 133);
            Log.d(TAG, "Credential public key: " + Hex.toHexString(credentialPubKey));

            // ------------------------------------------------------------------
            // Verify credential signature
            // ------------------------------------------------------------------
            boolean sigValid = AliroCryptoProvider.verifyCredentialSignature(
                    credentialSig, credentialPubKey,
                    readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            Log.d(TAG, "Aliro credential signature valid: " + sigValid);

            // ------------------------------------------------------------------
            // Parse signaling_bitmap from decrypted AUTH1 payload
            // Per Aliro §8.3.3.4.2 Table 8-11: tag 0x5E, 2 bytes big-endian.
            //   Bit0: Access Document available (gates Step-Up ENVELOPE)
            //   Bit2: Step-up AID SELECT required before ENVELOPE (NFC, §10.2)
            // ------------------------------------------------------------------
            int signalingBitmap = 0x0000;
            for (int si = 0; si < decrypted.length - 3; si++)
            {
                if ((decrypted[si] & 0xFF) == 0x5E && (decrypted[si + 1] & 0xFF) == 0x02)
                {
                    signalingBitmap = ((decrypted[si + 2] & 0xFF) << 8) | (decrypted[si + 3] & 0xFF);
                    Log.d(TAG, "AUTH1: signaling_bitmap=0x" + String.format("%04X", signalingBitmap));
                    break;
                }
            }
            boolean accessDocAvailable = (signalingBitmap & 0x0001) != 0; // Bit0

            // ------------------------------------------------------------------
            // Send EXCHANGE with access decision + optional mailbox operations
            // Per Table 8-15: 0xBA (mailbox) comes BEFORE 0x97 (access decision)
            // ------------------------------------------------------------------
            // Build mailbox TLVs if enabled in preferences
            SharedPreferences mailboxPrefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
            boolean mailboxEnabled = mailboxPrefs.getBoolean(AliroPreferences.MAILBOX_ENABLED, false);
            byte[] mailboxBA = null;
            String mailboxOp = null;
            int mailboxReadLen = 0;
            String mailboxResultHex = null; // populated if mailbox read succeeds

            if (mailboxEnabled)
            {
                mailboxOp = mailboxPrefs.getString(AliroPreferences.MAILBOX_OPERATION, "read");
                int mOffset = Integer.parseInt(mailboxPrefs.getString(AliroPreferences.MAILBOX_OFFSET, "0"));
                int mLength = Integer.parseInt(mailboxPrefs.getString(AliroPreferences.MAILBOX_LENGTH, "16"));
                boolean atomic = mailboxPrefs.getBoolean(AliroPreferences.MAILBOX_ATOMIC, false);

                java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

                // 0x8C is MANDATORY inside 0xBA (Table 8-16)
                if (atomic)
                {
                    baos.write(new byte[]{ (byte)0x8C, 0x01, 0x01 }, 0, 3); // start atomic
                }
                else
                {
                    baos.write(new byte[]{ (byte)0x8C, 0x01, 0x00 }, 0, 3); // no atomic
                }

                if ("read".equals(mailboxOp))
                {
                    // 0x87 04 offsetMSB offsetLSB lengthMSB lengthLSB
                    baos.write(new byte[]{
                        (byte)0x87, 0x04,
                        (byte)((mOffset >> 8) & 0xFF), (byte)(mOffset & 0xFF),
                        (byte)((mLength >> 8) & 0xFF), (byte)(mLength & 0xFF)
                    }, 0, 6);
                    mailboxReadLen = mLength;
                }
                else if ("write".equals(mailboxOp))
                {
                    String dataHex = mailboxPrefs.getString(AliroPreferences.MAILBOX_DATA, "");
                    byte[] writeData = dataHex.isEmpty() ? new byte[0] : Hex.decode(dataHex);
                    int writeLen = 2 + writeData.length; // offset(2) + data
                    baos.write(new byte[]{
                        (byte)0x8A, (byte)(writeLen & 0xFF),
                        (byte)((mOffset >> 8) & 0xFF), (byte)(mOffset & 0xFF)
                    }, 0, 4);
                    baos.write(writeData, 0, writeData.length);
                }
                else if ("set".equals(mailboxOp))
                {
                    String setValHex = mailboxPrefs.getString(AliroPreferences.MAILBOX_SET_VALUE, "00");
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
                    baos.write(new byte[]{ (byte)0x8C, 0x01, 0x00 }, 0, 3); // stop atomic
                }

                byte[] innerTlvs = baos.toByteArray();
                // Wrap in 0xBA outer tag (per Table 8-15, CI-7)
                mailboxBA = new byte[2 + innerTlvs.length];
                mailboxBA[0] = (byte)0xBA;
                mailboxBA[1] = (byte)(innerTlvs.length & 0xFF);
                System.arraycopy(innerTlvs, 0, mailboxBA, 2, innerTlvs.length);

                Log.d(TAG, "Mailbox BA TLV: " + Hex.toHexString(mailboxBA));
            }

            // ------------------------------------------------------------------
            // Determine whether step-up will follow this EXCHANGE.
            // If step-up is needed, we must NOT include tag 0x97 (reader status)
            // in this EXCHANGE — 0x97 signals end-of-transaction and the credential
            // MAY close the NFC link after receiving it (per §8.3.3.5).
            // Instead: send EXCHANGE with mailbox only, then ENVELOPE for step-up,
            // then a final EXCHANGE with 0x97 to close the transaction.
            // ------------------------------------------------------------------
            SharedPreferences stepUpPrefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
            String stepUpElementId = stepUpPrefs.getString(AliroPreferences.STEP_UP_ELEMENT_ID, "");
            boolean willDoStepUp = !stepUpElementId.isEmpty() && accessDocAvailable;

            byte[] statusTlv = new byte[]{ (byte)0x97, 0x02, sigValid ? (byte)0x01 : 0x00, (byte)0x82 };
            byte[] exchangePayload;
            if (willDoStepUp && mailboxBA != null)
            {
                // Mailbox only — no 0x97 yet (step-up will follow)
                exchangePayload = mailboxBA;
            }
            else if (willDoStepUp)
            {
                // No mailbox, but step-up is coming — skip this EXCHANGE entirely,
                // go straight to step-up, and send 0x97 in the post-step-up EXCHANGE.
                exchangePayload = null;
            }
            else if (mailboxBA != null)
            {
                // Mailbox + 0x97 (no step-up)
                exchangePayload = new byte[mailboxBA.length + statusTlv.length];
                System.arraycopy(mailboxBA, 0, exchangePayload, 0, mailboxBA.length);
                System.arraycopy(statusTlv, 0, exchangePayload, mailboxBA.length, statusTlv.length);
            }
            else
            {
                // Just 0x97 (no mailbox, no step-up)
                exchangePayload = statusTlv;
            }

            // Send pre-step-up EXCHANGE (mailbox only, or mailbox+0x97 if no step-up)
            if (exchangePayload != null)
            {
                byte[] encryptedExchange = AliroCryptoProvider.encryptReaderGcm(skReader, exchangePayload, readerCounter++);
                if (encryptedExchange == null)
                {
                    showAliroError("EXCHANGE encryption failed.");
                    return;
                }
                byte[] exchangeCmd = buildExchangeCommand(encryptedExchange);
                Log.d(TAG, "EXCHANGE command: " + Hex.toHexString(exchangeCmd));
                byte[] exchangeResponse = isoDep.transceive(exchangeCmd);
                Log.d(TAG, "EXCHANGE response: " + Hex.toHexString(exchangeResponse));

                // Decrypt and verify EXCHANGE response per §8.3.3.5.6.
                if (isSW9000(exchangeResponse) && exchangeResponse.length > 2)
                {
                    byte[] exchangeEncPayload = Arrays.copyOfRange(exchangeResponse, 0, exchangeResponse.length - 2);
                    byte[] exchangeDecrypted  = AliroCryptoProvider.decryptDeviceGcm(skDevice, exchangeEncPayload, deviceCounter++);
                    if (exchangeDecrypted != null)
                    {
                        Log.d(TAG, "EXCHANGE response decrypted: " + Hex.toHexString(exchangeDecrypted));

                        // Mailbox read data comes BEFORE the status bytes (0x00 0x02 0x00 0x00)
                        if (mailboxEnabled && "read".equals(mailboxOp) && mailboxReadLen > 0)
                        {
                            if (exchangeDecrypted.length > 4)
                            {
                                int readDataLen = exchangeDecrypted.length - 4;
                                if (readDataLen > 0)
                                {
                                    byte[] mailboxReadData = Arrays.copyOfRange(exchangeDecrypted, 0, readDataLen);
                                    // Parse §18 TLV if data starts with 0x60, else fall back to hex
                                    if (readDataLen > 0 && (mailboxReadData[0] & 0xFF) == 0x60)
                                    {
                                        mailboxResultHex = AliroMailbox.parseMailboxToString(
                                                mailboxReadData, readDataLen);
                                    }
                                    else
                                    {
                                        mailboxResultHex = "Read " + readDataLen + "B: "
                                                + Hex.toHexString(mailboxReadData);
                                    }
                                    Log.d(TAG, "Mailbox READ response (" + readDataLen + " bytes): "
                                            + Hex.toHexString(mailboxReadData));
                                }
                                else
                                {
                                    mailboxResultHex = "Read — empty (mailbox may not be initialized)";
                                    Log.d(TAG, "Mailbox READ: no data returned (response has no read bytes)");
                                }
                            }
                            else
                            {
                                mailboxResultHex = "Read — empty (mailbox may not be initialized)";
                                Log.d(TAG, "Mailbox READ: no data returned (response only has status bytes)");
                            }
                        }

                        if (mailboxEnabled && ("write".equals(mailboxOp) || "set".equals(mailboxOp)))
                        {
                            mailboxResultHex = mailboxOp.toUpperCase() + " OK";
                            Log.d(TAG, "Mailbox " + mailboxOp + " accepted by credential");
                        }

                        int statusStart = exchangeDecrypted.length - 4;
                        if (statusStart >= 0
                                && exchangeDecrypted[statusStart] == 0x00
                                && exchangeDecrypted[statusStart + 1] == 0x02
                                && exchangeDecrypted[statusStart + 2] == 0x00
                                && exchangeDecrypted[statusStart + 3] == 0x00)
                        {
                            Log.d(TAG, "EXCHANGE: credential confirmed success");
                        }
                    }
                }
            }

            // ------------------------------------------------------------------
            // Step-Up phase (optional) — send ENVELOPE with DeviceRequest if
            // configured AND Bit0 signals doc available.
            // Per Aliro §8.4 + §10.2 + ISO 18013-5 §9.1.1.4/9.1.1.5.
            // ------------------------------------------------------------------
            String stepUpResult = null;
            boolean stepupSelectRequired = (signalingBitmap & 0x0004) != 0; // Bit2 (NFC only)
            if (willDoStepUp)
            {
                // If Bit2 set: send step-up AID SELECT before ENVELOPE (§10.2, Table 10-3)
                if (stepupSelectRequired)
                {
                    Log.d(TAG, "Step-Up: sending step-up AID SELECT (signaling_bitmap Bit2)");
                    byte[] stepUpSelectApdu = new byte[]{
                        0x00, (byte)0xA4, 0x04, 0x00,
                        0x09,
                        (byte)0xA0, 0x00, 0x00, 0x09, 0x09, (byte)0xAC, (byte)0xCE, 0x55, 0x02,
                        0x00
                    };
                    byte[] selectResp = isoDep.transceive(stepUpSelectApdu);
                    if (selectResp == null || selectResp.length < 2
                            || selectResp[selectResp.length - 2] != (byte)0x90
                            || selectResp[selectResp.length - 1] != 0x00)
                    {
                        Log.w(TAG, "Step-Up: AID SELECT failed — skipping Step-Up");
                        willDoStepUp = false;
                    }
                    else
                    {
                        Log.d(TAG, "Step-Up: AID SELECT OK");
                    }
                }
            }
            if (willDoStepUp)
            {
                Log.d(TAG, "Step-Up: requesting element '" + stepUpElementId + "'");
                try
                {
                    stepUpResult = runAliroStepUp(isoDep, stepUpSK, stepUpElementId, stepUpPrefs);
                }
                catch (Exception e)
                {
                    Log.w(TAG, "Step-Up failed (non-fatal): " + e.getMessage());
                    stepUpResult = "Step-Up failed: " + e.getMessage();
                }

                // Send final EXCHANGE with 0x97 (reader status) to close the transaction
                // This must come AFTER step-up because 0x97 signals end-of-transaction.
                Log.d(TAG, "Sending final EXCHANGE with 0x97 (post step-up)");
                byte[] finalEncrypted = AliroCryptoProvider.encryptReaderGcm(skReader, statusTlv, readerCounter++);
                if (finalEncrypted != null)
                {
                    byte[] finalCmd = buildExchangeCommand(finalEncrypted);
                    byte[] finalResp = isoDep.transceive(finalCmd);
                    Log.d(TAG, "Final EXCHANGE response: " + Hex.toHexString(finalResp));
                    // Decrypt response (increment deviceCounter)
                    if (isSW9000(finalResp) && finalResp.length > 2)
                    {
                        byte[] finalEnc = Arrays.copyOfRange(finalResp, 0, finalResp.length - 2);
                        byte[] finalDec = AliroCryptoProvider.decryptDeviceGcm(skDevice, finalEnc, deviceCounter++);
                        if (finalDec != null)
                            Log.d(TAG, "Final EXCHANGE decrypted: " + Hex.toHexString(finalDec));
                    }
                }
            }
            else if (!stepUpElementId.isEmpty() && !accessDocAvailable)
            {
                Log.d(TAG, "Step-Up: skipped — signaling_bitmap Bit0 not set (no Access Document)");
            }

            // ------------------------------------------------------------------
            // Destroy all session-bound keys per section 10.2 and 8.3.3.1
            // ------------------------------------------------------------------
            java.util.Arrays.fill(skReader,  (byte)0);
            java.util.Arrays.fill(skDevice,  (byte)0);
            java.util.Arrays.fill(stepUpSK,  (byte)0);
            java.util.Arrays.fill(keybuf,    (byte)0);
            Log.d(TAG, "Aliro session keys destroyed");

            // ------------------------------------------------------------------
            // Show result on UI
            // ------------------------------------------------------------------
            final boolean finalSigValid    = sigValid;
            final String  finalMailboxResult = mailboxResultHex;
            final byte[]  finalCredPubKey  = credentialPubKey;
            final String  finalStepUpResult = stepUpResult;
            requireActivity().runOnUiThread(() ->
            {
                readerImageView.setVisibility(View.GONE);
                keypadLayout.setVisibility(View.GONE);
                String pk = Hex.toHexString(finalCredPubKey);
                Log.d(TAG, "Aliro credential public key: " + pk);
                String connectionType = formatAliroConnectionType(
                        "NFC", finalSigValid, finalStepUpResult, finalMailboxResult);
                displayPublicKeyInfo(pk, connectionType);

                ToneGenerator toneGen = new ToneGenerator(AudioManager.STREAM_RING, 100);
                if (finalSigValid)
                    toneGen.startTone(ToneGenerator.TONE_SUP_DIAL, 150);
                else
                    toneGen.startTone(ToneGenerator.TONE_CDMA_ABBR_ALERT, 150);
            });
        }
        catch (IOException e)
        {
            Log.e(TAG, "Aliro NFC IO error", e);
            showAliroError("NFC communication error: " + e.getMessage());
        }
        catch (Exception e)
        {
            Log.e(TAG, "Aliro NFC unexpected error", e);
            showAliroError("Aliro error: " + e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Aliro NFC helper methods
    // -------------------------------------------------------------------------

    /** Parse the Proprietary Information TLV (tag A5, including tag+length bytes) from SELECT response. */
    private byte[] parseSelectProprietaryTLV(byte[] selectResponse)
    {
        // Exclude SW (last 2 bytes) from the search
        int limit = selectResponse.length - 2;
        for (int i = 0; i < limit - 1; i++)
        {
            if (selectResponse[i] == (byte)0xA5)
            {
                int len = selectResponse[i + 1] & 0xFF;
                if (i + 2 + len <= limit)
                {
                    byte[] tlv = new byte[2 + len];
                    System.arraycopy(selectResponse, i, tlv, 0, 2 + len);
                    return tlv;
                }
            }
        }
        return null;
    }

    /** Parse the protocol version (tag 5C, first 2-byte version) from SELECT response */
    private byte[] parseProtocolVersion(byte[] selectResponse)
    {
        // Use 6F outer length to avoid including SW bytes
        int searchLimit = selectResponse.length;
        if (selectResponse.length > 2 && selectResponse[0] == 0x6F)
        {
            searchLimit = 2 + (selectResponse[1] & 0xFF);
        }
        for (int i = 0; i < searchLimit - 3; i++)
        {
            if (selectResponse[i] == 0x5C)
            {
                int len = selectResponse[i + 1] & 0xFF;
                if (len >= 2 && i + 2 + len <= searchLimit)
                {
                    // Prefer version 01 00 or 00 09 per aliro_flow.h
                    for (int j = 0; j < len - 1; j += 2)
                    {
                        byte v0 = selectResponse[i + 2 + j];
                        byte v1 = selectResponse[i + 3 + j];
                        if ((v0 == 0x01 && v1 == 0x00) || (v0 == 0x00 && v1 == 0x09))
                        {
                            return new byte[]{ v0, v1 };
                        }
                    }
                    // Fall back to first version in list
                    return new byte[]{ selectResponse[i + 2], selectResponse[i + 3] };
                }
            }
        }
        return null;
    }

    /** Parse optional vendor extension TLV (tag B2) starting at offset in buffer */
    private byte[] parseVendorExtensionTLV(byte[] buf, int startOffset)
    {
        for (int i = startOffset; i < buf.length - 2; i++)
        {
            if (buf[i] == (byte)0xB2)
            {
                int len = buf[i + 1] & 0xFF;
                if (i + 2 + len <= buf.length)
                {
                    byte[] tlv = new byte[2 + len];
                    System.arraycopy(buf, i, tlv, 0, 2 + len);
                    return tlv;
                }
            }
        }
        return null;
    }

    /** Build AUTH0 command per Table 8-3 and Table 8-4 of Aliro 1.0 spec.
     *  Data field is flat DER-TLVs in order: 41 42 5C 87 4C 4D (no outer wrapper). */
    private byte[] buildAuth0Command(byte[] protocolVersion, byte[] readerEphPub,
                                     byte[] transactionId, byte[] readerId)
    {
        // CLA=80 INS=80 P1=00 P2=00
        // Data: 41 01 <cmd_params>   command_parameters: 0x00 = expedited-standard
        //       42 01 <auth_policy>  authentication_policy: 0x01 = user device setting
        //       5C 02 <proto 2B>     selected protocol version
        //       87 41 <pub 65B>      reader ephemeral public key
        //       4C 10 <tid 16B>      transaction identifier
        //       4D 20 <id 32B>       reader identifier
        // Le = 00
        int dataLen = 2 + 1    // 41 01 <cmd_params>
                    + 2 + 1    // 42 01 <auth_policy>
                    + 2 + 2    // 5C 02 <proto>
                    + 2 + 65   // 87 41 <eph pub>
                    + 2 + 16   // 4C 10 <tid>
                    + 2 + 32;  // 4D 20 <reader id>
        byte[] cmd = new byte[4 + 1 + dataLen + 1]; // header + Lc + data + Le
        int idx = 0;
        cmd[idx++] = (byte)0x80; // CLA
        cmd[idx++] = (byte)0x80; // INS
        cmd[idx++] = 0x00;        // P1
        cmd[idx++] = 0x00;        // P2
        cmd[idx++] = (byte) dataLen; // Lc
        // 41: command_parameters (0x00 = expedited-standard, Bit0=0)
        cmd[idx++] = 0x41; cmd[idx++] = 0x01; cmd[idx++] = 0x00;
        // 42: authentication_policy (0x01 = user device setting)
        cmd[idx++] = 0x42; cmd[idx++] = 0x01; cmd[idx++] = 0x01;
        // 5C: selected protocol version
        cmd[idx++] = 0x5C; cmd[idx++] = 0x02;
        System.arraycopy(protocolVersion, 0, cmd, idx, 2); idx += 2;
        // 87: reader ephemeral public key
        cmd[idx++] = (byte)0x87; cmd[idx++] = 0x41;
        System.arraycopy(readerEphPub, 0, cmd, idx, 65); idx += 65;
        // 4C: transaction identifier
        cmd[idx++] = 0x4C; cmd[idx++] = 0x10;
        System.arraycopy(transactionId, 0, cmd, idx, 16); idx += 16;
        // 4D: reader identifier
        cmd[idx++] = 0x4D; cmd[idx++] = 0x20;
        System.arraycopy(readerId, 0, cmd, idx, 32); idx += 32;
        cmd[idx] = 0x00; // Le
        return cmd;
    }

    /** Build LOAD CERT command */
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
        cmd[idx + cert.length] = 0x00; // Le
        return cmd;
    }

    /** Build AUTH1 command: 80 81 00 00 45 41 01 01 9E 40 <sig 64 bytes> */
    private byte[] buildAuth1Command(byte[] signature)
    {
        byte[] header = { (byte)0x80, (byte)0x81, 0x00, 0x00, 0x45,
                          0x41, 0x01, 0x01, (byte)0x9E, 0x40 };
        byte[] cmd = new byte[header.length + 64];
        System.arraycopy(header, 0, cmd, 0, header.length);
        System.arraycopy(signature, 0, cmd, header.length, 64);
        return cmd;
    }

    /** Build EXCHANGE command: 80 C9 00 00 <Lc> <encrypted payload> 00 */
    private byte[] buildExchangeCommand(byte[] encryptedPayload)
    {
        byte[] cmd = new byte[5 + encryptedPayload.length + 1];
        cmd[0] = (byte)0x80; cmd[1] = (byte)0xC9; cmd[2] = 0x00; cmd[3] = 0x00;
        cmd[4] = (byte) encryptedPayload.length;
        System.arraycopy(encryptedPayload, 0, cmd, 5, encryptedPayload.length);
        cmd[5 + encryptedPayload.length] = 0x00;
        return cmd;
    }

    /** Derive the public key X coordinate from a raw 32-byte private key */
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

    /** Convert raw 32-byte private key bytes to a Java ECPrivateKey */
    private java.security.PrivateKey rawBytesToEcPrivateKey(byte[] rawBytes)
    {
        try
        {
            java.math.BigInteger s = new java.math.BigInteger(1, rawBytes);
            org.bouncycastle.jce.spec.ECNamedCurveParameterSpec bcSpec =
                    org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp256r1");
            org.bouncycastle.jce.spec.ECNamedCurveSpec spec =
                    new org.bouncycastle.jce.spec.ECNamedCurveSpec(
                            "secp256r1",
                            bcSpec.getCurve(),
                            bcSpec.getG(),
                            bcSpec.getN());
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

    /** Check if response ends with SW 90 00 */
    private boolean isSW9000(byte[] response)
    {
        return response != null && response.length >= 2
                && response[response.length - 2] == (byte)0x90
                && response[response.length - 1] == 0x00;
    }

    /** Get last 2 bytes of response as hex string for logging */
    private String swHex(byte[] response)
    {
        if (response == null || response.length < 2) return "null";
        return Hex.toHexString(new byte[]{
                response[response.length - 2],
                response[response.length - 1]});
    }

    /** Show a toast error for Aliro failures */
    // -------------------------------------------------------------------------
    // Aliro Step-Up phase — ENVELOPE/GET RESPONSE + DeviceResponse processing
    // Per Aliro §8.4: transfers Access Document from credential to reader.
    // Returns a short summary string for display, or null if nothing useful returned.
    // -------------------------------------------------------------------------

    @SuppressWarnings("NewApi")
    private String runAliroStepUp(android.nfc.tech.IsoDep isoDep,
                                   byte[] stepUpSK,
                                   String elementId,
                                   SharedPreferences prefs)
            throws java.io.IOException
    {
        // 1. Derive session keys per §8.4.3 / ISO 18013-5 §9.1.1.5
        //    SKDevice[0..31], SKReader[32..63]
        byte[] sessionKeys = AliroCryptoProvider.deriveStepUpSessionKeys(stepUpSK);
        if (sessionKeys == null)
        {
            Log.e(TAG, "Step-Up: session key derivation failed");
            return null;
        }
        byte[] suSKDevice = Arrays.copyOfRange(sessionKeys, 0,  32);
        byte[] suSKReader = Arrays.copyOfRange(sessionKeys, 32, 64);

        try
        {
            // 2. Build DeviceRequest CBOR per Aliro §8.4.2 + Table 8-21
            //
            // Per ISO 18013-5 §8.3.2.1.2.1 (referenced by Aliro §8.4.2):
            // itemsRequest is an INLINE embedded CBOR map — NOT a bstr wrapper.
            // Table 8-21 key mapping (integers encoded as text strings):
            //   "1" = nameSpaces, "5" = docType
            //
            // Structure:
            // { "1": "1.0",
            //   "2": [ { "1": { "5": "aliro-a",
            //                   "1": { "aliro-a": { <elementId>: false } } } } ] }
            com.upokecenter.cbor.CBORObject nameSpaceMap = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            com.upokecenter.cbor.CBORObject elemMap      = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            // intentToRetain = false per ISO 18013-5 §8.3.2.1.2.1
            elemMap.Add(com.upokecenter.cbor.CBORObject.FromObject(elementId),
                        com.upokecenter.cbor.CBORObject.False);
            nameSpaceMap.Add(com.upokecenter.cbor.CBORObject.FromObject("aliro-a"), elemMap);

            // itemsRequest is an inline map (NOT bstr-wrapped) per ISO 18013-5
            com.upokecenter.cbor.CBORObject itemsRequest = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            itemsRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("5"),
                    com.upokecenter.cbor.CBORObject.FromObject("aliro-a")); // docType
            itemsRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("1"), nameSpaceMap); // nameSpaces

            com.upokecenter.cbor.CBORObject docRequest = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            // key "1" = itemsRequest (inline map, not bstr)
            docRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("1"), itemsRequest);

            com.upokecenter.cbor.CBORObject deviceRequest = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            deviceRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("1"),
                    com.upokecenter.cbor.CBORObject.FromObject("1.0"));
            com.upokecenter.cbor.CBORObject docRequests = com.upokecenter.cbor.CBORObject.NewArray();
            docRequests.Add(docRequest);
            deviceRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("2"), docRequests);

            byte[] deviceRequestBytes = deviceRequest.EncodeToBytes();
            Log.d(TAG, "Step-Up: DeviceRequest CBOR (" + deviceRequestBytes.length + " bytes)");

            // 3. Encrypt DeviceRequest into SessionData per Aliro §8.4.3 + ISO 18013-5 §9.1.1.4
            //
            // Per §8.4.3 the reader encrypts with StepUpSKReader using the same AES-GCM
            // procedure as §8.3.1.8 (reader command encryption):
            //   IV = 0x0000000000000000 || reader_counter (counter=1, big-endian 4 bytes)
            //
            // SessionData CBOR: { "data": bstr(ciphertext+tag) }
            byte[] encryptedRequest = AliroCryptoProvider.encryptReaderGcm(suSKReader, deviceRequestBytes);
            if (encryptedRequest == null)
            {
                Log.e(TAG, "Step-Up: failed to encrypt DeviceRequest");
                return null;
            }

            // Build SessionData CBOR: { "data": bstr }
            com.upokecenter.cbor.CBORObject sessionDataOut = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            sessionDataOut.Add(com.upokecenter.cbor.CBORObject.FromObject("data"),
                    com.upokecenter.cbor.CBORObject.FromObject(encryptedRequest));
            byte[] sessionDataBytes = sessionDataOut.EncodeToBytes();
            Log.d(TAG, "Step-Up: SessionData ENVELOPE payload (" + sessionDataBytes.length + " bytes)");

            // 4. Send ENVELOPE (CLA=0x80, INS=0xC3) containing encrypted SessionData
            byte[] envelopeCmd = buildEnvelopeCommand(sessionDataBytes);
            Log.d(TAG, "Step-Up: sending ENVELOPE");
            byte[] envelopeResp = isoDep.transceive(envelopeCmd);

            // 5. Collect full response, handling GET RESPONSE (SW 61 xx)
            java.io.ByteArrayOutputStream responseAcc = new java.io.ByteArrayOutputStream();
            byte[] currentResp = envelopeResp;
            while (currentResp != null && currentResp.length >= 2)
            {
                byte sw1 = currentResp[currentResp.length - 2];
                byte sw2 = currentResp[currentResp.length - 1];
                if (currentResp.length > 2)
                    responseAcc.write(currentResp, 0, currentResp.length - 2);

                if (sw1 == 0x61)
                {
                    byte[] getResp = new byte[]{ 0x00, (byte)0xC0, 0x00, 0x00, sw2 };
                    currentResp = isoDep.transceive(getResp);
                }
                else if (sw1 == (byte)0x90 && sw2 == 0x00)
                {
                    break;
                }
                else
                {
                    Log.w(TAG, "Step-Up: unexpected SW " + String.format("%02X%02X", sw1, sw2));
                    return "SW=" + String.format("%02X%02X", sw1, sw2);
                }
            }

            byte[] rawResponse = responseAcc.toByteArray();
            Log.d(TAG, "Step-Up: raw SessionData response (" + rawResponse.length + " bytes): "
                    + org.bouncycastle.util.encoders.Hex.toHexString(rawResponse));

            if (rawResponse.length == 0)
            {
                Log.d(TAG, "Step-Up: empty response");
                return null;
            }

            // 6. Unwrap SessionData response and decrypt with StepUpSKDevice
            //    per Aliro §8.4.3 + ISO 18013-5 §9.1.1.5
            //    Device encrypts with IV = 0x0000000000000001 || device_counter (counter=1)
            com.upokecenter.cbor.CBORObject sessionDataIn =
                    com.upokecenter.cbor.CBORObject.DecodeFromBytes(rawResponse);
            com.upokecenter.cbor.CBORObject dataField =
                    sessionDataIn.get(com.upokecenter.cbor.CBORObject.FromObject("data"));
            if (dataField == null)
            {
                Log.e(TAG, "Step-Up: SessionData response missing 'data' field");
                return null;
            }
            byte[] encryptedResponse = dataField.GetByteString();
            byte[] deviceResponseBytes = AliroCryptoProvider.decryptDeviceGcm(suSKDevice, encryptedResponse);
            if (deviceResponseBytes == null)
            {
                Log.e(TAG, "Step-Up: DeviceResponse AES-GCM authentication failed");
                return null;
            }
            Log.d(TAG, "Step-Up: DeviceResponse (" + deviceResponseBytes.length + " bytes): "
                    + org.bouncycastle.util.encoders.Hex.toHexString(deviceResponseBytes));

            // 7. Parse DeviceResponse CBOR per Aliro Table 8-22
            com.upokecenter.cbor.CBORObject deviceResponse =
                    com.upokecenter.cbor.CBORObject.DecodeFromBytes(deviceResponseBytes);

            com.upokecenter.cbor.CBORObject docs = deviceResponse.get(
                    com.upokecenter.cbor.CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0)
            {
                Log.d(TAG, "Step-Up: no documents in DeviceResponse");
                return null;
            }

            // 6. Extract first document's IssuerAuth + IssuerSignedItems
            com.upokecenter.cbor.CBORObject firstDoc   = docs.get(0);
            com.upokecenter.cbor.CBORObject iSigned    = firstDoc.get(
                    com.upokecenter.cbor.CBORObject.FromObject("1"));
            com.upokecenter.cbor.CBORObject iAuth      = iSigned.get(
                    com.upokecenter.cbor.CBORObject.FromObject("2"));
            com.upokecenter.cbor.CBORObject nameSpaces = iSigned.get(
                    com.upokecenter.cbor.CBORObject.FromObject("1"));

            // 7. Verify COSE_Sign1 signature if issuer pub key is configured
            boolean docVerified = false;
            String issuerKeyHex = prefs.getString(AliroPreferences.STEP_UP_ISSUER_PUB_KEY, "");
            if (!issuerKeyHex.isEmpty() && iAuth != null)
            {
                docVerified = verifyCoseSign1(iAuth, issuerKeyHex);
                Log.d(TAG, "Step-Up: COSE_Sign1 verification = " + docVerified);
            }
            else
            {
                Log.d(TAG, "Step-Up: no issuer key configured, skipping signature verification");
            }

            // 8. Extract AccessData element value for display
            String accessSummary = extractAccessDataSummary(nameSpaces, elementId);

            // Build result: sig status on first line, then access summary
            String sigStatus = (issuerKeyHex.isEmpty() ? "(sig not verified)"
                    : (docVerified ? "Signature Valid" : "Signature INVALID"));
            StringBuilder result = new StringBuilder(sigStatus);
            if (accessSummary != null)
                result.append("\n").append(accessSummary);
            return result.toString();
        }
        finally
        {
            // Zero session keys
            java.util.Arrays.fill(suSKDevice, (byte)0);
            java.util.Arrays.fill(suSKReader, (byte)0);
            java.util.Arrays.fill(sessionKeys, (byte)0);
        }
    }

    /** Build ENVELOPE command (single chunk — data must be ≤ 255 bytes) */
    /**
     * Parse a decrypted DeviceResponse (received over BLE ENVELOPE) and return a
     * human-readable step-up result string matching the NFC path format.
     * Returns null if parsing fails (caller falls back to generic message).
     */
    private String parseBleStepUpResult(byte[] deviceResponseBytes, String elementId)
    {
        try
        {
            SharedPreferences prefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
            String issuerKeyHex = prefs.getString(AliroPreferences.STEP_UP_ISSUER_PUB_KEY, "");

            com.upokecenter.cbor.CBORObject deviceResponse =
                    com.upokecenter.cbor.CBORObject.DecodeFromBytes(deviceResponseBytes);

            // Key "2" = documents array (Aliro Table 8-22)
            com.upokecenter.cbor.CBORObject docs = deviceResponse.get(
                    com.upokecenter.cbor.CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0)
            {
                Log.d(TAG, "BLE Step-Up: no documents in DeviceResponse");
                return null;
            }

            com.upokecenter.cbor.CBORObject firstDoc = docs.get(0);
            com.upokecenter.cbor.CBORObject iSigned  = firstDoc.get(
                    com.upokecenter.cbor.CBORObject.FromObject("1"));
            if (iSigned == null) return null;

            com.upokecenter.cbor.CBORObject iAuth      = iSigned.get(
                    com.upokecenter.cbor.CBORObject.FromObject("2"));
            com.upokecenter.cbor.CBORObject nameSpaces = iSigned.get(
                    com.upokecenter.cbor.CBORObject.FromObject("1"));

            // Verify COSE_Sign1 if issuer key configured
            boolean docVerified = false;
            if (!issuerKeyHex.isEmpty() && iAuth != null)
            {
                docVerified = verifyCoseSign1(iAuth, issuerKeyHex);
                Log.d(TAG, "BLE Step-Up: COSE_Sign1 verification = " + docVerified);
            }
            else
            {
                Log.d(TAG, "BLE Step-Up: no issuer key configured, skipping sig verification");
            }

            String accessSummary = extractAccessDataSummary(nameSpaces, elementId);

            String sigStatus = (issuerKeyHex.isEmpty() ? "(sig not verified)"
                    : (docVerified ? "Signature Valid" : "Signature INVALID"));
            StringBuilder result = new StringBuilder(sigStatus);
            if (accessSummary != null)
                result.append("\n").append(accessSummary);
            return result.toString();
        }
        catch (Exception e)
        {
            Log.w(TAG, "parseBleStepUpResult failed: " + e.getMessage());
            return null;
        }
    }

        private static byte[] buildEnvelopeCommand(byte[] data)
    {
        // CLA=80 INS=C3 P1=00 P2=00 Lc=<len> <data>
        byte[] cmd = new byte[5 + data.length];
        cmd[0] = (byte)0x80;
        cmd[1] = (byte)0xC3;
        cmd[2] = 0x00;
        cmd[3] = 0x00;
        cmd[4] = (byte) data.length;
        System.arraycopy(data, 0, cmd, 5, data.length);
        return cmd;
    }

    /**
     * Verify COSE_Sign1 over the IssuerAuth using the configured issuer public key.
     * IssuerAuth = [ protected_header_bytes, unprotected_header, payload_bytes, signature ]
     */
    private boolean verifyCoseSign1(com.upokecenter.cbor.CBORObject coseSign1, String issuerKeyHex)
    {
        try
        {
            // Extract components
            byte[] protectedHeaderBytes = coseSign1.get(0).GetByteString();
            byte[] payloadBytes         = coseSign1.get(2).GetByteString();
            byte[] rawSig               = coseSign1.get(3).GetByteString();

            // Build Sig_Structure: ["Signature1", protected, external_aad="", payload]
            com.upokecenter.cbor.CBORObject sigStruct = com.upokecenter.cbor.CBORObject.NewArray();
            sigStruct.Add(com.upokecenter.cbor.CBORObject.FromObject("Signature1"));
            sigStruct.Add(com.upokecenter.cbor.CBORObject.FromObject(protectedHeaderBytes));
            sigStruct.Add(com.upokecenter.cbor.CBORObject.FromObject(new byte[0]));
            sigStruct.Add(com.upokecenter.cbor.CBORObject.FromObject(payloadBytes));
            byte[] toBeSigned = sigStruct.EncodeToBytes();

            // Decode issuer public key — use standard JCA (no explicit provider, Android resolves EC natively)
            byte[] issuerPubBytes = org.bouncycastle.util.encoders.Hex.decode(issuerKeyHex);
            java.security.spec.ECPoint point = new java.security.spec.ECPoint(
                    new java.math.BigInteger(1, Arrays.copyOfRange(issuerPubBytes, 1, 33)),
                    new java.math.BigInteger(1, Arrays.copyOfRange(issuerPubBytes, 33, 65)));
            java.security.AlgorithmParameters ap =
                    java.security.AlgorithmParameters.getInstance("EC");
            ap.init(new java.security.spec.ECGenParameterSpec("secp256r1"));
            java.security.spec.ECParameterSpec ecParams =
                    ap.getParameterSpec(java.security.spec.ECParameterSpec.class);
            java.security.spec.ECPublicKeySpec pubSpec =
                    new java.security.spec.ECPublicKeySpec(point, ecParams);
            java.security.PublicKey issuerPubKey =
                    java.security.KeyFactory.getInstance("EC").generatePublic(pubSpec);

            // Convert raw R||S to DER
            byte[] r = Arrays.copyOfRange(rawSig, 0, 32);
            byte[] s = Arrays.copyOfRange(rawSig, 32, 64);
            byte[] derSig = rawToDer(r, s);

            java.security.Signature verifier = java.security.Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(issuerPubKey);
            verifier.update(toBeSigned);
            return verifier.verify(derSig);
        }
        catch (Exception e)
        {
            Log.e(TAG, "verifyCoseSign1 failed", e);
            return false;
        }
    }

    /** Convert raw 32-byte R + 32-byte S to DER-encoded ECDSA signature */
    private static byte[] rawToDer(byte[] r, byte[] s)
    {
        // Strip leading zeros, add 0x00 padding if high bit set
        byte[] rPad = padIfNeeded(r);
        byte[] sPad = padIfNeeded(s);
        int len = 2 + rPad.length + 2 + sPad.length;
        byte[] der = new byte[2 + len];
        int i = 0;
        der[i++] = 0x30;
        der[i++] = (byte) len;
        der[i++] = 0x02;
        der[i++] = (byte) rPad.length;
        System.arraycopy(rPad, 0, der, i, rPad.length); i += rPad.length;
        der[i++] = 0x02;
        der[i++] = (byte) sPad.length;
        System.arraycopy(sPad, 0, der, i, sPad.length);
        return der;
    }

    private static byte[] padIfNeeded(byte[] b)
    {
        // Remove leading zeros
        int start = 0;
        while (start < b.length - 1 && b[start] == 0) start++;
        byte[] trimmed = Arrays.copyOfRange(b, start, b.length);
        // Pad with 0x00 if high bit set (DER positive integer requirement)
        if ((trimmed[0] & 0x80) != 0)
        {
            byte[] padded = new byte[trimmed.length + 1];
            System.arraycopy(trimmed, 0, padded, 1, trimmed.length);
            return padded;
        }
        return trimmed;
    }

    /**
     * Extract a human-readable summary from the AccessData element in the DeviceResponse.
     *
     * Parses the full AccessData map per Aliro 1.0 §7.3:
     *   0 = version, 1 = id (bstr), 2 = AccessRules array, 3 = Schedules array
     *
     * AccessRule (§7.3.3): { 0: capabilities(uint), 1: allowScheduleIds(uint) }
     *   capability bitmask: bit0=Secure, bit1=Unsecure, bit3=Momentary_Unsecure
     *
     * Schedule (§7.3.4): { 0: startPeriod, 1: endPeriod, 2: recurrenceRule[], 3: flags }
     *   recurrenceRule: [durationSeconds, dayMask, pattern, interval, ordinal]
     *   dayMask bits: 0=Mon,1=Tue,2=Wed,3=Thu,4=Fri,5=Sat,6=Sun
     *
     * Returns null if parsing fails (caller shows a generic result).
     */
    private String extractAccessDataSummary(com.upokecenter.cbor.CBORObject nameSpaces,
                                             String elementId)
    {
        try
        {
            if (nameSpaces == null) return null;
            com.upokecenter.cbor.CBORObject items = nameSpaces.get(
                    com.upokecenter.cbor.CBORObject.FromObject("aliro-a"));
            if (items == null || items.size() == 0) return null;

            for (int i = 0; i < items.size(); i++)
            {
                // Each item is a bstr wrapping an IssuerSignedItem CBOR map
                byte[] itemBytes = items.get(i).GetByteString();
                com.upokecenter.cbor.CBORObject item =
                        com.upokecenter.cbor.CBORObject.DecodeFromBytes(itemBytes);
                com.upokecenter.cbor.CBORObject eid =
                        item.get(com.upokecenter.cbor.CBORObject.FromObject("3"));
                if (eid == null || !elementId.equals(eid.AsString())) continue;

                com.upokecenter.cbor.CBORObject val =
                        item.get(com.upokecenter.cbor.CBORObject.FromObject("4"));
                if (val == null) return null;

                // ---- version (key 0) ----
                com.upokecenter.cbor.CBORObject versionObj =
                        val.get(com.upokecenter.cbor.CBORObject.FromObject(0));
                int version = (versionObj != null) ? versionObj.AsInt32Value() : -1;

                StringBuilder sb = new StringBuilder();

                // ---- employee ID (key 1, optional bstr) ----
                com.upokecenter.cbor.CBORObject idObj =
                        val.get(com.upokecenter.cbor.CBORObject.FromObject(1));
                if (idObj != null && idObj.getType() ==
                        com.upokecenter.cbor.CBORType.ByteString)
                {
                    try
                    {
                        String empId = new String(idObj.GetByteString(),
                                java.nio.charset.StandardCharsets.UTF_8);
                        sb.append("  Employee ID:    ").append(empId).append("\n");
                    }
                    catch (Exception ignored) {}
                }

                sb.append("  Element:        ").append(elementId)
                  .append(" (v").append(version).append(")\n");

                // ---- AccessRules (key 2, optional array) ----
                com.upokecenter.cbor.CBORObject rulesArr =
                        val.get(com.upokecenter.cbor.CBORObject.FromObject(2));

                // Collect schedules now so rules can reference them
                com.upokecenter.cbor.CBORObject schedsArr =
                        val.get(com.upokecenter.cbor.CBORObject.FromObject(3));

                if (rulesArr != null && rulesArr.getType() ==
                        com.upokecenter.cbor.CBORType.Array)
                {
                    int numRules = rulesArr.size();
                    sb.append("  Access Rules:   ").append(numRules).append("\n");
                    for (int r = 0; r < numRules; r++)
                    {
                        com.upokecenter.cbor.CBORObject rule = rulesArr.get(r);
                        com.upokecenter.cbor.CBORObject capObj =
                                rule.get(com.upokecenter.cbor.CBORObject.FromObject(0));
                        com.upokecenter.cbor.CBORObject schedIdsObj =
                                rule.get(com.upokecenter.cbor.CBORObject.FromObject(1));

                        String capStr = (capObj != null)
                                ? decodeCapabilities(capObj.AsInt32Value()) : "";
                        sb.append("    Rule ").append(r + 1).append(":  ")
                          .append(capStr).append("\n");

                        // Attach associated schedules
                        if (schedIdsObj != null && schedsArr != null
                                && schedsArr.getType() == com.upokecenter.cbor.CBORType.Array)
                        {
                            // schedIdsObj may be a single int or an array
                            java.util.List<Integer> schedIds = new java.util.ArrayList<>();
                            if (schedIdsObj.getType() == com.upokecenter.cbor.CBORType.Array)
                            {
                                for (int si = 0; si < schedIdsObj.size(); si++)
                                    schedIds.add(schedIdsObj.get(si).AsInt32Value());
                            }
                            else
                            {
                                schedIds.add(schedIdsObj.AsInt32Value());
                            }
                            for (int sid : schedIds)
                            {
                                if (sid < schedsArr.size())
                                {
                                    String schedStr = decodeScheduleSummary(
                                            schedsArr.get(sid), sid);
                                    if (schedStr != null)
                                        sb.append("             Schedule: ")
                                          .append(schedStr).append("\n");
                                }
                            }
                        }
                    }
                }

                return sb.toString().trim();
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "extractAccessDataSummary failed: " + e.getMessage());
        }
        return null;
    }

    /**
     * Decode capabilities bitmask (§7.3.3 Table 7-7) to a human-readable label string.
     * bit0=Secure, bit1=Unsecure, bit3=Momentary_Unsecure
     */
    private static String decodeCapabilities(int cap)
    {
        if (cap == 0) return "None";
        java.util.List<String> parts = new java.util.ArrayList<>();
        if ((cap & 0x01) != 0) parts.add("Secure");
        if ((cap & 0x02) != 0) parts.add("Unsecure");
        if ((cap & 0x08) != 0) parts.add("Momentary Unsecure");
        int unknown = cap & ~0x0B;
        if (unknown != 0) parts.add(String.format("0x%02X", unknown));
        StringBuilder sb = new StringBuilder();
        for (int idx = 0; idx < parts.size(); idx++)
        {
            if (idx > 0) sb.append(", ");
            sb.append(parts.get(idx));
        }
        return sb.toString();
    }

    /**
     * Decode a Schedule CBOR map (§7.3.4) to a human-readable string.
     * recurrenceRule: [durationSeconds, dayMask, pattern, interval, ordinal]
     * dayMask bits: 0=Mon 1=Tue 2=Wed 3=Thu 4=Fri 5=Sat 6=Sun
     *
     * Example output: "Mon-Fri (12 hours)" or "Sat-Sun (8 hours)"
     */
    private static String decodeScheduleSummary(com.upokecenter.cbor.CBORObject sched, int index)
    {
        try
        {
            com.upokecenter.cbor.CBORObject recRule =
                    sched.get(com.upokecenter.cbor.CBORObject.FromObject(2));
            if (recRule == null || recRule.size() < 2) return null;

            int durationSec = recRule.get(0).AsInt32Value();
            int dayMask     = recRule.get(1).AsInt32Value();

            // Build day-of-week string — try to compress consecutive runs
            final String[] DAY_FULL  = { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
            java.util.List<String> activeDays = new java.util.ArrayList<>();
            for (int d = 0; d < 7; d++)
                if ((dayMask & (1 << d)) != 0) activeDays.add(DAY_FULL[d]);

            String daysStr;
            if (activeDays.isEmpty())
            {
                daysStr = "(no days)";
            }
            else if (activeDays.size() == 7)
            {
                daysStr = "Every day";
            }
            else if (activeDays.size() == 1)
            {
                daysStr = activeDays.get(0);
            }
            else
            {
                // Show first-last if consecutive, otherwise comma-separated
                daysStr = activeDays.get(0) + "-" + activeDays.get(activeDays.size() - 1);
            }

            // Duration: show hours + minutes
            int hours   = durationSec / 3600;
            int minutes = (durationSec % 3600) / 60;
            String durStr;
            if (minutes == 0)
                durStr = hours + (hours == 1 ? " hour" : " hours");
            else
                durStr = hours + "h " + minutes + "m";

            return daysStr + " (" + durStr + ")";
        }
        catch (Exception e) { return null; }
    }

    /**
     * Build a cleanly formatted multi-line connectionType string for Aliro result display.
     *
     * The first line is the transport + signature status (used as bold title).
     * Subsequent section headers ("ACCESS DOCUMENT", "MAILBOX") are ALL-CAPS so
     * displayPublicKeyInfo() can detect and style them.
     *
     * @param transport     "NFC" or "BLE"
     * @param sigValid      whether the credential signature was verified
     * @param stepUpResult  parsed step-up result string, or null
     * @param mailboxResult parsed mailbox string, or null
     * @return formatted string ready for displayPublicKeyInfo()
     */
    private static String formatAliroConnectionType(String transport,
                                                     boolean sigValid,
                                                     String stepUpResult,
                                                     String mailboxResult)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("Aliro ").append(transport).append(" — ")
          .append(sigValid ? "Signature Valid" : "Signature INVALID");

        if (stepUpResult != null)
        {
            sb.append("\n\nACCESS DOCUMENT\n");
            // Each line of stepUpResult is already indented with leading spaces
            // (produced by extractAccessDataSummary). Append as-is.
            for (String line : stepUpResult.split("\n", -1))
            {
                sb.append(line).append("\n");
            }
        }

        if (mailboxResult != null)
        {
            sb.append("\nMAILBOX (").append(AliroMailbox.MAILBOX_SIZE).append(" bytes)\n");
            for (String line : mailboxResult.split("\n", -1))
            {
                sb.append(line).append("\n");
            }
        }

        // Trim trailing whitespace but keep the content intact
        return sb.toString().trim();
    }

    private void showAliroCredentialRejectDialog(String sw)
    {
        Log.e(TAG, "Aliro AUTH1 rejected by credential: SW=" + sw);
        requireActivity().runOnUiThread(() ->
        {
            if (!isAdded()) return;
            new AlertDialog.Builder(requireContext())
                    .setTitle("Credential Rejected Reader")
                    .setMessage(
                        "The credential rejected this reader during authentication (SW=" + sw + ").\n\n" +
                        "This typically means:\n\n" +
                        "\u2022 The reader\u2019s certificate was not signed by an issuer the credential trusts, or\n" +
                        "\u2022 The reader\u2019s private key does not match the public key in its certificate, or\n" +
                        "\u2022 The reader certificate or issuer public key is not correctly configured.\n\n" +
                        "Check the Aliro Config screen and verify that the reader certificate, " +
                        "private key, and issuer public key are all from the same trusted issuer.")
                    .setPositiveButton("Open Aliro Config", (d, w) ->
                    {
                        if (requireActivity() instanceof MainActivity)
                            ((MainActivity) requireActivity()).navigateToAliroConfig();
                    })
                    .setNegativeButton("Dismiss", null)
                    .setIcon(android.R.drawable.ic_dialog_alert)
                    .show();
        });
    }

    private void showAliroError(String message)
    {
        Log.e(TAG, "Aliro error: " + message);
        requireActivity().runOnUiThread(() ->
                Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show());
    }

    /**
     * Send CONTROL FLOW command to signal transaction failure when no secure channel exists.
     * Per section 10.2.2 and Table 8-2 rows 3/9: used when SW != 9000 or no EXCHANGE key.
     * INS=0x3C, data: 41 01 00 (S1=failure) 42 01 00 (S2=no info)
     */
    private void sendControlFlow(IsoDep isoDep)
    {
        try
        {
            // CONTROL FLOW: CLA=80 INS=3C P1=00 P2=00 Lc=06 [41 01 00 42 01 00] Le=00
            byte[] controlFlow = {
                (byte)0x80, 0x3C, 0x00, 0x00, 0x06,
                0x41, 0x01, 0x00,   // S1 = 0x00: transaction finished with failure
                0x42, 0x01, 0x00,   // S2 = 0x00: no information
                0x00                // Le
            };
            Log.d(TAG, "Sending CONTROL FLOW");
            byte[] response = isoDep.transceive(controlFlow);
            Log.d(TAG, "CONTROL FLOW response: " + Hex.toHexString(response));
        }
        catch (Exception e)
        {
            Log.w(TAG, "CONTROL FLOW send failed (non-fatal): " + e.getMessage());
        }
    }
}
