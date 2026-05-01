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
import java.io.ByteArrayOutputStream;
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

    /**
     * DESFire 3-byte AID for the LEAF Verified application on MIFARE DUOX cards.
     * Used with the DESFire wrapped SELECT APPLICATION command (CLA=0x90, INS=0x5A).
     */
    private static final byte[] DESFIRE_LEAF_AID = { (byte)0xD6, 0x1C, (byte)0xF5 };

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
    /** Cached ScrollView so setKeypadVisibility() can flip its bottom anchor in lockstep. */
    private android.view.View scrollViewForResultArea;

    private TextView pinDisplay;
    private boolean isDisplayingResult = false;

    // Cached Aliro reader private key — loaded once when config changes to avoid
    // rebuilding the ECPrivateKey on every NFC tap (which takes ~400ms).
    private java.security.PrivateKey cachedAliroReaderPrivKey = null;
    private String cachedAliroPrivKeyHex = null;

    // FAST mode session state — stored in memory (not SharedPrefs) so it
    // only persists within the current app session. First tap = STANDARD,
    // second tap = FAST (if checkbox is enabled).
    private byte[] sessionKpersistent = null;
    private byte[] sessionCredentialPubKeyX = null;

    // Last document verification result from step-up phase
    // Set by runAliroStepUp(), consumed by performAliroNfcTransaction() for post-step-up EXCHANGE status
    private volatile AliroAccessDocumentVerifier.VerificationResult lastDocVerifyResult = null;

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

                    // Parse step-up result using the SAME full verifier as NFC
                    // Both transports must produce identical verification results.
                    // Multi-element responses (Aliro 1.0 §8.4.2) are sliced
                    // into one DeviceResponse per document so each is verified
                    // by the same single-doc verifier path the NFC flow uses.
                    String bleStepUpResult = null;
                    if (deviceResponse != null)
                    {
                        try
                        {
                            byte[] credPubKeyBytes = (credPubKeyHex != null && !credPubKeyHex.isEmpty())
                                    ? org.bouncycastle.util.encoders.Hex.decode(credPubKeyHex) : null;

                            // Load step-up issuer key(s) and element ID from prefs.
                            // The Step-Up Issuer Public Key field accepts a single
                            // hex value or a CSV list (Aliro 1.0 §7.7) — multiple
                            // stored documents may carry different issuers.
                            SharedPreferences stepUpPrefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
                            String issuerKeyHex = stepUpPrefs.getString(AliroPreferences.STEP_UP_ISSUER_PUB_KEY, "");
                            java.util.List<byte[]> trustedIssuerKeys = parseIssuerPubKeyList(issuerKeyHex);

                            // Determine docType: prefer aliro-a (access) over aliro-r (revocation)
                            String docType = "aliro-a";

                            java.util.List<String> requestedIds = parseElementIdList(stepUpElemId);
                            java.util.List<byte[]> slices = sliceDeviceResponsePerDocument(deviceResponse);

                            if (slices.isEmpty())
                            {
                                byte[] fallbackKey = trustedIssuerKeys.isEmpty() ? null : trustedIssuerKeys.get(0);
                                AliroAccessDocumentVerifier.VerificationResult verifyResult =
                                        AliroAccessDocumentVerifier.verifyDocument(
                                                deviceResponse, docType, credPubKeyBytes,
                                                requestedIds.get(0), fallbackKey);
                                lastDocVerifyResult = verifyResult;
                                bleStepUpResult = verifyResult.stepUpResultText;
                            }
                            else
                            {
                                StringBuilder combined = new StringBuilder();
                                AliroAccessDocumentVerifier.VerificationResult lastVr = null;
                                for (int i = 0; i < slices.size(); i++)
                                {
                                    String sliceElementId = (i < requestedIds.size())
                                            ? requestedIds.get(i)
                                            : requestedIds.get(requestedIds.size() - 1);
                                    byte[] sliceIssuerKey = trustedIssuerKeys.isEmpty()
                                            ? null
                                            : pickIssuerKeyForKid(slices.get(i), trustedIssuerKeys);
                                    AliroAccessDocumentVerifier.VerificationResult vr =
                                            AliroAccessDocumentVerifier.verifyDocument(
                                                    slices.get(i), docType, credPubKeyBytes,
                                                    sliceElementId, sliceIssuerKey);
                                    lastVr = vr;
                                    if (vr.stepUpResultText != null && !vr.stepUpResultText.isEmpty())
                                    {
                                        if (combined.length() > 0) combined.append("\n\n");
                                        combined.append(vr.stepUpResultText);
                                    }
                                }
                                lastDocVerifyResult = lastVr;
                                bleStepUpResult = (combined.length() > 0)
                                        ? combined.toString()
                                        : (lastVr != null ? lastVr.stepUpResultText : null);
                            }
                            Log.d(TAG, "BLE Step-Up verification: " + bleStepUpResult);
                        }
                        catch (Exception e)
                        {
                            Log.w(TAG, "BLE Step-Up verification failed, falling back: " + e.getMessage());
                            bleStepUpResult = parseBleStepUpResult(deviceResponse, stepUpElemId);
                        }
                        if (bleStepUpResult == null)
                            bleStepUpResult = "Access Document received";
                    }

                    // Parse mailbox using the same logic as NFC: look for §18 container
                    // tag 0x60 and parse structured TLV content into human-readable form.
                    String bleMailboxParsed = null;
                    if (mailboxResult != null)
                    {
                        try
                        {
                            byte[] mailboxBytes;
                            if (mailboxResult.matches("[0-9A-Fa-f]+") && mailboxResult.length() >= 4)
                                mailboxBytes = org.bouncycastle.util.encoders.Hex.decode(mailboxResult);
                            else
                                mailboxBytes = null;

                            if (mailboxBytes != null && mailboxBytes.length > 0)
                            {
                                // Scan for §18 container tag 0x60 within the first few bytes
                                int tlvStart = -1;
                                for (int s = 0; s < Math.min(4, mailboxBytes.length); s++)
                                {
                                    if ((mailboxBytes[s] & 0xFF) == 0x60) { tlvStart = s; break; }
                                }
                                if (tlvStart >= 0)
                                {
                                    byte[] tlvData = java.util.Arrays.copyOfRange(
                                            mailboxBytes, tlvStart, mailboxBytes.length);
                                    bleMailboxParsed = AliroMailbox.parseMailboxToString(
                                            tlvData, tlvData.length);
                                }
                                else
                                {
                                    // No structured TLV found — show clean summary
                                    String fullHex = org.bouncycastle.util.encoders.Hex.toHexString(mailboxBytes);
                                    String preview = (fullHex.length() > 64)
                                            ? fullHex.substring(0, 64) + "..."
                                            : fullHex;
                                    bleMailboxParsed = "Read " + mailboxBytes.length + " bytes\n"
                                            + "  Preview: " + preview;
                                }
                            }
                            else
                            {
                                bleMailboxParsed = mailboxResult;
                            }
                        }
                        catch (Exception e)
                        {
                            Log.w(TAG, "BLE mailbox parse failed: " + e.getMessage());
                            bleMailboxParsed = mailboxResult;
                        }
                    }

                    connectionType = formatAliroConnectionType("BLE", sigValid, bleStepUpResult, bleMailboxParsed);

                    // Show the credential result screen — same as Aliro NFC
                    setKeypadVisibility(View.GONE);
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

        // ---------------------------------------------------------------
        // Adaptive ScrollView bottom constraint
        // ---------------------------------------------------------------
        // The fragment_home.xml layout clamps the ScrollView's bottom to
        // guidelineKeypadTop (55%) so the protocol toggle + buttons can never
        // spill into the keypad's first row. That works perfectly while the
        // keypad is visible, but during a result display we hide both the
        // reader image and the keypad — and the guideline doesn't move with
        // them. The ScrollView would then waste the lower 45% of the screen,
        // truncating long Aliro multi-element verification results.
        //
        // We expose setKeypadVisibility(int) which both flips the keypad's
        // visibility AND updates the ScrollView's bottom anchor in the same
        // call, so the two stay in sync without relying on layout-pass timing
        // (an earlier OnLayoutChangeListener attempt raced against the parent
        // ConstraintLayout's measure pass and left the constraint stale by
        // one frame). All keypad show/hide call sites use this helper.
        // ---------------------------------------------------------------
        scrollViewForResultArea = view.findViewById(R.id.scrollView);
        // Apply initial state — keypad starts visible, so anchor to guideline.
        applyScrollViewBottomConstraint();

        // Position the keypad overlay once the reader image has been measured.
        // OnGlobalLayoutListener may fire multiple times before measurement is
        // complete — especially when navigating back to this fragment from
        // another screen (e.g. credential read). We hold the listener until
        // positionKeypad returns true (image and root both have non-zero
        // height), then remove it to avoid wasting frames.
        readerImage.getViewTreeObserver().addOnGlobalLayoutListener(
                new android.view.ViewTreeObserver.OnGlobalLayoutListener() {
                    @Override
                    public void onGlobalLayout() {
                        if (positionKeypad(readerImage, view)) {
                            readerImage.getViewTreeObserver()
                                    .removeOnGlobalLayoutListener(this);
                        }
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

        // Always re-position the keypad on resume.
        //
        // The keypad is a LinearLayout of digit Buttons (R.id.keypadLayout)
        // overlaid on the reader_background drawable. The bitmap is a portrait
        // reader silhouette with the LED indicator and ELATEC/Allegion logos
        // baked in across roughly the upper third; the lower portion is left
        // blank so the keypad LinearLayout can render real buttons inside the
        // reader's keypad area. positionKeypad() sets the keypad's pixel
        // coordinates as 36%–94% of the reader image's measured height, which
        // assumes the image and the root view have the dimensions they had at
        // the moment positionKeypad() ran.
        //
        // When the user navigates to Aliro Config and back, the fragment may
        // either be recreated (in which case keypadPositioned starts false) or
        // retained (in which case it's still true from the previous session).
        // In the retained case, the previously-computed margins may no longer
        // match the current layout — the container can re-measure to a
        // different size after navigation (toolbar inset re-application on
        // Android 16, soft-keyboard dismiss, configuration changes), leaving
        // the keypad anchored at stale coordinates. Symptom: the digit "1"
        // button renders near the top of the bitmap at the same vertical
        // position as the bitmap's baked-in LED indicator, and the rest of the
        // keypad is compressed upward into the logo area.
        //
        // Resetting the flag and unconditionally requesting a reposition
        // ensures a fresh measurement pass every time the fragment becomes
        // active. requestKeypadReposition() installs a one-shot global-layout
        // listener that retries until the image and root both have non-zero
        // height, so this is safe even if measurement isn't ready yet.
        keypadPositioned = false;
        requestKeypadReposition();

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

        // Use built-in defaults from PKOC_Preferences if nothing has been configured.
        // Users can override these in Settings → ECDHE Perfect Secrecy.
        String existingReader = prefs.getString(PKOC_Preferences.ReaderUUID, null);
        String existingSite = prefs.getString(PKOC_Preferences.SiteUUID, null);

        boolean needsSave = false;
        SharedPreferences.Editor editor = prefs.edit();

        if (existingReader == null || existingReader.isEmpty())
        {
            existingReader = PKOC_Preferences.DEFAULT_READER_UUID;
            editor.putString(PKOC_Preferences.ReaderUUID, existingReader);
            needsSave = true;
        }

        if (existingSite == null || existingSite.isEmpty())
        {
            existingSite = PKOC_Preferences.DEFAULT_SITE_UUID;
            editor.putString(PKOC_Preferences.SiteUUID, existingSite);
            needsSave = true;
        }

        if (needsSave)
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
        mBluetoothAdapter.setName("ELATEC PKOC");

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
            isoDep.setTimeout(10000); // 10 second timeout for crypto-heavy Aliro flow + harness processing

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
                textView.setText("Scan a Aliro NFC or BLE Credential");
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
            setKeypadVisibility(View.VISIBLE);
            pinDisplay.setText("");

            // Re-position the keypad over the reader image. After a credential
            // read the views have been hidden and re-shown, and on some devices
            // the original positioning may not have completed if the layout
            // listener fired before the image was measured. Without this call
            // the keypad can render at its default full-parent constraints and
            // overlap the title bar at the top of the screen.
            requestKeypadReposition();

            // Reset font in case diagnostic mode changed it to monospace
            textView.setTextSize(16);
            textView.setTypeface(android.graphics.Typeface.DEFAULT);

            isDisplayingResult = false;
        });
    }

    private void showRdrDetails()
    {
        setKeypadVisibility(View.GONE);
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
        setKeypadVisibility(View.VISIBLE);
        requestKeypadReposition();
        rdrButton.setText(R.string.show_reader_details);
        rdrButton.setOnClickListener(v -> showRdrDetails());
    }

    /**
     * Toggle keypad + reader-image visibility AND adjust the ScrollView's
     * bottom anchor in a single call. The two changes need to stay in sync:
     * when the keypad is visible the ScrollView's bottom is clamped to
     * guidelineKeypadTop (55%) so it can never overlap the keypad's first
     * row; when the keypad is hidden during a result display the ScrollView
     * stretches to the full screen so long Aliro multi-element results
     * aren't truncated. All callers should use this helper rather than
     * calling {@code keypadLayout.setVisibility()} directly.
     *
     * <p>Note: the readerImageView and keypadLayout always toggle together
     * in this fragment — every existing call site sets them to the same
     * visibility — so we handle both here.
     */
    private void setKeypadVisibility(int visibility)
    {
        if (readerImageView != null) readerImageView.setVisibility(visibility);
        if (keypadLayout != null) keypadLayout.setVisibility(visibility);
        applyScrollViewBottomConstraint();
    }

    /**
     * Update the ScrollView's bottom constraint to match the current keypad
     * visibility. Called from {@link #setKeypadVisibility(int)} and once at
     * fragment startup to apply the initial state. Idempotent — safe to call
     * even if no change is needed.
     */
    private void applyScrollViewBottomConstraint()
    {
        if (scrollViewForResultArea == null || keypadLayout == null) return;
        try
        {
            androidx.constraintlayout.widget.ConstraintLayout.LayoutParams lp =
                    (androidx.constraintlayout.widget.ConstraintLayout.LayoutParams)
                            scrollViewForResultArea.getLayoutParams();
            if (keypadLayout.getVisibility() == View.VISIBLE)
            {
                // Clamp ScrollView bottom to the keypad-top guideline so the
                // protocol toggle + buttons cannot bleed into the keypad.
                lp.bottomToTop    = R.id.guidelineKeypadTop;
                lp.bottomToBottom = androidx.constraintlayout.widget.ConstraintLayout
                        .LayoutParams.UNSET;
            }
            else
            {
                // Keypad hidden — ScrollView gets the full screen height for
                // long result text (Aliro multi-element verification, public
                // key bit-length breakdown, etc.).
                lp.bottomToTop    = androidx.constraintlayout.widget.ConstraintLayout
                        .LayoutParams.UNSET;
                lp.bottomToBottom = androidx.constraintlayout.widget.ConstraintLayout
                        .LayoutParams.PARENT_ID;
            }
            scrollViewForResultArea.setLayoutParams(lp);
        }
        catch (ClassCastException e)
        {
            // Layout file changed and ScrollView is no longer in a
            // ConstraintLayout — ignore, the fixed XML constraints will apply.
            Log.w(TAG, "applyScrollViewBottomConstraint: " + e.getMessage());
        }
    }

    /**
     * Position the keypad overlay to align with the reader image.
     * Computes absolute top/bottom margins from the image's measured
     * dimensions so the keypad sits over the physical keypad area of
     * the reader graphic.  Safe to call multiple times — skips the
     * work when the image has not been laid out yet (height == 0).
     */
    private boolean positionKeypad(View readerImage, View rootView) {
        if (readerImage == null || keypadLayout == null || rootView == null) return false;

        int imageTop = readerImage.getTop();
        int imageHeight = readerImage.getHeight();
        int screenHeight = rootView.getHeight();

        // Guard: if layout hasn't happened yet, don't set bogus margins.
        // Returning false signals to the caller (the OnGlobalLayoutListener)
        // that it should NOT remove itself yet — we need another layout pass.
        // Without this, a layout pass that fires before the image is measured
        // would silently fail and leave the keypad at its default constraints
        // (full-parent), causing it to overlap the title bar after the user
        // returns from a credential read.
        if (imageHeight == 0 || screenHeight == 0) return false;

        // Stronger guard: also reject INTERMEDIATE measurement passes where
        // readerImageView reports a partial height because the FragmentContainer
        // is still expanding to fill its parent. After returning from Aliro
        // Config, the global-layout listener fires multiple times — the first
        // few passes report imageHeight ≈ 56% of final (e.g. 967 instead of
        // 1735 on Samsung S10). Anchoring the keypad to those stale dimensions
        // pulls its top up by ~318px, overlapping the radio buttons. The image
        // is constrained top=parent / bottom=parent so its final height equals
        // screenHeight; require the measured value to be within 5% of that
        // before trusting it.
        if (imageHeight < screenHeight - (screenHeight / 20)) return false;

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
        return true;
    }

    /**
     * Re-trigger keypad positioning. Use whenever the keypad/image visibility
     * has just changed back to VISIBLE — for example, after a credential read
     * completes and the result UI clears. Schedules a fresh positioning attempt
     * once the next layout pass finishes, so even if the original positioning
     * silently failed (e.g. listener fired before measurement was complete),
     * we get another chance.
     *
     * Without this, the keypad can render at its default constraints
     * (parent-top to parent-bottom) and overlap the title bar.
     */
    private void requestKeypadReposition() {
        final View root = getView();
        if (readerImageView == null || root == null) return;
        readerImageView.getViewTreeObserver().addOnGlobalLayoutListener(
                new android.view.ViewTreeObserver.OnGlobalLayoutListener() {
                    @Override
                    public void onGlobalLayout() {
                        if (positionKeypad(readerImageView, root)) {
                            readerImageView.getViewTreeObserver()
                                    .removeOnGlobalLayoutListener(this);
                        }
                    }
                });
        // Also poke the view tree so the listener fires promptly even if
        // nothing else is requesting layout.
        readerImageView.requestLayout();
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
            deviceModel.counter = 1; // Per PKOC v3.1.1 spec §7.2.4: counter starts at 1
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
                // PKOC v3.1.1 Protocol Identifiers: spec version 0x01, vendor 0x0000, features 0x0001 (CCM)
                byte[] version = new byte[]
                        {
                                (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
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
                                // PKOC v3.1.1: spec version 0x01, vendor 0x0000, features 0x0001 (CCM)
                                deviceModel.protocolVersion = new byte[]
                                        {
                                                (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01
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
                        setKeypadVisibility(View.GONE);

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

                    // PKOC v3.1.1 §7.2.5 Step 9: Discard ephemeral keys and Z_AB
                    // after transaction to ensure Perfect Forward Secrecy.
                    deviceModel.transientKeyPair = null;
                    deviceModel.sharedSecret = null;
                    deviceModel.receivedTransientPublicKey = null;
                    Log.d(TAG, "Ephemeral keys and shared secret discarded (PFS)");

                    boolean finalSigValid = sigValid;
                    new Handler(Looper.getMainLooper()).post(() ->
                    {
                        setKeypadVisibility(View.GONE);

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
                        setKeypadVisibility(View.GONE);
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
     * Perform a LEAF NFC transaction supporting both HCE (ISO 7816-4) and
     * real MIFARE DUOX (DESFire wrapped) cards.
     *
     * Auto-detection logic:
     *   1. Try DESFire SELECT APP (CLA=0x90, INS=0x5A, AID=D6 1C F5).
     *      If the response ends with 91 00 or 90 00 → DUOX path.
     *   2. If DESFire fails, try the ISO 7816-4 path:
     *      SELECT AID (00 A4 04) → SELECT EF → READ BINARY.
     *      If both EF candidates fail → run diagnostic probes.
     *
     * Both paths produce a certDER byte[]. Steps 3-5 (cert verify,
     * INTERNAL AUTHENTICATE, sig verify) are then common to both paths,
     * with slight differences in challenge size and TLV format for DUOX.
     *
     * @param isoDep  Connected IsoDep tag
     * @return true if LEAF credential was detected and processed
     *         (even if cert or sig verification fails),
     *         false if the tag did not respond to any LEAF SELECT
     */
    private boolean performLeafNfcTransaction(android.nfc.tech.IsoDep isoDep)
    {
        try
        {
            // ==================================================================
            // AUTO-DETECTION: Try DESFire SELECT APP first (DUOX cards)
            // ==================================================================
            byte[] desfireSelect = new byte[] {
                (byte)0x90, 0x5A, 0x00, 0x00, 0x03,
                DESFIRE_LEAF_AID[0], DESFIRE_LEAF_AID[1], DESFIRE_LEAF_AID[2],
                0x00
            };
            Log.d(TAG, "LEAF DESFIRE SELECT APP: " + Hex.toHexString(desfireSelect));
            byte[] desfireSelectResp = isoDep.transceive(desfireSelect);
            Log.d(TAG, "LEAF DESFIRE SELECT APP response: " + Hex.toHexString(desfireSelectResp));

            boolean isDuox = isDesfireSuccess(desfireSelectResp);
            Log.d(TAG, "LEAF: card type detection — isDuox=" + isDuox);

            // certDER will be populated by whichever path succeeds
            byte[] certDER = null;

            if (isDuox)
            {
                // ==============================================================
                // DUOX PATH: DESFire wrapped READ DATA from file 02
                // ==============================================================
                Log.d(TAG, "LEAF: DUOX path selected — reading certificate via DESFire READ DATA");
                certDER = readDuoxCertificate(isoDep);
                if (certDER == null)
                {
                    showLeafError("LEAF DUOX: failed to read certificate from file 2.");
                    return true;
                }
            }
            else
            {
                // ==============================================================
                // ISO 7816-4 PATH: SELECT LEAF Open App AID, then SELECT EF,
                // then READ BINARY
                // ==============================================================
                Log.d(TAG, "LEAF: ISO 7816-4 path selected — DESFire SELECT APP response was: "
                        + (desfireSelectResp != null ? Hex.toHexString(desfireSelectResp) : "null"));

                // Step 1: SELECT LEAF Open App AID
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
                    return false;  // not a LEAF credential at all
                }

                // Step 2: SELECT certificate EF
                // Try DUOX file ID (E103) first, then fallback to 0001.
                // If both fail, run diagnostic probes.
                byte[][] efCandidates = {
                        LeafVerifiedManager.LEAF_CERT_FILE_ID,
                        LeafVerifiedManager.LEAF_CERT_FILE_ID_ALT
                };
                byte[] selectEFResp = null;
                byte[] usedFileId = null;
                for (byte[] fid : efCandidates)
                {
                    byte[] selectEF = { 0x00, (byte)0xA4, 0x02, 0x00, 0x02, fid[0], fid[1] };
                    Log.d(TAG, "LEAF SELECT EF: " + Hex.toHexString(selectEF));
                    selectEFResp = isoDep.transceive(selectEF);
                    Log.d(TAG, "LEAF SELECT EF response: " + Hex.toHexString(selectEFResp));
                    if (isSW9000(selectEFResp))
                    {
                        usedFileId = fid;
                        Log.d(TAG, "LEAF: EF " + Hex.toHexString(fid) + " selected successfully");
                        break;
                    }
                    Log.d(TAG, "LEAF: EF " + Hex.toHexString(fid) + " failed ("
                            + swHex(selectEFResp) + "), trying next...");
                }

                if (usedFileId == null)
                {
                    Log.w(TAG, "LEAF: SELECT EF failed (" + swHex(selectEFResp)
                            + ") — running diagnostic probes...");

                    // === DIAGNOSTIC: Probe the card's file structure ===
                    StringBuilder diag = new StringBuilder();
                    diag.append("LEAF Verified Diagnostic Report\n");
                    diag.append("================================\n\n");
                    diag.append("DESFire SELECT APP: FAILED (not DUOX)\n");
                    diag.append("ISO AID SELECT: OK (" + Hex.toHexString(selectResp) + ")\n");
                    diag.append("SELECT EF (all candidates): FAILED (" + swHex(selectEFResp) + ")\n\n");

                    // Probe 1: DESFire GetFileIDs (native cmd 0x6F, wrapped)
                    diag.append("--- Probe 1: DESFire GetFileIDs (90 6F 00 00 00) ---\n");
                    try
                    {
                        byte[] getFileIDs = { (byte)0x90, 0x6F, 0x00, 0x00, 0x00 };
                        byte[] fileIDsResp = isoDep.transceive(getFileIDs);
                        String fileIDsHex = Hex.toHexString(fileIDsResp);
                        diag.append("Response: ").append(fileIDsHex).append("\n");
                        Log.d(TAG, "LEAF DIAG GetFileIDs: " + fileIDsHex);
                        if (fileIDsResp.length > 2)
                        {
                            diag.append("File numbers: ");
                            for (int i = 0; i < fileIDsResp.length - 2; i++)
                                diag.append(String.format("0x%02X ", fileIDsResp[i]));
                            diag.append("\n");
                        }
                    }
                    catch (Exception e)
                    {
                        diag.append("Error: ").append(e.getMessage()).append("\n");
                        Log.w(TAG, "LEAF DIAG GetFileIDs failed", e);
                    }

                    // Probe 2: DESFire GetISOFileIDs (native cmd 0x61, wrapped)
                    diag.append("\n--- Probe 2: DESFire GetISOFileIDs (90 61 00 00 00) ---\n");
                    try
                    {
                        byte[] getISOFileIDs = { (byte)0x90, 0x61, 0x00, 0x00, 0x00 };
                        byte[] isoFileIDsResp = isoDep.transceive(getISOFileIDs);
                        String isoFileIDsHex = Hex.toHexString(isoFileIDsResp);
                        diag.append("Response: ").append(isoFileIDsHex).append("\n");
                        Log.d(TAG, "LEAF DIAG GetISOFileIDs: " + isoFileIDsHex);
                        if (isoFileIDsResp.length > 2)
                        {
                            diag.append("ISO File IDs: ");
                            for (int i = 0; i < isoFileIDsResp.length - 2; i += 2)
                            {
                                if (i + 1 < isoFileIDsResp.length - 2)
                                    diag.append(String.format("0x%02X%02X ",
                                            isoFileIDsResp[i], isoFileIDsResp[i + 1]));
                            }
                            diag.append("\n");
                        }
                    }
                    catch (Exception e)
                    {
                        diag.append("Error: ").append(e.getMessage()).append("\n");
                        Log.w(TAG, "LEAF DIAG GetISOFileIDs failed", e);
                    }

                    // Probe 3: DESFire GetFileSettings for file 0 (native cmd 0xF5, wrapped)
                    diag.append("\n--- Probe 3: DESFire GetFileSettings file 0 (90 F5 00 00 01 00 00) ---\n");
                    try
                    {
                        byte[] getSettings = { (byte)0x90, (byte)0xF5, 0x00, 0x00, 0x01, 0x00, 0x00 };
                        byte[] settingsResp = isoDep.transceive(getSettings);
                        String settingsHex = Hex.toHexString(settingsResp);
                        diag.append("Response: ").append(settingsHex).append("\n");
                        Log.d(TAG, "LEAF DIAG GetFileSettings(0): " + settingsHex);
                        if (settingsResp.length > 2
                                && settingsResp[settingsResp.length - 2] == (byte)0x91
                                && settingsResp[settingsResp.length - 1] == 0x00)
                        {
                            diag.append("File type: ").append(String.format("0x%02X", settingsResp[0]));
                            if (settingsResp[0] == 0x00) diag.append(" (Standard Data File)");
                            else if (settingsResp[0] == 0x01) diag.append(" (Backup Data File)");
                            diag.append("\n");
                            if (settingsResp.length >= 7)
                            {
                                int fileSize = (settingsResp[4] & 0xFF)
                                        | ((settingsResp[5] & 0xFF) << 8)
                                        | ((settingsResp[6] & 0xFF) << 16);
                                diag.append("File size: ").append(fileSize).append(" bytes\n");
                            }
                        }
                    }
                    catch (Exception e)
                    {
                        diag.append("Error: ").append(e.getMessage()).append("\n");
                        Log.w(TAG, "LEAF DIAG GetFileSettings failed", e);
                    }

                    // Probe 4: Try common EF IDs via ISO SELECT
                    diag.append("\n--- Probe 4: ISO SELECT EF scan ---\n");
                    int[][] diagEfCandidates = {
                        {0x00, 0x01}, {0x00, 0x02}, {0x00, 0x03},
                        {0x01, 0x00}, {0x01, 0x01}, {0x01, 0x02},
                        {0x02, 0x00}, {0x02, 0x01},
                        {0xE1, 0x01}, {0xE1, 0x02}, {0xE1, 0x03}, {0xE1, 0x04},
                        {0x3F, 0x00}, {0x3F, 0x01},
                        {0x00, 0x00},
                    };
                    for (int[] ef : diagEfCandidates)
                    {
                        try
                        {
                            byte[] tryEF = { 0x00, (byte)0xA4, 0x02, 0x00, 0x02,
                                    (byte)ef[0], (byte)ef[1] };
                            byte[] tryResp = isoDep.transceive(tryEF);
                            String efHex = String.format("%02X%02X", ef[0], ef[1]);
                            String respHex = Hex.toHexString(tryResp);
                            String sw = swHex(tryResp);
                            if (isSW9000(tryResp) || tryResp.length > 2)
                            {
                                diag.append("  EF ").append(efHex).append(": \u2705 ").append(sw);
                                if (tryResp.length > 2)
                                    diag.append(" FCI=").append(respHex);
                                diag.append("\n");
                                Log.d(TAG, "LEAF DIAG EF " + efHex + ": FOUND — " + respHex);
                            }
                            else
                            {
                                Log.d(TAG, "LEAF DIAG EF " + efHex + ": " + sw);
                            }
                        }
                        catch (Exception e)
                        {
                            Log.w(TAG, "LEAF DIAG EF scan exception", e);
                        }
                    }

                    // Probe 5: Try READ BINARY with short EF IDs (P1 bit 7 set)
                    diag.append("\n--- Probe 5: READ BINARY with short EF IDs ---\n");
                    for (int shortEF = 1; shortEF <= 5; shortEF++)
                    {
                        try
                        {
                            // P1 = 0x80 | (shortEF & 0x1F), P2 = 0x00, Le = 0x04
                            byte p1diag = (byte)(0x80 | (shortEF & 0x1F));
                            byte[] readCmd = { 0x00, (byte)0xB0, p1diag, 0x00, 0x04 };
                            byte[] readResp = isoDep.transceive(readCmd);
                            String sw = swHex(readResp);
                            if (readResp.length > 2)
                            {
                                diag.append("  Short EF ").append(shortEF)
                                        .append(": \u2705 ").append(sw)
                                        .append(" data=").append(Hex.toHexString(readResp))
                                        .append("\n");
                                Log.d(TAG, "LEAF DIAG ShortEF " + shortEF + ": "
                                        + Hex.toHexString(readResp));
                            }
                        }
                        catch (Exception e)
                        {
                            Log.w(TAG, "LEAF DIAG ShortEF scan exception", e);
                        }
                    }

                    // Probe 6: GET DATA for FCI template
                    diag.append("\n--- Probe 6: GET DATA (00 CA 00 6E) ---\n");
                    try
                    {
                        byte[] getData = { 0x00, (byte)0xCA, 0x00, 0x6E, 0x00 };
                        byte[] gdResp = isoDep.transceive(getData);
                        diag.append("Response: ").append(Hex.toHexString(gdResp)).append("\n");
                        Log.d(TAG, "LEAF DIAG GET DATA 006E: " + Hex.toHexString(gdResp));
                    }
                    catch (Exception e)
                    {
                        diag.append("Error: ").append(e.getMessage()).append("\n");
                    }

                    String diagReport = diag.toString();
                    Log.i(TAG, "\n" + diagReport);

                    // Display diagnostic on screen
                    final String finalDiag = diagReport;
                    requireActivity().runOnUiThread(() ->
                    {
                        if (!isAdded()) return;
                        setKeypadVisibility(View.GONE);
                        requireView().findViewById(R.id.protocolModeGroup).setVisibility(View.GONE);

                        Button rdrBtn = requireView().findViewById(R.id.rdrButton);
                        rdrBtn.setVisibility(View.GONE);

                        textView.setText(finalDiag);
                        textView.setTextSize(11);
                        textView.setTypeface(android.graphics.Typeface.MONOSPACE);

                        readerLocationUUIDView.setVisibility(View.GONE);
                        readerSiteUUIDView.setVisibility(View.GONE);
                        sitePublicKeyView.setVisibility(View.GONE);
                        nfcAdvertisingStatusView.setVisibility(View.GONE);
                        bleAdvertisingStatusView.setVisibility(View.GONE);

                        Button scanButton = requireView().findViewById(R.id.scanButton);
                        scanButton.setVisibility(View.VISIBLE);
                        scanButton.setOnClickListener(v -> resetToScanScreen());

                        Button emailButton = requireView().findViewById(R.id.emailButton);
                        emailButton.setVisibility(View.VISIBLE);
                        emailButton.setOnClickListener(v -> sendEmail());

                        isDisplayingResult = true;
                    });

                    return true;
                } // end if (usedFileId == null)

                // ------------------------------------------------------------------
                // Step 3 (ISO path): READ BINARY in 224-byte chunks
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
                        // End of file reached
                        Log.d(TAG, "LEAF READ BINARY: end of file at offset=" + offset);
                        done = true;
                    }
                    else
                    {
                        Log.e(TAG, "LEAF READ BINARY: unexpected SW "
                                + String.format("%02X%02X", sw1, sw2));
                        showLeafError("LEAF READ BINARY failed: "
                                + String.format("%02X%02X", sw1, sw2));
                        return true;
                    }
                }

                certDER = certAcc.toByteArray();
                Log.d(TAG, "LEAF: ISO certificate read complete, " + certDER.length + " bytes");

                if (certDER.length == 0)
                {
                    showLeafError("LEAF: empty certificate received from ISO path.");
                    return true;
                }
            } // end else (ISO 7816-4 path)

            // ==================================================================
            // COMMON STEPS 3-9: Both DUOX and ISO paths converge here.
            // certDER is now populated by whichever path ran above.
            // ==================================================================

            // ------------------------------------------------------------------
            // Step 3: Verify certificate against Root CA public key
            // Try the reader-configured Root CA first; if absent or invalid,
            // also try the built-in production LEAF Root CA.
            // ------------------------------------------------------------------
            byte[] rootCAPub = LeafVerifiedManager.getReaderRootCAPubKey(requireContext());
            boolean certVerified = false;
            String certVerifyMsg;

            if (rootCAPub != null)
            {
                certVerified = LeafVerifiedManager.verifyCertificate(certDER, rootCAPub);
                Log.d(TAG, "LEAF: cert verify against reader Root CA=" + certVerified);
            }

            // If not verified yet, try the built-in production LEAF Root CA
            // (covers real DUOX cards even when no custom Root CA is configured)
            if (!certVerified)
            {
                byte[] prodRootCAPub = LeafVerifiedManager.getProductionRootCAPubKey();
                if (prodRootCAPub != null)
                {
                    certVerified = LeafVerifiedManager.verifyCertificate(certDER, prodRootCAPub);
                    Log.d(TAG, "LEAF: cert verify against production Root CA=" + certVerified);
                    if (certVerified)
                        rootCAPub = prodRootCAPub; // remember which key worked
                }
            }

            if (rootCAPub == null && !certVerified)
            {
                Log.e(TAG, "LEAF: no Root CA public key configured — aborting");
                showLeafError("LEAF: Root CA not configured. Import via LEAF Config.");
                return true;
            }

            certVerifyMsg = certVerified ? "Verified \u2713" : "FAILED \u2717";
            Log.d(TAG, "LEAF: cert verification result=" + certVerified);

            if (!certVerified)
            {
                Log.e(TAG, "LEAF: certificate failed Root CA verification — aborting");
                showLeafError("LEAF: certificate verification failed.");
                return true;
            }

            // Step 3b: Extract credential public key and Open ID from cert
            byte[] credPubKey = LeafVerifiedManager.extractPublicKeyFromCert(certDER);
            String openId     = LeafVerifiedManager.extractOpenIDFromCert(certDER);

            if (credPubKey == null)
            {
                showLeafError("LEAF: failed to extract credential public key from cert.");
                return true;
            }

            // Validate Open ID is present and numeric
            if (openId == null || openId.isEmpty())
            {
                showLeafError("LEAF: Open ID not found in certificate.");
                return true;
            }
            Log.d(TAG, "LEAF Open ID: " + openId + " (" + openId.length() + " chars)");

            // ------------------------------------------------------------------
            // Step 4: INTERNAL AUTHENTICATE (ISO 7816-4, INS=0x88)
            //
            // DUOX cards use a TLV-wrapped command with a 16-byte challenge:
            //   00 88 00 00 <Lc> 80 00 7C 12 81 10 <16-byte challenge> 00
            //   where Lc = 2 (OptsA) + 2 (7C tag+len) + 2 (81 tag+len) + 16 = 22 = 0x16
            //
            // HCE cards use a raw command with a 32-byte challenge:
            //   00 88 00 00 20 <32-byte challenge>
            //
            // Response TLV for DUOX:
            //   7C <len> 81 10 <card_random 16 bytes> 82 40 <signature_rs 64 bytes>
            // Response for HCE: raw DER-encoded ECDSA signature || 90 00
            // ------------------------------------------------------------------
            boolean sigVerified;

            if (isDuox)
            {
                // DUOX: 16-byte challenge, TLV-wrapped INTERNAL AUTHENTICATE
                byte[] challenge16 = new byte[16];
                new java.security.SecureRandom().nextBytes(challenge16);
                Log.d(TAG, "LEAF DUOX challenge: " + Hex.toHexString(challenge16));

                // Build TLV command body:
                //   80 00           — OptsA TLV (tag 80, length 00, no value)
                //   7C 12           — Data Object tag 7C, length 0x12 = 18
                //   81 10 <16bytes> — Challenge TLV (tag 81, length 16, challenge)
                // Lc = 2 + 2 + 2 + 16 = 22 = 0x16
                // Full APDU: 00 88 00 00 16 80 00 7C 12 81 10 <16 bytes> 00
                byte[] authCmd = new byte[6 + 22]; // header(5) + body(22) + Le(1)
                authCmd[0] = 0x00;          // CLA
                authCmd[1] = (byte)0x88;    // INS = INTERNAL AUTHENTICATE
                authCmd[2] = 0x00;          // P1
                authCmd[3] = 0x00;          // P2
                authCmd[4] = 0x16;          // Lc = 22 bytes of data
                authCmd[5] = (byte)0x80;    // OptsA tag
                authCmd[6] = 0x00;          // OptsA length (0)
                authCmd[7] = 0x7C;          // Dynamic Auth Data tag
                authCmd[8] = 0x12;          // Dynamic Auth Data length (18 = 2 + 16)
                authCmd[9] = (byte)0x81;    // Challenge tag
                authCmd[10] = 0x10;         // Challenge length (16)
                System.arraycopy(challenge16, 0, authCmd, 11, 16);
                authCmd[27] = 0x00;         // Le

                Log.d(TAG, "LEAF DUOX INTERNAL AUTHENTICATE: " + Hex.toHexString(authCmd));
                byte[] authResp = isoDep.transceive(authCmd);
                Log.d(TAG, "LEAF DUOX INTERNAL AUTHENTICATE response: " + Hex.toHexString(authResp));

                if (!isSW9000(authResp) || authResp.length < 4)
                {
                    showLeafError("LEAF DUOX INTERNAL AUTHENTICATE failed: " + swHex(authResp));
                    return true;
                }

                // Parse response TLV:
                //   7C <len> 81 10 <cardRandom 16> 82 40 <sigRS 64>
                // Response data is everything before the trailing 90 00
                byte[] respData = java.util.Arrays.copyOfRange(authResp, 0, authResp.length - 2);
                Log.d(TAG, "LEAF DUOX auth response data: " + Hex.toHexString(respData));

                byte[] cardRandom16 = parseDuoxTlvTag(respData, (byte)0x81, 16);
                byte[] sigRS64      = parseDuoxTlvTag(respData, (byte)0x82, 64);

                if (cardRandom16 == null || sigRS64 == null)
                {
                    showLeafError("LEAF DUOX: failed to parse TLV response from INTERNAL AUTHENTICATE.");
                    return true;
                }

                Log.d(TAG, "LEAF DUOX cardRandom: " + Hex.toHexString(cardRandom16));
                Log.d(TAG, "LEAF DUOX sigRS64: " + Hex.toHexString(sigRS64));

                // Verify DUOX signature: msg = F0F0 || OptsA(80 00) || RndB(16) || RndA(16)
                sigVerified = LeafVerifiedManager.verifyDuoxSignature(
                        cardRandom16, challenge16, sigRS64, credPubKey);
                Log.d(TAG, "LEAF DUOX: sig verify=" + sigVerified);
            }
            else
            {
                // HCE (ISO 7816-4): 32-byte challenge, raw INTERNAL AUTHENTICATE
                byte[] challenge32 = new byte[32];
                new java.security.SecureRandom().nextBytes(challenge32);
                Log.d(TAG, "LEAF HCE challenge: " + Hex.toHexString(challenge32));

                byte[] authCmd = new byte[5 + challenge32.length];
                authCmd[0] = 0x00;            // CLA
                authCmd[1] = (byte)0x88;      // INS = INTERNAL AUTHENTICATE
                authCmd[2] = 0x00;            // P1
                authCmd[3] = 0x00;            // P2
                authCmd[4] = (byte)challenge32.length; // Lc
                System.arraycopy(challenge32, 0, authCmd, 5, challenge32.length);

                Log.d(TAG, "LEAF HCE INTERNAL AUTHENTICATE: " + Hex.toHexString(authCmd));
                byte[] authResp = isoDep.transceive(authCmd);
                Log.d(TAG, "LEAF HCE INTERNAL AUTHENTICATE response: " + Hex.toHexString(authResp));

                if (!isSW9000(authResp) || authResp.length < 4)
                {
                    showLeafError("LEAF INTERNAL AUTHENTICATE failed: " + swHex(authResp));
                    return true;
                }

                // DER signature is everything before the trailing 90 00
                byte[] sigDER = java.util.Arrays.copyOfRange(authResp, 0, authResp.length - 2);

                // Verify ECDSA signature against credential's public key (challenge is the message)
                sigVerified = LeafVerifiedManager.verifyChallenge(challenge32, sigDER, credPubKey);
                Log.d(TAG, "LEAF HCE: sig verify=" + sigVerified);
            }

            // ------------------------------------------------------------------
            // Step 5: Build display string and show result on UI thread
            // ------------------------------------------------------------------
            final String finalOpenId       = openId;
            final boolean finalCertVerified = certVerified;
            final boolean finalSigVerified  = sigVerified;
            final String finalCertMsg       = certVerifyMsg;
            final String finalPubKeyHex     = Hex.toHexString(credPubKey).toUpperCase();
            final boolean finalIsDuox       = isDuox;

            requireActivity().runOnUiThread(() ->
            {
                if (!isAdded()) return;
                setKeypadVisibility(View.GONE);

                // Build the connectionType string in the same style as Aliro results.
                // The first line becomes the bold title; section headers are ALL-CAPS.
                StringBuilder sb = new StringBuilder();
                // Compute 40-bit Wiegand output per LEAF spec
                String wiegandDisplay = LeafVerifiedManager.formatWiegand40Display(finalOpenId);

                String cardType = finalIsDuox ? "MIFARE DUOX" : "HCE";
                sb.append("LEAF NFC \u2014 Open ID ").append(finalSigVerified ? "Verified" : "FAILED");
                sb.append("\n\nOPEN ID APPLICATION\n");
                sb.append("  ID:             ").append(finalOpenId).append("\n");
                sb.append("  Card type:      ").append(cardType).append("\n");
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

    /**
     * Check whether a DESFire APDU response indicates success.
     * DESFire wrapped commands return SW 91 00 (or 90 00 in some implementations).
     * An optional single 0x00 data byte may precede the status bytes.
     *
     * @param resp raw response bytes from isoDep.transceive()
     * @return true if the response signals success
     */
    private boolean isDesfireSuccess(byte[] resp)
    {
        if (resp == null || resp.length < 2) return false;
        byte sw1 = resp[resp.length - 2];
        byte sw2 = resp[resp.length - 1];
        return (sw1 == (byte)0x91 && sw2 == 0x00)
                || (sw1 == (byte)0x90 && sw2 == 0x00);
    }

    /**
     * Read the LEAF certificate from a MIFARE DUOX card using DESFire wrapped
     * READ DATA commands (CLA=0x90, INS=0xAD) from file number 0x02.
     *
     * Protocol:
     *  a) First read 8 bytes to obtain the DER header and calculate total cert length.
     *  b) Read remaining bytes in 59-byte chunks (fits within 64-byte NFC frame).
     *  c) If any response returns SW 91 AF, send GET ADDITIONAL FRAME (90 AF 00 00 00)
     *     to continue reading. Repeat until SW is 91 00 or 90 00.
     *
     * @param isoDep connected IsoDep tag; DESFire application already selected
     * @return DER-encoded certificate bytes, or null on error
     */
    private byte[] readDuoxCertificate(android.nfc.tech.IsoDep isoDep)
    {
        try
        {
            final byte FILE_NO = 0x02;  // LEAF certificate is stored in DESFire file 2

            // Step a: Read first 8 bytes to get DER header (tag + length)
            // This lets us determine the total certificate length before reading all data.
            byte[] header = readDuoxFileChunk(isoDep, FILE_NO, 0, 8);
            if (header == null)
            {
                Log.e(TAG, "readDuoxCertificate: failed to read DER header");
                return null;
            }
            Log.d(TAG, "LEAF DUOX: DER header bytes: " + Hex.toHexString(header));

            // Parse DER length from header to find total certificate size
            int totalLength = parseDerTotalLength(header);
            if (totalLength <= 0)
            {
                Log.e(TAG, "readDuoxCertificate: could not parse DER length from header");
                return null;
            }
            Log.d(TAG, "LEAF DUOX: DER total length=" + totalLength);

            // Step b: Read the full certificate starting from offset 0
            // Read in chunks; handle GET ADDITIONAL FRAME (91 AF) chaining.
            java.io.ByteArrayOutputStream certAcc = new java.io.ByteArrayOutputStream();
            final int CHUNK_SIZE = 59; // safe chunk size for NFC frames
            int offset = 0;

            while (certAcc.size() < totalLength)
            {
                int remaining = totalLength - certAcc.size();
                int toRead = Math.min(remaining, CHUNK_SIZE);

                // Build DESFire READ DATA APDU:
                // 90 AD 00 00 07 <fileNo> <offset 3 LE> <length 3 LE> 00
                byte[] readCmd = buildDuoxReadDataCmd(FILE_NO, offset, toRead);
                Log.d(TAG, "LEAF DUOX READ DATA: offset=" + offset
                        + " len=" + toRead + " cmd=" + Hex.toHexString(readCmd));

                byte[] resp = isoDep.transceive(readCmd);
                Log.d(TAG, "LEAF DUOX READ DATA response: " + Hex.toHexString(resp));

                if (resp == null || resp.length < 2)
                {
                    Log.e(TAG, "LEAF DUOX READ DATA: null/short response at offset=" + offset);
                    return null;
                }

                // Accumulate data (all bytes before the trailing 2 SW bytes)
                int dataLen = resp.length - 2;
                if (dataLen > 0)
                    certAcc.write(resp, 0, dataLen);

                byte respSw1 = resp[resp.length - 2];
                byte respSw2 = resp[resp.length - 1];

                if (respSw1 == (byte)0x91 && respSw2 == (byte)0xAF)
                {
                    // More data available — drain with GET ADDITIONAL FRAME
                    Log.d(TAG, "LEAF DUOX READ DATA: got 91AF, sending GET ADDITIONAL FRAME");
                    boolean moreData = true;
                    while (moreData)
                    {
                        byte[] getMoreFrame = { (byte)0x90, (byte)0xAF, 0x00, 0x00, 0x00 };
                        byte[] moreResp = isoDep.transceive(getMoreFrame);
                        Log.d(TAG, "LEAF DUOX GET ADDITIONAL FRAME: "
                                + Hex.toHexString(moreResp));
                        if (moreResp == null || moreResp.length < 2)
                        {
                            Log.e(TAG, "LEAF DUOX GET ADDITIONAL FRAME: null/short response");
                            return null;
                        }
                        int moreDataLen = moreResp.length - 2;
                        if (moreDataLen > 0)
                            certAcc.write(moreResp, 0, moreDataLen);

                        byte moreSw1 = moreResp[moreResp.length - 2];
                        byte moreSw2 = moreResp[moreResp.length - 1];
                        if ((moreSw1 == (byte)0x91 || moreSw1 == (byte)0x90) && moreSw2 == 0x00)
                        {
                            moreData = false; // done
                        }
                        else if (moreSw1 == (byte)0x91 && moreSw2 == (byte)0xAF)
                        {
                            // More frames to come — continue loop
                        }
                        else
                        {
                            Log.e(TAG, "LEAF DUOX GET ADDITIONAL FRAME: unexpected SW "
                                    + String.format("%02X%02X", moreSw1, moreSw2));
                            return null;
                        }
                    }
                    // After draining chained frames, exit the outer while loop
                    break;
                }
                else if ((respSw1 == (byte)0x91 || respSw1 == (byte)0x90) && respSw2 == 0x00)
                {
                    // This chunk was read successfully; advance offset
                    offset += dataLen;
                    // If we've accumulated enough data, stop
                    if (certAcc.size() >= totalLength)
                        break;
                }
                else
                {
                    Log.e(TAG, "LEAF DUOX READ DATA: unexpected SW "
                            + String.format("%02X%02X", respSw1, respSw2)
                            + " at offset=" + offset);
                    return null;
                }
            }

            byte[] certDER = certAcc.toByteArray();
            Log.d(TAG, "LEAF DUOX: certificate read complete, " + certDER.length + " bytes");

            if (certDER.length == 0)
            {
                Log.e(TAG, "LEAF DUOX: empty certificate");
                return null;
            }

            return certDER;
        }
        catch (Exception e)
        {
            Log.e(TAG, "readDuoxCertificate failed", e);
            return null;
        }
    }

    /**
     * Build a DESFire wrapped READ DATA APDU.
     * Format: 90 AD 00 00 07 &lt;fileNo&gt; &lt;offset 3 bytes LE&gt; &lt;length 3 bytes LE&gt; 00
     *
     * @param fileNo  DESFire file number
     * @param offset  byte offset into the file (little-endian, 3 bytes)
     * @param length  number of bytes to read (little-endian, 3 bytes)
     * @return 9-byte APDU
     */
    private byte[] buildDuoxReadDataCmd(byte fileNo, int offset, int length)
    {
        return new byte[] {
            (byte)0x90, (byte)0xAD, 0x00, 0x00, 0x07,
            fileNo,
            (byte)(offset & 0xFF),          // offset byte 0 (LSB)
            (byte)((offset >> 8) & 0xFF),   // offset byte 1
            (byte)((offset >> 16) & 0xFF),  // offset byte 2 (MSB)
            (byte)(length & 0xFF),          // length byte 0 (LSB)
            (byte)((length >> 8) & 0xFF),   // length byte 1
            (byte)((length >> 16) & 0xFF),  // length byte 2 (MSB)
            0x00                            // Le
        };
    }

    /**
     * Read a chunk of data from a DESFire file using a single READ DATA command.
     * Returns the data bytes only (SW bytes stripped), or null on error.
     *
     * @param isoDep  connected IsoDep tag
     * @param fileNo  DESFire file number
     * @param offset  byte offset into the file
     * @param length  number of bytes to read
     * @return data bytes (without SW), or null on error
     */
    private byte[] readDuoxFileChunk(
            android.nfc.tech.IsoDep isoDep, byte fileNo, int offset, int length)
    {
        try
        {
            byte[] cmd = buildDuoxReadDataCmd(fileNo, offset, length);
            byte[] resp = isoDep.transceive(cmd);
            if (resp == null || resp.length < 2) return null;
            byte sw1 = resp[resp.length - 2];
            byte sw2 = resp[resp.length - 1];
            boolean ok = (sw1 == (byte)0x91 || sw1 == (byte)0x90) && sw2 == 0x00;
            if (!ok && !(sw1 == (byte)0x91 && sw2 == (byte)0xAF)) return null;
            int dataLen = resp.length - 2;
            if (dataLen <= 0) return new byte[0];
            byte[] data = new byte[dataLen];
            System.arraycopy(resp, 0, data, 0, dataLen);
            return data;
        }
        catch (Exception e)
        {
            Log.e(TAG, "readDuoxFileChunk failed", e);
            return null;
        }
    }

    /**
     * Parse the total DER-encoded structure length from the first few bytes of a
     * DER TLV header. Handles both short-form (1-byte) and long-form (multi-byte)
     * ASN.1 length encodings.
     *
     * @param header at least 4 bytes from the start of the DER-encoded certificate
     * @return total length of the DER structure (tag + length octets + value octets),
     *         or -1 if the header is too short or malformed
     */
    private int parseDerTotalLength(byte[] header)
    {
        if (header == null || header.length < 2) return -1;
        // byte[0] is the tag (0x30 = SEQUENCE for X.509)
        // byte[1] onwards is the length
        int tagLen = 1; // skip the tag byte
        int lenByte = header[tagLen] & 0xFF;
        int valueLen;
        int headerBytes; // number of bytes consumed by tag + length
        if ((lenByte & 0x80) == 0)
        {
            // Short form: length is in this byte
            valueLen  = lenByte;
            headerBytes = 2; // 1 tag + 1 length
        }
        else
        {
            // Long form: lower 7 bits = number of subsequent length bytes
            int numLenBytes = lenByte & 0x7F;
            if (header.length < 2 + numLenBytes) return -1;
            valueLen = 0;
            for (int i = 0; i < numLenBytes; i++)
                valueLen = (valueLen << 8) | (header[2 + i] & 0xFF);
            headerBytes = 2 + numLenBytes; // 1 tag + 1 length-of-length + numLenBytes
        }
        return headerBytes + valueLen;
    }

    /**
     * Parse a TLV value from the DUOX INTERNAL AUTHENTICATE response data.
     * Searches for the given single-byte tag and returns its value bytes.
     * Tags 0x81 (card random, 16 bytes) and 0x82 (signature R||S, 64 bytes)
     * are expected inside the outer 0x7C Data Object wrapper.
     *
     * This parser strips the outer 0x7C wrapper if present before searching.
     *
     * @param data     response data (SW bytes already removed)
     * @param tag      single-byte tag to find
     * @param expected expected length of the value in bytes
     * @return value bytes of the found TLV, or null if not found / wrong length
     */
    private byte[] parseDuoxTlvTag(byte[] data, byte tag, int expected)
    {
        if (data == null || data.length < 2) return null;

        // Strip outer 0x7C wrapper if present
        byte[] inner = data;
        if (data[0] == 0x7C)
        {
            // 0x7C <len> <contents>
            int outerLenByte = data[1] & 0xFF;
            int outerHeaderBytes;
            int innerLen;
            if ((outerLenByte & 0x80) == 0)
            {
                outerHeaderBytes = 2;
                innerLen = outerLenByte;
            }
            else
            {
                int n = outerLenByte & 0x7F;
                if (data.length < 2 + n) return null;
                innerLen = 0;
                for (int i = 0; i < n; i++)
                    innerLen = (innerLen << 8) | (data[2 + i] & 0xFF);
                outerHeaderBytes = 2 + n;
            }
            if (data.length < outerHeaderBytes + innerLen) return null;
            inner = java.util.Arrays.copyOfRange(data, outerHeaderBytes,
                    outerHeaderBytes + innerLen);
        }

        // Search for the target tag in the (possibly unwrapped) contents
        int i = 0;
        while (i < inner.length - 1)
        {
            byte curTag = inner[i];
            int curLenByte = inner[i + 1] & 0xFF;
            int curHeaderBytes;
            int curLen;
            if ((curLenByte & 0x80) == 0)
            {
                curLen = curLenByte;
                curHeaderBytes = 2;
            }
            else
            {
                int n = curLenByte & 0x7F;
                if (i + 2 + n > inner.length) return null;
                curLen = 0;
                for (int j = 0; j < n; j++)
                    curLen = (curLen << 8) | (inner[i + 2 + j] & 0xFF);
                curHeaderBytes = 2 + n;
            }
            if (curTag == tag)
            {
                if (curLen != expected)
                {
                    Log.w(TAG, "parseDuoxTlvTag: tag 0x" + String.format("%02X", tag & 0xFF)
                            + " found but length=" + curLen + " expected=" + expected);
                    return null;
                }
                if (i + curHeaderBytes + curLen > inner.length) return null;
                return java.util.Arrays.copyOfRange(
                        inner, i + curHeaderBytes, i + curHeaderBytes + curLen);
            }
            i += curHeaderBytes + curLen;
        }
        Log.w(TAG, "parseDuoxTlvTag: tag 0x" + String.format("%02X", tag & 0xFF) + " not found");
        return null;
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

            // Certificate delivery mode: "none", "load_cert", or "auth1"
            String certMode = prefs.getString(AliroPreferences.CERT_DELIVERY_MODE,
                    AliroPreferences.CERT_MODE_LOAD_CERT);
            boolean hasCert = (certBytes != null && issuerKeyBytes != null);
            boolean useCert = hasCert && !AliroPreferences.CERT_MODE_NONE.equals(certMode);
            boolean certInAuth1 = hasCert && AliroPreferences.CERT_MODE_AUTH1.equals(certMode);
            boolean forceChaining = prefs.getBoolean(AliroPreferences.CERT_FORCE_CHAINING, false);
            Log.d(TAG, "Cert mode: " + certMode + " hasCert=" + hasCert
                    + " useCert=" + useCert + " certInAuth1=" + certInAuth1
                    + " forceChaining=" + forceChaining);

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

            if (selectProprietaryTLV == null)
            {
                Log.e(TAG, "Aliro SELECT response parse failed");
                sendControlFlow(isoDep);
                showAliroError("Aliro SELECT response invalid.");
                return;
            }
            if (protocolVersion == null)
            {
                Log.e(TAG, "No common Aliro protocol version — sending CONTROL FLOW S2=0x27");
                sendControlFlow(isoDep, (byte)0x27); // S2 = protocol version not supported
                showAliroError("No common protocol version with credential.");
                return;
            }
            Log.d(TAG, "Aliro protocol version: " + Hex.toHexString(protocolVersion));
            Log.d(TAG, "Aliro proprietary TLV (full): " + Hex.toHexString(selectProprietaryTLV));

            // Per §8.3.1.12 / §8.3.1.13 the salt uses "0xA5 proprietary
            // information TLV according to Table 10-2". The harness only
            // includes the core children (0x80 Type, 0x5C versions) and
            // strips transport-layer DO'7F66' (extended length) and 0xB3
            // (vendor extensions) before computing the HKDF salt.
            // Keep the full TLV for extended-length detection below, but
            // use the stripped version for all key derivation calls.
            // Use the full A5 proprietary TLV (including DO'7F66' and vendor tags)
            // for HKDF salt computation. The CSA harness uses the full TLV as received
            // in the SELECT response for its HKDF (reader.py line 2254:
            // proprietary_information=self.proprietary_tlv.to_bytes()). Both sides
            // must use the identical bytes to derive matching session keys.
            byte[] selectTLVForCrypto = selectProprietaryTLV;
            Log.d(TAG, "Aliro proprietary TLV (crypto): " + Hex.toHexString(selectTLVForCrypto));

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
            // Derive reader public key X from private key.
            // Used for both reader signature (AUTH1) and HKDF salt.
            //
            // Per Aliro §6.2, reader_group_identifier_key is the reader's own
            // public key (self-signed cert: reader key = issuer CA key).
            // The credential stores this same key, so HKDF uses the same X
            // coordinate regardless of cert or no-cert mode.
            // ------------------------------------------------------------------
            byte[] readerPubKeyX = derivePublicKeyXFromPrivate(readerPrivKeyBytes);
            if (readerPubKeyX == null)
            {
                showAliroError("Failed to derive reader public key.");
                return;
            }
            byte[] hkdfReaderPubKeyX = readerPubKeyX;
            Log.d(TAG, "HKDF reader_group_identifier_key.x: " + Hex.toHexString(hkdfReaderPubKeyX));

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
            // FAST mode detection (moved before AUTH0 to set command_parameters)
            //
            // FAST mode uses Kpersistent from a prior STANDARD transaction.
            // We use in-memory state (sessionKpersistent) so FAST only activates
            // after a STANDARD transaction in the SAME test session. Stale
            // Kpersistent from a previous test run is ignored.
            //
            // The FAST_MODE_ENABLED checkbox acts as a gate — when unchecked,
            // FAST is never used (always STANDARD). When checked, FAST will
            // activate automatically after the first STANDARD tap stores
            // Kpersistent in the session variable.
            // ------------------------------------------------------------------
            boolean fastModeEnabled = prefs.getBoolean(AliroPreferences.FAST_MODE_ENABLED, false);
            boolean useFastMode = fastModeEnabled
                    && sessionKpersistent != null
                    && sessionCredentialPubKeyX != null;
            byte cmdParams = useFastMode ? (byte)0x01 : (byte)0x00;
            Log.d(TAG, "FAST mode: enabled=" + fastModeEnabled
                    + " hasSessionKp=" + (sessionKpersistent != null)
                    + " useFastMode=" + useFastMode);

            // ------------------------------------------------------------------
            // Build and send AUTH0
            // ------------------------------------------------------------------
            byte[] auth0 = buildAuth0Command(protocolVersion, readerEphPub, transactionId, readerIdBytes, cmdParams);
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
                // Keep the NFC link alive briefly so the harness can complete
                // processing of the CONTROL FLOW before we return and the link drops.
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                showAliroError("AUTH0 response format invalid.");
                return;
            }
            byte[] udEphPub  = Arrays.copyOfRange(auth0Response, 2, 67);
            byte[] udEphPubX = Arrays.copyOfRange(udEphPub, 1, 33);
            Log.d(TAG, "UD ephemeral public key: " + Hex.toHexString(udEphPub));

            // Parse optional vendor extension TLV (tag B2) from AUTH0 response
            byte[] auth0RspVendorTLV = parseVendorExtensionTLV(auth0Response, 67);

            // ------------------------------------------------------------------
            // §8.3.3.2.8: If STANDARD was requested, reject any unexpected cryptogram
            // (tag 0x9D) in the AUTH0 response — mandatory failure condition.
            // ------------------------------------------------------------------
            if (!useFastMode)
            {
                boolean unexpectedCryptogram = false;
                int swLen0 = 2; // status word at end of response
                int pos0 = 67; // right after tag 0x86 payload
                while (pos0 + 2 <= auth0Response.length - swLen0)
                {
                    int tag0 = auth0Response[pos0] & 0xFF;
                    int len0 = auth0Response[pos0 + 1] & 0xFF;
                    if (tag0 == 0x9D)
                    {
                        unexpectedCryptogram = true;
                        break;
                    }
                    if (len0 == 0 || pos0 + 2 + len0 > auth0Response.length - swLen0) break;
                    pos0 += 2 + len0;
                }
                if (unexpectedCryptogram)
                {
                    Log.w(TAG, "STANDARD AUTH0 response contains unexpected cryptogram (0x9D) — CONTROL FLOW");
                    sendControlFlow(isoDep);
                    showAliroError("AUTH0 STANDARD response contained unexpected cryptogram.");
                    return;
                }
            }

            // ------------------------------------------------------------------
            // FAST cryptogram verification (§8.3.3.2.8)
            //
            // If we requested FAST, the AUTH0 response contains a cryptogram
            // (tag 0x9D, 64 bytes). We must verify it by deriving CryptogramSK
            // from Kpersistent and decrypting. If verification fails, the
            // Kpersistent is stale — fall back to STANDARD for this transaction.
            // ------------------------------------------------------------------
            boolean fellBackFromFast = false;
            if (useFastMode)
            {
                // Extract cryptogram (tag 0x9D, length 0x40 = 64 bytes)
                byte[] fastCryptogram = null;
                int swLen = 2; // status word at end of response
                int pos = 67;  // right after tag 0x86 payload
                while (pos + 2 < auth0Response.length - swLen)
                {
                    int tag = auth0Response[pos] & 0xFF;
                    int len = auth0Response[pos + 1] & 0xFF;
                    if (tag == 0x9D && len == 0x40 && pos + 2 + len <= auth0Response.length - swLen)
                    {
                        fastCryptogram = Arrays.copyOfRange(auth0Response, pos + 2, pos + 2 + 64);
                        break;
                    }
                    pos += 2 + len;
                }

                if (fastCryptogram == null)
                {
                    // §8.3.3.2.8: cryptogram not present while FAST was requested → failure
                    Log.w(TAG, "FAST requested but no cryptogram (0x9D) in AUTH0 response");
                    sendControlFlow(isoDep);
                    showAliroError("AUTH0 response missing FAST cryptogram.");
                    return;
                }
                Log.d(TAG, "FAST cryptogram (0x9D): " + Hex.toHexString(fastCryptogram));

                // Derive FAST keys to get CryptogramSK for verification.
                // auth0Flag must be FAST (0x01) since that's what we sent.
                byte[] fastFlag = new byte[]{ 0x01, 0x01 };
                byte[] fastKeybuf = AliroCryptoProvider.deriveFastKeys(
                        sessionKpersistent,
                        160,  // CryptogramSK(32) + SKReader(32) + SKDevice(32) + BleSK(32) + StepUpSK(32)
                        protocolVersion,
                        hkdfReaderPubKeyX,
                        readerIdBytes,
                        transactionId,
                        readerEphPubX,
                        udEphPubX,
                        sessionCredentialPubKeyX,
                        selectTLVForCrypto,
                        null,                                    // auth0CmdVendorTLV
                        auth0RspVendorTLV,
                        AliroCryptoProvider.INTERFACE_BYTE_NFC,
                        fastFlag);

                boolean fastVerified = false;
                if (fastKeybuf != null)
                {
                    // CryptogramSK = first 32 bytes of FAST key material
                    byte[] cryptogramSK = Arrays.copyOfRange(fastKeybuf, 0, 32);
                    // §8.3.1.11: decrypt cryptogram to verify authentication_tag
                    byte[] cryptogramPlain = AliroCryptoProvider.decryptCryptogram(
                            cryptogramSK, fastCryptogram);
                    fastVerified = (cryptogramPlain != null);
                    Log.d(TAG, "FAST cryptogram verification: " + (fastVerified ? "SUCCESS" : "FAILED"));
                }
                else
                {
                    Log.w(TAG, "FAST key derivation failed — cannot verify cryptogram");
                }

                if (!fastVerified)
                {
                    // Kpersistent is stale or doesn't match this session.
                    // Fall back to STANDARD for this transaction.
                    // This works when the harness has no Kpersistent (random
                    // cryptogram → STD keys on both sides). If the harness
                    // DID have Kpersistent, it committed to FAST keys and
                    // the AUTH1 decryption will fail — the failure EXCHANGE
                    // handler will deal with that case.
                    Log.w(TAG, "FAST cryptogram verification failed — falling back to STANDARD");
                    useFastMode = false;
                    fellBackFromFast = true;
                    sessionKpersistent = null;
                    sessionCredentialPubKeyX = null;
                }
                else
                {
                    Log.d(TAG, "FAST cryptogram verified — proceeding with FAST mode");
                }
            }

            // ------------------------------------------------------------------
            // Compute reader signature and derive session keys.
            // useFastMode may have been cleared above if cryptogram failed.
            // ------------------------------------------------------------------
            byte[] readerSig = AliroCryptoProvider.computeReaderSignature(
                    readerPrivKey, readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            if (readerSig == null)
            {
                showAliroError("Failed to compute reader signature.");
                return;
            }

            // flag = command_parameters || authentication_policy per Table 8-4
            // Note: auth0Flag reflects what was SENT in AUTH0 (0x01 if FAST was
            // originally requested), not the current useFastMode. The flag is
            // used in key derivation salt, which must match what both sides used.
            byte[] auth0Flag = cmdParams == (byte)0x01
                    ? new byte[]{ 0x01, 0x01 }   // FAST was requested
                    : new byte[]{ 0x00, 0x01 };  // STANDARD was requested

            byte[] skReader;
            byte[] skDevice;
            byte[] stepUpSK;
            byte[] credentialPubKeyX = null; // populated during STANDARD AUTH1

            if (useFastMode)
            {
                // -------------------------------------------------------
                // FAST key derivation: use Kpersistent, no ECDH
                // Keys already derived above during verification; re-derive
                // to get the session keys (or reuse fastKeybuf — but it's
                // out of scope, so re-derive cleanly).
                // -------------------------------------------------------
                credentialPubKeyX = sessionCredentialPubKeyX;

                byte[] fastKeybuf = AliroCryptoProvider.deriveFastKeys(
                        sessionKpersistent,
                        160,
                        protocolVersion,
                        hkdfReaderPubKeyX,
                        readerIdBytes,
                        transactionId,
                        readerEphPubX,
                        udEphPubX,
                        credentialPubKeyX,
                        selectTLVForCrypto,
                        null,                                    // auth0CmdVendorTLV
                        auth0RspVendorTLV,
                        AliroCryptoProvider.INTERFACE_BYTE_NFC,
                        auth0Flag);

                if (fastKeybuf == null)
                {
                    showAliroError("FAST key derivation failed.");
                    return;
                }
                // FAST output layout (§8.3.1.12):
                //   [0..31]   CryptogramSK (used for AUTH0 response cryptogram)
                //   [32..63]  ExpeditedSKReader
                //   [64..95]  ExpeditedSKDevice
                //   [96..127] BleSK (Bluetooth LE only — not used on NFC)
                //   [128..159] StepUpSK
                skReader = Arrays.copyOfRange(fastKeybuf, 32, 64);
                skDevice = Arrays.copyOfRange(fastKeybuf, 64, 96);
                // [96..127] is BleSK — skip it
                stepUpSK = Arrays.copyOfRange(fastKeybuf, 128, 160);
                Log.d(TAG, "FAST keys derived from Kpersistent");
            }
            else
            {
                // -------------------------------------------------------
                // STANDARD key derivation: ECDH + HKDF (§8.3.1.13)
                // Note: when falling back from FAST, auth0Flag still
                // reflects 0x01 (what was sent), which is correct per
                // spec — the salt uses the original command_parameters.
                // -------------------------------------------------------
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
                        selectTLVForCrypto,
                        null,                                    // auth0CmdVendorTLV
                        auth0RspVendorTLV,
                        AliroCryptoProvider.INTERFACE_BYTE_NFC,
                        auth0Flag);

                if (keybuf == null)
                {
                    showAliroError("Key derivation failed.");
                    return;
                }
                skReader = Arrays.copyOfRange(keybuf, 0,  32);
                skDevice = Arrays.copyOfRange(keybuf, 32, 64);
                stepUpSK = Arrays.copyOfRange(keybuf, 64, 96);
            }

            // ------------------------------------------------------------------
            // LOAD CERT / AUTH1 (STANDARD only — FAST skips AUTH1 entirely)
            // ------------------------------------------------------------------
            boolean sigValid = false; // will be set during AUTH1 or FAST EXCHANGE

            // auth1Response — only used in STANDARD mode, declared here for scope
            byte[] auth1Response = null;

            // Decrypted AUTH1 payload — only populated in STANDARD mode
            byte[] decrypted = null;
            byte[] credentialPubKey = null; // from AUTH1 response (STANDARD only)

            // GCM counters — declared here so they're in scope for EXCHANGE.
            // STANDARD: AUTH1 response uses device_counter=1, EXCHANGE starts at 2.
            // FAST: no AUTH1, EXCHANGE response uses device_counter=1.
            int deviceCounter = 1; // both FAST and STANDARD start at 1 per §8.3.1.12
            int readerCounter = 1;

            if (useFastMode)
            {
                // FAST mode: skip LOAD CERT and AUTH1 entirely.
                // Keys are already derived from Kpersistent above.
                // Go straight to EXCHANGE (handled below).
                Log.d(TAG, "FAST mode: skipping LOAD CERT + AUTH1");
                sigValid = true; // FAST assumes prior STANDARD established trust
            }
            else
            {
            // Three modes controlled by CERT_DELIVERY_MODE preference:
            //   "none"      → skip LOAD CERT, AUTH1 has no cert
            //   "load_cert" → send cert via LOAD CERT (INS D1), AUTH1 has no cert
            //   "auth1"     → skip LOAD CERT, embed cert in AUTH1 (tag 0x90)
            // ------------------------------------------------------------------
            if (useCert && !certInAuth1)
            {
                if (forceChaining)
                {
                    // Mode: load_cert with command chaining (§8.3.2.2)
                    // Split cert into chunks; CLA=0x90 for non-final, 0x80 for final.
                    // Chunk size: half the cert, so we always get at least 2 chunks.
                    int chunkSize = Math.max(1, certBytes.length / 2);
                    int offset = 0;
                    int chunkNum = 0;
                    while (offset < certBytes.length)
                    {
                        int remaining = certBytes.length - offset;
                        int thisChunk = Math.min(chunkSize, remaining);
                        boolean lastChunk = (offset + thisChunk >= certBytes.length);
                        byte cla = lastChunk ? (byte)0x80 : (byte)0x90;

                        byte[] chunk = new byte[5 + thisChunk + 1];
                        chunk[0] = cla;
                        chunk[1] = (byte)0xD1; // INS = LOAD CERT
                        chunk[2] = 0x00;        // P1
                        chunk[3] = 0x00;        // P2
                        chunk[4] = (byte)thisChunk; // Lc
                        System.arraycopy(certBytes, offset, chunk, 5, thisChunk);
                        chunk[5 + thisChunk] = 0x00; // Le

                        Log.d(TAG, "LOAD CERT chain[" + chunkNum + "] CLA=0x"
                                + String.format("%02X", cla & 0xFF)
                                + " len=" + thisChunk
                                + (lastChunk ? " (final)" : " (more)"));

                        byte[] resp = isoDep.transceive(chunk);
                        Log.d(TAG, "LOAD CERT chain[" + chunkNum + "] response: "
                                + Hex.toHexString(resp));

                        if (!isSW9000(resp))
                        {
                            sendControlFlow(isoDep);
                            showAliroError("LOAD CERT chaining failed at chunk "
                                    + chunkNum + ": SW=" + swHex(resp));
                            return;
                        }
                        offset += thisChunk;
                        chunkNum++;
                    }
                    Log.d(TAG, "LOAD CERT chaining complete: " + chunkNum + " chunks sent");
                }
                else
                {
                    // Mode: load_cert single APDU (no chaining)
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
            }

            // Build and send AUTH1
            //
            // Two cert-in-AUTH1 delivery modes per §8.3.2.2:
            //   1. Command chaining (CLA=0x90/0x80) — mandatory, always supported
            //   2. Extended-length APDU — optional, requires User Device support
            //
            // Check forceChaining preference:
            //   true  → always use command chaining (WITH_CHAINING test)
            //   false → use extended-length if device supports it (NO_CHAINING test)
            //
            // If extended-length is attempted but fails, fall back to chaining.
            // Per §8.3.2.2: extended-length is only supported if the User Device
            // advertised DO'7F66' in the SELECT response. Parse the proprietary
            // TLV (tag A5) from the SELECT response for tag 7F66.
            boolean udSupportsExtendedLength = false;
            if (selectProprietaryTLV != null) {
                // Scan proprietary TLV bytes for tag 0x7F66
                for (int i = 0; i < selectProprietaryTLV.length - 3; i++) {
                    if (selectProprietaryTLV[i] == 0x7F
                            && selectProprietaryTLV[i + 1] == 0x66) {
                        udSupportsExtendedLength = true;
                        Log.d(TAG, "User Device advertised DO'7F66' — extended-length supported");
                        break;
                    }
                }
            }
            boolean useExtendedLength = certInAuth1 && !forceChaining
                    && udSupportsExtendedLength;
            Log.d(TAG, "AUTH1 cert delivery: certInAuth1=" + certInAuth1
                    + " forceChaining=" + forceChaining
                    + " udExtLen=" + udSupportsExtendedLength
                    + " useExtLen=" + useExtendedLength);

            if (certInAuth1 && !useExtendedLength)
            {
                // Mode: auth1 with cert + command chaining (§8.3.2.2)
                // Build the AUTH1 data field: 41 01 01 | 9E 40 <sig> | 90 xx <cert>
                // Then split across chained APDUs.
                ByteArrayOutputStream auth1Data = new ByteArrayOutputStream();
                auth1Data.write(0x41); auth1Data.write(0x01); auth1Data.write(0x01);
                auth1Data.write((byte)0x9E); auth1Data.write(0x40);
                auth1Data.write(readerSig, 0, 64);
                auth1Data.write((byte)0x90);
                if (certBytes.length > 127) {
                    auth1Data.write((byte)0x81);
                    auth1Data.write((byte)(certBytes.length & 0xFF));
                } else {
                    auth1Data.write((byte)certBytes.length);
                }
                auth1Data.write(certBytes, 0, certBytes.length);
                byte[] dataField = auth1Data.toByteArray();

                int chunkSize = Math.max(1, dataField.length / 2);
                int offset = 0;
                int chunkNum = 0;
                auth1Response = null;
                while (offset < dataField.length)
                {
                    int remaining = dataField.length - offset;
                    int thisChunk = Math.min(chunkSize, remaining);
                    boolean lastChunk = (offset + thisChunk >= dataField.length);
                    byte cla = lastChunk ? (byte)0x80 : (byte)0x90;

                    byte[] chunk = new byte[5 + thisChunk + (lastChunk ? 1 : 0)];
                    chunk[0] = cla;
                    chunk[1] = (byte)0x81; // INS = AUTH1
                    chunk[2] = 0x00;       // P1
                    chunk[3] = 0x00;       // P2
                    chunk[4] = (byte)thisChunk; // Lc
                    System.arraycopy(dataField, offset, chunk, 5, thisChunk);
                    if (lastChunk) chunk[5 + thisChunk] = 0x00; // Le on final

                    Log.d(TAG, "AUTH1 chain[" + chunkNum + "] CLA=0x"
                            + String.format("%02X", cla & 0xFF)
                            + " len=" + thisChunk
                            + (lastChunk ? " (final)" : " (more)"));

                    byte[] resp = isoDep.transceive(chunk);
                    Log.d(TAG, "AUTH1 chain[" + chunkNum + "] response: "
                            + Hex.toHexString(resp));

                    if (!lastChunk)
                    {
                        if (!isSW9000(resp))
                        {
                            sendControlFlow(isoDep);
                            showAliroError("AUTH1 chaining failed at chunk "
                                    + chunkNum + ": SW=" + swHex(resp));
                            return;
                        }
                    }
                    else
                    {
                        auth1Response = resp;
                    }
                    offset += thisChunk;
                    chunkNum++;
                }
                Log.d(TAG, "AUTH1 chaining complete: " + chunkNum + " chunks sent");
            }
            else if (useExtendedLength)
            {
                // Mode: auth1 with cert + single extended-length APDU (no chaining)
                byte[] auth1 = buildAuth1Command(readerSig, certBytes);
                Log.d(TAG, "AUTH1 command (cert embedded, extended-length, " + auth1.length
                        + " bytes): " + Hex.toHexString(auth1));
                try
                {
                    auth1Response = isoDep.transceive(auth1);
                }
                catch (Exception extEx)
                {
                    Log.w(TAG, "Extended-length AUTH1 failed (" + extEx.getMessage()
                            + ") — retrying with command chaining");
                    // Fall back to chaining on the same IsoDep connection
                    useExtendedLength = false;
                    // Re-build and send via chaining
                    ByteArrayOutputStream auth1Data2 = new ByteArrayOutputStream();
                    auth1Data2.write(0x41); auth1Data2.write(0x01); auth1Data2.write(0x01);
                    auth1Data2.write((byte)0x9E); auth1Data2.write(0x40);
                    auth1Data2.write(readerSig, 0, 64);
                    auth1Data2.write((byte)0x90);
                    if (certBytes.length > 127) {
                        auth1Data2.write((byte)0x81);
                        auth1Data2.write((byte)(certBytes.length & 0xFF));
                    } else {
                        auth1Data2.write((byte)certBytes.length);
                    }
                    auth1Data2.write(certBytes, 0, certBytes.length);
                    byte[] df = auth1Data2.toByteArray();
                    int cs = Math.max(1, df.length / 2);
                    int off = 0;
                    while (off < df.length)
                    {
                        int rem = df.length - off;
                        int tc2 = Math.min(cs, rem);
                        boolean last = (off + tc2 >= df.length);
                        byte cla2 = last ? (byte)0x80 : (byte)0x90;
                        byte[] ch = new byte[5 + tc2 + (last ? 1 : 0)];
                        ch[0] = cla2; ch[1] = (byte)0x81; ch[2] = 0; ch[3] = 0;
                        ch[4] = (byte)tc2;
                        System.arraycopy(df, off, ch, 5, tc2);
                        if (last) ch[5 + tc2] = 0x00;
                        byte[] r2 = isoDep.transceive(ch);
                        if (last) auth1Response = r2;
                        else if (!isSW9000(r2)) {
                            sendControlFlow(isoDep);
                            showAliroError("AUTH1 chaining fallback failed: SW=" + swHex(r2));
                            return;
                        }
                        off += tc2;
                    }
                    Log.d(TAG, "AUTH1 chaining fallback complete");
                }
            }
            else
            {
                // No cert in AUTH1 — short APDU, no chaining needed
                byte[] auth1 = buildAuth1Command(readerSig, null);
                Log.d(TAG, "AUTH1 command: " + Hex.toHexString(auth1));
                auth1Response = isoDep.transceive(auth1);
            }
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
            // (deviceCounter and readerCounter declared in outer scope above)

            if (!useFastMode)
            {
                // ------------------------------------------------------------------
                // Decrypt AUTH1 response with SKDevice, device_counter=1 (§8.3.1.7)
                // Encrypted payload = auth1Response minus final 2 SW bytes
                // ------------------------------------------------------------------
                byte[] encryptedPayload = Arrays.copyOfRange(auth1Response, 0, auth1Response.length - 2);
                decrypted = AliroCryptoProvider.decryptDeviceGcm(skDevice, encryptedPayload, deviceCounter++);
            if (decrypted == null)
            {
                if (fellBackFromFast)
                {
                    // FAST→STANDARD fallback: the User Device may have used
                    // FAST keys (it had Kpersistent), so our STANDARD keys
                    // don't match. Sending a failure EXCHANGE would fail too
                    // (key mismatch). Just drop the link cleanly — the
                    // sessionKpersistent was already cleared, so the next
                    // tap will use STANDARD from the start.
                    Log.w(TAG, "AUTH1 decryption failed after FAST fallback "
                            + "— key mismatch expected, dropping link");
                    try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                    showAliroError("AUTH1 decryption failed (FAST fallback key mismatch).");
                    return;
                }
                // Per Table 8-2 Row 1: EXCHANGE key available + last AUTH1 response SW=9000
                // → send EXCHANGE with Reader status (tag 0x97) indicating failure.
                Log.w(TAG, "AUTH1 decryption failed — sending failure EXCHANGE (0x00,0x25)");
                byte[] failStatusTlv = new byte[]{ (byte)0x97, 0x02, 0x00, 0x25 };
                byte[] failPayload = new byte[EXCHANGE_NOTIFY_TLV.length + failStatusTlv.length];
                System.arraycopy(EXCHANGE_NOTIFY_TLV, 0, failPayload, 0, EXCHANGE_NOTIFY_TLV.length);
                System.arraycopy(failStatusTlv, 0, failPayload, EXCHANGE_NOTIFY_TLV.length, failStatusTlv.length);
                byte[] encFail = AliroCryptoProvider.encryptReaderGcm(skReader, failPayload, readerCounter++);
                if (encFail != null)
                {
                    byte[] failCmd = buildExchangeCommand(encFail);
                    try {
                        byte[] failResp = isoDep.transceive(failCmd);
                        Log.d(TAG, "Failure EXCHANGE response: " + Hex.toHexString(failResp));
                    } catch (Exception ex) {
                        Log.w(TAG, "Failure EXCHANGE send error: " + ex.getMessage());
                    }
                }
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                showAliroError("AUTH1 decryption failed.");
                return;
            }
            Log.d(TAG, "AUTH1 decrypted: " + Hex.toHexString(decrypted));

            // Parse: 5A 41 <credential pub key 65 bytes> 9E 40 <signature 64 bytes>
            if (decrypted.length < 131 || decrypted[0] != 0x5A || decrypted[1] != 0x41)
            {
                // Per Table 8-2 Row 1: EXCHANGE key available + last response SW=9000
                // → send EXCHANGE with Reader status (tag 0x97) indicating failure.
                Log.w(TAG, "AUTH1 response format invalid — sending failure EXCHANGE (0x00,0x25)");
                byte[] failStatusTlv = new byte[]{ (byte)0x97, 0x02, 0x00, 0x25 };
                byte[] failPayload = new byte[EXCHANGE_NOTIFY_TLV.length + failStatusTlv.length];
                System.arraycopy(EXCHANGE_NOTIFY_TLV, 0, failPayload, 0, EXCHANGE_NOTIFY_TLV.length);
                System.arraycopy(failStatusTlv, 0, failPayload, EXCHANGE_NOTIFY_TLV.length, failStatusTlv.length);
                byte[] encFail = AliroCryptoProvider.encryptReaderGcm(skReader, failPayload, readerCounter++);
                if (encFail != null)
                {
                    byte[] failCmd = buildExchangeCommand(encFail);
                    try {
                        byte[] failResp = isoDep.transceive(failCmd);
                        Log.d(TAG, "Failure EXCHANGE response: " + Hex.toHexString(failResp));
                    } catch (Exception ex) {
                        Log.w(TAG, "Failure EXCHANGE send error: " + ex.getMessage());
                    }
                }
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                showAliroError("AUTH1 response format invalid.");
                return;
            }
            credentialPubKey = Arrays.copyOfRange(decrypted, 2, 67);
            if (decrypted[67] != (byte)0x9E || decrypted[68] != 0x40)
            {
                // Per Table 8-2 Row 1: EXCHANGE key available + last response SW=9000
                // → send EXCHANGE with Reader status (tag 0x97) indicating failure.
                Log.w(TAG, "AUTH1 missing credential signature — sending failure EXCHANGE (0x00,0x25)");
                byte[] failStatusTlv2 = new byte[]{ (byte)0x97, 0x02, 0x00, 0x25 };
                byte[] failPayload2 = new byte[EXCHANGE_NOTIFY_TLV.length + failStatusTlv2.length];
                System.arraycopy(EXCHANGE_NOTIFY_TLV, 0, failPayload2, 0, EXCHANGE_NOTIFY_TLV.length);
                System.arraycopy(failStatusTlv2, 0, failPayload2, EXCHANGE_NOTIFY_TLV.length, failStatusTlv2.length);
                byte[] encFail2 = AliroCryptoProvider.encryptReaderGcm(skReader, failPayload2, readerCounter++);
                if (encFail2 != null)
                {
                    byte[] failCmd2 = buildExchangeCommand(encFail2);
                    try {
                        byte[] failResp2 = isoDep.transceive(failCmd2);
                        Log.d(TAG, "Failure EXCHANGE response: " + Hex.toHexString(failResp2));
                    } catch (Exception ex) {
                        Log.w(TAG, "Failure EXCHANGE send error: " + ex.getMessage());
                    }
                }
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                showAliroError("AUTH1 missing credential signature.");
                return;
            }
            byte[] credentialSig = Arrays.copyOfRange(decrypted, 69, 133);
            Log.d(TAG, "Credential public key: " + Hex.toHexString(credentialPubKey));

            // ------------------------------------------------------------------
            // Verify credential signature
            // ------------------------------------------------------------------
            sigValid = AliroCryptoProvider.verifyCredentialSignature(
                    credentialSig, credentialPubKey,
                    readerIdBytes, udEphPubX, readerEphPubX, transactionId);
            Log.d(TAG, "Aliro credential signature valid: " + sigValid);

            if (!sigValid)
            {
                // Per Table 8-2 Row 1: EXCHANGE key available + last response SW=9000
                // → send EXCHANGE with Reader status (tag 0x97) indicating failure.
                Log.w(TAG, "Credential signature INVALID — sending failure EXCHANGE");
                // 0x97: status 0x00=failure, 0x04=Invalid User Device signature
                byte[] failStatusTlv = new byte[]{ (byte)0x97, 0x02, 0x00, 0x04 };
                byte[] failPayload = new byte[EXCHANGE_NOTIFY_TLV.length + failStatusTlv.length];
                System.arraycopy(EXCHANGE_NOTIFY_TLV, 0, failPayload, 0, EXCHANGE_NOTIFY_TLV.length);
                System.arraycopy(failStatusTlv, 0, failPayload, EXCHANGE_NOTIFY_TLV.length, failStatusTlv.length);
                byte[] failStatus = failPayload;
                byte[] encFail = AliroCryptoProvider.encryptReaderGcm(skReader, failStatus, readerCounter++);
                if (encFail != null)
                {
                    byte[] failCmd = buildExchangeCommand(encFail);
                    try {
                        byte[] failResp = isoDep.transceive(failCmd);
                        Log.d(TAG, "Failure EXCHANGE response: " + Hex.toHexString(failResp));
                    } catch (Exception ex) {
                        Log.w(TAG, "Failure EXCHANGE send error: " + ex.getMessage());
                    }
                }
                // Keep the NFC link alive briefly so the harness can complete
                // processing before we return and the link drops.
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                showAliroError("Credential signature verification failed.");
                return;
            }

            // ------------------------------------------------------------------
            // Derive and store Kpersistent for future FAST transactions.
            // Also store the credential static public key X (needed by FAST
            // key derivation). These persist across NFC taps.
            // ------------------------------------------------------------------
            credentialPubKeyX = Arrays.copyOfRange(credentialPubKey, 1, 33);
            byte[] kpersistentDerived = AliroCryptoProvider.deriveKpersistent(
                    readerEphKP.getPrivate(),
                    udEphPub,
                    protocolVersion,
                    hkdfReaderPubKeyX,
                    readerIdBytes,
                    transactionId,
                    readerEphPubX,
                    udEphPubX,
                    credentialPubKeyX,
                    selectTLVForCrypto,
                    null,                                    // auth0CmdVendorTLV
                    auth0RspVendorTLV,
                    AliroCryptoProvider.INTERFACE_BYTE_NFC,
                    auth0Flag);
            if (kpersistentDerived != null)
            {
                // Store in session memory for FAST mode on next tap
                sessionKpersistent = kpersistentDerived;
                sessionCredentialPubKeyX = credentialPubKeyX;
                Log.d(TAG, "Kpersistent stored in session: " + Hex.toHexString(kpersistentDerived));
            }
            else
            {
                Log.w(TAG, "Kpersistent derivation failed — FAST mode will not be available");
            }

            } // end of if (!useFastMode) — AUTH1 decryption + Kpersistent
            } // end of STANDARD (else) block

            // ------------------------------------------------------------------
            // Parse signaling_bitmap from decrypted AUTH1 payload (STANDARD only).
            // In FAST mode, there is no AUTH1 response — default to 0x0000.
            // ------------------------------------------------------------------
            int signalingBitmap = 0x0000;
            if (!useFastMode && decrypted != null)
            {
                // AUTH1 decrypted payload structure (Table 8-11):
                //   5A 41 <credential pub key 65 bytes>   = offset 0..66  (67 bytes)
                //   9E 40 <credential signature 64 bytes> = offset 67..132 (66 bytes)
                //   Optional: 4B xx <mailbox_data_subset> (variable length)
                //   5E 02 <signaling_bitmap 2 bytes>
                //   91 xx <timestamp> (optional)
                //
                // FIX §8.3.3.4.6: Use a TLV-aware walk starting after the fixed
                // fields (offset 133) to locate tag 0x5E. This prevents false
                // matches inside optional tag 0x4B (mailbox_data_subset) data.
                int scanStart = 133; // after 5A(1)+41(1)+pubkey(65) + 9E(1)+40(1)+sig(64)
                int si = scanStart;
                while (si + 2 <= decrypted.length)
                {
                    int tlvTag = decrypted[si] & 0xFF;
                    if (si + 1 >= decrypted.length) break;
                    int tlvLen = decrypted[si + 1] & 0xFF;
                    if (tlvTag == 0x5E && tlvLen == 0x02 && si + 4 <= decrypted.length)
                    {
                        signalingBitmap = ((decrypted[si + 2] & 0xFF) << 8) | (decrypted[si + 3] & 0xFF);
                        Log.d(TAG, "AUTH1: signaling_bitmap=0x" + String.format("%04X", signalingBitmap)
                                + " at offset " + si);
                        break;
                    }
                    // Skip this TLV and advance to the next one
                    if (tlvLen == 0 || si + 2 + tlvLen > decrypted.length) break;
                    si += 2 + tlvLen;
                }
            }
            boolean accessDocAvailable  = (signalingBitmap & 0x0001) != 0; // Bit0
            boolean revocationDocAvail  = (signalingBitmap & 0x0002) != 0; // Bit1
            boolean docAvailableForStepUp = accessDocAvailable || revocationDocAvail;
            boolean mailboxReadable     = (signalingBitmap & 0x0010) != 0; // Bit4
            boolean mailboxWritable     = (signalingBitmap & 0x0020) != 0; // Bit5

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

            // Per Table 8-11: Bit4 = mailbox readable, Bit5 = mailbox writable.
            // "attempts to read the mailbox SHALL return an error if [Bit4] not set"
            // Only include mailbox BA if the signaling_bitmap permits the operation.
            if (mailboxEnabled && (mailboxReadable || mailboxWritable))
            {
                mailboxOp = mailboxPrefs.getString(AliroPreferences.MAILBOX_OPERATION, "read");
                int mOffset = Integer.parseInt(mailboxPrefs.getString(AliroPreferences.MAILBOX_OFFSET, "0"));
                // Use the configured read length directly. The harness mailbox is small
                // (0x20 = 32 bytes) but the simulator credential's sample mailbox is 300
                // bytes with 73+ bytes of §18 TLV data. Capping at 32 truncates the TLV
                // structure and prevents the parser from displaying readable content.
                int rawLen = Integer.parseInt(mailboxPrefs.getString(AliroPreferences.MAILBOX_LENGTH, "256"));
                int mLength = rawLen;
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
            //
            // IMPORTANT: Per §8.3.1 the mailbox SHALL NOT be used during step-up
            // phase. Also, the harness step-up negative tests do NOT configure a
            // mailbox, so sending a mailbox read request (tag 0xBA) causes them to
            // fail. When step-up is pending, do NOT include mailbox in EXCHANGE.
            // ------------------------------------------------------------------
            SharedPreferences stepUpPrefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
            String stepUpElementId = stepUpPrefs.getString(AliroPreferences.STEP_UP_ELEMENT_ID, "");
            boolean willDoStepUp = !stepUpElementId.isEmpty() && docAvailableForStepUp;

            // When step-up is pending, send a pre-step-up EXCHANGE with ONLY the
            // mailbox read request (no 0x97 status, no 0xAE notify). The 0x97 status
            // is deferred to the post-step-up EXCHANGE after ENVELOPE completes.
            // Per §8.3.3.5: mailbox operations occur in the expedited phase EXCHANGE,
            // not during the step-up phase.
            if (willDoStepUp && mailboxBA != null)
            {
                Log.d(TAG, "Step-up pending — sending mailbox-only pre-step-up EXCHANGE");
                byte[] mbEncrypted = AliroCryptoProvider.encryptReaderGcm(skReader, mailboxBA, readerCounter++);
                if (mbEncrypted != null)
                {
                    byte[] mbCmd = buildExchangeCommand(mbEncrypted);
                    Log.d(TAG, "Pre-step-up EXCHANGE (mailbox only): " + Hex.toHexString(mbCmd));
                    byte[] mbResp = isoDep.transceive(mbCmd);
                    Log.d(TAG, "Pre-step-up EXCHANGE response: " + Hex.toHexString(mbResp));
                    if (isSW9000(mbResp) && mbResp.length > 2)
                    {
                        byte[] mbEncPayload = Arrays.copyOfRange(mbResp, 0, mbResp.length - 2);
                        byte[] mbDecrypted = AliroCryptoProvider.decryptDeviceGcm(skDevice, mbEncPayload, deviceCounter++);
                        if (mbDecrypted != null && mailboxEnabled && "read".equals(mailboxOp))
                        {
                            Log.d(TAG, "Pre-step-up mailbox decrypted (" + mbDecrypted.length + " bytes): "
                                    + Hex.toHexString(mbDecrypted));
                            if (mbDecrypted.length > 4)
                            {
                                int readDataLen = mbDecrypted.length - 4;
                                byte[] mailboxReadData = Arrays.copyOfRange(mbDecrypted, 0, readDataLen);
                                int tlvStart = -1;
                                for (int s = 0; s < Math.min(4, readDataLen); s++)
                                {
                                    if ((mailboxReadData[s] & 0xFF) == 0x60) { tlvStart = s; break; }
                                }
                                if (tlvStart >= 0)
                                {
                                    byte[] tlvData = Arrays.copyOfRange(mailboxReadData, tlvStart, readDataLen);
                                    mailboxResultHex = AliroMailbox.parseMailboxToString(tlvData, tlvData.length);
                                }
                                else
                                {
                                    String fullHex = Hex.toHexString(mailboxReadData);
                                    String preview = (fullHex.length() > 64)
                                            ? fullHex.substring(0, 64) + "..."
                                            : fullHex;
                                    mailboxResultHex = "Read " + readDataLen + " bytes\n"
                                            + "  Preview: " + preview;
                                }
                            }
                        }
                    }
                }
                // Clear mailboxBA so it's not included again in the non-step-up EXCHANGE path
                mailboxBA = null;
            }

            // Check revocation database before making access decision.
            // Per §7.6: the Reader must enforce revocation entries.
            boolean isRevoked = false;
            if (sigValid && credentialPubKey != null) {
                isRevoked = AliroAccessDocumentVerifier.isRevoked(credentialPubKey);
                if (isRevoked) {
                    Log.w(TAG, "Credential public key is REVOKED — rejecting access");
                }
            }
            boolean accessGranted = sigValid && !isRevoked;
            // Per Table 8-18: first byte 0x01 = accepted, 0x00 = rejected.
            // Second byte: when accepted, 0x82 = reader state unknown.
            // When rejected, use a valid rejection reason code:
            //   0x03 = Access Credential public key not trusted (revoked)
            //   0x04 = Invalid User Device signature
            byte[] statusTlv;
            if (accessGranted) {
                statusTlv = new byte[]{ (byte)0x97, 0x02, 0x01, (byte)0x82 };
            } else if (isRevoked) {
                statusTlv = new byte[]{ (byte)0x97, 0x02, 0x00, 0x03 }; // not trusted (revoked)
            } else {
                statusTlv = new byte[]{ (byte)0x97, 0x02, 0x00, 0x04 }; // invalid signature
            }
            // Notify (0xAE with descriptor inside) + status (0x97)
            // Per Table 8-15 ordering: 0xBA (mailbox) → 0xAE (notify{descriptor}) → 0x97 (status)
            byte[] descAndStatus = new byte[EXCHANGE_NOTIFY_TLV.length + statusTlv.length];
            System.arraycopy(EXCHANGE_NOTIFY_TLV, 0, descAndStatus, 0, EXCHANGE_NOTIFY_TLV.length);
            System.arraycopy(statusTlv, 0, descAndStatus, EXCHANGE_NOTIFY_TLV.length, statusTlv.length);

            byte[] exchangePayload;
            if (willDoStepUp)
            {
                // Step-up is coming — skip the pre-step-up EXCHANGE entirely.
                // Per §8.2 the Reader proceeds directly from AUTH1 to step-up phase
                // (optional SELECT + ENVELOPE). The 0x97 reader status is sent in the
                // post-step-up EXCHANGE after the ENVELOPE completes.
                exchangePayload = null;
            }
            else if (mailboxBA != null)
            {
                // Mailbox + descriptor + 0x97 (no step-up)
                exchangePayload = new byte[mailboxBA.length + descAndStatus.length];
                System.arraycopy(mailboxBA, 0, exchangePayload, 0, mailboxBA.length);
                System.arraycopy(descAndStatus, 0, exchangePayload, mailboxBA.length, descAndStatus.length);
            }
            else
            {
                // Descriptor + 0x97 (no mailbox, no step-up)
                exchangePayload = descAndStatus;
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
                                    // Find the §18 container tag 0x60 within the first few bytes.
                                    // The EXCHANGE mailbox read response may have a 2-byte prefix
                                    // (read offset echo) before the actual mailbox content.
                                    int tlvStart = -1;
                                    for (int s = 0; s < Math.min(4, readDataLen); s++)
                                    {
                                        if ((mailboxReadData[s] & 0xFF) == 0x60) { tlvStart = s; break; }
                                    }
                                    if (tlvStart >= 0)
                                    {
                                        byte[] tlvData = Arrays.copyOfRange(mailboxReadData, tlvStart, readDataLen);
                                        mailboxResultHex = AliroMailbox.parseMailboxToString(
                                                tlvData, tlvData.length);
                                    }
                                    else
                                    {
                                        // Show a clean summary with truncated hex for readability
                                        String fullHex = Hex.toHexString(mailboxReadData);
                                        String preview = (fullHex.length() > 64)
                                                ? fullHex.substring(0, 64) + "..."
                                                : fullHex;
                                        mailboxResultHex = "Read " + readDataLen + " bytes\n"
                                                + "  Preview: " + preview;
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
            // Determine docType based on signaling bitmap
            // Bit0 = Access Document (aliro-a), Bit1 = Revocation Document (aliro-r)
            // Prioritize access document — it contains access rules, schedules, and
            // employee badge data. Revocation is supplementary (processed separately
            // if needed after the access document).
            String stepUpDocType = accessDocAvailable ? "aliro-a" : "aliro-r";

            // Verification result — determines post-step-up EXCHANGE reader status
            AliroAccessDocumentVerifier.VerificationResult docVerifyResult = null;

            if (willDoStepUp)
            {
                Log.d(TAG, "Step-Up: requesting element '" + stepUpElementId
                        + "' docType=" + stepUpDocType
                        + "' stepUpSK=" + Hex.toHexString(stepUpSK));
                try
                {
                    stepUpResult = runAliroStepUp(isoDep, stepUpSK, stepUpElementId,
                            stepUpPrefs, stepUpDocType, credentialPubKey);
                }
                catch (Exception e)
                {
                    Log.w(TAG, "Step-Up failed (non-fatal): " + e.getMessage());
                    stepUpResult = "Step-Up failed: " + e.getMessage();
                }

                // Extract verification result from the step-up run
                docVerifyResult = lastDocVerifyResult; // set by runAliroStepUp

                // Send final EXCHANGE with 0x97 (reader status) to close the transaction.
                // This must come AFTER step-up because 0x97 signals end-of-transaction.
                // Per Aliro §8.3.3.5: post-ENVELOPE EXCHANGE uses StepUpSKReader/StepUpSKDevice,
                // NOT the expedited SKReader/SKDevice. Counter starts at 2 (ENVELOPE used 1).
                byte[] suKeys = AliroCryptoProvider.deriveStepUpSessionKeys(stepUpSK);
                if (suKeys == null)
                {
                    Log.e(TAG, "Post step-up: failed to derive step-up session keys for EXCHANGE");
                }
                else
                {
                    byte[] postSuSKReader = Arrays.copyOfRange(suKeys, 32, 64);
                    byte[] postSuSKDevice = Arrays.copyOfRange(suKeys, 0,  32);
                    int suReaderCounter = 2; // ENVELOPE used counter 1
                    int suDeviceCounter = 2;

                    // Build final payload: descriptor + status.
                    // Per §8.3.1: "The mailbox SHALL NOT be used when in the step-up phase."
                    // Do NOT include mailbox (tag 0xBA) in post-step-up EXCHANGE.
                    //
                    // Use the verification result status if available, otherwise
                    // fall back to the expedited-phase status.
                    byte[] postStepUpStatusTlv;
                    if (docVerifyResult != null)
                    {
                        postStepUpStatusTlv = new byte[]{
                                (byte)0x97, 0x02,
                                (byte)docVerifyResult.readerStatusByte1,
                                (byte)docVerifyResult.readerStatusByte2
                        };
                        Log.d(TAG, "Post step-up EXCHANGE status: 0x"
                                + String.format("%02X%02X",
                                        docVerifyResult.readerStatusByte1,
                                        docVerifyResult.readerStatusByte2)
                                + " (" + docVerifyResult.reason + ")");
                    }
                    else
                    {
                        postStepUpStatusTlv = statusTlv;
                    }
                    byte[] finalPayload = new byte[EXCHANGE_NOTIFY_TLV.length + postStepUpStatusTlv.length];
                    System.arraycopy(EXCHANGE_NOTIFY_TLV, 0, finalPayload, 0, EXCHANGE_NOTIFY_TLV.length);
                    System.arraycopy(postStepUpStatusTlv, 0, finalPayload, EXCHANGE_NOTIFY_TLV.length, postStepUpStatusTlv.length);
                    Log.d(TAG, "Sending final EXCHANGE with 0x97 (post step-up, using StepUpSK)");
                    byte[] finalEncrypted = AliroCryptoProvider.encryptReaderGcm(
                            postSuSKReader, finalPayload, suReaderCounter++);
                    if (finalEncrypted != null)
                    {
                        byte[] finalCmd = buildExchangeCommand(finalEncrypted);
                        byte[] finalResp = isoDep.transceive(finalCmd);
                        Log.d(TAG, "Final EXCHANGE response: " + Hex.toHexString(finalResp));
                        // Decrypt response with step-up device key
                        if (isSW9000(finalResp) && finalResp.length > 2)
                        {
                            byte[] finalEnc = Arrays.copyOfRange(finalResp, 0, finalResp.length - 2);
                            byte[] finalDec = AliroCryptoProvider.decryptDeviceGcm(
                                    postSuSKDevice, finalEnc, suDeviceCounter++);
                            if (finalDec != null)
                                Log.d(TAG, "Final EXCHANGE decrypted: " + Hex.toHexString(finalDec));
                        }
                    }
                    java.util.Arrays.fill(postSuSKReader, (byte)0);
                    java.util.Arrays.fill(postSuSKDevice, (byte)0);
                }
            }
            else if (!stepUpElementId.isEmpty() && !docAvailableForStepUp)
            {
                Log.d(TAG, "Step-Up: skipped — signaling_bitmap Bit0/Bit1 not set (no Access/Revocation Document)");
            }

            // ------------------------------------------------------------------
            // Destroy all session-bound keys per section 10.2 and 8.3.3.1
            // ------------------------------------------------------------------
            java.util.Arrays.fill(skReader,  (byte)0);
            java.util.Arrays.fill(skDevice,  (byte)0);
            java.util.Arrays.fill(stepUpSK,  (byte)0);
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
                setKeypadVisibility(View.GONE);
                String pk = finalCredPubKey != null ? Hex.toHexString(finalCredPubKey) : "(FAST mode)";
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

    /**
     * Strip transport-layer tags (DO'7F66' extended length, 0xB3 vendor extensions)
     * from the A5 proprietary TLV so only the core children (0x80, 0x5C) remain.
     * Per §8.3.1.12/§8.3.1.13 the harness uses only the core children in the
     * HKDF salt.  The input is the full A5 TLV (tag + length + value).
     * Returns a rebuilt A5 TLV containing only 0x80 and 0x5C children.
     */
    private byte[] stripNonCryptoTags(byte[] a5Tlv)
    {
        if (a5Tlv == null || a5Tlv.length < 2 || a5Tlv[0] != (byte) 0xA5)
            return a5Tlv;

        int a5Len = a5Tlv[1] & 0xFF;
        // Walk child TLVs inside the A5 value, keeping only 0x80 and 0x5C
        java.io.ByteArrayOutputStream kept = new java.io.ByteArrayOutputStream();
        int pos = 2; // start of A5 value
        int end = 2 + a5Len;
        while (pos < end)
        {
            // Handle two-byte tags (0x7F66)
            int tag;
            int tagBytes;
            if (pos + 1 < end && (a5Tlv[pos] & 0xFF) == 0x7F)
            {
                tag = ((a5Tlv[pos] & 0xFF) << 8) | (a5Tlv[pos + 1] & 0xFF);
                tagBytes = 2;
            }
            else
            {
                tag = a5Tlv[pos] & 0xFF;
                tagBytes = 1;
            }
            if (pos + tagBytes >= end) break;
            int childLen = a5Tlv[pos + tagBytes] & 0xFF;
            int totalChild = tagBytes + 1 + childLen;
            if (pos + totalChild > end) break;

            // Keep only 0x80 (Type) and 0x5C (protocol versions)
            if (tag == 0x80 || tag == 0x5C)
            {
                kept.write(a5Tlv, pos, totalChild);
            }
            pos += totalChild;
        }
        byte[] keptBytes = kept.toByteArray();
        byte[] result = new byte[2 + keptBytes.length];
        result[0] = (byte) 0xA5;
        result[1] = (byte) keptBytes.length;
        System.arraycopy(keptBytes, 0, result, 2, keptBytes.length);
        return result;
    }

    /** Parse the protocol version (tag 5C, first 2-byte version) from SELECT response.
     *  Returns a SUPPORTED version (0x0100 or 0x0009) if found, or null if no common
     *  protocol version exists. Per Aliro §10.2, when no common version is found the
     *  Reader SHALL send CONTROL FLOW with S2=0x27 (protocol version not supported). */
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
                    // Only return a version we actually support (0x0100 or 0x0009)
                    for (int j = 0; j < len - 1; j += 2)
                    {
                        byte v0 = selectResponse[i + 2 + j];
                        byte v1 = selectResponse[i + 3 + j];
                        if ((v0 == 0x01 && v1 == 0x00) || (v0 == 0x00 && v1 == 0x09))
                        {
                            return new byte[]{ v0, v1 };
                        }
                    }
                    // No supported version found — return null to trigger CONTROL FLOW
                    Log.w(TAG, "No common protocol version — credential offers versions we don't support");
                    return null;
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
     *  Data field is flat DER-TLVs in order: 41 42 5C 87 4C 4D (no outer wrapper).
     *  @param cmdParams  0x00 = expedited-standard, 0x01 = expedited-fast */
    private byte[] buildAuth0Command(byte[] protocolVersion, byte[] readerEphPub,
                                     byte[] transactionId, byte[] readerId,
                                     byte cmdParams)
    {
        // CLA=80 INS=80 P1=00 P2=00
        // Data: 41 01 <cmd_params>   command_parameters
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
        // 41: command_parameters
        cmd[idx++] = 0x41; cmd[idx++] = 0x01; cmd[idx++] = cmdParams;
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

    /**
     * Build AUTH1 command per Table 8-10 of Aliro 1.0 spec.
     *
     * Data field TLVs:
     *   41 01 <command_parameters>   (0x01 = expect credential_public_key)
     *   9E 40 <reader signature 64 bytes>
     *   90 xx <reader_Cert>          (optional — only in cert-in-AUTH1 mode)
     *
     * When certBytes is non-null, the cert is embedded as tag 0x90.
     * Uses extended Lc (3-byte) when data field exceeds 255 bytes.
     *
     * @param signature  64-byte ECDSA reader signature
     * @param certBytes  Profile0000 cert bytes, or null to omit
     */
    private byte[] buildAuth1Command(byte[] signature, byte[] certBytes)
    {
        // Data field: 41 01 01 | 9E 40 <sig 64> | [90 xx <cert>]
        int dataLen = 3 + 2 + 64;  // tag41 + tag9E header + sig
        if (certBytes != null)
        {
            // tag 0x90 + length encoding + cert bytes
            dataLen += 1 + encodeLcLength(certBytes.length) + certBytes.length;
        }

        boolean extended = (dataLen > 255);
        // APDU: CLA INS P1 P2 [Lc] data [Le]
        int headerLen = 4;  // CLA INS P1 P2
        int lcLen = extended ? 3 : 1;
        int leLen = extended ? 2 : 1;
        byte[] cmd = new byte[headerLen + lcLen + dataLen + leLen];

        int idx = 0;
        cmd[idx++] = (byte)0x80; // CLA
        cmd[idx++] = (byte)0x81; // INS = AUTH1
        cmd[idx++] = 0x00;       // P1
        cmd[idx++] = 0x00;       // P2

        // Lc
        if (extended)
        {
            cmd[idx++] = 0x00;
            cmd[idx++] = (byte)((dataLen >> 8) & 0xFF);
            cmd[idx++] = (byte)(dataLen & 0xFF);
        }
        else
        {
            cmd[idx++] = (byte)dataLen;
        }

        // Tag 0x41: command_parameters = 0x01 (expect credential_public_key)
        cmd[idx++] = 0x41;
        cmd[idx++] = 0x01;
        cmd[idx++] = 0x01;

        // Tag 0x9E: reader signature (64 bytes)
        cmd[idx++] = (byte)0x9E;
        cmd[idx++] = 0x40;
        System.arraycopy(signature, 0, cmd, idx, 64);
        idx += 64;

        // Tag 0x90: reader_Cert (optional)
        if (certBytes != null)
        {
            cmd[idx++] = (byte)0x90;
            if (certBytes.length > 127)
            {
                cmd[idx++] = (byte)0x81;
                cmd[idx++] = (byte)(certBytes.length & 0xFF);
            }
            else
            {
                cmd[idx++] = (byte)certBytes.length;
            }
            System.arraycopy(certBytes, 0, cmd, idx, certBytes.length);
            idx += certBytes.length;
        }

        // Le
        if (extended)
        {
            cmd[idx++] = 0x00;
            cmd[idx++] = 0x00;
        }
        else
        {
            cmd[idx++] = 0x00;
        }

        return cmd;
    }

    /** Return the number of bytes needed to encode a TLV length value. */
    private int encodeLcLength(int length)
    {
        return (length > 127) ? 2 : 1;
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
    // Multi-element Step-Up helpers (Aliro 1.0 §7.3 / §8.4.2)
    //
    // The Step-Up Element Identifier preference is a free-form string. Users
    // may enter "floor1" for a single element or "floor1, floor2, pool_door"
    // to request multiple elements in one Step-Up. parseElementIdList splits
    // the CSV; sliceDeviceResponsePerDocument unpacks the multi-document
    // DeviceResponse the credential returns into one DeviceResponse per
    // document so the existing verifyDocument can verify each independently.
    // -------------------------------------------------------------------------

    /**
     * Parse the Step-Up Element Identifier preference string into an ordered
     * list of element IDs. Splits on commas, trims whitespace, drops empty
     * tokens. Returns a single-element list ["access"] when the input is
     * null or fully blank — matches the documented default in §7.2.5 / §7.7
     * so the request always carries at least one identifier.
     */
    private static java.util.List<String> parseElementIdList(String csv)
    {
        java.util.List<String> out = new java.util.ArrayList<>();
        if (csv != null)
        {
            for (String tok : csv.split(","))
            {
                String t = tok.trim();
                if (!t.isEmpty()) out.add(t);
            }
        }
        if (out.isEmpty()) out.add("access");
        return out;
    }

    /**
     * Slice a multi-document DeviceResponse into one DeviceResponse per
     * document so the existing single-document verifier can verify each one.
     * Each slice keeps the version (key "1") and status (key "3") fields and
     * carries exactly one document under the documents array (key "2").
     *
     * <p>Returns an empty list when the input is unparseable or carries no
     * documents — callers fall back to verifying the original bytes whole.
     */
    private static java.util.List<byte[]> sliceDeviceResponsePerDocument(byte[] deviceResponseBytes)
    {
        java.util.List<byte[]> out = new java.util.ArrayList<>();
        try
        {
            com.upokecenter.cbor.CBORObject deviceResponse =
                    com.upokecenter.cbor.CBORObject.DecodeFromBytes(deviceResponseBytes);
            com.upokecenter.cbor.CBORObject docs =
                    deviceResponse.get(com.upokecenter.cbor.CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return out;

            com.upokecenter.cbor.CBORObject version =
                    deviceResponse.get(com.upokecenter.cbor.CBORObject.FromObject("1"));
            com.upokecenter.cbor.CBORObject status  =
                    deviceResponse.get(com.upokecenter.cbor.CBORObject.FromObject("3"));

            for (int i = 0; i < docs.size(); i++)
            {
                com.upokecenter.cbor.CBORObject one = com.upokecenter.cbor.CBORObject.NewOrderedMap();
                if (version != null)
                    one.Add(com.upokecenter.cbor.CBORObject.FromObject("1"), version);
                com.upokecenter.cbor.CBORObject arr = com.upokecenter.cbor.CBORObject.NewArray();
                arr.Add(docs.get(i));
                one.Add(com.upokecenter.cbor.CBORObject.FromObject("2"), arr);
                if (status != null)
                    one.Add(com.upokecenter.cbor.CBORObject.FromObject("3"), status);
                out.add(one.EncodeToBytes());
            }
        }
        catch (Exception e)
        {
            Log.w(TAG, "sliceDeviceResponsePerDocument failed: " + e.getMessage());
        }
        return out;
    }

    /**
     * Parse the Step-Up Issuer Public Key preference into a list of trusted
     * 65-byte uncompressed EC public keys. Accepts a single hex value or a
     * comma-separated list (Aliro 1.0 §7.7) — multiple stored documents on
     * the credential side may carry different issuers, and the reader can
     * trust any/all of them by listing their public keys here.
     *
     * <p>Returns an empty list when the input is null/blank or no token
     * decodes cleanly to 65 bytes; in that case downstream code skips
     * COSE_Sign1 verification ("(sig not verified)").
     */
    private static java.util.List<byte[]> parseIssuerPubKeyList(String csv)
    {
        java.util.List<byte[]> out = new java.util.ArrayList<>();
        if (csv == null) return out;
        for (String tok : csv.split(","))
        {
            String hex = tok.trim();
            if (hex.isEmpty()) continue;
            try
            {
                byte[] bytes = org.bouncycastle.util.encoders.Hex.decode(hex);
                if (bytes.length == 65 && bytes[0] == 0x04)
                {
                    out.add(bytes);
                }
                else
                {
                    Log.w(TAG, "parseIssuerPubKeyList: skipping malformed entry (length="
                            + bytes.length + ")");
                }
            }
            catch (Exception e)
            {
                Log.w(TAG, "parseIssuerPubKeyList: hex decode failed for '" + hex + "'");
            }
        }
        return out;
    }

    /**
     * Pick the trusted issuer key whose kid matches the IssuerAuth in the
     * given DeviceResponse slice. The kid is derived from each candidate
     * key as {@code SHA-256("key-identifier" || pubKey)[0:8]} per Aliro
     * 1.0 §7.2.1, then matched against the kid byte string in the slice's
     * COSE_Sign1 protected header.
     *
     * <p>If the slice carries no kid (e.g. x5chain-based docs) or no key
     * matches, returns the first key in the list as a best-effort fallback
     * — the verifier will then either accept it (single-issuer case where
     * everything happens to share one kid) or fail signature verification
     * cleanly. Returns null only when the candidate list itself is empty.
     */
    private static byte[] pickIssuerKeyForKid(byte[] sliceBytes,
                                                java.util.List<byte[]> trustedKeys)
    {
        if (trustedKeys == null || trustedKeys.isEmpty()) return null;
        if (trustedKeys.size() == 1) return trustedKeys.get(0);

        byte[] kid = extractKidFromSlice(sliceBytes);
        if (kid == null)
        {
            Log.d(TAG, "pickIssuerKeyForKid: no kid in slice, defaulting to first key");
            return trustedKeys.get(0);
        }

        for (byte[] candidate : trustedKeys)
        {
            try
            {
                java.security.MessageDigest sha =
                        java.security.MessageDigest.getInstance("SHA-256");
                sha.update("key-identifier".getBytes("US-ASCII"));
                sha.update(candidate);
                byte[] expectedKid = java.util.Arrays.copyOfRange(sha.digest(), 0, 8);
                if (java.util.Arrays.equals(expectedKid, kid))
                {
                    Log.d(TAG, "pickIssuerKeyForKid: matched kid="
                            + org.bouncycastle.util.encoders.Hex.toHexString(kid));
                    return candidate;
                }
            }
            catch (Exception e)
            {
                Log.w(TAG, "pickIssuerKeyForKid: kid compute failed", e);
            }
        }
        Log.w(TAG, "pickIssuerKeyForKid: no trusted key matches kid="
                + org.bouncycastle.util.encoders.Hex.toHexString(kid)
                + " — falling back to first key (verification will likely fail)");
        return trustedKeys.get(0);
    }

    /**
     * Extract the {@code kid} byte string from a DeviceResponse slice's
     * IssuerAuth COSE_Sign1 header. Returns null if absent or if the response
     * can't be parsed.
     *
     * <p>Per RFC 9052 §3 a COSE_Sign1 is {@code [protected, unprotected,
     * payload, signature]}. Header parameters MAY appear in either header
     * bucket, so we check both — protected first per RFC convention, then
     * unprotected. The Aliro credential build path (AliroAccessDocument.java
     * {@code buildCoseSign1}) puts kid in the unprotected header, and the
     * reader's verifier (AliroAccessDocumentVerifier Step 1) reads from
     * either — this helper mirrors that policy so {@code pickIssuerKeyForKid}
     * sees the same kid value Step 2 will validate against.
     */
    private static byte[] extractKidFromSlice(byte[] sliceBytes)
    {
        try
        {
            com.upokecenter.cbor.CBORObject deviceResponse =
                    com.upokecenter.cbor.CBORObject.DecodeFromBytes(sliceBytes);
            com.upokecenter.cbor.CBORObject docs =
                    deviceResponse.get(com.upokecenter.cbor.CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0) return null;
            com.upokecenter.cbor.CBORObject doc      = docs.get(0);
            com.upokecenter.cbor.CBORObject iSigned  =
                    doc.get(com.upokecenter.cbor.CBORObject.FromObject("1"));
            if (iSigned == null) return null;
            com.upokecenter.cbor.CBORObject iAuth    =
                    iSigned.get(com.upokecenter.cbor.CBORObject.FromObject("2"));
            if (iAuth == null || iAuth.size() < 2) return null;

            // Try protected header first (RFC 9052 convention)
            byte[] protectedHeaderBytes = iAuth.get(0).GetByteString();
            if (protectedHeaderBytes != null && protectedHeaderBytes.length > 0)
            {
                try
                {
                    com.upokecenter.cbor.CBORObject protectedHeader =
                            com.upokecenter.cbor.CBORObject.DecodeFromBytes(protectedHeaderBytes);
                    com.upokecenter.cbor.CBORObject kidObj =
                            protectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(4));
                    if (kidObj != null) return kidObj.GetByteString();
                }
                catch (Exception ignored) { /* fall through to unprotected */ }
            }

            // Fall back to unprotected header (where the credential actually puts kid)
            com.upokecenter.cbor.CBORObject unprotectedHeader = iAuth.get(1);
            if (unprotectedHeader != null)
            {
                com.upokecenter.cbor.CBORObject kidObj =
                        unprotectedHeader.get(com.upokecenter.cbor.CBORObject.FromObject(4));
                if (kidObj != null) return kidObj.GetByteString();
            }

            return null;
        }
        catch (Exception e)
        {
            Log.d(TAG, "extractKidFromSlice: " + e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Aliro Step-Up phase — ENVELOPE/GET RESPONSE + DeviceResponse processing
    // Per Aliro §8.4: transfers Access Document from credential to reader.
    // Returns a short summary string for display, or null if nothing useful returned.
    // -------------------------------------------------------------------------

    @SuppressWarnings("NewApi")
    private String runAliroStepUp(android.nfc.tech.IsoDep isoDep,
                                   byte[] stepUpSK,
                                   String elementId,
                                   SharedPreferences prefs,
                                   String docType,
                                   byte[] credentialPubKey)
            throws java.io.IOException
    {
        // Reset last verification result
        lastDocVerifyResult = null;

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
            // Per the harness (doc_request.py line 64), the itemsRequest MUST be
            // wrapped in CBOR Tag 24 ("encoded CBOR") as a byte string:
            //   docRequest["1"] = CBORTag(24, bstr(ItemsRequest CBOR))
            //
            // ItemsRequest keys per items_request.py:
            //   "5" = docType (e.g. "aliro-a" or "aliro-r" per §7.7)
            //   "1" = nameSpaces: { <docType>: { <elementId>: false, ... } }
            //
            // Multi-element support (Aliro 1.0 §7.3 / §8.4.2):
            //   The Step-Up Element Identifier preference accepts a single value
            //   ("floor1") or a comma-separated list ("floor1, floor2, pool_door")
            //   to request multiple elements in a single Step-Up. Each element
            //   gets its own entry in the inner element map; the credential
            //   returns one document per matching element under documents[].
            java.util.List<String> requestElementIds = parseElementIdList(elementId);
            com.upokecenter.cbor.CBORObject nameSpaceMap = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            com.upokecenter.cbor.CBORObject elemMap      = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            for (String eid : requestElementIds)
            {
                elemMap.Add(com.upokecenter.cbor.CBORObject.FromObject(eid),
                            com.upokecenter.cbor.CBORObject.False);
            }
            nameSpaceMap.Add(com.upokecenter.cbor.CBORObject.FromObject(docType), elemMap);

            com.upokecenter.cbor.CBORObject itemsRequest = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            itemsRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("5"),
                    com.upokecenter.cbor.CBORObject.FromObject(docType)); // docType per §7.7
            itemsRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("1"), nameSpaceMap); // nameSpaces

            // Encode ItemsRequest to CBOR bytes, then wrap in Tag 24
            byte[] itemsRequestBytes = itemsRequest.EncodeToBytes();
            com.upokecenter.cbor.CBORObject taggedItemsRequest =
                    com.upokecenter.cbor.CBORObject.FromObjectAndTag(
                            itemsRequestBytes, 24);

            com.upokecenter.cbor.CBORObject docRequest = com.upokecenter.cbor.CBORObject.NewOrderedMap();
            docRequest.Add(com.upokecenter.cbor.CBORObject.FromObject("1"), taggedItemsRequest);

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

            // 4. Wrap SessionData CBOR in tag 0x53 per Table 10-7, then send ENVELOPE
            byte[] tag53Wrapped;
            if (sessionDataBytes.length > 127)
            {
                tag53Wrapped = new byte[3 + sessionDataBytes.length];
                tag53Wrapped[0] = 0x53;
                tag53Wrapped[1] = (byte)0x81;
                tag53Wrapped[2] = (byte)(sessionDataBytes.length & 0xFF);
                System.arraycopy(sessionDataBytes, 0, tag53Wrapped, 3, sessionDataBytes.length);
            }
            else
            {
                tag53Wrapped = new byte[2 + sessionDataBytes.length];
                tag53Wrapped[0] = 0x53;
                tag53Wrapped[1] = (byte)sessionDataBytes.length;
                System.arraycopy(sessionDataBytes, 0, tag53Wrapped, 2, sessionDataBytes.length);
            }
            byte[] envelopeCmd = buildEnvelopeCommand(tag53Wrapped);
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
            //
            //    The credential wraps the ENVELOPE response in BER-TLV tag 0x53
            //    per Aliro Table 10-7. Strip the 0x53 TLV header to get the CBOR SessionData.
            byte[] sessionDataBytes2 = rawResponse;
            if (rawResponse.length > 2 && (rawResponse[0] & 0xFF) == 0x53)
            {
                int valOffset;
                int lenByte = rawResponse[1] & 0xFF;
                if (lenByte < 0x80)
                    valOffset = 2;
                else if (lenByte == 0x81)
                    valOffset = 3;
                else if (lenByte == 0x82)
                    valOffset = 4;
                else
                    valOffset = 2; // fallback
                sessionDataBytes2 = Arrays.copyOfRange(rawResponse, valOffset, rawResponse.length);
                Log.d(TAG, "Step-Up: stripped 0x53 TLV header (" + valOffset + " bytes), CBOR payload = " + sessionDataBytes2.length + " bytes");
            }
            com.upokecenter.cbor.CBORObject sessionDataIn =
                    com.upokecenter.cbor.CBORObject.DecodeFromBytes(sessionDataBytes2);
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

            // 7. Full Access Document / Revocation Document verification per §7.4 + §7.5
            // Load credential issuer public key(s) from preferences for kid-based
            // signature verification. The Step-Up Issuer Public Key field accepts
            // a single hex value or a comma-separated list (Aliro 1.0 §7.7) —
            // each stored credential document may have its own issuer keypair
            // and own kid, and the reader trusts any/all of them by listing
            // their public keys here.
            String issuerKeyHex = prefs.getString(AliroPreferences.STEP_UP_ISSUER_PUB_KEY, "");
            java.util.List<byte[]> trustedIssuerKeys = parseIssuerPubKeyList(issuerKeyHex);
            Log.d(TAG, "Step-Up: configured " + trustedIssuerKeys.size()
                    + " trusted issuer key(s)");

            // Multi-element verification: when the request asked for multiple
            // elements, the response carries multiple documents under "2".
            // Slice into one DeviceResponse per document and verify each
            // independently, concatenating the results for display. The last
            // VerificationResult wins for downstream status flags — any failure
            // among the slices surfaces in lastDocVerifyResult.
            java.util.List<byte[]> slices = sliceDeviceResponsePerDocument(deviceResponseBytes);
            if (slices.isEmpty())
            {
                // Fall back to the original single-doc path so callers still
                // see a meaningful result on a malformed/empty response.
                byte[] fallbackKey = trustedIssuerKeys.isEmpty() ? null : trustedIssuerKeys.get(0);
                AliroAccessDocumentVerifier.VerificationResult verifyResult =
                        AliroAccessDocumentVerifier.verifyDocument(
                                deviceResponseBytes, docType, credentialPubKey,
                                requestElementIds.get(0), fallbackKey);
                lastDocVerifyResult = verifyResult;
                Log.d(TAG, "Step-Up: verification result (single fallback): " + verifyResult);
                return verifyResult.stepUpResultText;
            }

            StringBuilder combinedText = new StringBuilder();
            AliroAccessDocumentVerifier.VerificationResult lastResult = null;
            int sliceIndex = 0;
            for (byte[] slice : slices)
            {
                // Pick the requested element ID for this slice. When we
                // requested N elements, slices arrive in the same order the
                // credential matched them, which mirrors the request order
                // in normal operation. If counts diverge (e.g. credential
                // dropped one as expired), we still verify each slice but
                // pass the i-th request ID where available.
                String sliceElementId = (sliceIndex < requestElementIds.size())
                        ? requestElementIds.get(sliceIndex)
                        : requestElementIds.get(requestElementIds.size() - 1);

                // Multi-issuer support (§7.7): pick the trusted key whose kid
                // matches THIS slice's IssuerAuth. With one trusted key
                // configured this is a no-op (returns it unchanged); with
                // multiple keys configured this picks the right one per slice.
                byte[] sliceIssuerKey = trustedIssuerKeys.isEmpty()
                        ? null
                        : pickIssuerKeyForKid(slice, trustedIssuerKeys);

                AliroAccessDocumentVerifier.VerificationResult vr =
                        AliroAccessDocumentVerifier.verifyDocument(
                                slice, docType, credentialPubKey, sliceElementId, sliceIssuerKey);
                lastResult = vr;
                if (vr.stepUpResultText != null && !vr.stepUpResultText.isEmpty())
                {
                    if (combinedText.length() > 0) combinedText.append("\n\n");
                    combinedText.append(vr.stepUpResultText);
                }
                sliceIndex++;
            }

            lastDocVerifyResult = lastResult;
            Log.d(TAG, "Step-Up: verified " + slices.size() + " document(s); "
                    + "lastResult=" + lastResult);

            return (combinedText.length() > 0)
                    ? combinedText.toString()
                    : (lastResult != null ? lastResult.stepUpResultText : null);
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
            // Multi-issuer support (Aliro 1.0 §7.7) — the field accepts a
            // single hex value or a CSV list. Picking happens per slice
            // below, matched by kid.
            java.util.List<byte[]> trustedIssuerKeys = parseIssuerPubKeyList(issuerKeyHex);

            com.upokecenter.cbor.CBORObject deviceResponse =
                    com.upokecenter.cbor.CBORObject.DecodeFromBytes(deviceResponseBytes);

            // Key "2" = documents array (Aliro Table 8-22). Multi-element
            // Step-Up returns one document per matching element, so iterate.
            com.upokecenter.cbor.CBORObject docs = deviceResponse.get(
                    com.upokecenter.cbor.CBORObject.FromObject("2"));
            if (docs == null || docs.size() == 0)
            {
                Log.d(TAG, "BLE Step-Up: no documents in DeviceResponse");
                return null;
            }

            // Resolve which element ID to anchor each summary on. When the
            // request carried a CSV ("floor1, floor2"), match each doc to
            // its corresponding requested ID by document order; this matches
            // how the credential composes the response (per-element slices
            // appended in request order).
            java.util.List<String> requestedIds = parseElementIdList(elementId);

            // Verify COSE_Sign1 once per IssuerAuth. With multi-doc each
            // doc may carry its own IssuerAuth signed by a different
            // issuer key (§7.7); allDocsVerified stays true only if every
            // doc verifies against some configured trusted key. We slice
            // each document into its own DeviceResponse to extract the
            // kid byte string for matching.
            boolean sawAnyVerification = false;
            boolean allDocsVerified    = true;

            // Re-slice once for kid extraction (extractKidFromSlice expects
            // a full single-doc DeviceResponse).
            java.util.List<byte[]> docSlices = sliceDeviceResponsePerDocument(deviceResponseBytes);

            StringBuilder all = new StringBuilder();
            for (int d = 0; d < docs.size(); d++)
            {
                com.upokecenter.cbor.CBORObject doc      = docs.get(d);
                com.upokecenter.cbor.CBORObject iSigned  = doc.get(
                        com.upokecenter.cbor.CBORObject.FromObject("1"));
                if (iSigned == null) continue;

                com.upokecenter.cbor.CBORObject iAuth      = iSigned.get(
                        com.upokecenter.cbor.CBORObject.FromObject("2"));
                com.upokecenter.cbor.CBORObject nameSpaces = iSigned.get(
                        com.upokecenter.cbor.CBORObject.FromObject("1"));

                if (!trustedIssuerKeys.isEmpty() && iAuth != null)
                {
                    byte[] sliceForKid = (d < docSlices.size()) ? docSlices.get(d) : null;
                    byte[] picked = (sliceForKid != null)
                            ? pickIssuerKeyForKid(sliceForKid, trustedIssuerKeys)
                            : trustedIssuerKeys.get(0);
                    String pickedHex = (picked != null)
                            ? org.bouncycastle.util.encoders.Hex.toHexString(picked)
                            : "";
                    boolean docVerified = !pickedHex.isEmpty()
                            && verifyCoseSign1(iAuth, pickedHex);
                    sawAnyVerification = true;
                    if (!docVerified) allDocsVerified = false;
                    Log.d(TAG, "BLE Step-Up: doc[" + d + "] COSE_Sign1 = " + docVerified
                            + " (key=" + (picked != null ? pickedHex.substring(0, 16) + "..." : "(none)") + ")");
                }

                String elemForSummary = (d < requestedIds.size())
                        ? requestedIds.get(d)
                        : (requestedIds.isEmpty() ? "access" : requestedIds.get(0));
                String accessSummary = extractAccessDataSummary(nameSpaces, elemForSummary);
                if (accessSummary != null && !accessSummary.isEmpty())
                {
                    if (all.length() > 0) all.append("\n\n");
                    all.append(accessSummary);
                }
            }

            String sigStatus;
            if (issuerKeyHex.isEmpty())            sigStatus = "(sig not verified)";
            else if (!sawAnyVerification)          sigStatus = "(sig not verified)";
            else                                   sigStatus = allDocsVerified
                                                         ? "Signature Valid"
                                                         : "Signature INVALID";

            StringBuilder result = new StringBuilder(sigStatus);
            if (all.length() > 0)
                result.append("\n").append(all);
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
        // CLA=00 INS=C3 P1=00 P2=00 Lc=<len> <data> Le=00
        // CLA=0x00 (interindustry class) per ISO 7816-4 §5.1.1
        // Le=0x00 (expect up to 256 bytes response) — MUST be present to avoid
        // harness setting apdu_response_length=0 which crashes response chaining.
        byte[] cmd = new byte[5 + data.length + 1];
        cmd[0] = 0x00;
        cmd[1] = (byte)0xC3;
        cmd[2] = 0x00;
        cmd[3] = 0x00;
        cmd[4] = (byte) data.length;
        System.arraycopy(data, 0, cmd, 5, data.length);
        cmd[5 + data.length] = 0x00; // Le
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

            // Try to find the requested elementId first; if not found, use the first
            // element available in the document (handles config mismatch gracefully).
            int matchIndex = -1;
            for (int i = 0; i < items.size(); i++)
            {
                byte[] ib = items.get(i).GetByteString();
                com.upokecenter.cbor.CBORObject it =
                        com.upokecenter.cbor.CBORObject.DecodeFromBytes(ib);
                com.upokecenter.cbor.CBORObject e =
                        it.get(com.upokecenter.cbor.CBORObject.FromObject("3"));
                if (e != null && elementId.equals(e.AsString())) { matchIndex = i; break; }
            }
            if (matchIndex < 0) matchIndex = 0; // fallback to first element

            for (int i = matchIndex; i <= matchIndex; i++)
            {
                // Each item is a bstr wrapping an IssuerSignedItem CBOR map
                byte[] itemBytes = items.get(i).GetByteString();
                com.upokecenter.cbor.CBORObject item =
                        com.upokecenter.cbor.CBORObject.DecodeFromBytes(itemBytes);
                com.upokecenter.cbor.CBORObject eid =
                        item.get(com.upokecenter.cbor.CBORObject.FromObject("3"));
                // Use the actual element ID from the document
                if (eid != null) elementId = eid.AsString();

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
            // Step-up is "Success" if the ENVELOPE exchange completed and a document
            // was returned, regardless of the access decision. A schedule-based deny
            // (error 00 25) is a valid step-up outcome, not a transport failure.
            // Only report "Failed" if the step-up transport itself broke (null result,
            // GCM failure, CBOR parse error, etc.).
            boolean stepUpSuccess = stepUpResult != null
                    && !stepUpResult.startsWith("Step-Up failed")
                    && !stepUpResult.isEmpty();
            sb.append("\n\nSTEP-UP: ").append(stepUpSuccess ? "Success" : "Failed");
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
            sb.append("\n\nMAILBOX\n");
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

    // -------------------------------------------------------------------------
    // Reader Descriptor TLV (Table 8-17): tag 0xB5 containing vendor/product/FW.
    // ELATEC IEEE OUI = 0x001CF7 (from Elatec GmbH's registered OUI).
    //
    // For EXCHANGE: descriptor must be inside tag 0xAE (Notify)
    // For CONTROL FLOW: descriptor must be inside tag 0x63 (Domain Specific Data)
    // -------------------------------------------------------------------------
    private static final byte[] READER_DESCRIPTOR_B5;
    private static final byte[] EXCHANGE_NOTIFY_TLV;     // 0xAE { 0xB5 { ... } }
    private static final byte[] CONTROL_FLOW_DOMAIN_TLV; // 0x63 { 0xB5 { ... } }
    static {
        byte[] vendorId  = { 0x04, 0x03, 0x00, 0x1C, (byte)0xF7 };           // tag 04, len 3, OUI
        byte[] productId = { (byte)0x80, 0x04, 'T', 'W', 'N', '4' };         // tag 80, len 4
        byte[] fwVersion = { (byte)0x81, 0x05, '1', '.', '0', '.', '0' };    // tag 81, len 5
        int innerLen = vendorId.length + productId.length + fwVersion.length;
        // B5 <len> <vendor + product + fw>
        byte[] b5 = new byte[2 + innerLen];
        b5[0] = (byte)0xB5;
        b5[1] = (byte)innerLen;
        int p = 2;
        System.arraycopy(vendorId,  0, b5, p, vendorId.length);  p += vendorId.length;
        System.arraycopy(productId, 0, b5, p, productId.length); p += productId.length;
        System.arraycopy(fwVersion, 0, b5, p, fwVersion.length);
        READER_DESCRIPTOR_B5 = b5;

        // EXCHANGE: wrap in 0xAE (Notify tag)
        EXCHANGE_NOTIFY_TLV = new byte[2 + b5.length];
        EXCHANGE_NOTIFY_TLV[0] = (byte)0xAE;
        EXCHANGE_NOTIFY_TLV[1] = (byte)b5.length;
        System.arraycopy(b5, 0, EXCHANGE_NOTIFY_TLV, 2, b5.length);

        // CONTROL FLOW: wrap in 0x63 (Domain Specific Data tag)
        CONTROL_FLOW_DOMAIN_TLV = new byte[2 + b5.length];
        CONTROL_FLOW_DOMAIN_TLV[0] = 0x63;
        CONTROL_FLOW_DOMAIN_TLV[1] = (byte)b5.length;
        System.arraycopy(b5, 0, CONTROL_FLOW_DOMAIN_TLV, 2, b5.length);
    }

    /**
     * Send CONTROL FLOW command to signal transaction failure when no secure channel exists.
     * Per section 10.2.2 and Table 8-2 rows 3/9: used when SW != 9000 or no EXCHANGE key.
     * INS=0x3C, data: 41 01 S1 | 42 01 S2 | [63 xx { B5 ... }] (reader descriptor)
     *
     * CLA=0x80 per §8.3.2.1 (proprietary class for all expedited-phase commands).
     * No Le byte — §10.2.2.2 says empty response data field (Case 3 APDU).
     */
    private void sendControlFlow(IsoDep isoDep)
    {
        sendControlFlow(isoDep, (byte)0x00); // S2 = 0x00: no information
    }

    /**
     * Send CONTROL FLOW with a specific S2 parameter.
     * @param s2val  S2 byte: 0x00=no info, 0x27=protocol version not supported
     */
    private void sendControlFlow(IsoDep isoDep, byte s2val)
    {
        try
        {
            // Data: 41 01 00 | 42 01 S2 | 63 xx { B5 xx { ... } } (domain specific data)
            byte[] s1 = { 0x41, 0x01, 0x00 };       // S1 = 0x00: failure
            byte[] s2 = { 0x42, 0x01, s2val };      // S2 = caller-specified
            int dataLen = s1.length + s2.length + CONTROL_FLOW_DOMAIN_TLV.length;
            byte[] controlFlow = new byte[5 + dataLen]; // header(5) + data, NO Le byte
            controlFlow[0] = (byte)0x80;
            controlFlow[1] = 0x3C;
            controlFlow[2] = 0x00;
            controlFlow[3] = 0x00;
            controlFlow[4] = (byte)dataLen;
            int idx = 5;
            System.arraycopy(s1, 0, controlFlow, idx, s1.length); idx += s1.length;
            System.arraycopy(s2, 0, controlFlow, idx, s2.length); idx += s2.length;
            System.arraycopy(CONTROL_FLOW_DOMAIN_TLV, 0, controlFlow, idx, CONTROL_FLOW_DOMAIN_TLV.length);
            Log.d(TAG, "Sending CONTROL FLOW S2=0x" + String.format("%02X", s2val)
                    + " (" + dataLen + " bytes data)");
            byte[] response = isoDep.transceive(controlFlow);
            Log.d(TAG, "CONTROL FLOW response: " + Hex.toHexString(response));
        }
        catch (Exception e)
        {
            Log.w(TAG, "CONTROL FLOW send failed (non-fatal): " + e.getMessage());
        }
    }
}
