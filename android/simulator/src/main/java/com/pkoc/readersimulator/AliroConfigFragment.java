package com.pkoc.readersimulator;

import android.app.AlertDialog;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextUtils;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.AdapterView;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.TextView;

import androidx.activity.OnBackPressedCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.journeyapps.barcodescanner.ScanContract;
import com.journeyapps.barcodescanner.ScanIntentResult;
import com.journeyapps.barcodescanner.ScanOptions;

import org.json.JSONObject;

/**
 * Fragment for configuring Aliro reader parameters.
 *
 * Values are stored in SharedPreferences and loaded by HomeFragment
 * when an Aliro NFC or BLE transaction begins.
 *
 * LEAF Verified configuration has been moved to {@link LeafConfigFragment}.
 */
public class AliroConfigFragment extends Fragment
{
    private EditText editReaderPrivateKey;
    private EditText editReaderId;
    private EditText editReaderIssuerPublicKey;
    private EditText editReaderCertificate;
    private EditText editStepUpElementId;
    private EditText editStepUpIssuerPubKey;
    private TextView txtStatus;

    // Cert delivery mode
    private Spinner  spinnerCertMode;
    private static final String[] CERT_MODE_VALUES = {
            AliroPreferences.CERT_MODE_NONE,
            AliroPreferences.CERT_MODE_LOAD_CERT,
            AliroPreferences.CERT_MODE_AUTH1
    };
    private static final String[] CERT_MODE_LABELS = {
            "None (no cert)",
            "LOAD CERT command",
            "Embed in AUTH1"
    };

    // Chaining + FAST mode
    private CheckBox chkForceChaining;
    private CheckBox chkFastMode;

    // Mailbox fields
    private CheckBox chkMailboxEnabled;
    private Spinner  spinnerMailboxOperation;
    private EditText editMailboxOffset;
    private Spinner  spinnerMailboxLength;
    private static final String[] MAILBOX_LENGTH_OPTIONS = { "64", "128", "256", "512", "1024" };
    private static final String[] MAILBOX_LENGTH_LABELS  = { "64 bytes", "128 bytes", "256 bytes", "512 bytes", "1024 bytes" };
    private TextView lblMailboxLength;
    private EditText editMailboxData;
    private TextView lblMailboxData;
    private EditText editMailboxSetValue;
    private TextView lblMailboxSetValue;
    private CheckBox chkMailboxAtomic;

    // Dirty tracking — prompts user to save when navigating away
    private boolean dirty = false;
    private boolean loadingPrefs = false; // suppress dirty during initial load

    // Separate launchers for two different QR scan purposes
    private final ActivityResultLauncher<ScanOptions> qrScanLauncher =
            registerForActivityResult(new ScanContract(), this::onQrScanResult);

    private final ActivityResultLauncher<ScanOptions> importConfigScanLauncher =
            registerForActivityResult(new ScanContract(), this::onImportConfigScanResult);

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState)
    {
        return inflater.inflate(R.layout.fragment_aliro_config, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        editReaderPrivateKey    = view.findViewById(R.id.editReaderPrivateKey);
        editReaderId            = view.findViewById(R.id.editReaderId);
        editReaderIssuerPublicKey = view.findViewById(R.id.editReaderIssuerPublicKey);
        editReaderCertificate   = view.findViewById(R.id.editReaderCertificate);
        editStepUpElementId     = view.findViewById(R.id.editStepUpElementId);
        editStepUpIssuerPubKey  = view.findViewById(R.id.editStepUpIssuerPubKey);
        txtStatus               = view.findViewById(R.id.txtAliroConfigStatus);
        Button btnSave          = view.findViewById(R.id.btnSaveAliroConfig);
        Button btnScanQr        = view.findViewById(R.id.btnScanIssuerKeyQr);
        Button btnImportConfig  = view.findViewById(R.id.btnImportFromCredential);

        // Cert delivery mode spinner
        spinnerCertMode = view.findViewById(R.id.spinnerCertMode);
        ArrayAdapter<String> certModeAdapter = new ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_item, CERT_MODE_LABELS);
        certModeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerCertMode.setAdapter(certModeAdapter);
        chkForceChaining = view.findViewById(R.id.chkForceChaining);
        chkFastMode      = view.findViewById(R.id.chkFastMode);

        // Mailbox bindings
        chkMailboxEnabled       = view.findViewById(R.id.chkMailboxEnabled);
        spinnerMailboxOperation = view.findViewById(R.id.spinnerMailboxOperation);
        editMailboxOffset       = view.findViewById(R.id.editMailboxOffset);
        spinnerMailboxLength    = view.findViewById(R.id.spinnerMailboxLength);
        android.widget.ArrayAdapter<String> mailboxLenAdapter = new android.widget.ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_item, MAILBOX_LENGTH_LABELS);
        mailboxLenAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerMailboxLength.setAdapter(mailboxLenAdapter);
        lblMailboxLength        = view.findViewById(R.id.lblMailboxLength);
        editMailboxData         = view.findViewById(R.id.editMailboxData);
        lblMailboxData          = view.findViewById(R.id.lblMailboxData);
        editMailboxSetValue     = view.findViewById(R.id.editMailboxSetValue);
        lblMailboxSetValue      = view.findViewById(R.id.lblMailboxSetValue);
        chkMailboxAtomic        = view.findViewById(R.id.chkMailboxAtomic);

        // Setup mailbox operation spinner
        String[] ops = { "read", "write", "set" };
        ArrayAdapter<String> adapter = new ArrayAdapter<>(requireContext(),
                android.R.layout.simple_spinner_item, ops);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerMailboxOperation.setAdapter(adapter);
        spinnerMailboxOperation.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener()
        {
            @Override public void onItemSelected(AdapterView<?> parent, View v, int pos, long id)
            {
                updateMailboxFieldVisibility(ops[pos]);
            }
            @Override public void onNothingSelected(AdapterView<?> parent) {}
        });

        loadingPrefs = true;
        loadFromPreferences();
        loadingPrefs = false;

        btnSave.setOnClickListener(v -> saveToPreferences());
        btnScanQr.setOnClickListener(v -> launchQrScanner());
        btnImportConfig.setOnClickListener(v -> launchImportConfigScanner());

        // ---------------------------------------------------------------
        // Dirty tracking: mark form as dirty when any field changes.
        // Suppressed during loadFromPreferences() via loadingPrefs flag.
        // ---------------------------------------------------------------
        TextWatcher dirtyWatcher = new TextWatcher()
        {
            @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) {}
            @Override public void onTextChanged(CharSequence s, int start, int before, int count) {}
            @Override public void afterTextChanged(Editable s)
            {
                if (!loadingPrefs) dirty = true;
            }
        };
        editReaderPrivateKey.addTextChangedListener(dirtyWatcher);
        editReaderId.addTextChangedListener(dirtyWatcher);
        editReaderIssuerPublicKey.addTextChangedListener(dirtyWatcher);
        editReaderCertificate.addTextChangedListener(dirtyWatcher);
        editStepUpElementId.addTextChangedListener(dirtyWatcher);
        editStepUpIssuerPubKey.addTextChangedListener(dirtyWatcher);
        editMailboxOffset.addTextChangedListener(dirtyWatcher);
        editMailboxData.addTextChangedListener(dirtyWatcher);
        editMailboxSetValue.addTextChangedListener(dirtyWatcher);

        AdapterView.OnItemSelectedListener dirtySpinnerListener =
                new AdapterView.OnItemSelectedListener()
        {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id)
            {
                if (!loadingPrefs) dirty = true;
            }
            @Override public void onNothingSelected(AdapterView<?> p) {}
        };
        spinnerCertMode.setOnItemSelectedListener(dirtySpinnerListener);
        // Note: spinnerMailboxOperation already has a listener for visibility;
        // dirty is also set via the TextWatcher on dependent fields.

        CheckBox.OnCheckedChangeListener dirtyCheckListener =
                (buttonView, isChecked) -> { if (!loadingPrefs) dirty = true; };
        chkForceChaining.setOnCheckedChangeListener(dirtyCheckListener);
        chkFastMode.setOnCheckedChangeListener(dirtyCheckListener);
        chkMailboxEnabled.setOnCheckedChangeListener(dirtyCheckListener);
        chkMailboxAtomic.setOnCheckedChangeListener(dirtyCheckListener);

        // ---------------------------------------------------------------
        // Intercept back navigation: prompt to save if dirty
        // ---------------------------------------------------------------
        requireActivity().getOnBackPressedDispatcher().addCallback(
                getViewLifecycleOwner(), new OnBackPressedCallback(true)
        {
            @Override
            public void handleOnBackPressed()
            {
                if (dirty)
                {
                    new AlertDialog.Builder(requireContext())
                            .setTitle("Unsaved Changes")
                            .setMessage("You have unsaved changes. Save before leaving?")
                            .setPositiveButton("Save", (d, w) -> {
                                saveToPreferences();
                                dirty = false;
                                setEnabled(false);
                                requireActivity().getOnBackPressedDispatcher().onBackPressed();
                            })
                            .setNegativeButton("Discard", (d, w) -> {
                                dirty = false;
                                setEnabled(false);
                                requireActivity().getOnBackPressedDispatcher().onBackPressed();
                            })
                            .setNeutralButton("Cancel", null)
                            .show();
                }
                else
                {
                    setEnabled(false);
                    requireActivity().getOnBackPressedDispatcher().onBackPressed();
                }
            }
        });
    }

    private void updateMailboxFieldVisibility(String op)
    {
        boolean isWrite = "write".equals(op);
        boolean isSet   = "set".equals(op);
        boolean isRead  = "read".equals(op);

        lblMailboxLength.setVisibility(isRead || isSet ? View.VISIBLE : View.GONE);
        spinnerMailboxLength.setVisibility(isRead || isSet ? View.VISIBLE : View.GONE);
        lblMailboxData.setVisibility(isWrite ? View.VISIBLE : View.GONE);
        editMailboxData.setVisibility(isWrite ? View.VISIBLE : View.GONE);
        lblMailboxSetValue.setVisibility(isSet ? View.VISIBLE : View.GONE);
        editMailboxSetValue.setVisibility(isSet ? View.VISIBLE : View.GONE);
    }

    // -------------------------------------------------------------------------

    private void loadFromPreferences()
    {
        SharedPreferences prefs = requireActivity()
                .getPreferences(Context.MODE_PRIVATE);

        editReaderPrivateKey.setText(
                prefs.getString(AliroPreferences.READER_PRIVATE_KEY, ""));
        editReaderId.setText(
                prefs.getString(AliroPreferences.READER_ID, ""));
        editReaderIssuerPublicKey.setText(
                prefs.getString(AliroPreferences.READER_ISSUER_PUBLIC_KEY, ""));
        editReaderCertificate.setText(
                prefs.getString(AliroPreferences.READER_CERTIFICATE, ""));
        editStepUpElementId.setText(
                prefs.getString(AliroPreferences.STEP_UP_ELEMENT_ID, ""));
        editStepUpIssuerPubKey.setText(
                prefs.getString(AliroPreferences.STEP_UP_ISSUER_PUB_KEY, ""));

        // Load cert delivery mode
        String savedCertMode = prefs.getString(AliroPreferences.CERT_DELIVERY_MODE,
                AliroPreferences.CERT_MODE_LOAD_CERT);
        spinnerCertMode.setSelection(1); // default: LOAD CERT
        for (int i = 0; i < CERT_MODE_VALUES.length; i++)
        {
            if (CERT_MODE_VALUES[i].equals(savedCertMode))
            {
                spinnerCertMode.setSelection(i);
                break;
            }
        }

        // Load chaining + FAST
        chkForceChaining.setChecked(prefs.getBoolean(AliroPreferences.CERT_FORCE_CHAINING, false));
        chkFastMode.setChecked(prefs.getBoolean(AliroPreferences.FAST_MODE_ENABLED, false));

        // Load mailbox config
        chkMailboxEnabled.setChecked(prefs.getBoolean(AliroPreferences.MAILBOX_ENABLED, false));
        String mailboxOp = prefs.getString(AliroPreferences.MAILBOX_OPERATION, "read");
        String[] ops = { "read", "write", "set" };
        for (int i = 0; i < ops.length; i++)
        {
            if (ops[i].equals(mailboxOp))
            {
                spinnerMailboxOperation.setSelection(i);
                break;
            }
        }
        editMailboxOffset.setText(prefs.getString(AliroPreferences.MAILBOX_OFFSET, "0"));
        // Restore mailbox length spinner to saved position
        String savedLen = prefs.getString(AliroPreferences.MAILBOX_LENGTH, "256");
        spinnerMailboxLength.setSelection(2); // default: 256 bytes
        for (int i = 0; i < MAILBOX_LENGTH_OPTIONS.length; i++)
        {
            if (MAILBOX_LENGTH_OPTIONS[i].equals(savedLen))
            {
                spinnerMailboxLength.setSelection(i);
                break;
            }
        }
        editMailboxData.setText(prefs.getString(AliroPreferences.MAILBOX_DATA, ""));
        editMailboxSetValue.setText(prefs.getString(AliroPreferences.MAILBOX_SET_VALUE, "00"));
        chkMailboxAtomic.setChecked(prefs.getBoolean(AliroPreferences.MAILBOX_ATOMIC, false));
        updateMailboxFieldVisibility(mailboxOp);
    }

    private void saveToPreferences()
    {
        String privateKey      = editReaderPrivateKey.getText().toString().trim().toLowerCase();
        String readerId        = editReaderId.getText().toString().trim().toLowerCase();
        String issuerKey       = editReaderIssuerPublicKey.getText().toString().trim().toLowerCase();
        String cert            = editReaderCertificate.getText().toString().trim().toLowerCase();
        String stepUpElementId = editStepUpElementId.getText().toString().trim();
        String stepUpIssuerKey = editStepUpIssuerPubKey.getText().toString().trim().toLowerCase();

        // Validate required fields
        if (!isValidHex(privateKey, 64))
        {
            showStatus("Reader Private Key must be exactly 64 hex characters (32 bytes).", false);
            return;
        }
        if (!isValidHex(readerId, 64))
        {
            showStatus("Reader Identifier must be exactly 64 hex characters (32 bytes).", false);
            return;
        }

        // Validate optional certificate fields — both must be present or both absent
        boolean hasCert    = !TextUtils.isEmpty(cert);
        boolean hasIssuer  = !TextUtils.isEmpty(issuerKey);

        if (hasCert != hasIssuer)
        {
            showStatus("Provide both Issuer Public Key and Certificate, or leave both blank.", false);
            return;
        }
        if (hasIssuer && !isValidHex(issuerKey, 130))
        {
            showStatus("Reader Issuer Public Key must be exactly 130 hex characters (65 bytes).", false);
            return;
        }
        if (hasCert && (cert.length() % 2 != 0))
        {
            showStatus("Reader Certificate must be an even number of hex characters.", false);
            return;
        }

        SharedPreferences.Editor editor = requireActivity()
                .getPreferences(Context.MODE_PRIVATE)
                .edit();
        editor.putString(AliroPreferences.READER_PRIVATE_KEY,    privateKey);
        editor.putString(AliroPreferences.READER_ID,             readerId);
        editor.putString(AliroPreferences.READER_ISSUER_PUBLIC_KEY, issuerKey);
        editor.putString(AliroPreferences.READER_CERTIFICATE,    cert);
        editor.putString(AliroPreferences.STEP_UP_ELEMENT_ID,    stepUpElementId);
        editor.putString(AliroPreferences.STEP_UP_ISSUER_PUB_KEY, stepUpIssuerKey);

        // Save cert delivery mode + chaining
        editor.putString(AliroPreferences.CERT_DELIVERY_MODE,
                CERT_MODE_VALUES[spinnerCertMode.getSelectedItemPosition()]);
        editor.putBoolean(AliroPreferences.CERT_FORCE_CHAINING,
                chkForceChaining.isChecked());
        editor.putBoolean(AliroPreferences.FAST_MODE_ENABLED,
                chkFastMode.isChecked());

        // Save mailbox config
        editor.putBoolean(AliroPreferences.MAILBOX_ENABLED,
                chkMailboxEnabled.isChecked());
        editor.putString(AliroPreferences.MAILBOX_OPERATION,
                (String) spinnerMailboxOperation.getSelectedItem());
        editor.putString(AliroPreferences.MAILBOX_OFFSET,
                editMailboxOffset.getText().toString().trim());
        editor.putString(AliroPreferences.MAILBOX_LENGTH,
                MAILBOX_LENGTH_OPTIONS[spinnerMailboxLength.getSelectedItemPosition()]);
        editor.putString(AliroPreferences.MAILBOX_DATA,
                editMailboxData.getText().toString().trim());
        editor.putString(AliroPreferences.MAILBOX_SET_VALUE,
                editMailboxSetValue.getText().toString().trim());
        editor.putBoolean(AliroPreferences.MAILBOX_ATOMIC,
                chkMailboxAtomic.isChecked());

        // Use commit() (synchronous) instead of apply() (asynchronous) so that
        // the preference is guaranteed to be on disk before the process can die
        // between tests. This prevents CERT_DELIVERY_MODE and other settings from
        // reverting to defaults if the Activity is recreated by the test harness.
        editor.commit();

        dirty = false;
        showStatus("Saved.", true);
    }

    // -------------------------------------------------------------------------
    // QR scanner: Step-Up Issuer Key (legacy single-key QR)
    // -------------------------------------------------------------------------

    private void launchQrScanner()
    {
        ScanOptions options = new ScanOptions();
        options.setDesiredBarcodeFormats(ScanOptions.QR_CODE);
        options.setPrompt("Scan the issuer key QR from the credential device");
        options.setBeepEnabled(false);
        options.setOrientationLocked(false);
        qrScanLauncher.launch(options);
    }

    private void onQrScanResult(ScanIntentResult result)
    {
        if (result.getContents() == null) return;   // cancelled
        String scanned = result.getContents().trim().toLowerCase();
        if (scanned.length() == 130 && scanned.matches("[0-9a-f]+"))
        {
            editStepUpIssuerPubKey.setText(scanned);
            // Auto-populate Step-Up Element ID if empty — the Aliro spec
            // default element identifier is "access" (see §7.2.5, Table 7-7).
            // Without this, the reader won't request the Access Document even
            // though the credential signals one is available (Bit0=1).
            if (editStepUpElementId.getText().toString().trim().isEmpty())
            {
                editStepUpElementId.setText("access");
            }
            showStatus("Issuer key scanned — tap Save to apply.", true);
        }
        else
        {
            showStatus("QR scan did not contain a valid 65-byte EC public key.", false);
        }
    }

    // -------------------------------------------------------------------------
    // QR scanner: Import full reader config from credential app
    // -------------------------------------------------------------------------

    private void launchImportConfigScanner()
    {
        ScanOptions options = new ScanOptions();
        options.setDesiredBarcodeFormats(ScanOptions.QR_CODE);
        options.setPrompt("Scan the Reader Config QR from the credential app");
        options.setBeepEnabled(false);
        options.setOrientationLocked(false);
        importConfigScanLauncher.launch(options);
    }

    private void onImportConfigScanResult(ScanIntentResult result)
    {
        if (result.getContents() == null) return;   // cancelled
        String scanned = result.getContents().trim();
        try
        {
            JSONObject obj = new JSONObject(scanned);
            if (obj.optInt("v", 0) != 1 ||
                !"aliro_reader_config".equals(obj.optString("type", "")))
            {
                showStatus("QR does not contain a valid Aliro reader config.", false);
                return;
            }

            String readerPrivKey   = obj.getString("readerPrivateKey").toLowerCase(java.util.Locale.US);
            String readerId        = obj.getString("readerId").toLowerCase(java.util.Locale.US);
            String readerCert      = obj.getString("readerCert").toLowerCase(java.util.Locale.US);
            String issuerPubKey    = obj.getString("issuerPubKey").toLowerCase(java.util.Locale.US);

            // Populate the edit fields
            editReaderPrivateKey.setText(readerPrivKey);
            editReaderId.setText(readerId);
            editReaderIssuerPublicKey.setText(issuerPubKey);
            editReaderCertificate.setText(readerCert);

            // Auto-fill Step-Up Element ID if empty
            if (editStepUpElementId.getText().toString().trim().isEmpty())
            {
                editStepUpElementId.setText("access");
            }

            // NOTE: Do NOT auto-fill Step-Up Issuer Public Key from the Reader CA key.
            // The Reader Issuer CA key (issuerPubKey) signs the reader certificate.
            // The Step-Up Issuer key signs the Access/Revocation Documents on the
            // credential side — it's a completely different keypair. Use the
            // credential app's COPY KEY button to get the correct value.

            showStatus("\u2713 Reader config imported\n"
                    + "Reader ID: " + readerId.substring(0, Math.min(8, readerId.length())) + "...\n"
                    + "Cert: " + (readerCert.length() / 2) + " bytes\n"
                    + "Tap Save to apply.", true);
        }
        catch (Exception e)
        {
            showStatus("Failed to parse reader config QR: " + e.getMessage(), false);
        }
    }

    // -------------------------------------------------------------------------

    private void showStatus(String message, boolean success)
    {
        txtStatus.setVisibility(View.VISIBLE);
        txtStatus.setText(message);
        txtStatus.setTextColor(success
                ? requireContext().getColor(R.color.colorAccent)
                : requireContext().getColor(android.R.color.holo_red_dark));
    }

    /**
     * Check that a string is a valid hex string of exactly the expected length.
     * Pass expectedLength = -1 to skip length check.
     */
    private static boolean isValidHex(String s, int expectedLength)
    {
        if (TextUtils.isEmpty(s)) return false;
        if (expectedLength >= 0 && s.length() != expectedLength) return false;
        return s.matches("[0-9a-f]+");
    }
}
