package com.psia.pkoc;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.util.Base64;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.psia.pkoc.core.AliroAccessDocument;
import com.psia.pkoc.core.AliroMailbox;
import com.psia.pkoc.core.AliroProvisioningManager;

import java.security.KeyStore;
import java.security.interfaces.ECPublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Credential-side Aliro configuration screen.
 *
 * Allows the user to:
 *   1. Generate a self-signed test Access Document (minimal, for Step-Up flow testing)
 *   2. Load a realistic sample Access Document (employee badge with schedules + rules)
 *   3. Import a pre-built Access Document from Base64 CBOR + issuer public key
 *   4. View the current document status (mode, element ID, expiry)
 *   5. Clear the stored document
 *   6. Initialize mailbox with all-zero bytes (selected size)
 *   7. Load a realistic sample mailbox (ELATEC §18 TLV with reader config + door status)
 *   8. Clear the mailbox
 *
 * LEAF Verified configuration has been moved to {@link CredentialLeafConfigFragment}.
 */
public class CredentialAliroConfigFragment extends Fragment
{
    // Provisioning section views
    private TextView    txtProvisioningStatus;
    private Button      btnProvision;
    private CheckBox    chkStrictMode;
    private Button      btnExportReaderConfig;
    private Button      btnClearProvisioning;

    // Test Harness section views
    private EditText    editTestHarnessGroupId;
    private EditText    editTestHarnessIssuerCa;
    private EditText    editTestHarnessReaderPubKey;
    private Button      btnApplyTestHarness;

    private TextView    txtDocumentStatus;
    private Button      btnGenerateTest;
    private Button      btnLoadSampleDoc;
    private Button      btnAddElement;
    private Button      btnImport;
    private Button      btnClear;
    private Button      btnCopyIssuerKey;
    private Button      btnShowQr;
    private LinearLayout layoutIssuerKey;
    private TextView    txtIssuerKeyPreview;
    private EditText    editElementId;
    private EditText    editEmployeeId;
    private Spinner     spinnerSchedulePreset;
    private TextView    txtStatus;

    // Multi-document UI (Aliro 1.0 §8.4.2 multi-element)
    private Spinner     spinnerStoredDocs;
    private Button      btnCreateNewDoc;
    private Button      btnDeleteCurrentDoc;
    private Button      btnRefreshValidity;
    /** True when we are programmatically updating spinnerStoredDocs and want
     *  to suppress the OnItemSelected callback to avoid recursive refresh. */
    private boolean     suppressDocSpinnerEvent = false;

    // Edit-element-in-place UI (preserves issuer keypair / kid per §7.3)
    private Spinner     spinnerExistingElements;
    /** Recursion guard for spinnerExistingElements: programmatic adapter
     *  rebuilds and selection changes from refresh shouldn't fire the
     *  per-element form-populate handler. */
    private boolean     suppressElemSpinnerEvent = false;
    /** Sentinel for the "(new element…)" first row of spinnerExistingElements;
     *  when this is selected the form is in fresh-add mode. */
    private static final String NEW_ELEMENT_LABEL = "(new element\u2026)";

    // Mailbox viewer
    private TextView    txtMailboxSize;
    private TextView    txtMailboxHexDump;
    private Spinner     spinnerMailboxSize;
    private Button      btnInitMailbox;
    private Button      btnLoadSampleMailbox;
    private Button      btnClearMailbox;

    private static final String MAILBOX_PREFS_NAME = "AliroMailbox";
    private static final String MAILBOX_PREF_KEY   = "mailbox";
    private static final String[] MAILBOX_SIZES       = { "64", "128", "256", "512", "1024" };
    private static final String[] MAILBOX_SIZE_LABELS  = { "64 bytes", "128 bytes", "256 bytes", "512 bytes", "1024 bytes" };

    /**
     * Schedule preset labels, in {@link AliroAccessDocument.SchedulePreset#values()}
     * order so spinner position maps 1:1 to enum ordinal. Update both arrays
     * together if a new preset is added on the production side.
     */
    private static final String[] SCHEDULE_PRESET_LABELS = {
            "Always Allow (24x7)",
            "Weekday + Weekend (legacy sample)",
            "Weekday Extended (06:00-22:00)",
            "Weekend 24h (Secure only)",
            "Night Shift (Mon-Fri 22:00-06:00)"
    };

    private final ExecutorService executor = Executors.newSingleThreadExecutor();
    private final Handler         uiHandler = new Handler(Looper.getMainLooper());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState)
    {
        return inflater.inflate(R.layout.fragment_credential_aliro_config, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        // Provisioning section
        txtProvisioningStatus = view.findViewById(R.id.txtProvisioningStatus);
        btnProvision          = view.findViewById(R.id.btnProvisionCredential);
        chkStrictMode         = view.findViewById(R.id.chkStrictMode);
        btnExportReaderConfig = view.findViewById(R.id.btnExportReaderConfig);
        btnClearProvisioning  = view.findViewById(R.id.btnClearProvisioning);

        txtDocumentStatus  = view.findViewById(R.id.txtAccessDocStatus);
        btnGenerateTest    = view.findViewById(R.id.btnGenerateTestDoc);
        btnLoadSampleDoc   = view.findViewById(R.id.btnLoadSampleDoc);
        btnAddElement      = view.findViewById(R.id.btnAddElement);
        btnImport          = view.findViewById(R.id.btnImportDoc);
        btnClear           = view.findViewById(R.id.btnClearDoc);
        btnCopyIssuerKey   = view.findViewById(R.id.btnCopyIssuerKey);
        btnShowQr          = view.findViewById(R.id.btnShowQr);
        layoutIssuerKey    = view.findViewById(R.id.layoutIssuerKey);
        txtIssuerKeyPreview = view.findViewById(R.id.txtIssuerKeyPreview);
        editElementId      = view.findViewById(R.id.editElementIdentifier);
        editEmployeeId     = view.findViewById(R.id.editEmployeeId);
        spinnerSchedulePreset = view.findViewById(R.id.spinnerSchedulePreset);
        txtStatus          = view.findViewById(R.id.txtCredAliroStatus);

        // Multi-doc UI (Aliro 1.0 §8.4.2 multi-element)
        spinnerStoredDocs    = view.findViewById(R.id.spinnerStoredDocs);
        btnCreateNewDoc      = view.findViewById(R.id.btnCreateNewDoc);
        btnDeleteCurrentDoc  = view.findViewById(R.id.btnDeleteCurrentDoc);
        btnRefreshValidity   = view.findViewById(R.id.btnRefreshValidity);

        // Edit-element UI: spinner of elements in the currently selected
        // document. Selecting one populates the form so the user can edit
        // it and tap "Update Element" to apply the change in place.
        spinnerExistingElements = view.findViewById(R.id.spinnerExistingElements);
        if (spinnerExistingElements != null)
        {
            spinnerExistingElements.setOnItemSelectedListener(
                    new android.widget.AdapterView.OnItemSelectedListener()
                    {
                        @Override public void onItemSelected(
                                android.widget.AdapterView<?> parent,
                                android.view.View v, int position, long id)
                        {
                            if (suppressElemSpinnerEvent) return;
                            Object selected = parent.getItemAtPosition(position);
                            String label = (selected != null) ? selected.toString() : "";
                            onExistingElementSelected(label);
                        }
                        @Override public void onNothingSelected(
                                android.widget.AdapterView<?> parent) { }
                    });
        }

        // Schedule Preset spinner — labels in same order as
        // AliroAccessDocument.SchedulePreset.values() so position maps
        // directly to enum ordinal.
        ArrayAdapter<String> presetAdapter = new ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_item, SCHEDULE_PRESET_LABELS);
        presetAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerSchedulePreset.setAdapter(presetAdapter);
        // Default selection: WEEKDAY_AND_WEEKEND (legacy sample) — position 1.
        // Keeps "Generate Test Doc" / "Load Sample Doc" producing the same
        // bytes they always did when the user hasn't picked a preset.
        spinnerSchedulePreset.setSelection(1);

        // Mailbox viewer
        txtMailboxSize        = view.findViewById(R.id.txtMailboxSize);
        txtMailboxHexDump     = view.findViewById(R.id.txtMailboxHexDump);
        spinnerMailboxSize    = view.findViewById(R.id.spinnerMailboxSize);
        btnInitMailbox        = view.findViewById(R.id.btnInitMailbox);
        btnLoadSampleMailbox  = view.findViewById(R.id.btnLoadSampleMailbox);
        btnClearMailbox       = view.findViewById(R.id.btnClearMailbox);

        ArrayAdapter<String> sizeAdapter = new ArrayAdapter<>(
                requireContext(), android.R.layout.simple_spinner_item, MAILBOX_SIZE_LABELS);
        sizeAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinnerMailboxSize.setAdapter(sizeAdapter);
        spinnerMailboxSize.setSelection(2); // default: 256

        refreshProvisioningStatus();
        refreshDocumentStatus();
        refreshMailboxViewer();

        // Provisioning listeners
        btnProvision.setOnClickListener(v -> provisionRealCredential());
        chkStrictMode.setOnCheckedChangeListener((cb, checked) ->
                AliroProvisioningManager.setStrictMode(requireContext(), checked));
        btnExportReaderConfig.setOnClickListener(v -> exportReaderConfig());
        btnClearProvisioning.setOnClickListener(v -> confirmClearProvisioning());

        // Test Harness section
        editTestHarnessGroupId      = view.findViewById(R.id.editTestHarnessGroupId);
        editTestHarnessIssuerCa     = view.findViewById(R.id.editTestHarnessIssuerCa);
        editTestHarnessReaderPubKey = view.findViewById(R.id.editTestHarnessReaderPubKey);
        btnApplyTestHarness         = view.findViewById(R.id.btnApplyTestHarness);

        // Pre-populate with current values if set
        loadTestHarnessFields();

        btnApplyTestHarness.setOnClickListener(v -> applyTestHarnessConfig());

        btnGenerateTest.setOnClickListener(v -> generateTestDocument());
        btnLoadSampleDoc.setOnClickListener(v -> loadSampleDocument());
        btnAddElement.setOnClickListener(v -> addElementToDocument());
        btnImport.setOnClickListener(v -> showImportDialog());
        btnClear.setOnClickListener(v -> clearDocument());
        btnCopyIssuerKey.setOnClickListener(v -> copyIssuerKeyToClipboard());
        btnShowQr.setOnClickListener(v -> showIssuerKeyQrDialog());
        btnInitMailbox.setOnClickListener(v -> initializeMailbox());
        btnLoadSampleMailbox.setOnClickListener(v -> loadSampleMailbox());
        btnClearMailbox.setOnClickListener(v -> clearMailbox());

        // Multi-doc handlers
        btnCreateNewDoc.setOnClickListener(v -> showCreateNewDocumentDialog());
        btnDeleteCurrentDoc.setOnClickListener(v -> confirmDeleteCurrentDocument());
        btnRefreshValidity.setOnClickListener(v -> confirmRefreshValidity());
        spinnerStoredDocs.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener()
        {
            @Override
            public void onItemSelected(android.widget.AdapterView<?> parent, View v, int pos, long id)
            {
                if (suppressDocSpinnerEvent) return;
                onStoredDocSelected(pos);
            }
            @Override public void onNothingSelected(android.widget.AdapterView<?> parent) { }
        });
    }

    @Override
    public void onResume()
    {
        super.onResume();
        refreshMailboxViewer();
    }

    @Override
    public void onDestroyView()
    {
        super.onDestroyView();
        executor.shutdown();
    }

    // -------------------------------------------------------------------------
    // Real Credential Provisioning
    // -------------------------------------------------------------------------

    private void refreshProvisioningStatus()
    {
        if (!isAdded()) return;
        boolean provisioned = AliroProvisioningManager.isProvisioned(requireContext());
        boolean strictMode  = AliroProvisioningManager.isStrictMode(requireContext());

        txtProvisioningStatus.setText(AliroProvisioningManager.getStatusSummary(requireContext()));
        txtProvisioningStatus.setTextColor(provisioned
                ? requireContext().getColor(R.color.colorAccent)
                : requireContext().getColor(android.R.color.darker_gray));

        // Suppress the listener while programmatically setting the checkbox
        chkStrictMode.setOnCheckedChangeListener(null);
        chkStrictMode.setChecked(strictMode);
        chkStrictMode.setOnCheckedChangeListener((cb, checked) ->
                AliroProvisioningManager.setStrictMode(requireContext(), checked));

        btnExportReaderConfig.setEnabled(provisioned);
        btnClearProvisioning.setEnabled(provisioned);
        chkStrictMode.setEnabled(provisioned);
    }

    private void provisionRealCredential()
    {
        new AlertDialog.Builder(requireContext())
                .setTitle("Provision Real Credential")
                .setMessage("This will generate a new Issuer CA keypair and reader certificate. "
                        + "Any previously provisioned keys will be replaced. Continue?")
                .setPositiveButton("Provision", (d, w) -> doProvision())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void doProvision()
    {
        showStatus("Generating keys and certificate...", false);
        btnProvision.setEnabled(false);
        executor.execute(() ->
        {
            String result = AliroProvisioningManager.provisionCredential(requireContext());
            uiHandler.post(() ->
            {
                if (!isAdded()) return;
                btnProvision.setEnabled(true);
                if (result != null)
                {
                    refreshProvisioningStatus();
                    showStatus("\u2713 " + result, true);
                }
                else
                {
                    showStatus("Provisioning failed — check logs.", false);
                }
            });
        });
    }

    private void exportReaderConfig()
    {
        String json = AliroProvisioningManager.buildExportJson(requireContext());
        if (json == null)
        {
            showStatus("No provisioning data to export.", false);
            return;
        }

        // Generate QR code
        Bitmap qrBitmap = generateQrBitmap(json, 800);

        // Also copy to clipboard as fallback
        ClipboardManager clipboard = (ClipboardManager)
                requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("Aliro Reader Config", json));

        View dialogView = LayoutInflater.from(requireContext())
                .inflate(android.R.layout.activity_list_item, null, false);

        if (qrBitmap != null)
        {
            ImageView imageView = new ImageView(requireContext());
            imageView.setImageBitmap(qrBitmap);
            int padding = (int)(24 * requireContext().getResources().getDisplayMetrics().density);
            imageView.setPadding(padding, padding, padding, padding);

            new AlertDialog.Builder(requireContext())
                    .setTitle("Scan on Reader Device")
                    .setMessage("Scan this QR code in the reader\u2019s Aliro Config \u2192 \"Import from Credential\"."
                            + " JSON also copied to clipboard.")
                    .setView(imageView)
                    .setPositiveButton("Done", null)
                    .show();
        }
        else
        {
            showStatus("QR generation failed. JSON copied to clipboard.", true);
        }
    }

    private void confirmClearProvisioning()
    {
        new AlertDialog.Builder(requireContext())
                .setTitle("Clear Provisioning")
                .setMessage("Remove all provisioning data? The credential will revert to simulator mode "
                        + "(accepts any reader). This cannot be undone.")
                .setPositiveButton("Clear", (d, w) ->
                {
                    AliroProvisioningManager.clearProvisioning(requireContext());
                    refreshProvisioningStatus();
                    showStatus("Provisioning cleared. Credential is in simulator mode.", true);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // -------------------------------------------------------------------------
    // Test Harness Configuration
    // -------------------------------------------------------------------------

    private static final String DEFAULT_TH_GROUP_ID   = "00113344667799AA00113344667799AA";
    private static final String DEFAULT_TH_ISSUER_CA   = "043928f322019d4757893bde6a0fe5e13e3e537b9ca0f549c0bd2f40f79060252a0a4f291192157a95cb6eb202759428c00cd834998c5d0eab192ee8873c5d34ee";
    private static final String DEFAULT_TH_READER_PUB  = "043928f322019d4757893bde6a0fe5e13e3e537b9ca0f549c0bd2f40f79060252a0a4f291192157a95cb6eb202759428c00cd834998c5d0eab192ee8873c5d34ee";

    private void loadTestHarnessFields()
    {
        if (!isAdded()) return;
        String groupId = AliroProvisioningManager.getAuthorizedReaderGroupIdHex(requireContext());
        String issuerCa = AliroProvisioningManager.getIssuerCAPubKeyHex(requireContext());
        String readerPub = AliroProvisioningManager.getTestHarnessReaderPubKeyHex(requireContext());

        // Use defaults if nothing is stored
        if (groupId == null || groupId.isEmpty()) groupId = DEFAULT_TH_GROUP_ID;
        if (issuerCa == null || issuerCa.isEmpty()) issuerCa = DEFAULT_TH_ISSUER_CA;
        if (readerPub == null || readerPub.isEmpty()) readerPub = DEFAULT_TH_READER_PUB;

        if (editTestHarnessGroupId != null) editTestHarnessGroupId.setText(groupId);
        if (editTestHarnessIssuerCa != null) editTestHarnessIssuerCa.setText(issuerCa);
        if (editTestHarnessReaderPubKey != null) editTestHarnessReaderPubKey.setText(readerPub);
    }

    private void applyTestHarnessConfig()
    {
        // Always reset to CSA test harness defaults — this is the entire purpose
        // of this button. The text fields show whatever was previously provisioned,
        // but "APPLY TEST HARNESS CONFIG" must always restore the known-good CSA
        // defaults regardless of what the fields currently contain.
        String groupIdHex  = DEFAULT_TH_GROUP_ID.toLowerCase(java.util.Locale.US);
        String issuerCaHex = DEFAULT_TH_ISSUER_CA.toLowerCase(java.util.Locale.US);
        String readerPubHex = DEFAULT_TH_READER_PUB.toLowerCase(java.util.Locale.US);

        // Apply to provisioning storage
        AliroProvisioningManager.setAuthorizedReaderGroupId(requireContext(), groupIdHex);
        AliroProvisioningManager.setIssuerCAPubKey(requireContext(), issuerCaHex);
        AliroProvisioningManager.setTestHarnessReaderPubKey(requireContext(), readerPubHex);

        // Disable strict mode for test harness — harness uses a simulated reader
        // that won't match real provisioned credentials
        AliroProvisioningManager.setStrictMode(requireContext(), false);
        if (chkStrictMode != null) chkStrictMode.setChecked(false);

        // Update the text fields on screen to reflect the applied defaults
        if (editTestHarnessGroupId != null) editTestHarnessGroupId.setText(groupIdHex);
        if (editTestHarnessIssuerCa != null) editTestHarnessIssuerCa.setText(issuerCaHex);
        if (editTestHarnessReaderPubKey != null) editTestHarnessReaderPubKey.setText(readerPubHex);

        showStatus("\u2713 Test Harness config reset to CSA defaults.\n"
                + "Group ID: " + groupIdHex.substring(0, 8) + "...\n"
                + "Issuer CA: " + issuerCaHex.substring(0, 8) + "...\n"
                + "Reader Key: " + readerPubHex.substring(0, 8) + "...\n"
                + "Strict Mode: OFF", true);
        refreshProvisioningStatus();
    }

    // -------------------------------------------------------------------------
    // Document status display
    // -------------------------------------------------------------------------

    private void refreshDocumentStatus()
    {
        if (!isAdded()) return;

        // Update the multi-doc spinner first so the rest of the status text
        // reflects the currently-selected document.
        refreshStoredDocsSpinner();

        Context ctx  = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);

        if (docId == null)
        {
            txtDocumentStatus.setText("No Access Document stored.");
            txtDocumentStatus.setTextColor(ctx.getColor(android.R.color.darker_gray));
            btnClear.setEnabled(false);
            btnDeleteCurrentDoc.setEnabled(false);
            layoutIssuerKey.setVisibility(View.GONE);
            return;
        }

        String mode       = AliroAccessDocument.getDocumentMode(ctx, docId);
        if (mode.isEmpty()) mode = "\u2014";
        String validUntil = AliroAccessDocument.getDocumentValidUntil(ctx, docId);
        if (validUntil.isEmpty()) validUntil = "\u2014";
        String issuerHex  = AliroAccessDocument.getIssuerPubKeyHex(ctx, docId);
        byte[] docBytes   = AliroAccessDocument.getDocumentBytes(ctx, docId);
        int size          = docBytes != null ? docBytes.length : 0;

        java.util.List<String> elementIds =
                AliroAccessDocument.getElementIdentifiers(ctx, docId);
        String elementsLine;
        if (elementIds.isEmpty())
        {
            elementsLine = "Elements: \u2014 (empty document — add an element)";
        }
        else if (elementIds.size() == 1)
        {
            elementsLine = "Element: " + elementIds.get(0);
        }
        else
        {
            StringBuilder sb = new StringBuilder("Elements (").append(elementIds.size()).append("): ");
            for (int i = 0; i < elementIds.size(); i++)
            {
                if (i > 0) sb.append(", ");
                sb.append(elementIds.get(i));
            }
            elementsLine = sb.toString();
        }

        // Position-of-N for context.
        int totalDocs = AliroAccessDocument.getDocumentIds(ctx).size();
        int idxOfThis = AliroAccessDocument.getDocumentIds(ctx).indexOf(docId) + 1;
        String headerLine = "Document " + idxOfThis + " of " + totalDocs
                + ": " + AliroAccessDocument.getDocumentLabel(ctx, docId);

        if (validUntil.length() > 10) validUntil = validUntil.substring(0, 10);

        String status = headerLine + "\n"
                + "Mode: " + mode.toUpperCase() + "\n"
                + elementsLine + "\n"
                + "Valid until: " + (validUntil.isEmpty() ? "unknown" : validUntil) + "\n"
                + "Size: " + size + " bytes";

        txtDocumentStatus.setText(status);
        txtDocumentStatus.setTextColor(ctx.getColor(R.color.colorAccent));
        btnClear.setEnabled(docBytes != null);
        btnDeleteCurrentDoc.setEnabled(true);

        // Show issuer key row if a key is available for this document
        if (!issuerHex.isEmpty())
        {
            layoutIssuerKey.setVisibility(View.VISIBLE);
            String preview = issuerHex.length() > 24
                    ? issuerHex.substring(0, 16) + "\u2026" + issuerHex.substring(issuerHex.length() - 8)
                    : issuerHex;
            txtIssuerKeyPreview.setText(preview);
        }
        else
        {
            layoutIssuerKey.setVisibility(View.GONE);
        }

        // Repopulate the existing-elements spinner. The form fields are
        // controlled by whichever element is selected there; we don't pre-fill
        // editElementId here anymore (the spinner handler does it).
        refreshExistingElementsSpinner();
    }

    /**
     * Repopulate the Stored Documents spinner with one entry per stored
     * document. Each label shows {@code "<userLabel> — kid: xxxxxxxx —
     * N elements"} so the user can tell them apart at a glance. The
     * current document is auto-selected.
     */
    private void refreshStoredDocsSpinner()
    {
        if (!isAdded() || spinnerStoredDocs == null) return;
        Context ctx = requireContext();
        java.util.List<String> ids = AliroAccessDocument.getDocumentIds(ctx);
        java.util.List<String> labels = new java.util.ArrayList<>();
        if (ids.isEmpty())
        {
            labels.add("(no documents stored)");
        }
        else
        {
            for (String id : ids)
            {
                String label = AliroAccessDocument.getDocumentLabel(ctx, id);
                String pubHex = AliroAccessDocument.getIssuerPubKeyHex(ctx, id);
                String kid = "????";
                if (pubHex != null && pubHex.length() >= 16)
                {
                    // Mirror computeKidHex logic for display: SHA-256("key-identifier" || pub)[0:8]
                    try
                    {
                        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
                        sha.update("key-identifier".getBytes());
                        sha.update(org.bouncycastle.util.encoders.Hex.decode(pubHex));
                        byte[] digest = sha.digest();
                        kid = org.bouncycastle.util.encoders.Hex.toHexString(
                                java.util.Arrays.copyOfRange(digest, 0, 8));
                    }
                    catch (Exception ignore) { }
                }
                int elemCount = AliroAccessDocument.getElementIdentifiers(ctx, id).size();
                labels.add(label + "  \u2014  kid: " + kid + "\u2026  \u2014  "
                        + elemCount + " elem" + (elemCount == 1 ? "" : "s"));
            }
        }
        ArrayAdapter<String> adapter = new ArrayAdapter<>(
                ctx, android.R.layout.simple_spinner_item, labels);
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);

        suppressDocSpinnerEvent = true;
        try
        {
            spinnerStoredDocs.setAdapter(adapter);
            spinnerStoredDocs.setEnabled(!ids.isEmpty());
            String current = AliroAccessDocument.getCurrentDocumentId(ctx);
            if (current != null)
            {
                int idx = ids.indexOf(current);
                if (idx >= 0) spinnerStoredDocs.setSelection(idx);
            }
        }
        finally { suppressDocSpinnerEvent = false; }
    }

    /** Spinner-selection callback: switch the current document. */
    private void onStoredDocSelected(int position)
    {
        if (!isAdded()) return;
        Context ctx = requireContext();
        java.util.List<String> ids = AliroAccessDocument.getDocumentIds(ctx);
        if (position < 0 || position >= ids.size()) return;
        String docId = ids.get(position);
        if (docId.equals(AliroAccessDocument.getCurrentDocumentId(ctx))) return;
        AliroAccessDocument.setCurrentDocumentId(ctx, docId);
        refreshDocumentStatus();
        showStatus("Selected: " + AliroAccessDocument.getDocumentLabel(ctx, docId), true);
    }

    /**
     * Repopulate the Existing Elements spinner with one entry per element
     * in the currently selected document, plus a "(new element…)" sentinel
     * as the first row. Selection is preserved when possible: if the
     * previously-selected element label still exists we keep it; otherwise
     * fall back to "(new element…)" so the form is in fresh-add mode.
     *
     * <p>Programmatically rebuilding the adapter triggers OnItemSelected, so
     * the call is bracketed by {@link #suppressElemSpinnerEvent} to avoid
     * spuriously clobbering the form fields the user is typing into.
     */
    private void refreshExistingElementsSpinner()
    {
        if (!isAdded() || spinnerExistingElements == null) return;
        Context ctx = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);

        // Capture previous selection so we can preserve it across a refresh
        Object prevSelObj = spinnerExistingElements.getSelectedItem();
        String prevSel    = prevSelObj != null ? prevSelObj.toString() : null;

        java.util.List<String> labels = new java.util.ArrayList<>();
        labels.add(NEW_ELEMENT_LABEL);
        if (docId != null)
        {
            labels.addAll(AliroAccessDocument.getElementIdentifiers(ctx, docId));
        }

        suppressElemSpinnerEvent = true;
        try
        {
            ArrayAdapter<String> adapter = new ArrayAdapter<>(
                    ctx, android.R.layout.simple_spinner_item, labels);
            adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
            spinnerExistingElements.setAdapter(adapter);

            int selPos = 0; // default: "(new element…)"
            if (prevSel != null)
            {
                int idx = labels.indexOf(prevSel);
                if (idx >= 0) selPos = idx;
            }
            spinnerExistingElements.setSelection(selPos);
        }
        finally
        {
            suppressElemSpinnerEvent = false;
        }

        // Apply button label / form state for the (possibly reset) selection
        Object cur = spinnerExistingElements.getSelectedItem();
        applyExistingElementSelectionToForm(cur != null ? cur.toString() : NEW_ELEMENT_LABEL,
                                             /* populateForm = */ false);
    }

    /**
     * Called when the user picks a row in the Existing Elements spinner.
     * If the row is "(new element…)", clear the form for a fresh add and
     * reset the action button to "Add Element to Document". Otherwise
     * load that element's stored {@link AliroAccessDocument.AccessDocConfig}
     * back into the form fields and switch the action button to
     * "Update Element".
     */
    private void onExistingElementSelected(String label)
    {
        applyExistingElementSelectionToForm(label, /* populateForm = */ true);
    }

    /**
     * Shared body for spinner-driven selection + post-refresh re-application.
     * When {@code populateForm} is false we only update the button label /
     * editability state (used during refresh so we don't overwrite fields
     * the user is mid-typing). When true we also load the stored values.
     */
    private void applyExistingElementSelectionToForm(String label, boolean populateForm)
    {
        if (label == null) label = NEW_ELEMENT_LABEL;
        boolean isNew = NEW_ELEMENT_LABEL.equals(label);

        if (btnAddElement != null)
        {
            btnAddElement.setText(isNew ? "Add Element to Document" : "Update Element");
        }

        if (!populateForm) return;

        if (isNew)
        {
            // Fresh-add mode: clear form so the user starts clean. Don't
            // wipe the schedule preset spinner — leave whatever the user
            // last picked, since "(new element…)" right after editing
            // floor1 likely intends a similar config for floor2.
            if (editElementId  != null) editElementId.setText("");
            if (editEmployeeId != null) editEmployeeId.setText("");
            return;
        }

        // Edit mode: load the stored element's config into the form.
        Context ctx = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);
        AliroAccessDocument.AccessDocConfig cfg =
                AliroAccessDocument.getElementConfig(ctx, docId, label);
        if (cfg == null)
        {
            showStatus("Could not load element '" + label
                    + "'. Pick a Schedule Preset to overwrite.", false);
            if (editElementId  != null) editElementId.setText(label);
            if (editEmployeeId != null) editEmployeeId.setText("");
            return;
        }

        if (editElementId  != null) editElementId.setText(cfg.name);
        if (editEmployeeId != null) editEmployeeId.setText(cfg.employeeId);
        if (spinnerSchedulePreset != null && cfg.preset != null)
        {
            int ord = cfg.preset.ordinal();
            if (ord >= 0 && ord < spinnerSchedulePreset.getCount())
            {
                spinnerSchedulePreset.setSelection(ord);
            }
        }
        showStatus("Loaded '" + label + "' for editing. Tap Update Element to apply.", true);
    }

    /**
     * Prompt the user for a label, then create a new empty document slot
     * with a fresh issuer keypair (Aliro 1.0 §8.4.2). The new document
     * becomes the current document; existing documents are preserved.
     */
    private void showCreateNewDocumentDialog()
    {
        if (!isAdded()) return;
        Context ctx = requireContext();
        int next = AliroAccessDocument.getDocumentIds(ctx).size() + 1;
        final EditText input = new EditText(ctx);
        input.setHint("Document " + next);
        input.setSingleLine(true);

        new androidx.appcompat.app.AlertDialog.Builder(ctx)
                .setTitle("Create New Document")
                .setMessage("Each document has its own issuer keypair (its own kid). The reader needs the matching Step-Up Issuer Public Key for each document it should trust. Per Aliro 1.0 §8.4.2.")
                .setView(input)
                .setPositiveButton("Create", (dlg, which) ->
                {
                    String label = input.getText().toString().trim();
                    if (label.isEmpty()) label = "Document " + (AliroAccessDocument.getDocumentIds(ctx).size() + 1);
                    String docId = AliroAccessDocument.createNewDocument(ctx, label);
                    if (docId != null)
                    {
                        showStatus("\u2713 Created '" + label + "' (empty). Add an element to populate it.", true);
                        refreshDocumentStatus();
                    }
                    else
                    {
                        showStatus("Failed to create document. Check logs.", false);
                    }
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    /** Confirm + delete the currently-selected document. */
    private void confirmDeleteCurrentDocument()
    {
        if (!isAdded()) return;
        Context ctx = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);
        if (docId == null)
        {
            showStatus("No document selected.", false);
            return;
        }
        String label = AliroAccessDocument.getDocumentLabel(ctx, docId);
        new androidx.appcompat.app.AlertDialog.Builder(ctx)
                .setTitle("Delete Document?")
                .setMessage("This will delete '" + label + "' (docId=" + docId
                        + ") and its issuer keypair. The reader will no longer be able to verify this document. Existing other documents are unaffected.")
                .setPositiveButton("Delete", (dlg, which) ->
                {
                    AliroAccessDocument.removeDocument(ctx, docId);
                    showStatus("\u2713 Deleted '" + label + "'.", true);
                    refreshDocumentStatus();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    /**
     * Confirm + refresh the validity window of the currently-selected
     * document. Bumps the document-level validUntil to {@code now + 5y}
     * and rewrites every schedule's endPeriod to 2030-01-01 (matching
     * {@code FAR_FUTURE_END_PERIOD} on the storage side). The issuer
     * keypair is reused so kid stays stable per Aliro 1.0 §7.3 / §8.4.2.
     */
    private void confirmRefreshValidity()
    {
        if (!isAdded()) return;
        Context ctx = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);
        if (docId == null)
        {
            showStatus("No document selected.", false);
            return;
        }
        String label = AliroAccessDocument.getDocumentLabel(ctx, docId);

        // Compute new endpoints. Document validUntil = now + 5y; per-schedule
        // endPeriod = 2030-01-01 00:00 UTC. Both are spec-conformant uint32
        // epoch seconds, well past any near-term test horizon, and applied
        // identically to every element regardless of preset.
        final long FAR_FUTURE_END_EPOCH = 1893456000L; // 2030-01-01 00:00 UTC
        final int  FIVE_YEARS_DAYS      = 5 * 365;

        new androidx.appcompat.app.AlertDialog.Builder(ctx)
                .setTitle("Refresh Validity?")
                .setMessage("Bump '" + label + "'\u2019s validity to expire "
                        + FIVE_YEARS_DAYS + " days from now and rewrite every schedule's "
                        + "endPeriod to 2030-01-01. The issuer keypair (and kid) are "
                        + "preserved \u2014 no reader changes needed. AccessRules, "
                        + "Capabilities, dayMasks, and time-of-day windows are all kept "
                        + "as-is.")
                .setPositiveButton("Refresh", (dlg, which) ->
                {
                    btnRefreshValidity.setEnabled(false);
                    showStatus("Refreshing validity for '" + label + "'\u2026", false);
                    executor.execute(() ->
                    {
                        String result = AliroAccessDocument.refreshDocumentValidity(
                                ctx, docId, FIVE_YEARS_DAYS, FAR_FUTURE_END_EPOCH);
                        uiHandler.post(() ->
                        {
                            if (!isAdded()) return;
                            btnRefreshValidity.setEnabled(true);
                            if (result != null)
                            {
                                showStatus("\u2713 " + result, true);
                                refreshDocumentStatus();
                            }
                            else
                            {
                                showStatus("Failed to refresh validity. Check logs.", false);
                            }
                        });
                    });
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // -------------------------------------------------------------------------
    // Generate minimal test document
    // -------------------------------------------------------------------------

    private void generateTestDocument()
    {
        String elementId = editElementId.getText().toString().trim();
        if (TextUtils.isEmpty(elementId))
        {
            elementId = "access"; // default
            editElementId.setText(elementId);
        }

        final String finalElementId = elementId;
        showStatus("Generating test document...", false);
        btnGenerateTest.setEnabled(false);

        executor.execute(() ->
        {
            byte[] credPubKeyBytes = getCredentialPublicKeyBytes();
            if (credPubKeyBytes == null)
            {
                uiHandler.post(() ->
                {
                    if (!isAdded()) return;
                    showStatus("Credential keypair not found. Open the main screen first.", false);
                    btnGenerateTest.setEnabled(true);
                });
                return;
            }

            String result = AliroAccessDocument.generateTestDocument(
                    requireContext(), credPubKeyBytes, finalElementId, 365);

            uiHandler.post(() ->
            {
                if (!isAdded()) return;
                btnGenerateTest.setEnabled(true);
                if (result != null)
                {
                    showStatus("\u2713 " + result, true);
                    refreshDocumentStatus();
                }
                else
                {
                    showStatus("Failed to generate document. Check logs.", false);
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // Load realistic sample document (employee badge with schedules)
    // -------------------------------------------------------------------------

    private void loadSampleDocument()
    {
        String elementId = editElementId.getText().toString().trim();
        if (TextUtils.isEmpty(elementId))
        {
            elementId = "access";
            editElementId.setText(elementId);
        }

        final String finalElementId = elementId;
        showStatus("Generating sample document (ELATEC001, 2 rules, 2 schedules)...", false);
        btnLoadSampleDoc.setEnabled(false);

        executor.execute(() ->
        {
            byte[] credPubKeyBytes = getCredentialPublicKeyBytes();
            if (credPubKeyBytes == null)
            {
                uiHandler.post(() ->
                {
                    if (!isAdded()) return;
                    showStatus("Credential keypair not found. Open the main screen first.", false);
                    btnLoadSampleDoc.setEnabled(true);
                });
                return;
            }

            String result = AliroAccessDocument.generateRealisticSampleDocument(
                    requireContext(), credPubKeyBytes, finalElementId, 365);

            uiHandler.post(() ->
            {
                if (!isAdded()) return;
                btnLoadSampleDoc.setEnabled(true);
                if (result != null)
                {
                    showStatus("\u2713 " + result, true);
                    refreshDocumentStatus();
                }
                else
                {
                    showStatus("Failed to generate sample document. Check logs.", false);
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // Add element to existing document (multi-element support per Aliro §7.3)
    // -------------------------------------------------------------------------

    /**
     * Add another element to the currently stored Access Document, reusing its
     * issuer keypair so the kid stays stable. If no document is stored yet,
     * this creates a new one — same end result as Load Sample Doc, but the
     * mental model from the user's perspective is "I'm building up the set of
     * elements this credential carries."
     *
     * Per Aliro 1.0 §7.3, an Access Document may contain multiple
     * IssuerSignedItems sharing one IssuerAuth. The reader configures which
     * single element it requests via Step-Up Element ID; switching from
     * "floor1" to "floor2" without re-importing the issuer key now works
     * because both are signed by the same persistent key.
     */
    private void addElementToDocument()
    {
        String elementId = editElementId.getText().toString().trim();
        if (TextUtils.isEmpty(elementId))
        {
            showStatus("Enter an Element Identifier first (e.g. floor1, floor2).", false);
            return;
        }

        // Detect edit-vs-add based on the existing-elements spinner: if the
        // user picked an existing element row, we're updating in place
        // (storage layer reuses the issuer keypair → kid is preserved).
        final boolean isUpdate = isEditingExistingElement();
        final String verbing = isUpdate ? "Updating" : "Adding";
        final String verbed  = isUpdate ? "Updated"  : "Added";

        final AliroAccessDocument.AccessDocConfig config = currentDocConfig(elementId);
        showStatus(verbing + " element '" + elementId + "' (id="
                + config.employeeId + ", preset=" + config.preset.name() + ")...", false);
        btnAddElement.setEnabled(false);

        executor.execute(() ->
        {
            byte[] credPubKeyBytes = getCredentialPublicKeyBytes();
            if (credPubKeyBytes == null)
            {
                uiHandler.post(() ->
                {
                    if (!isAdded()) return;
                    showStatus("Credential keypair not found. Open the main screen first.", false);
                    btnAddElement.setEnabled(true);
                });
                return;
            }

            // Honor the per-document Employee/Badge ID + Schedule Preset
            // pulled from the UI. Each Add Element call appends a fresh
            // IssuerSignedItem to the existing document with these custom
            // values, so stored elements are visibly distinct when the
            // verifier reads them back. The issuer keypair is reused so kid
            // stays stable across the whole multi-element document
            // (Aliro 1.0 §7.3). When elementId matches an existing entry the
            // storage layer replaces it in place — same code path serves
            // both add and edit.
            String result = AliroAccessDocument.addAccessElement(
                    requireContext(), credPubKeyBytes, elementId, 365, config);

            uiHandler.post(() ->
            {
                if (!isAdded()) return;
                btnAddElement.setEnabled(true);
                if (result != null)
                {
                    showStatus("\u2713 " + verbed + ": " + result, true);
                    refreshDocumentStatus();
                    // Keep the just-saved element selected so the user can
                    // see it in the spinner. refreshExistingElementsSpinner
                    // ran via refreshDocumentStatus and may have reset to
                    // "(new element…)"; explicitly re-select the saved id.
                    selectExistingElementInSpinner(elementId);
                }
                else
                {
                    showStatus("Failed to " + (isUpdate ? "update" : "add")
                            + " element. Check logs.", false);
                }
            });
        });
    }

    /**
     * @return true when the existing-elements spinner currently has a real
     *         element selected (i.e. anything other than "(new element…)").
     */
    private boolean isEditingExistingElement()
    {
        if (spinnerExistingElements == null) return false;
        Object cur = spinnerExistingElements.getSelectedItem();
        return cur != null && !NEW_ELEMENT_LABEL.equals(cur.toString());
    }

    /**
     * Move the existing-elements spinner selection to the named element if
     * it's present in the adapter. Used after a save so the just-saved row
     * stays highlighted.
     */
    private void selectExistingElementInSpinner(String elementId)
    {
        if (spinnerExistingElements == null || elementId == null) return;
        ArrayAdapter<?> adapter = (ArrayAdapter<?>) spinnerExistingElements.getAdapter();
        if (adapter == null) return;
        for (int i = 0; i < adapter.getCount(); i++)
        {
            Object item = adapter.getItem(i);
            if (item != null && elementId.equals(item.toString()))
            {
                suppressElemSpinnerEvent = true;
                try { spinnerExistingElements.setSelection(i); }
                finally { suppressElemSpinnerEvent = false; }
                applyExistingElementSelectionToForm(elementId, /* populateForm = */ false);
                return;
            }
        }
    }

    /**
     * Read the current per-document configuration from the UI fields:
     * Element Identifier (passed in), Employee/Badge ID (defaults to
     * "ELATEC001" if blank), and Schedule Preset (spinner position →
     * AliroAccessDocument.SchedulePreset enum value).
     */
    private AliroAccessDocument.AccessDocConfig currentDocConfig(String elementId)
    {
        String employeeId = editEmployeeId != null
                ? editEmployeeId.getText().toString().trim()
                : "";
        if (TextUtils.isEmpty(employeeId)) employeeId = "ELATEC001";

        AliroAccessDocument.SchedulePreset preset =
                AliroAccessDocument.SchedulePreset.WEEKDAY_AND_WEEKEND;
        if (spinnerSchedulePreset != null)
        {
            int pos = spinnerSchedulePreset.getSelectedItemPosition();
            AliroAccessDocument.SchedulePreset[] all =
                    AliroAccessDocument.SchedulePreset.values();
            if (pos >= 0 && pos < all.length) preset = all[pos];
        }
        return new AliroAccessDocument.AccessDocConfig(elementId, employeeId, preset);
    }

    // -------------------------------------------------------------------------
    // Import document
    // -------------------------------------------------------------------------

    private void showImportDialog()
    {
        View dialogView = LayoutInflater.from(requireContext())
                .inflate(R.layout.dialog_import_access_doc, null);
        EditText editCbor      = dialogView.findViewById(R.id.editImportCbor);
        EditText editIssuerKey = dialogView.findViewById(R.id.editImportIssuerKey);

        new AlertDialog.Builder(requireContext())
                .setTitle("Import Access Document")
                .setView(dialogView)
                .setPositiveButton("Import", (d, w) ->
                {
                    String cbor      = editCbor.getText().toString().trim();
                    String issuerKey = editIssuerKey.getText().toString().trim().toLowerCase();
                    importDocument(cbor, issuerKey);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void importDocument(String base64Cbor, String issuerPubHex)
    {
        if (TextUtils.isEmpty(base64Cbor))
        {
            showStatus("CBOR Base64 is required.", false);
            return;
        }

        showStatus("Importing document...", false);
        btnImport.setEnabled(false);

        executor.execute(() ->
        {
            String result = AliroAccessDocument.importDocument(
                    requireContext(), base64Cbor, issuerPubHex);

            uiHandler.post(() ->
            {
                if (!isAdded()) return;
                btnImport.setEnabled(true);
                if (result != null)
                {
                    showStatus("\u2713 " + result, true);
                    refreshDocumentStatus();
                }
                else
                {
                    showStatus("Import failed — invalid CBOR structure.", false);
                }
            });
        });
    }

    // -------------------------------------------------------------------------
    // Copy issuer key to clipboard
    // -------------------------------------------------------------------------

    private void copyIssuerKeyToClipboard()
    {
        if (!isAdded()) return;
        Context ctx = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);
        if (docId == null)
        {
            showStatus("No document selected — create one first.", false);
            return;
        }
        String issuerHex = AliroAccessDocument.getIssuerPubKeyHex(ctx, docId);
        if (issuerHex == null || issuerHex.isEmpty())
        {
            showStatus("No issuer key stored for this document.", false);
            return;
        }
        ClipboardManager clipboard = (ClipboardManager)
                ctx.getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Aliro Issuer Public Key", issuerHex);
        clipboard.setPrimaryClip(clip);
        String label = AliroAccessDocument.getDocumentLabel(ctx, docId);
        showStatus("Issuer key for '" + label + "' copied to clipboard.\n"
                + "Paste into the reader's Step-Up Issuer Public Key field. "
                + "If the reader already has keys for other documents, append "
                + "this one with a comma in between.", true);
    }

    private void showIssuerKeyQrDialog()
    {
        if (!isAdded()) return;
        Context ctx = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);
        if (docId == null)
        {
            showStatus("No document selected — create one first.", false);
            return;
        }
        String issuerHex = AliroAccessDocument.getIssuerPubKeyHex(ctx, docId);
        if (issuerHex == null || issuerHex.isEmpty())
        {
            showStatus("No issuer key stored for this document.", false);
            return;
        }

        Bitmap qrBitmap = generateQrBitmap(issuerHex, 600);
        if (qrBitmap == null)
        {
            showStatus("Failed to generate QR code.", false);
            return;
        }

        ImageView imageView = new ImageView(ctx);
        imageView.setImageBitmap(qrBitmap);
        int padding = (int)(24 * ctx.getResources().getDisplayMetrics().density);
        imageView.setPadding(padding, padding, padding, padding);

        String label = AliroAccessDocument.getDocumentLabel(ctx, docId);
        new AlertDialog.Builder(ctx)
                .setTitle("Issuer Public Key — " + label)
                .setMessage("Scan this QR code in the reader\u2019s Aliro Config \u2192 "
                        + "Step-Up Issuer Public Key field. "
                        + "If the reader already trusts other documents, append this "
                        + "one with a comma after scanning (Aliro 1.0 \u00a77.7).")
                .setView(imageView)
                .setPositiveButton("Done", null)
                .show();
    }

    private static Bitmap generateQrBitmap(String content, int sizePx)
    {
        try
        {
            QRCodeWriter writer = new QRCodeWriter();
            BitMatrix matrix = writer.encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx);
            int w = matrix.getWidth();
            int h = matrix.getHeight();
            int[] pixels = new int[w * h];
            for (int y = 0; y < h; y++)
                for (int x = 0; x < w; x++)
                    pixels[y * w + x] = matrix.get(x, y) ? 0xFF000000 : 0xFFFFFFFF;
            return Bitmap.createBitmap(pixels, w, h, Bitmap.Config.ARGB_8888);
        }
        catch (WriterException e)
        {
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Clear document
    // -------------------------------------------------------------------------

    private void clearDocument()
    {
        Context ctx = requireContext();
        String docId = AliroAccessDocument.getCurrentDocumentId(ctx);
        if (docId == null)
        {
            showStatus("No document to clear.", false);
            return;
        }
        String label = AliroAccessDocument.getDocumentLabel(ctx, docId);
        new AlertDialog.Builder(ctx)
                .setTitle("Clear Document")
                .setMessage("Remove the currently-selected Access Document ('" + label
                        + "')? Other stored documents are unaffected. The credential "
                        + "will still work for expedited-phase transactions and other "
                        + "stored documents.")
                .setPositiveButton("Clear", (d, w) ->
                {
                    AliroAccessDocument.clearDocument(ctx);
                    showStatus("Document '" + label + "' cleared.", true);
                    refreshDocumentStatus();
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // -------------------------------------------------------------------------
    // KeyStore helper — get credential public key bytes
    // -------------------------------------------------------------------------

    private byte[] getCredentialPublicKeyBytes()
    {
        try
        {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            java.security.cert.Certificate cert =
                    ks.getCertificate(Aliro_HostApduService.ALIRO_KEYSTORE_ALIAS);
            if (cert == null) return null;
            ECPublicKey pub = (ECPublicKey) cert.getPublicKey();
            byte[] x = toBytes32(pub.getW().getAffineX());
            byte[] y = toBytes32(pub.getW().getAffineY());
            byte[] out = new byte[65];
            out[0] = 0x04;
            System.arraycopy(x, 0, out, 1,  32);
            System.arraycopy(y, 0, out, 33, 32);
            return out;
        }
        catch (Exception e) { return null; }
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
    // Mailbox viewer
    // -------------------------------------------------------------------------

    private void refreshMailboxViewer()
    {
        if (!isAdded()) return;
        byte[] mailbox = loadMailboxBytes();
        if (mailbox == null || mailbox.length == 0)
        {
            txtMailboxSize.setText("Size: 0 bytes");
            txtMailboxHexDump.setText("(empty)");
            return;
        }

        txtMailboxSize.setText("Size: " + mailbox.length + " bytes");
        txtMailboxHexDump.setText(formatHexDump(mailbox));
    }

    private void initializeMailbox()
    {
        int size = Integer.parseInt(MAILBOX_SIZES[spinnerMailboxSize.getSelectedItemPosition()]);
        byte[] mailbox = new byte[size];
        saveMailboxBytes(mailbox);
        refreshMailboxViewer();
        showStatus("Mailbox initialized: " + size + " bytes (all zeros)", true);
    }

    /**
     * Write the realistic §18 ELATEC sample mailbox (256 bytes) and refresh the viewer.
     *
     * Content:
     *   Entry 0 — Reader Config (Type 0x01): firmware "2.1.0", serial "ELA-TWN4-00042",
     *             zone "Building A - Main Lobby", door #42
     *   Entry 1 — Door Status (Type 0x02): locked, 95% battery, 22°C, last event, 163 txns
     */
    private void loadSampleMailbox()
    {
        byte[] mailbox = AliroMailbox.buildSampleMailbox();
        saveMailboxBytes(mailbox);
        refreshMailboxViewer();
        showStatus("\u2713 Sample mailbox loaded: "
                + AliroMailbox.MAILBOX_SIZE + " bytes\n"
                + "  OUI: 00:13:7D (ELATEC)\n"
                + "  Entry 0 (0x01): Reader Config — FW 2.1.0, Door #42\n"
                + "  Entry 1 (0x02): Door Status — Locked, 95%, 22\u00B0C", true);
    }

    private void clearMailbox()
    {
        new android.app.AlertDialog.Builder(requireContext())
                .setTitle("Clear Mailbox")
                .setMessage("Remove all mailbox data?")
                .setPositiveButton("Clear", (d, w) ->
                {
                    saveMailboxBytes(new byte[0]);
                    refreshMailboxViewer();
                    showStatus("Mailbox cleared.", true);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    private byte[] loadMailboxBytes()
    {
        try
        {
            SharedPreferences prefs = requireContext()
                    .getSharedPreferences(MAILBOX_PREFS_NAME, Context.MODE_PRIVATE);
            String encoded = prefs.getString(MAILBOX_PREF_KEY, null);
            if (encoded == null) return new byte[0];
            return Base64.decode(encoded, Base64.DEFAULT);
        }
        catch (Exception e) { return new byte[0]; }
    }

    private void saveMailboxBytes(byte[] data)
    {
        SharedPreferences prefs = requireContext()
                .getSharedPreferences(MAILBOX_PREFS_NAME, Context.MODE_PRIVATE);
        if (data == null || data.length == 0)
        {
            prefs.edit().remove(MAILBOX_PREF_KEY).apply();
        }
        else
        {
            prefs.edit().putString(MAILBOX_PREF_KEY,
                    Base64.encodeToString(data, Base64.DEFAULT)).apply();
        }
    }

    /**
     * Format byte array as hex dump with address offsets (16 bytes per line).
     * e.g. "0000: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"
     */
    private static String formatHexDump(byte[] data)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < data.length; i += 16)
        {
            sb.append(String.format("%04X: ", i));
            for (int j = 0; j < 16; j++)
            {
                if (i + j < data.length)
                {
                    sb.append(String.format("%02X ", data[i + j] & 0xFF));
                }
                else
                {
                    sb.append("   ");
                }
            }
            sb.append('\n');
        }
        return sb.toString().trim();
    }

    // -------------------------------------------------------------------------
    // UI helper
    // -------------------------------------------------------------------------

    private void showStatus(String message, boolean success)
    {
        if (!isAdded()) return;
        txtStatus.setVisibility(View.VISIBLE);
        txtStatus.setText(message);
        txtStatus.setTextColor(success
                ? requireContext().getColor(R.color.colorAccent)
                : requireContext().getColor(android.R.color.holo_red_dark));
    }
}
