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
    private Button      btnImport;
    private Button      btnClear;
    private Button      btnCopyIssuerKey;
    private Button      btnShowQr;
    private LinearLayout layoutIssuerKey;
    private TextView    txtIssuerKeyPreview;
    private EditText    editElementId;
    private TextView    txtStatus;

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
        btnImport          = view.findViewById(R.id.btnImportDoc);
        btnClear           = view.findViewById(R.id.btnClearDoc);
        btnCopyIssuerKey   = view.findViewById(R.id.btnCopyIssuerKey);
        btnShowQr          = view.findViewById(R.id.btnShowQr);
        layoutIssuerKey    = view.findViewById(R.id.layoutIssuerKey);
        txtIssuerKeyPreview = view.findViewById(R.id.txtIssuerKeyPreview);
        editElementId      = view.findViewById(R.id.editElementIdentifier);
        txtStatus          = view.findViewById(R.id.txtCredAliroStatus);

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
        btnImport.setOnClickListener(v -> showImportDialog());
        btnClear.setOnClickListener(v -> clearDocument());
        btnCopyIssuerKey.setOnClickListener(v -> copyIssuerKeyToClipboard());
        btnShowQr.setOnClickListener(v -> showIssuerKeyQrDialog());
        btnInitMailbox.setOnClickListener(v -> initializeMailbox());
        btnLoadSampleMailbox.setOnClickListener(v -> loadSampleMailbox());
        btnClearMailbox.setOnClickListener(v -> clearMailbox());
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
        String groupIdHex = editTestHarnessGroupId.getText().toString()
                .trim().replaceAll("\\s+", "").replaceAll("[^0-9a-fA-F]", "").toLowerCase(java.util.Locale.US);
        String issuerCaHex = editTestHarnessIssuerCa.getText().toString()
                .trim().replaceAll("\\s+", "").replaceAll("[^0-9a-fA-F]", "").toLowerCase(java.util.Locale.US);

        boolean hasGroup = !groupIdHex.isEmpty();
        boolean hasIssuer = !issuerCaHex.isEmpty();

        String readerPubHex = editTestHarnessReaderPubKey.getText().toString()
                .trim().replaceAll("\\s+", "").replaceAll("[^0-9a-fA-F]", "").toLowerCase(java.util.Locale.US);
        boolean hasReaderPub = !readerPubHex.isEmpty();

        if (hasGroup && groupIdHex.length() != 32)
        {
            showStatus("Reader Group ID must be exactly 32 hex characters (16 bytes).", false);
            return;
        }
        if (hasIssuer && issuerCaHex.length() != 130)
        {
            showStatus("Issuer CA must be exactly 130 hex characters (65 bytes).", false);
            return;
        }
        if (hasIssuer && !issuerCaHex.startsWith("04"))
        {
            showStatus("Issuer CA must start with 04 (uncompressed EC point).", false);
            return;
        }
        if (hasReaderPub && readerPubHex.length() != 130)
        {
            showStatus("Reader Public Key must be exactly 130 hex characters (65 bytes).", false);
            return;
        }
        if (hasReaderPub && !readerPubHex.startsWith("04"))
        {
            showStatus("Reader Public Key must start with 04 (uncompressed EC point).", false);
            return;
        }

        if (hasGroup)
            AliroProvisioningManager.setAuthorizedReaderGroupId(requireContext(), groupIdHex);
        if (hasIssuer)
            AliroProvisioningManager.setIssuerCAPubKey(requireContext(), issuerCaHex);
        if (hasReaderPub)
            AliroProvisioningManager.setTestHarnessReaderPubKey(requireContext(), readerPubHex);

        // Do NOT enable strict mode for test harness — leave it unchecked

        StringBuilder msg = new StringBuilder("\u2713 Test Harness config applied.");
        if (hasGroup)  msg.append("\nGroup ID: ").append(groupIdHex.substring(0, 8)).append("...");
        if (hasIssuer) msg.append("\nIssuer CA: ").append(issuerCaHex.substring(0, 8)).append("...");
        if (hasReaderPub) msg.append("\nReader Key: ").append(readerPubHex.substring(0, 8)).append("...");

        showStatus(msg.toString(), true);
        refreshProvisioningStatus();
    }

    // -------------------------------------------------------------------------
    // Document status display
    // -------------------------------------------------------------------------

    private void refreshDocumentStatus()
    {
        if (!isAdded()) return;
        SharedPreferences prefs = requireContext()
                .getSharedPreferences(AliroAccessDocument.PREFS_NAME, Context.MODE_PRIVATE);

        boolean hasDoc = prefs.contains(AliroAccessDocument.KEY_ACCESS_DOC);
        if (!hasDoc)
        {
            txtDocumentStatus.setText("No Access Document stored.");
            txtDocumentStatus.setTextColor(requireContext().getColor(android.R.color.darker_gray));
            btnClear.setEnabled(false);
            return;
        }

        String mode       = prefs.getString(AliroAccessDocument.KEY_DOC_MODE,        "\u2014");
        String elementId  = prefs.getString(AliroAccessDocument.KEY_ELEMENT_ID,      "\u2014");
        String validUntil = prefs.getString(AliroAccessDocument.KEY_DOC_VALID_UNTIL, "\u2014");
        String issuerHex  = prefs.getString(AliroAccessDocument.KEY_ISSUER_PUB_KEY,  "");
        byte[] docBytes   = AliroAccessDocument.getDocumentBytes(requireContext());
        int size          = docBytes != null ? docBytes.length : 0;

        // Show validity date shortened
        if (validUntil.length() > 10) validUntil = validUntil.substring(0, 10);

        String status = "Mode: " + mode.toUpperCase() + "\n"
                + "Element ID: " + elementId + "\n"
                + "Valid until: " + (validUntil.isEmpty() ? "unknown" : validUntil) + "\n"
                + "Size: " + size + " bytes";

        txtDocumentStatus.setText(status);
        txtDocumentStatus.setTextColor(requireContext().getColor(R.color.colorAccent));
        btnClear.setEnabled(true);

        // Show issuer key row if a key is available
        if (!issuerHex.isEmpty())
        {
            layoutIssuerKey.setVisibility(View.VISIBLE);
            // Preview: first 16 chars + "…" + last 8 chars
            String preview = issuerHex.length() > 24
                    ? issuerHex.substring(0, 16) + "\u2026" + issuerHex.substring(issuerHex.length() - 8)
                    : issuerHex;
            txtIssuerKeyPreview.setText(preview);
        }
        else
        {
            layoutIssuerKey.setVisibility(View.GONE);
        }

        // Pre-fill element ID field
        if (editElementId.getText().toString().isEmpty())
        {
            editElementId.setText(elementId);
        }
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
        SharedPreferences prefs = requireContext()
                .getSharedPreferences(AliroAccessDocument.PREFS_NAME, Context.MODE_PRIVATE);
        String issuerHex = prefs.getString(AliroAccessDocument.KEY_ISSUER_PUB_KEY, "");
        if (issuerHex.isEmpty())
        {
            showStatus("No issuer key stored.", false);
            return;
        }
        ClipboardManager clipboard = (ClipboardManager)
                requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        ClipData clip = ClipData.newPlainText("Aliro Issuer Public Key", issuerHex);
        clipboard.setPrimaryClip(clip);
        showStatus("Issuer key copied to clipboard.", true);
    }

    private void showIssuerKeyQrDialog()
    {
        if (!isAdded()) return;
        SharedPreferences prefs = requireContext()
                .getSharedPreferences(AliroAccessDocument.PREFS_NAME, Context.MODE_PRIVATE);
        String issuerHex = prefs.getString(AliroAccessDocument.KEY_ISSUER_PUB_KEY, "");
        if (issuerHex.isEmpty())
        {
            showStatus("No issuer key stored.", false);
            return;
        }

        Bitmap qrBitmap = generateQrBitmap(issuerHex, 600);
        if (qrBitmap == null)
        {
            showStatus("Failed to generate QR code.", false);
            return;
        }

        ImageView imageView = new ImageView(requireContext());
        imageView.setImageBitmap(qrBitmap);
        int padding = (int)(24 * requireContext().getResources().getDisplayMetrics().density);
        imageView.setPadding(padding, padding, padding, padding);

        new AlertDialog.Builder(requireContext())
                .setTitle("Scan on Reader Device")
                .setMessage("Scan this QR code in the simulator\u2019s Aliro Config \u2192 Step-Up Issuer Public Key field.")
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
        new AlertDialog.Builder(requireContext())
                .setTitle("Clear Access Document")
                .setMessage("Remove the stored Access Document? The credential will still work for expedited-phase transactions.")
                .setPositiveButton("Clear", (d, w) ->
                {
                    AliroAccessDocument.clearDocument(requireContext());
                    showStatus("Access Document cleared.", true);
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
