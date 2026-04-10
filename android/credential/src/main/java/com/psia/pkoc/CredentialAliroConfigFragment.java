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
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.psia.pkoc.core.AliroAccessDocument;

import java.security.KeyStore;
import java.security.interfaces.ECPublicKey;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Credential-side Aliro configuration screen.
 *
 * Allows the user to:
 *   1. Generate a self-signed test Access Document (for Step-Up flow testing)
 *   2. Import a pre-built Access Document from Base64 CBOR + issuer public key
 *   3. View the current document status (mode, element ID, expiry)
 *   4. Clear the stored document
 */
public class CredentialAliroConfigFragment extends Fragment
{
    private TextView    txtDocumentStatus;
    private Button      btnGenerateTest;
    private Button      btnImport;
    private Button      btnClear;
    private Button      btnCopyIssuerKey;
    private Button      btnShowQr;
    private LinearLayout layoutIssuerKey;
    private TextView    txtIssuerKeyPreview;
    private EditText    editElementId;
    private TextView    txtStatus;

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

        txtDocumentStatus  = view.findViewById(R.id.txtAccessDocStatus);
        btnGenerateTest    = view.findViewById(R.id.btnGenerateTestDoc);
        btnImport          = view.findViewById(R.id.btnImportDoc);
        btnClear           = view.findViewById(R.id.btnClearDoc);
        btnCopyIssuerKey   = view.findViewById(R.id.btnCopyIssuerKey);
        btnShowQr          = view.findViewById(R.id.btnShowQr);
        layoutIssuerKey    = view.findViewById(R.id.layoutIssuerKey);
        txtIssuerKeyPreview = view.findViewById(R.id.txtIssuerKeyPreview);
        editElementId      = view.findViewById(R.id.editElementIdentifier);
        txtStatus          = view.findViewById(R.id.txtCredAliroStatus);

        refreshDocumentStatus();

        btnGenerateTest.setOnClickListener(v -> generateTestDocument());
        btnImport.setOnClickListener(v -> showImportDialog());
        btnClear.setOnClickListener(v -> clearDocument());
        btnCopyIssuerKey.setOnClickListener(v -> copyIssuerKeyToClipboard());
        btnShowQr.setOnClickListener(v -> showIssuerKeyQrDialog());
    }

    @Override
    public void onDestroyView()
    {
        super.onDestroyView();
        executor.shutdown();
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

        String mode       = prefs.getString(AliroAccessDocument.KEY_DOC_MODE,        "—");
        String elementId  = prefs.getString(AliroAccessDocument.KEY_ELEMENT_ID,      "—");
        String validUntil = prefs.getString(AliroAccessDocument.KEY_DOC_VALID_UNTIL, "—");
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
            // Preview: first 16 chars + "..." + last 8 chars
            String preview = issuerHex.length() > 24
                    ? issuerHex.substring(0, 16) + "…" + issuerHex.substring(issuerHex.length() - 8)
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
    // Generate test document
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
            // Get credential public key from Android KeyStore
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
                    showStatus("✓ " + result, true);
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
                    showStatus("✓ " + result, true);
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
