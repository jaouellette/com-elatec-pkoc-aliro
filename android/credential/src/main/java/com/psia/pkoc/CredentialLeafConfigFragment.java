package com.psia.pkoc;

import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.psia.pkoc.core.LeafVerifiedManager;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Credential-side LEAF Verified configuration screen.
 *
 * Extracted from {@link CredentialAliroConfigFragment} so that LEAF and Aliro
 * concerns live in separate, independently navigable screens.
 *
 * Features:
 *   1. Provisioning status — Open ID, certificate size, Root CA key preview
 *   2. Provision LEAF Credential — generates Root CA keypair + self-signed cert
 *   3. Export Root CA — shows QR + copies JSON to clipboard for reader import
 *   4. Clear LEAF — wipes all LEAF provisioning data
 */
public class CredentialLeafConfigFragment extends Fragment
{
    private TextView txtLeafStatus;
    private Button   btnLeafProvision;
    private Button   btnLeafExportRootCA;
    private Button   btnLeafClear;
    private TextView txtStatus;

    private final ExecutorService executor  = Executors.newSingleThreadExecutor();
    private final Handler         uiHandler = new Handler(Looper.getMainLooper());

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState)
    {
        return inflater.inflate(R.layout.fragment_credential_leaf_config, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        txtLeafStatus       = view.findViewById(R.id.txtLeafStatus);
        btnLeafProvision    = view.findViewById(R.id.btnLeafProvision);
        btnLeafExportRootCA = view.findViewById(R.id.btnLeafExportRootCA);
        btnLeafClear        = view.findViewById(R.id.btnLeafClear);
        txtStatus           = view.findViewById(R.id.txtCredLeafStatus);

        refreshLeafStatus();

        btnLeafProvision.setOnClickListener(v -> provisionLeafCredential());
        btnLeafExportRootCA.setOnClickListener(v -> exportLeafRootCA());
        btnLeafClear.setOnClickListener(v -> confirmClearLeaf());
    }

    @Override
    public void onResume()
    {
        super.onResume();
        refreshLeafStatus();
    }

    @Override
    public void onDestroyView()
    {
        super.onDestroyView();
        executor.shutdown();
    }

    // =========================================================================
    // LEAF Verified status
    // =========================================================================

    /**
     * Refresh the LEAF status text view with current provisioning state.
     * Shows Open ID, certificate size, and Root CA key preview when provisioned.
     */
    private void refreshLeafStatus()
    {
        if (!isAdded() || txtLeafStatus == null) return;

        if (!LeafVerifiedManager.isProvisioned(requireContext()))
        {
            txtLeafStatus.setText("Not provisioned");
            txtLeafStatus.setTextColor(
                    requireContext().getColor(android.R.color.darker_gray));
            btnLeafExportRootCA.setEnabled(false);
            btnLeafClear.setEnabled(false);
            return;
        }

        String openId    = LeafVerifiedManager.getOpenID(requireContext());
        byte[] certDER   = LeafVerifiedManager.getCredentialCertDER(requireContext());
        byte[] rootCAPub = LeafVerifiedManager.getRootCAPubKey(requireContext());

        String rootCaPreview = "";
        if (rootCAPub != null && rootCAPub.length >= 8)
        {
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 8; i++) hex.append(String.format("%02X", rootCAPub[i] & 0xFF));
            rootCaPreview = hex + "...";
        }

        String statusText = "Open ID:    " + (openId != null ? openId : "(none)") + "\n"
                + "Cert:       " + (certDER != null ? certDER.length + " bytes" : "(none)") + "\n"
                + "Root CA:    " + rootCaPreview;

        txtLeafStatus.setText(statusText);
        txtLeafStatus.setTextColor(requireContext().getColor(R.color.colorAccent));
        btnLeafExportRootCA.setEnabled(true);
        btnLeafClear.setEnabled(true);
    }

    // =========================================================================
    // Provision
    // =========================================================================

    /** Show confirmation dialog, then generate all LEAF credential material asynchronously. */
    private void provisionLeafCredential()
    {
        new AlertDialog.Builder(requireContext())
                .setTitle("Provision LEAF Credential")
                .setMessage("This generates a new LEAF Root CA keypair and credential certificate "
                        + "with a random 12-digit Open ID. Any existing LEAF credential will be "
                        + "replaced. Continue?")
                .setPositiveButton("Provision", (d, w) -> doProvisionLeaf())
                .setNegativeButton("Cancel", null)
                .show();
    }

    private void doProvisionLeaf()
    {
        showStatus("Generating LEAF credential...", false);
        if (btnLeafProvision != null) btnLeafProvision.setEnabled(false);

        executor.execute(() ->
        {
            String result = LeafVerifiedManager.provisionLeafCredential(requireContext());
            uiHandler.post(() ->
            {
                if (!isAdded()) return;
                if (btnLeafProvision != null) btnLeafProvision.setEnabled(true);
                if (result != null)
                {
                    refreshLeafStatus();
                    showStatus("\u2713 " + result, true);
                }
                else
                {
                    showStatus("LEAF provisioning failed \u2014 check logs.", false);
                }
            });
        });
    }

    // =========================================================================
    // Export Root CA
    // =========================================================================

    /**
     * Export the LEAF Root CA public key as a QR code and copy to clipboard.
     * The reader app scans this to configure Root CA trust for credential
     * verification.
     *
     * QR/clipboard JSON format:
     *   {"v":1,"type":"leaf_reader_config","rootCAPubKey":"04..."}
     */
    private void exportLeafRootCA()
    {
        String json = LeafVerifiedManager.buildExportJson(requireContext());
        if (json == null)
        {
            showStatus("No LEAF provisioning data to export.", false);
            return;
        }

        // Copy to clipboard as fallback
        ClipboardManager clipboard = (ClipboardManager)
                requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("LEAF Root CA", json));

        // Generate QR bitmap
        Bitmap qrBitmap = generateQrBitmap(json, 800);

        if (qrBitmap != null)
        {
            ImageView imageView = new ImageView(requireContext());
            imageView.setImageBitmap(qrBitmap);
            int padding = (int)(24 * requireContext().getResources().getDisplayMetrics().density);
            imageView.setPadding(padding, padding, padding, padding);

            new AlertDialog.Builder(requireContext())
                    .setTitle("LEAF Root CA \u2014 Scan on Reader Device")
                    .setMessage("Scan this QR code in the reader app\u2019s LEAF Config screen"
                            + " \u2192 \u201cImport Root CA\u201d."
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

    // =========================================================================
    // Clear LEAF
    // =========================================================================

    /** Confirm and wipe all LEAF credential data. */
    private void confirmClearLeaf()
    {
        new AlertDialog.Builder(requireContext())
                .setTitle("Clear LEAF Credential")
                .setMessage("Remove all LEAF provisioning data? The LEAF HCE service will stop "
                        + "responding to LEAF NFC readers until re-provisioned.")
                .setPositiveButton("Clear", (d, w) ->
                {
                    LeafVerifiedManager.clearProvisioning(requireContext());
                    refreshLeafStatus();
                    showStatus("LEAF credential cleared.", true);
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    // =========================================================================
    // QR code helper
    // =========================================================================

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

    // =========================================================================
    // UI helper
    // =========================================================================

    private void showStatus(String message, boolean success)
    {
        if (!isAdded() || txtStatus == null) return;
        txtStatus.setVisibility(View.VISIBLE);
        txtStatus.setText(message);
        txtStatus.setTextColor(success
                ? requireContext().getColor(R.color.colorAccent)
                : requireContext().getColor(android.R.color.holo_red_dark));
    }
}
