package com.pkoc.readersimulator;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.journeyapps.barcodescanner.ScanContract;
import com.journeyapps.barcodescanner.ScanIntentResult;
import com.journeyapps.barcodescanner.ScanOptions;

import com.psia.pkoc.core.LeafVerifiedManager;

import org.json.JSONObject;

/**
 * Fragment for configuring LEAF Verified reader trust.
 *
 * Extracts all LEAF-related settings out of AliroConfigFragment into this
 * dedicated screen so that Aliro and LEAF concerns are independently navigable.
 *
 * Values are stored in the "LeafVerified" SharedPreferences via
 * {@link LeafVerifiedManager} and are read by HomeFragment when an NFC or BLE
 * transaction begins in LEAF detection mode.
 *
 * Features:
 *   - LEAF Mode checkbox — enables LEAF detection in Auto/reader mode
 *   - Root CA status display — shows configured key or "not configured"
 *   - Import Root CA button — scans QR exported from the credential app
 *   - Clear Root CA button — removes the stored Root CA key
 */
public class LeafConfigFragment extends Fragment
{
    private CheckBox chkLeafMode;
    private TextView txtLeafRootCaStatus;
    private Button   btnImportLeafRootCa;
    private Button   btnClearLeafRootCa;
    private TextView txtStatus;

    /** QR scanner for LEAF Root CA import. */
    private final ActivityResultLauncher<ScanOptions> leafRootCaScanLauncher =
            registerForActivityResult(new ScanContract(), this::onLeafRootCaScanResult);

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState)
    {
        return inflater.inflate(R.layout.fragment_leaf_config, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        chkLeafMode         = view.findViewById(R.id.chkLeafMode);
        txtLeafRootCaStatus = view.findViewById(R.id.txtLeafRootCaStatus);
        btnImportLeafRootCa = view.findViewById(R.id.btnImportLeafRootCa);
        btnClearLeafRootCa  = view.findViewById(R.id.btnClearLeafRootCa);
        txtStatus           = view.findViewById(R.id.txtLeafConfigStatus);

        loadFromPreferences();

        chkLeafMode.setOnCheckedChangeListener((cb, checked) -> saveLeafModeEnabled(checked));
        btnImportLeafRootCa.setOnClickListener(v -> launchLeafRootCaScanner());
        btnClearLeafRootCa.setOnClickListener(v -> clearLeafRootCa());
    }

    @Override
    public void onResume()
    {
        super.onResume();
        refreshLeafRootCaStatus();
    }

    // =========================================================================
    // Preferences
    // =========================================================================

    private void loadFromPreferences()
    {
        // LEAF mode flag is stored in both activity prefs (read by HomeFragment)
        // and the LEAF-specific prefs (LeafVerifiedManager).  Read from the
        // activity prefs so the two always agree.
        boolean leafMode = requireActivity()
                .getPreferences(Context.MODE_PRIVATE)
                .getBoolean(LeafVerifiedManager.READER_PREF_LEAF_MODE, false);
        chkLeafMode.setChecked(leafMode);

        refreshLeafRootCaStatus();
    }

    /**
     * Persist the LEAF mode flag.
     *
     * The flag is written to both the activity-level SharedPreferences
     * (consumed by HomeFragment's onTagDiscovered) and the LEAF-specific
     * "LeafVerified" SharedPreferences (consumed by LeafVerifiedManager).
     */
    private void saveLeafModeEnabled(boolean enabled)
    {
        // Activity prefs — read by HomeFragment
        requireActivity().getPreferences(Context.MODE_PRIVATE)
                .edit()
                .putBoolean(LeafVerifiedManager.READER_PREF_LEAF_MODE, enabled)
                .apply();

        // LeafVerified prefs — for consistency / LeafVerifiedManager consumers
        requireContext()
                .getSharedPreferences(LeafVerifiedManager.PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(LeafVerifiedManager.READER_PREF_LEAF_MODE, enabled)
                .apply();

        showStatus("LEAF mode " + (enabled ? "enabled" : "disabled") + ".", true);
    }

    // =========================================================================
    // Root CA status
    // =========================================================================

    /**
     * Refresh the Root CA status label with the currently configured key, or
     * show "not configured" when no key is stored.
     */
    private void refreshLeafRootCaStatus()
    {
        if (!isAdded() || txtLeafRootCaStatus == null) return;

        String rootCaHex = LeafVerifiedManager.getReaderRootCAPubKeyHex(requireContext());
        if (rootCaHex == null || rootCaHex.isEmpty())
        {
            txtLeafRootCaStatus.setText("Root CA: not configured");
            txtLeafRootCaStatus.setTextColor(
                    requireContext().getColor(android.R.color.darker_gray));
            if (btnClearLeafRootCa != null) btnClearLeafRootCa.setEnabled(false);
        }
        else
        {
            // Show preview: first 16 hex chars + "…"
            String preview = rootCaHex.length() > 16
                    ? rootCaHex.substring(0, 16) + "\u2026"
                    : rootCaHex;
            txtLeafRootCaStatus.setText("Root CA: " + preview);
            txtLeafRootCaStatus.setTextColor(
                    requireContext().getColor(R.color.colorAccent));
            if (btnClearLeafRootCa != null) btnClearLeafRootCa.setEnabled(true);
        }
    }

    // =========================================================================
    // QR scanner — Root CA import
    // =========================================================================

    /**
     * Launch the ZXing QR scanner to import the LEAF Root CA public key from
     * the credential app.
     *
     * Expected QR content:
     *   JSON  — {"v":1,"type":"leaf_reader_config","rootCAPubKey":"04..."}
     *   Plain — 130 hex characters (raw 65-byte uncompressed EC public key)
     */
    private void launchLeafRootCaScanner()
    {
        ScanOptions options = new ScanOptions();
        options.setDesiredBarcodeFormats(ScanOptions.QR_CODE);
        options.setPrompt("Scan the LEAF Root CA QR from the credential app");
        options.setBeepEnabled(false);
        options.setOrientationLocked(false);
        leafRootCaScanLauncher.launch(options);
    }

    private void onLeafRootCaScanResult(ScanIntentResult result)
    {
        if (result.getContents() == null) return;   // user cancelled
        String scanned = result.getContents().trim();

        // Try JSON format first: {"v":1,"type":"leaf_reader_config","rootCAPubKey":"04..."}
        try
        {
            JSONObject obj = new JSONObject(scanned);
            if (obj.optInt("v", 0) == 1
                    && "leaf_reader_config".equals(obj.optString("type", "")))
            {
                String rootCaHex = obj.getString("rootCAPubKey")
                        .toLowerCase(java.util.Locale.US);
                if (isValidHex(rootCaHex, 130))
                {
                    LeafVerifiedManager.setReaderRootCAPubKey(requireContext(), rootCaHex);
                    refreshLeafRootCaStatus();
                    showStatus("\u2713 LEAF Root CA imported.\n"
                            + "Key: " + rootCaHex.substring(0, 16) + "...", true);
                    return;
                }
            }
        }
        catch (Exception ignored) {}

        // Fallback: raw 130-hex-char public key
        String hex = scanned.toLowerCase(java.util.Locale.US);
        if (isValidHex(hex, 130))
        {
            LeafVerifiedManager.setReaderRootCAPubKey(requireContext(), hex);
            refreshLeafRootCaStatus();
            showStatus("\u2713 LEAF Root CA imported (raw key).", true);
        }
        else
        {
            showStatus("QR does not contain a valid LEAF Root CA "
                    + "(expected JSON or 130-char hex).", false);
        }
    }

    // =========================================================================
    // Clear Root CA
    // =========================================================================

    /** Remove the stored LEAF Root CA public key from this reader. */
    private void clearLeafRootCa()
    {
        requireContext()
                .getSharedPreferences(LeafVerifiedManager.PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .remove(LeafVerifiedManager.READER_PREF_ROOT_CA_PUB)
                .apply();
        refreshLeafRootCaStatus();
        showStatus("LEAF Root CA cleared.", true);
    }

    // =========================================================================
    // UI helpers
    // =========================================================================

    private void showStatus(String message, boolean success)
    {
        if (txtStatus == null) return;
        txtStatus.setVisibility(View.VISIBLE);
        txtStatus.setText(message);
        txtStatus.setTextColor(success
                ? requireContext().getColor(R.color.colorAccent)
                : requireContext().getColor(android.R.color.holo_red_dark));
    }

    /**
     * Returns true when {@code s} is a non-empty hex string of exactly
     * {@code expectedLength} characters ({@code expectedLength == -1} skips the
     * length check).
     */
    private static boolean isValidHex(String s, int expectedLength)
    {
        if (TextUtils.isEmpty(s)) return false;
        if (expectedLength >= 0 && s.length() != expectedLength) return false;
        return s.matches("[0-9a-f]+");
    }
}
