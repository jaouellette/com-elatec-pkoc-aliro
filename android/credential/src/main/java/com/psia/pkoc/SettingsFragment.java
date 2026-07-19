package com.psia.pkoc;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.SeekBar;

import androidx.annotation.NonNull;
import androidx.fragment.app.Fragment;

import com.psia.pkoc.core.CryptoProvider;
import com.psia.pkoc.core.PKOC_ConnectionType;
import com.psia.pkoc.core.PKOC_Preferences;
import com.psia.pkoc.core.PKOC_TransmissionType;
import com.psia.pkoc.databinding.FragmentSettingsBinding;
import com.psia.pkoc.core.PkocBleReaderCredential;
import com.psia.pkoc.core.PkocBlePreferences;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.graphics.Bitmap;
import android.widget.ImageView;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;

import com.psia.pkoc.core.PkocNfcCardCredential;

import org.bouncycastle.util.encoders.Hex;
import org.json.JSONObject;

public class SettingsFragment extends Fragment
{
    private FragmentSettingsBinding binding;
    private SharedPreferences sharedPrefs;

    // -------------------------------------------------------------------------
    // Enrollment prefs (separate file from the activity-default sharedPrefs).
    // Keys MUST match those used by Aliro_HostApduService (Piece 5) and
    // CertEnrollConfirmActivity (Piece 3) — those classes read from the same
    // SharedPreferences file so the values written here take effect at the
    // next 0xE3 fetch / 0xE2 approve respectively.
    // -------------------------------------------------------------------------
    private static final String PREFS_APP_NAME                  = "AliroAppPrefs";
    private static final String PREF_ENROLL_PENDING_TIMEOUT_SEC = "enroll_pending_timeout_sec";
    private static final String PREF_ENROLL_GRACE_WINDOW_SEC    = "enroll_grace_window_sec";
    private static final String PREF_ENROLL_CERT_VALIDITY_DAYS  = "enroll_cert_validity_days";
    private static final int    DEFAULT_PENDING_TIMEOUT_SEC     = 60;
    private static final int    DEFAULT_GRACE_WINDOW_SEC        = 30;
    private static final int    DEFAULT_CERT_VALIDITY_DAYS      = 0;  // 0 = §13.3 defaults

    private SharedPreferences enrollmentPrefs;

    // Guards against a programmatic setText() (config load) being treated as a
    // user edit and persisting over a QR-scanned site key.
    private boolean isLoadingEcdheConfig = false;

    private void persistSiteIfValid()
    {
        if (isLoadingEcdheConfig) return;
        String siteUuidStr = safeText(binding.siteIdentifierInput);
        String pubKeyHex   = safeText(binding.sitePublicKeyInput);

        boolean ok = true;

        if (Validators.isValidUuid(siteUuidStr))
        {
            setError(binding.siteIdentifierInput, "Invalid Site UUID");
            ok = false;
        }
        else
        {
            clearError(binding.siteIdentifierInput);
        }

        if (!pubKeyHex.isEmpty() && !Validators.isValidHex(pubKeyHex, 65))
        {
            setError(binding.sitePublicKeyInput, "Must be 65-byte hex (130 chars) or empty for device key");
            ok = false;
        }
        else
        {
            clearError(binding.sitePublicKeyInput);
        }

        if (!ok) return;

        java.util.UUID siteUuid = java.util.UUID.fromString(siteUuidStr);
        byte[] sid = UuidConverters.fromUuid(siteUuid);
        byte[] pk  = org.bouncycastle.util.encoders.Hex.decode(pubKeyHex);
        // Do NOT persist the default/placeholder site key — otherwise simply opening
        // Settings in ECDHE mode overwrites a key provisioned by QR scan with the default.
        if (pubKeyHex.isEmpty() || pubKeyHex.equalsIgnoreCase(PKOC_Preferences.DEFAULT_SITE_PUBLIC_KEY))
        {
            return;
        }
        PKOC_Application.getDb().getQueryExecutor().execute(() ->
            PKOC_Application.getDb().siteDao().upsert(new SiteModel(sid, pk)));
    }

    private void persistReaderIfValid()
    {
        if (isLoadingEcdheConfig) return;
        String readerUuidStr = safeText(binding.readerIdentifierInput);
        String siteUuidStr   = safeText(binding.siteIdentifierInput);

        boolean ok = true;

        if (Validators.isValidUuid(readerUuidStr))
        {
            setError(binding.readerIdentifierInput, "Invalid Reader UUID");
            ok = false;
        }
        else
        {
            clearError(binding.readerIdentifierInput);
        }

        if (Validators.isValidUuid(siteUuidStr))
        {
            setError(binding.siteIdentifierInput, "Invalid Site UUID");
            ok = false;
        }
        else
        {
            clearError(binding.siteIdentifierInput);
        }

        if (!ok) return;

        byte[] rid = UuidConverters.fromUuid(java.util.UUID.fromString(readerUuidStr));
        byte[] sid = UuidConverters.fromUuid(java.util.UUID.fromString(siteUuidStr));

        PKOC_Application.getDb().getQueryExecutor().execute(() ->
            PKOC_Application.getDb().readerDao().upsert(new ReaderModel(rid, sid)));
    }

    // ---- tiny UI helpers ----
    private static String safeText(@NonNull android.widget.TextView tv)
    {
        CharSequence cs = tv.getText();
        return cs == null ? "" : cs.toString().trim();
    }

    private static void setError(@NonNull android.widget.TextView tv, @NonNull String msg)
    {
        if (tv.getParent() instanceof com.google.android.material.textfield.TextInputLayout)
        {
            ((com.google.android.material.textfield.TextInputLayout) tv.getParent()).setError(msg);
        }
        else
        {
            tv.setError(msg);
        }
    }

    private static void clearError(@NonNull android.widget.TextView tv)
    {
        if (tv.getParent() instanceof com.google.android.material.textfield.TextInputLayout)
        {
            ((com.google.android.material.textfield.TextInputLayout) tv.getParent()).setError(null);
        }
        else
        {
            tv.setError(null);
        }
    }

    @Override
    public View onCreateView (@NonNull LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState)
    {
        binding = FragmentSettingsBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    private void configureListeners()
    {
        binding.TransmissionRadioGroup.setOnCheckedChangeListener((group, checkedId) ->
        {
            if (checkedId == binding.NfcButton.getId())
            {
                binding.BleSettings.setVisibility(View.GONE);
                binding.NfcSettings.setVisibility(View.VISIBLE);
                sharedPrefs
                    .edit()
                    .putInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.NFC.ordinal())
                    .apply();
            }
            else
            {
                binding.BleSettings.setVisibility(View.VISIBLE);
                binding.NfcSettings.setVisibility(View.GONE);
                sharedPrefs
                    .edit()
                    .putInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.BLE.ordinal())
                    .apply();
            }
        });

        binding.RadioGroup.setOnCheckedChangeListener((group, checkedId) ->
        {
            if (checkedId == binding.UncompressedButton.getId())
            {

                binding.ecdheConfigStatus.setVisibility(View.GONE);
                binding.btnResetEcdheDefaults.setVisibility(View.GONE);
                binding.btnClearEcdheConfig.setVisibility(View.GONE);
                ((View) binding.btnResetEcdheDefaults.getParent()).setVisibility(View.GONE);
                binding.siteIdentifierLabel.setVisibility(View.GONE);
                binding.siteIdentifierInput.setVisibility(View.GONE);
                binding.readerIdentifierLabel.setVisibility(View.GONE);
                binding.readerIdentifierInput.setVisibility(View.GONE);
                binding.sitePublicKeyLabel.setVisibility(View.GONE);
                binding.sitePublicKeyInput.setVisibility(View.GONE);

                sharedPrefs
                    .edit()
                    .putInt(PKOC_Preferences.PKOC_TransmissionFlow, PKOC_ConnectionType.Uncompressed.ordinal())
                    .apply();
            }
            else
            {

                binding.ecdheConfigStatus.setVisibility(View.VISIBLE);
                ((View) binding.btnResetEcdheDefaults.getParent()).setVisibility(View.VISIBLE);
                binding.siteIdentifierLabel.setVisibility(View.VISIBLE);
                binding.siteIdentifierInput.setVisibility(View.VISIBLE);
                binding.readerIdentifierLabel.setVisibility(View.VISIBLE);
                binding.readerIdentifierInput.setVisibility(View.VISIBLE);
                binding.sitePublicKeyLabel.setVisibility(View.VISIBLE);
                binding.sitePublicKeyInput.setVisibility(View.VISIBLE);

                loadAndDisplayEcdheConfig();

                sharedPrefs
                    .edit()
                    .putInt(PKOC_Preferences.PKOC_TransmissionFlow, PKOC_ConnectionType.ECHDE_Full.ordinal())
                    .apply();
            }
        });

        binding.autoDiscoverSwitch.setOnCheckedChangeListener((buttonView, isChecked) ->
            sharedPrefs
                .edit()
                .putBoolean(PKOC_Preferences.AutoDiscoverDevices, isChecked)
                .apply());

        binding.enableRangingSwitch.setOnCheckedChangeListener((buttonView, isChecked) ->
        {
            sharedPrefs
                .edit()
                .putBoolean(PKOC_Preferences.EnableRanging, isChecked)
                .apply();

            if (isChecked)
            {
                binding.rangingSliderLabel.setVisibility(View.VISIBLE);
                binding.rangingSlider.setVisibility(View.VISIBLE);
                binding.rangingSliderLabelNear.setVisibility(View.VISIBLE);
                binding.rangingSliderLabelFar.setVisibility(View.VISIBLE);

                SharedPreferences sharedPref = requireActivity().getPreferences(Context.MODE_PRIVATE);
                int seekBarProgress = sharedPref.getInt(PKOC_Preferences.RangeValue, 0);
                binding.rangingSlider.setProgress(seekBarProgress);
            }
            else
            {
                binding.rangingSliderLabel.setVisibility(View.GONE);
                binding.rangingSlider.setVisibility(View.GONE);
                binding.rangingSliderLabelNear.setVisibility(View.GONE);
                binding.rangingSliderLabelFar.setVisibility(View.GONE);
            }
        });

        DebouncedTextWatcher.attach(binding.siteIdentifierInput, 300, t -> { persistSiteIfValid(); updateEcdheStatusLabel(); });
        DebouncedTextWatcher.attach(binding.sitePublicKeyInput,  300, t -> { persistSiteIfValid(); updateEcdheStatusLabel(); });
        DebouncedTextWatcher.attach(binding.readerIdentifierInput, 300, t -> { persistReaderIfValid(); updateEcdheStatusLabel(); });

        binding.btnResetEcdheDefaults.setOnClickListener(v -> resetEcdheToDefaults());
        binding.btnClearEcdheConfig.setOnClickListener(v -> clearEcdheForCustom());

        binding.rangingSlider.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener()
        {
            @Override
            public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser)
            {
                sharedPrefs
                    .edit()
                    .putInt(PKOC_Preferences.RangeValue, progress)
                    .apply();
            }

            @Override
            public void onStartTrackingTouch(SeekBar seekBar) {}
            @Override
            public void onStopTrackingTouch(SeekBar seekBar) {}
        });

        binding.displayMacSwitch.setOnCheckedChangeListener((buttonView, isChecked) ->
            sharedPrefs
                .edit()
                .putBoolean(PKOC_Preferences.DisplayMAC, isChecked)
                .apply());

        configureEnrollmentListeners();

        // ---- PKOC BLE v2.0.1 per-reader certificate controls ----
        binding.pkocPerreaderSwitch.setOnCheckedChangeListener((v, isChecked) ->
        {
            PkocBleReaderCredential.setEnabled(requireContext(), isChecked);
            if (isChecked && !binding.pkocCertModeImport.isChecked())
            {
                provisionPkocDemo();
            }
            updatePkocPerReaderStatus();
        });

        binding.pkocCertModeGroup.setOnCheckedChangeListener((group, checkedId) ->
        {
            boolean importMode = checkedId == binding.pkocCertModeImport.getId();
            binding.pkocImportGroup.setVisibility(importMode ? View.VISIBLE : View.GONE);
            requireContext()
                .getSharedPreferences(PkocBlePreferences.PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(PkocBlePreferences.MODE, importMode ? PkocBlePreferences.MODE_IMPORT : PkocBlePreferences.MODE_DEMO)
                .apply();
            if (!importMode && binding.pkocPerreaderSwitch.isChecked())
            {
                provisionPkocDemo();
            }
            updatePkocPerReaderStatus();
        });

        binding.pkocImportBtn.setOnClickListener(v ->
        {
            try
            {
                byte[] cert   = org.bouncycastle.util.encoders.Hex.decode(binding.pkocImportCertInput.getText().toString().trim());
                byte[] issuer = org.bouncycastle.util.encoders.Hex.decode(binding.pkocImportIssuerInput.getText().toString().trim());
                byte[] priv   = org.bouncycastle.util.encoders.Hex.decode(binding.pkocImportPrivInput.getText().toString().trim());
                boolean ok = PkocBleReaderCredential.importProvisioned(requireContext(), cert, issuer, priv);
                binding.pkocPerreaderStatus.setText(ok ? "Imported reader certificate OK." : "Import failed — check inputs.");
            }
            catch (Exception e)
            {
                binding.pkocPerreaderStatus.setText("Import failed: " + e.getMessage());
            }
        });
        binding.pkocScanReaderQrBtn.setOnClickListener(v ->
                androidx.navigation.fragment.NavHostFragment.findNavController(this)
                        .navigate(R.id.action_settingsFragment_to_scanReaderQrFragment));
        binding.scanSiteKeyQrBtn.setOnClickListener(v ->
                androidx.navigation.fragment.NavHostFragment.findNavController(this)
                        .navigate(R.id.action_settingsFragment_to_scanReaderQrFragment));

        // ---- PKOC NFC SE V2 card credential ----
        binding.pkocNfcCardSwitch.setOnCheckedChangeListener((v, isChecked) ->
        {
            PkocNfcCardCredential.setEnabled(requireContext(), isChecked);
            if (isChecked)
            {
                PkocNfcCardCredential.ensureDemoProvisioned(requireContext());
            }
            updatePkocNfcCardStatus();
        });

        binding.pkocExportSupplierBtn.setOnClickListener(v -> exportPkocSupplier());
    }

    private void initializeComponents()
    {
        int transmissionTypeInt = sharedPrefs.getInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.BLE.ordinal());
        PKOC_TransmissionType transmissionType = PKOC_TransmissionType.values()[transmissionTypeInt];

        if (transmissionType == PKOC_TransmissionType.NFC)
        {
            binding.TransmissionRadioGroup.check(binding.NfcButton.getId());
            binding.BleSettings.setVisibility(View.GONE);
            binding.NfcSettings.setVisibility(View.VISIBLE);
        }
        else
        {
            binding.TransmissionRadioGroup.check(binding.BleButton.getId());
            binding.BleSettings.setVisibility(View.VISIBLE);
            binding.NfcSettings.setVisibility(View.GONE);
        }

        int ToFlow_int = sharedPrefs.getInt(PKOC_Preferences.PKOC_TransmissionFlow, PKOC_ConnectionType.Uncompressed.ordinal());
        PKOC_ConnectionType toFlow = PKOC_ConnectionType.values()[ToFlow_int];

        if (toFlow == PKOC_ConnectionType.Uncompressed)
            binding.RadioGroup.check(binding.UncompressedButton.getId());

        if (toFlow == PKOC_ConnectionType.ECHDE_Full)
            binding.RadioGroup.check(binding.ECHDEComplete.getId());

        // Show/hide ECDHE-specific fields + status/buttons
        boolean isEcdhe = toFlow == PKOC_ConnectionType.ECHDE_Full;
        int visibility = isEcdhe ? View.VISIBLE : View.GONE;

        binding.ecdheConfigStatus.setVisibility(visibility);
        ((View) binding.btnResetEcdheDefaults.getParent()).setVisibility(visibility);
        binding.siteIdentifierLabel.setVisibility(visibility);
        binding.siteIdentifierInput.setVisibility(visibility);
        binding.readerIdentifierLabel.setVisibility(visibility);
        binding.readerIdentifierInput.setVisibility(visibility);
        binding.sitePublicKeyLabel.setVisibility(visibility);
        binding.sitePublicKeyInput.setVisibility(visibility);

        boolean AutoDiscover = sharedPrefs.getBoolean(PKOC_Preferences.AutoDiscoverDevices, false);
        binding.autoDiscoverSwitch.setChecked(AutoDiscover);

        boolean enableRanging = sharedPrefs.getBoolean(PKOC_Preferences.EnableRanging, false);
        binding.enableRangingSwitch.setChecked(enableRanging);

        boolean displayMAC = sharedPrefs.getBoolean(PKOC_Preferences.DisplayMAC, true);
        binding.displayMacSwitch.setChecked(displayMAC);

        if(enableRanging)
        {
            binding.rangingSliderLabel.setVisibility(View.VISIBLE);
            binding.rangingSlider.setVisibility(View.VISIBLE);
            binding.rangingSliderLabelNear.setVisibility(View.VISIBLE);
            binding.rangingSliderLabelFar.setVisibility(View.VISIBLE);

            int seekBarProgress = sharedPrefs.getInt(PKOC_Preferences.RangeValue, 0);
            binding.rangingSlider.setProgress(seekBarProgress);
        }
        else
        {
            binding.rangingSliderLabel.setVisibility(View.GONE);
            binding.rangingSlider.setVisibility(View.GONE);
            binding.rangingSliderLabelNear.setVisibility(View.GONE);
            binding.rangingSliderLabelFar.setVisibility(View.GONE);
        }

        if (toFlow == PKOC_ConnectionType.ECHDE_Full)
        {
            loadAndDisplayEcdheConfig();
        }

        initializeEnrollmentSettings();

        // ---- PKOC BLE v2.0.1 per-reader certificate state ----
        binding.pkocPerreaderSwitch.setChecked(PkocBleReaderCredential.isEnabled(requireContext()));
        String pkocMode = requireContext()
            .getSharedPreferences(PkocBlePreferences.PREFS_NAME, Context.MODE_PRIVATE)
            .getString(PkocBlePreferences.MODE, PkocBlePreferences.MODE_DEMO);
        boolean pkocImportMode = PkocBlePreferences.MODE_IMPORT.equals(pkocMode);
        binding.pkocCertModeGroup.check(pkocImportMode ? binding.pkocCertModeImport.getId() : binding.pkocCertModeDemo.getId());
        binding.pkocImportGroup.setVisibility(pkocImportMode ? View.VISIBLE : View.GONE);
        updatePkocPerReaderStatus();

        // ---- PKOC NFC SE V2 card credential state ----
        binding.pkocNfcCardSwitch.setChecked(PkocNfcCardCredential.isEnabled(requireContext()));
        updatePkocNfcCardStatus();
    }



    // =========================================================================
    // ECDHE config helpers
    // =========================================================================

    /** Load ECDHE values from prefs (with defaults) and display them. */
    private void loadAndDisplayEcdheConfig()
    {
        // Do NOT default to the device's own key — an empty field means "not set;
        // scan a reader" and avoids persisting a bogus key over a scanned one.
        String siteKey  = sharedPrefs.getString(
                PKOC_Preferences.ECDHE_SitePublicKey, "");
        String siteId   = sharedPrefs.getString(
                PKOC_Preferences.ECDHE_SiteId,
                PKOC_Preferences.DEFAULT_SITE_UUID);
        String readerId = sharedPrefs.getString(
                PKOC_Preferences.ECDHE_ReaderId,
                PKOC_Preferences.DEFAULT_READER_UUID);

        isLoadingEcdheConfig = true;
        binding.sitePublicKeyInput.setText(siteKey);
        binding.siteIdentifierInput.setText(siteId);
        binding.readerIdentifierInput.setText(readerId);
        isLoadingEcdheConfig = false;

        updateEcdheStatusLabel();
    }

    /** Check if current ECDHE values match the built-in defaults and update status label. */
    private void updateEcdheStatusLabel()
    {
        if (binding == null || binding.ecdheConfigStatus == null) return;

        String siteId   = safeText(binding.siteIdentifierInput);
        String readerId = safeText(binding.readerIdentifierInput);
        String siteKey  = safeText(binding.sitePublicKeyInput);

        boolean isDefault = siteId.equals(PKOC_Preferences.DEFAULT_SITE_UUID)
                && readerId.equals(PKOC_Preferences.DEFAULT_READER_UUID)
                && siteKey.equals(PKOC_Preferences.DEFAULT_SITE_PUBLIC_KEY);

        if (isDefault)
        {
            binding.ecdheConfigStatus.setText("Using built-in ELATEC defaults");
            binding.ecdheConfigStatus.setTextColor(0xFF4472C4); // blue
        }
        else
        {
            binding.ecdheConfigStatus.setText("Using custom configuration");
            binding.ecdheConfigStatus.setTextColor(0xFF2E7D32); // green
        }
    }

    /** Reset all ECDHE fields to built-in defaults. */
    private void resetEcdheToDefaults()
    {
        sharedPrefs.edit()
                .putString(PKOC_Preferences.ECDHE_SiteId, PKOC_Preferences.DEFAULT_SITE_UUID)
                .putString(PKOC_Preferences.ECDHE_ReaderId, PKOC_Preferences.DEFAULT_READER_UUID)
                .putString(PKOC_Preferences.ECDHE_SitePublicKey, PKOC_Preferences.DEFAULT_SITE_PUBLIC_KEY)
                .putString(PKOC_Preferences.ReaderUUID, PKOC_Preferences.DEFAULT_READER_UUID)
                .putString(PKOC_Preferences.SiteUUID, PKOC_Preferences.DEFAULT_SITE_UUID)
                .apply();

        // Re-load and display — this will resolve the empty site key
        // back to the device's own PKOC public key.
        loadAndDisplayEcdheConfig();

        android.widget.Toast.makeText(requireContext(),
                "ECDHE config reset to ELATEC defaults",
                android.widget.Toast.LENGTH_SHORT).show();
    }

    /** Clear all ECDHE fields so the user can enter custom values. */
    private void clearEcdheForCustom()
    {
        sharedPrefs.edit()
                .putString(PKOC_Preferences.ECDHE_SiteId, "")
                .putString(PKOC_Preferences.ECDHE_ReaderId, "")
                .putString(PKOC_Preferences.ECDHE_SitePublicKey, "")
                .apply();

        binding.siteIdentifierInput.setText("");
        binding.readerIdentifierInput.setText("");
        binding.sitePublicKeyInput.setText("");

        updateEcdheStatusLabel();

        binding.siteIdentifierInput.requestFocus();

        android.widget.Toast.makeText(requireContext(),
                "Enter your custom Site UUID, Reader UUID, and Site Public Key",
                android.widget.Toast.LENGTH_SHORT).show();
    }

    // =========================================================================
    // PKOC BLE v2.0.1 per-reader certificate helpers
    // =========================================================================

    /** Self-provision a demo Reader Signing key + self-signed Reader Certificate. */
    private void provisionPkocDemo()
    {
        SharedPreferences p = requireActivity().getPreferences(Context.MODE_PRIVATE);
        String siteStr   = p.getString(PKOC_Preferences.SiteUUID, PKOC_Preferences.DEFAULT_SITE_UUID);
        String readerStr = p.getString(PKOC_Preferences.ReaderUUID, PKOC_Preferences.DEFAULT_READER_UUID);
        byte[] siteId   = UuidConverters.fromUuid(java.util.UUID.fromString(siteStr));
        byte[] readerId = UuidConverters.fromUuid(java.util.UUID.fromString(readerStr));
        boolean ok = PkocBleReaderCredential.ensureDemoProvisioned(requireContext(), siteId, readerId);
        binding.pkocPerreaderStatus.setText(ok ? "Demo reader certificate provisioned." : "Demo provisioning failed.");
    }

    /** Refresh the per-reader status line. */
    private void updatePkocPerReaderStatus()
    {
        boolean enabled = PkocBleReaderCredential.isEnabled(requireContext());
        boolean provisioned = PkocBleReaderCredential.isProvisioned(requireContext());
        binding.pkocPerreaderStatus.setText(
            "Per-reader: " + (enabled ? "ON" : "OFF") + (provisioned ? " \u00B7 certificate ready" : " \u00B7 not provisioned"));
    }

    // =========================================================================
    // PKOC NFC SE V2 supplier export
    // =========================================================================

    /** Refresh the PKOC NFC SE V2 card credential status line. */
    private void updatePkocNfcCardStatus()
    {
        boolean enabled = PkocNfcCardCredential.isEnabled(requireContext());
        boolean provisioned = PkocNfcCardCredential.isProvisioned(requireContext());
        String iir = PkocNfcCardCredential.getIir(requireContext());
        binding.pkocNfcCardStatus.setText(
                "NFC SE V2: " + (enabled ? "ON" : "OFF")
                        + (provisioned ? " \u00B7 CVC ready" : " \u00B7 not provisioned")
                        + (iir != null && iir.length() == 16 ? " \u00B7 IIR " + iir : ""));
    }

    /**
     * Export this credential's PKOC supplier - its IIR and demo Card Issuer public
     * key - as a QR the reader app scans in "PKOC Credential Suppliers" to trust it
     * in Validated Mode (NFC Transport Profile 2.0.1 5.3 / 10).
     *
     * QR/clipboard JSON:
     *   {"v":1,"type":"pkoc_supplier","iir":"01000ELATEC00001","issuerPublicKey":"04..."}
     *
     * Available only when the card is demo-provisioned: in import mode the issuer
     * public key is not held on the device (the issuer signs the CVC out of band).
     */
    private void exportPkocSupplier()
    {
        // Self-provision on demand: the demo issuer key only exists once a demo
        // CVC has been generated. Don't require the user to toggle the switch first.
        if (PkocNfcCardCredential.getCardIssuerPublicKey(requireContext()) == null)
        {
            boolean ok = PkocNfcCardCredential.ensureDemoProvisioned(requireContext());
            updatePkocNfcCardStatus();
            if (!ok)
            {
                android.widget.Toast.makeText(requireContext(),
                        "Could not provision a demo PKOC credential (see log). "
                                + "Import mode has no local issuer key to export.",
                        android.widget.Toast.LENGTH_LONG).show();
                return;
            }
        }

        byte[] issuerPub = PkocNfcCardCredential.getCardIssuerPublicKey(requireContext());
        String iir = PkocNfcCardCredential.getIir(requireContext());
        if (issuerPub == null || iir == null || iir.length() != 16)
        {
            android.widget.Toast.makeText(requireContext(),
                    "Nothing to export — enable the NFC SE V2 card in demo mode first.",
                    android.widget.Toast.LENGTH_LONG).show();
            return;
        }

        String json;
        try
        {
            JSONObject obj = new JSONObject();
            obj.put("v", 1);
            obj.put("type", "pkoc_supplier");
            obj.put("iir", iir);
            obj.put("issuerPublicKey", Hex.toHexString(issuerPub));
            json = obj.toString();
        }
        catch (Exception e)
        {
            android.widget.Toast.makeText(requireContext(),
                    "Export failed: " + e.getMessage(), android.widget.Toast.LENGTH_LONG).show();
            return;
        }

        ClipboardManager clipboard =
                (ClipboardManager) requireContext().getSystemService(Context.CLIPBOARD_SERVICE);
        clipboard.setPrimaryClip(ClipData.newPlainText("PKOC Supplier", json));

        Bitmap qr = generateQrBitmap(json, 800);
        if (qr != null)
        {
            ImageView imageView = new ImageView(requireContext());
            imageView.setImageBitmap(qr);
            int padding = (int) (24 * requireContext().getResources().getDisplayMetrics().density);
            imageView.setPadding(padding, padding, padding, padding);

            new AlertDialog.Builder(requireContext())
                    .setTitle("PKOC Supplier \u2014 Scan on Reader")
                    .setMessage("Scan this QR in the reader app\u2019s \u201cPKOC Credential Suppliers\u201d"
                            + " screen \u2192 \u201cScan Supplier QR\u201d. JSON also copied to clipboard.\n\nIIR: " + iir)
                    .setView(imageView)
                    .setPositiveButton("Done", null)
                    .show();
        }
        else
        {
            android.widget.Toast.makeText(requireContext(),
                    "QR generation failed. JSON copied to clipboard.",
                    android.widget.Toast.LENGTH_LONG).show();
        }
    }

    /** QR bitmap helper - same approach as the app's other QR exports. */
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

    @Override
    public void onViewCreated (@NonNull View view, Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        sharedPrefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
        enrollmentPrefs = requireContext().getSharedPreferences(PREFS_APP_NAME, Context.MODE_PRIVATE);
        initializeComponents();
        configureListeners();
    }

    // =========================================================================
    // Enrollment settings (Aliro reader enrollment over NFC)
    // =========================================================================

    /** Load configured enrollment values into the three EditTexts. */
    private void initializeEnrollmentSettings()
    {
        int pendingSec   = enrollmentPrefs.getInt(PREF_ENROLL_PENDING_TIMEOUT_SEC, DEFAULT_PENDING_TIMEOUT_SEC);
        int graceSec     = enrollmentPrefs.getInt(PREF_ENROLL_GRACE_WINDOW_SEC,    DEFAULT_GRACE_WINDOW_SEC);
        int validityDays = enrollmentPrefs.getInt(PREF_ENROLL_CERT_VALIDITY_DAYS,  DEFAULT_CERT_VALIDITY_DAYS);

        binding.enrollmentPendingTimeoutInput.setText(String.valueOf(pendingSec));
        binding.enrollmentGraceWindowInput.setText(String.valueOf(graceSec));
        binding.enrollmentCertValidityInput.setText(String.valueOf(validityDays));
    }

    /** Wire up debounced text watchers so changes persist as the user types. */
    private void configureEnrollmentListeners()
    {
        DebouncedTextWatcher.attach(binding.enrollmentPendingTimeoutInput, 300, t ->
                writeEnrollmentIntPref(PREF_ENROLL_PENDING_TIMEOUT_SEC,
                        binding.enrollmentPendingTimeoutInput,
                        DEFAULT_PENDING_TIMEOUT_SEC,
                        1, 3600));   // 1 s to 1 h

        DebouncedTextWatcher.attach(binding.enrollmentGraceWindowInput, 300, t ->
                writeEnrollmentIntPref(PREF_ENROLL_GRACE_WINDOW_SEC,
                        binding.enrollmentGraceWindowInput,
                        DEFAULT_GRACE_WINDOW_SEC,
                        1, 3600));   // 1 s to 1 h

        DebouncedTextWatcher.attach(binding.enrollmentCertValidityInput, 300, t ->
                writeEnrollmentIntPref(PREF_ENROLL_CERT_VALIDITY_DAYS,
                        binding.enrollmentCertValidityInput,
                        DEFAULT_CERT_VALIDITY_DAYS,
                        0, 36500));  // 0 = defaults, up to 100 years
    }

    /**
     * Parse the EditText as an integer in [min,max] and persist; on bad input
     * clear the field's error indicator and write the default instead.
     */
    private void writeEnrollmentIntPref(String key, android.widget.EditText input,
                                        int defaultValue, int min, int max)
    {
        String raw = safeText(input);
        int value  = defaultValue;
        boolean valid = true;
        if (raw.isEmpty())
        {
            // Empty field — persist default but don't flag an error.
            value = defaultValue;
        }
        else
        {
            try
            {
                int parsed = Integer.parseInt(raw);
                if (parsed < min || parsed > max)
                {
                    valid = false;
                }
                else
                {
                    value = parsed;
                }
            }
            catch (NumberFormatException nfe)
            {
                valid = false;
            }
        }

        if (!valid)
        {
            setError(input, "Enter " + min + ".." + max);
            return;
        }
        clearError(input);
        enrollmentPrefs.edit().putInt(key, value).apply();
    }

    @Override
    public void onDestroyView ()
    {
        super.onDestroyView();
        binding = null;
    }
}
