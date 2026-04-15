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

public class SettingsFragment extends Fragment
{
    private FragmentSettingsBinding binding;
    private SharedPreferences sharedPrefs;

    private void persistSiteIfValid()
    {
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

        PKOC_Application.getDb().getQueryExecutor().execute(() ->
            PKOC_Application.getDb().siteDao().upsert(new SiteModel(sid, pk)));
    }

    private void persistReaderIfValid()
    {
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
                sharedPrefs
                    .edit()
                    .putInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.NFC.ordinal())
                    .apply();
            }
            else
            {
                binding.BleSettings.setVisibility(View.VISIBLE);
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
    }

    private void initializeComponents()
    {
        int transmissionTypeInt = sharedPrefs.getInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.BLE.ordinal());
        PKOC_TransmissionType transmissionType = PKOC_TransmissionType.values()[transmissionTypeInt];

        if (transmissionType == PKOC_TransmissionType.NFC)
        {
            binding.TransmissionRadioGroup.check(binding.NfcButton.getId());
            binding.BleSettings.setVisibility(View.GONE);
        }
        else
        {
            binding.TransmissionRadioGroup.check(binding.BleButton.getId());
            binding.BleSettings.setVisibility(View.VISIBLE);
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
    }



    // =========================================================================
    // ECDHE config helpers
    // =========================================================================

    /** Load ECDHE values from prefs (with defaults) and display them. */
    private void loadAndDisplayEcdheConfig()
    {
        String siteKey  = sharedPrefs.getString(
                PKOC_Preferences.ECDHE_SitePublicKey,
                PKOC_Preferences.DEFAULT_SITE_PUBLIC_KEY);
        String siteId   = sharedPrefs.getString(
                PKOC_Preferences.ECDHE_SiteId,
                PKOC_Preferences.DEFAULT_SITE_UUID);
        String readerId = sharedPrefs.getString(
                PKOC_Preferences.ECDHE_ReaderId,
                PKOC_Preferences.DEFAULT_READER_UUID);

        // If site public key is empty, show the device's own PKOC public key
        // as the default (self-signed demo mode).
        if (siteKey == null || siteKey.isEmpty())
        {
            try
            {
                byte[] devicePub = CryptoProvider.getUncompressedPublicKeyBytes();
                if (devicePub != null)
                {
                    siteKey = org.bouncycastle.util.encoders.Hex.toHexString(devicePub);
                }
            }
            catch (Exception e)
            {
                Log.w("SettingsFragment", "Could not get device public key for default", e);
            }
        }

        binding.sitePublicKeyInput.setText(siteKey);
        binding.siteIdentifierInput.setText(siteId);
        binding.readerIdentifierInput.setText(readerId);

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

    @Override
    public void onViewCreated (@NonNull View view, Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        sharedPrefs = requireActivity().getPreferences(Context.MODE_PRIVATE);
        initializeComponents();
        configureListeners();
    }

    @Override
    public void onDestroyView ()
    {
        super.onDestroyView();
        binding = null;
    }
}