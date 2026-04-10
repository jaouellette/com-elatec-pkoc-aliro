package com.pkoc.readersimulator;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.journeyapps.barcodescanner.ScanContract;
import com.journeyapps.barcodescanner.ScanIntentResult;
import com.journeyapps.barcodescanner.ScanOptions;

/**
 * Fragment for configuring Aliro reader parameters.
 * Values are stored in SharedPreferences and loaded by HomeFragment
 * when an Aliro NFC or BLE transaction begins.
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

    private final ActivityResultLauncher<ScanOptions> qrScanLauncher =
            registerForActivityResult(new ScanContract(), this::onQrScanResult);

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

        loadFromPreferences();

        btnSave.setOnClickListener(v -> saveToPreferences());
        btnScanQr.setOnClickListener(v -> launchQrScanner());
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
        editor.apply();

        showStatus("Saved.", true);
    }

    // -------------------------------------------------------------------------
    // QR scanner
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
            showStatus("Issuer key scanned — tap Save to apply.", true);
        }
        else
        {
            showStatus("QR scan did not contain a valid 65-byte EC public key.", false);
        }
    }

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
