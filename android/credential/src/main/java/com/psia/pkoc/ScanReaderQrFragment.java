package com.psia.pkoc;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.fragment.NavHostFragment;

import com.psia.pkoc.databinding.FragmentScanReaderQrBinding;

import org.json.JSONObject;

public class ScanReaderQrFragment extends Fragment
{
    private static final String TAG = "ScanReaderQr";
    private FragmentScanReaderQrBinding binding;
    private ScanReaderQrViewModel viewModel;
    private boolean handled = false;

    private final ActivityResultLauncher<String> requestPermissionLauncher =
            registerForActivityResult(new ActivityResultContracts.RequestPermission(), isGranted ->
            {
                if (isGranted) startCamera();
                else
                {
                    Toast.makeText(requireContext(), "Camera permission is required to scan QR codes", Toast.LENGTH_LONG).show();
                    NavHostFragment.findNavController(this).popBackStack();
                }
            });

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState)
    {
        binding = FragmentScanReaderQrBinding.inflate(inflater, container, false);
        viewModel = new ViewModelProvider(this).get(ScanReaderQrViewModel.class);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        if (ContextCompat.checkSelfPermission(requireContext(), Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
            startCamera();
        else
            requestPermissionLauncher.launch(Manifest.permission.CAMERA);

        viewModel.getToastMessage().observe(getViewLifecycleOwner(), message ->
                Toast.makeText(requireContext(), message, Toast.LENGTH_LONG).show());
    }

    private void startCamera()
    {
        binding.barcodeScanner.decodeContinuous(result ->
        {
            if (result.getText() != null) handleQrCode(result.getText());
        });
    }

    private void handleQrCode(String contents)
    {
        if (handled) return;   // decodeContinuous can fire repeatedly; act once
        handled = true;

        Log.i(TAG, "QR raw: " + contents);
        try
        {
            JSONObject j = new JSONObject(contents);
            String siteUuid   = j.getString("siteUuid");
            String readerUuid = j.getString("readerUuid");
            String publicKey  = j.getString("publicKey");
            String siteIssuerKey = j.has("siteIssuerKey") ? j.getString("siteIssuerKey") : null;
            String cert          = j.has("cert") ? j.getString("cert") : null;

            Log.i(TAG, "PARSED site=" + siteUuid + " reader=" + readerUuid
                    + " pk=" + publicKey + " issuer=" + siteIssuerKey);

            viewModel.upsertReader(siteUuid, readerUuid, publicKey, siteIssuerKey, cert);
            NavHostFragment.findNavController(this).popBackStack();
        }
        catch (Exception e)
        {
            handled = false;
            Log.e(TAG, "QR is not the expected JSON. Raw content above.", e);
            Toast.makeText(requireContext(), "Invalid QR code", Toast.LENGTH_SHORT).show();
        }
    }

    @Override
    public void onResume() { super.onResume(); binding.barcodeScanner.resume(); }

    @Override
    public void onPause() { super.onPause(); binding.barcodeScanner.pause(); }
}
