package com.pkoc.readersimulator;

import android.os.Bundle;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;

import com.journeyapps.barcodescanner.ScanContract;
import com.journeyapps.barcodescanner.ScanIntentResult;
import com.journeyapps.barcodescanner.ScanOptions;

import com.psia.pkoc.core.IssuerKey;
import com.psia.pkoc.core.PkocNfcReaderConfig;

import org.json.JSONObject;

import java.util.List;
import java.util.Locale;

/**
 * Reader-side configuration for PKOC NFC SE V2 Validated Mode: the operator adds
 * and retires credential suppliers (Issuer Keys) by IIR (NFC Transport Profile
 * 2.0.1 §5.3 / §10).
 *
 * <p>Each supplier is a 16-character Issuer Identification Reference (the IIR that
 * a presented PKOC-CVC carries in tag 42) paired with the issuer's EC P-256 public
 * key. Because a presented certificate resolves to whichever configured key its
 * IIR names, several suppliers coexist; migrating from one to another is just
 * adding the incoming supplier and retiring the outgoing one. All persistence goes
 * through {@link PkocNfcReaderConfig} — this screen owns no storage of its own.</p>
 *
 * <p>Suppliers can be added two ways: by scanning the QR the credential app's PKOC
 * export produces ({@code {"v":1,"type":"pkoc_supplier","iir":...,"issuerPublicKey":"04..."}}),
 * or by pasting the IIR and issuer public key by hand.</p>
 */
public class PkocNfcIssuerConfigFragment extends Fragment
{
    private CheckBox   chkValidatedMode;
    private CheckBox   chkRequireValidity;
    private Button     btnScanSupplier;
    private EditText   editIir;
    private EditText   editIssuerPubHex;
    private Button     btnAddSupplier;
    private Button     btnClearAll;
    private LinearLayout supplierListContainer;
    private TextView   txtEmptyState;
    private TextView   txtStatus;

    /** QR scanner for supplier import, mirroring the reader's other config imports. */
    private final ActivityResultLauncher<ScanOptions> supplierScanLauncher =
            registerForActivityResult(new ScanContract(), this::onSupplierScanResult);

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater,
                             @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState)
    {
        return inflater.inflate(R.layout.fragment_pkoc_nfc_issuer_config, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState)
    {
        super.onViewCreated(view, savedInstanceState);

        chkValidatedMode      = view.findViewById(R.id.chkPkocValidatedMode);
        chkRequireValidity    = view.findViewById(R.id.chkPkocRequireValidity);
        btnScanSupplier       = view.findViewById(R.id.btnPkocScanSupplier);
        editIir               = view.findViewById(R.id.editPkocIssuerIir);
        editIssuerPubHex      = view.findViewById(R.id.editPkocIssuerPubHex);
        btnAddSupplier        = view.findViewById(R.id.btnPkocAddSupplier);
        btnClearAll           = view.findViewById(R.id.btnPkocClearSuppliers);
        supplierListContainer = view.findViewById(R.id.pkocSupplierListContainer);
        txtEmptyState         = view.findViewById(R.id.txtPkocSupplierEmpty);
        txtStatus             = view.findViewById(R.id.txtPkocIssuerConfigStatus);

        chkValidatedMode.setOnCheckedChangeListener((cb, checked) ->
                PkocNfcReaderConfig.setValidatedMode(requireContext(), checked));
        chkRequireValidity.setOnCheckedChangeListener((cb, checked) ->
                PkocNfcReaderConfig.setRequireValidity(requireContext(), checked));
        btnScanSupplier.setOnClickListener(v -> launchSupplierScanner());
        btnAddSupplier.setOnClickListener(v -> onAddSupplierFromFields());
        btnClearAll.setOnClickListener(v -> onClearAll());
    }

    @Override
    public void onResume()
    {
        super.onResume();
        chkValidatedMode.setChecked(PkocNfcReaderConfig.isValidatedMode(requireContext()));
        chkRequireValidity.setChecked(PkocNfcReaderConfig.requireValidity(requireContext()));
        refreshSupplierList();
    }

    // =========================================================================
    // Import by QR
    // =========================================================================

    private void launchSupplierScanner()
    {
        ScanOptions options = new ScanOptions();
        options.setDesiredBarcodeFormats(ScanOptions.QR_CODE);
        options.setPrompt("Scan the PKOC supplier QR from the credential app");
        options.setBeepEnabled(false);
        options.setOrientationLocked(false);
        supplierScanLauncher.launch(options);
    }

    private void onSupplierScanResult(ScanIntentResult result)
    {
        if (result.getContents() == null) return; // user cancelled
        String scanned = result.getContents().trim();
        try
        {
            JSONObject obj = new JSONObject(scanned);
            if (obj.optInt("v", 0) != 1 || !"pkoc_supplier".equals(obj.optString("type", "")))
            {
                setStatus("That QR is not a PKOC supplier export.", true);
                return;
            }
            String iir = obj.getString("iir");
            String pubHex = obj.getString("issuerPublicKey");
            addSupplier(iir, pubHex, "imported from QR");
        }
        catch (Exception e)
        {
            setStatus("Could not read supplier QR: " + e.getMessage(), true);
        }
    }

    // =========================================================================
    // Add (from typed fields) / retire / clear
    // =========================================================================

    private void onAddSupplierFromFields()
    {
        addSupplier(editIir.getText().toString(),
                editIssuerPubHex.getText().toString(),
                "added");
    }

    /** Single validated add path shared by the QR-scan and the typed-field flows. */
    private void addSupplier(String rawIir, String rawPubHex, String verb)
    {
        String iir = rawIir == null ? "" : rawIir.trim().toUpperCase(Locale.US);
        String pubHex = rawPubHex == null ? "" : rawPubHex.trim().replaceAll("\\s", "");

        if (!isWellFormedIir(iir))
        {
            setStatus("IIR must be exactly 16 characters, A–Z and 0–9 only.", true);
            return;
        }
        byte[] pub = decodeHex(pubHex);
        if (pub == null || pub.length != 65 || (pub[0] & 0xFF) != 0x04)
        {
            setStatus("Issuer public key must be a 65-byte uncompressed EC point "
                    + "(04 ‖ X ‖ Y = 130 hex characters).", true);
            return;
        }

        IssuerKey key = IssuerKey.ecP256(iir, pub);
        if (key.getAlgorithm() != IssuerKey.Algorithm.EC_P256)
        {
            setStatus("That key is not a valid EC P-256 public key.", true);
            return;
        }

        PkocNfcReaderConfig.addIssuerKey(requireContext(), key);
        editIir.setText("");
        editIssuerPubHex.setText("");
        setStatus("Supplier " + iir + " " + verb + ".", false);
        refreshSupplierList();
    }

    private void onRetireSupplier(String iir)
    {
        PkocNfcReaderConfig.removeIssuerKey(requireContext(), iir);
        setStatus("Supplier " + iir + " retired.", false);
        refreshSupplierList();
    }

    private void onClearAll()
    {
        PkocNfcReaderConfig.clearIssuerKeys(requireContext());
        setStatus("All configured suppliers cleared.", false);
        refreshSupplierList();
    }

    // =========================================================================
    // Supplier list (built programmatically to match the single-file config style)
    // =========================================================================

    private void refreshSupplierList()
    {
        supplierListContainer.removeAllViews();
        List<IssuerKey> keys = PkocNfcReaderConfig.listIssuerKeys(requireContext());

        txtEmptyState.setVisibility(keys.isEmpty() ? View.VISIBLE : View.GONE);
        btnClearAll.setEnabled(!keys.isEmpty());

        for (IssuerKey key : keys)
        {
            supplierListContainer.addView(buildSupplierRow(key));
        }
    }

    private View buildSupplierRow(IssuerKey key)
    {
        LayoutInflater inflater = LayoutInflater.from(requireContext());
        View row = inflater.inflate(R.layout.item_pkoc_supplier, supplierListContainer, false);

        TextView txtIir = row.findViewById(R.id.txtSupplierIir);
        TextView txtAlg = row.findViewById(R.id.txtSupplierAlg);
        Button   btnRetire = row.findViewById(R.id.btnSupplierRetire);

        txtIir.setText(key.getIir());
        txtAlg.setText(key.getAlgorithm().name());
        btnRetire.setOnClickListener(v -> onRetireSupplier(key.getIir()));
        return row;
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void setStatus(String message, boolean isError)
    {
        txtStatus.setText(message);
        txtStatus.setTextColor(isError ? 0xFFA41D23 : 0xFF1E7A4D);
        if (isError)
        {
            Toast.makeText(requireContext(), message, Toast.LENGTH_SHORT).show();
        }
    }

    private static boolean isWellFormedIir(String iir)
    {
        if (iir == null || iir.length() != 16) return false;
        for (int i = 0; i < 16; i++)
        {
            char c = iir.charAt(i);
            if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))) return false;
        }
        return true;
    }

    @Nullable
    private static byte[] decodeHex(String s)
    {
        if (TextUtils.isEmpty(s) || (s.length() % 2) != 0) return null;
        try
        {
            byte[] out = new byte[s.length() / 2];
            for (int i = 0; i < out.length; i++)
            {
                out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
            }
            return out;
        }
        catch (NumberFormatException e)
        {
            return null;
        }
    }
}
