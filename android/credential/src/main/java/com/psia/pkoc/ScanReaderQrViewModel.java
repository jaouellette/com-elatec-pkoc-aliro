package com.psia.pkoc;

import android.app.Application;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.psia.pkoc.core.PkocBleTrustStore;

import org.bouncycastle.util.encoders.Hex;

import java.util.UUID;

public class ScanReaderQrViewModel extends AndroidViewModel
{
    private static final String TAG = "ScanReaderQr";
    private final MutableLiveData<String> toastMessage = new MutableLiveData<>();

    public ScanReaderQrViewModel(@NonNull Application application)
    {
        super(application);
    }

    public LiveData<String> getToastMessage()
    {
        return toastMessage;
    }

    public void upsertReader(String siteUuid, String readerUuid, String publicKeyHex)
    {
        upsertReader(siteUuid, readerUuid, publicKeyHex, null, null);
    }

    public void upsertReader(String siteUuid, String readerUuid, String publicKeyHex,
                             String siteIssuerKeyHex, String certHex)
    {
        PKOC_Application.getDb().getQueryExecutor().execute(() ->
        {
            try
            {
                byte[] siteId    = UuidConverters.fromUuid(UUID.fromString(siteUuid));
                byte[] readerId  = UuidConverters.fromUuid(UUID.fromString(readerUuid));
                byte[] publicKey = Hex.decode(publicKeyHex);

                Log.i(TAG, "WRITE site=" + siteUuid + " key=" + publicKeyHex);

                // Always overwrite the site's key with the reader's key.
                PKOC_Application.getDb().siteDao().upsert(new SiteModel(siteId, publicKey));

                // Read the row back so we can PROVE what is stored.
                SiteModel check = PKOC_Application.getDb().siteDao().findById(siteId);
                String stored = (check == null || check.PublicKey == null)
                        ? "NULL" : Hex.toHexString(check.PublicKey);
                Log.i(TAG, "READBACK site=" + siteUuid + " storedKey=" + stored);

                if (PKOC_Application.getDb().readerDao().findByIds(readerId, siteId) == null)
                {
                    PKOC_Application.getDb().readerDao().upsert(new ReaderModel(readerId, siteId));
                }

                if (siteIssuerKeyHex != null && !siteIssuerKeyHex.isEmpty())
                {
                    PkocBleTrustStore.putSiteIssuerKey(getApplication(), siteId, Hex.decode(siteIssuerKeyHex));
                    Log.i(TAG, "Stored Site Issuer anchor for per-reader path");
                }
                if (certHex != null && !certHex.isEmpty())
                {
                    PkocBleTrustStore.putReaderCertificate(getApplication(), siteId, Hex.decode(certHex));
                }

                // Immediate visual confirmation of the key that is now stored.
                toastMessage.postValue("Site key set: " + stored.substring(0, Math.min(12, stored.length())) + "…");
            }
            catch (Exception e)
            {
                Log.e(TAG, "upsert failed for QR content", e);
                toastMessage.postValue("Scan error: " + e.getMessage());
            }
        });
    }
}
