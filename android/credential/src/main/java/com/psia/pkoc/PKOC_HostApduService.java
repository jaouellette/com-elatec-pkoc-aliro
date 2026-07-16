package com.psia.pkoc;

import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import com.psia.pkoc.core.CryptoProvider;
import com.psia.pkoc.core.NfcSeV2CardHandler;
import com.psia.pkoc.core.PKOC_Preferences;
import com.psia.pkoc.core.PKOC_TransmissionType;
import com.psia.pkoc.core.PkocNfcCardCredential;
import com.psia.pkoc.core.transactions.NfcNormalFlowTransaction;

import org.bouncycastle.util.encoders.Hex;

import java.security.PrivateKey;

public class PKOC_HostApduService extends HostApduService
{
    private NfcNormalFlowTransaction normalFlow;

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras)
    {
        SharedPreferences prefs = getSharedPreferences("MainActivity", Context.MODE_PRIVATE);
        int transmissionTypeInt = prefs.getInt(PKOC_Preferences.PKOC_TransmissionType, PKOC_TransmissionType.BLE.ordinal());
        PKOC_TransmissionType transmissionType = PKOC_TransmissionType.values()[transmissionTypeInt];
        if (transmissionType != PKOC_TransmissionType.NFC)
        {
            return NfcNormalFlowTransaction.GENERAL_ERROR_STATUS;
        }

        Log.d("NFC", "Received APDU: " + Hex.toHexString(apdu));

        // ---- PKOC SE V2 Profile (NFC Transport Profile 2.0.1 §6.2, §8) ----
        // Handles GET DATA (INFO), GET DATA (PKOC-CVC), and INTERNAL AUTHENTICATE.
        // SELECT and the SE V1 AUTHENTICATE fall through to the existing flow, so a
        // v1.1 reader still works and an SE V2 Card MAY also answer SE V1.
        if (PkocNfcCardCredential.isEnabled(this) && NfcSeV2CardHandler.isSeV2Command(apdu))
        {
            byte[] cvc = PkocNfcCardCredential.getCvcBytes(this);
            PrivateKey seV2Key = PkocNfcCardCredential.getSeV2SigningPrivateKey(this);
            byte[] seV2Response = NfcSeV2CardHandler.handle(apdu, cvc, seV2Key);
            if (seV2Response != null)
            {
                // A successful INTERNAL AUTHENTICATE completes the SE V2 transaction.
                if (NfcSeV2CardHandler.isInternalAuth(apdu)
                        && com.psia.pkoc.core.NfcSeV2.isSuccess(seV2Response))
                {
                    Intent intent = new Intent("com.psia.pkoc.CREDENTIAL_SENT");
                    intent.setPackage(getPackageName());
                    sendBroadcast(intent);
                }
                Log.d("NFC", "SE V2 Response APDU: " + Hex.toHexString(seV2Response));
                return seV2Response;
            }
        }

        // ---- SE V1 Profile (SELECT + AUTHENTICATE) — unchanged ----
        if (normalFlow == null)
        {
            normalFlow = new NfcNormalFlowTransaction(true);
        }

        byte[] response = normalFlow.processDeviceCommand(apdu);

        if (normalFlow.isTransactionSuccessful())
        {
            Intent intent = new Intent("com.psia.pkoc.CREDENTIAL_SENT");
            intent.setPackage(getPackageName());
            sendBroadcast(intent);
        }

        Log.d("NFC", "Response APDU: " + Hex.toHexString(response));
        return response;
    }

    @Override
    public void onDeactivated(int reason)
    {
        normalFlow = null;
    }
}
