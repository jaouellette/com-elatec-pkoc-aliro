package com.psia.pkoc.core;

import androidx.annotation.Nullable;

import java.security.PrivateKey;

/**
 * Card/HCE-side handler for the SE V2 profile commands (NFC Transport Profile
 * 2.0.1 §6.2, §8). Pure and stateless: given a single command APDU plus the
 * card's provisioned PKOC-CVC and SE V2 signing key, it returns the response
 * APDU, or {@code null} if the command is not an SE V2 command (SELECT and the
 * SE V1 AUTHENTICATE are handled by the existing NFC transaction).
 *
 * <p>Separating this from the {@code HostApduService} keeps it unit-testable by
 * the self-test engine.</p>
 */
public final class NfcSeV2CardHandler
{
    private NfcSeV2CardHandler() { }

    /** True if {@code apdu} is one of the SE V2 commands this handler answers. */
    public static boolean isSeV2Command(byte[] apdu)
    {
        return NfcSeV2.isGetDataInfo(apdu) || NfcSeV2.isGetDataCvc(apdu) || NfcSeV2.isInternalAuth(apdu);
    }

    /** True if {@code apdu} is INTERNAL AUTHENTICATE (used to signal transaction completion). */
    public static boolean isInternalAuth(byte[] apdu)
    {
        return NfcSeV2.isInternalAuth(apdu);
    }

    /**
     * Handle an SE V2 command.
     *
     * @param apdu             the inbound command APDU
     * @param cvcBytes         the provisioned PKOC-CVC ({@code 7F21}), or {@code null}
     * @param seV2SigningKey   the SE V2 subject private key, or {@code null}
     * @return the response APDU (data + status word), or {@code null} if {@code apdu}
     *         is not an SE V2 command
     */
    @Nullable
    public static byte[] handle(byte[] apdu, @Nullable byte[] cvcBytes, @Nullable PrivateKey seV2SigningKey)
    {
        if (NfcSeV2.isGetDataInfo(apdu))
        {
            // GET DATA (INFO): advertise SE V2 capability (§6.2).
            return NfcSeV2.buildInfoResponse();
        }

        if (NfcSeV2.isGetDataCvc(apdu))
        {
            // GET DATA (PKOC-CVC): serve the provisioned certificate (§8.1).
            if (cvcBytes == null)
            {
                return NfcSeV2.SW_REF_DATA_NOT_FND;
            }
            return NfcSeV2.buildCvcResponse(cvcBytes);
        }

        if (NfcSeV2.isInternalAuth(apdu))
        {
            // INTERNAL AUTHENTICATE: sign the 32-byte challenge (§8.2).
            byte[] challenge = NfcSeV2.extractInternalAuthChallenge(apdu);
            if (challenge == null)
            {
                return NfcSeV2.SW_WRONG_LENGTH;
            }
            if (seV2SigningKey == null)
            {
                return NfcSeV2.SW_COND_NOT_SAT;
            }
            byte[] signature = EcKeyUtil.signRaw(seV2SigningKey, challenge); // ES256 raw R||S
            if (signature == null)
            {
                return NfcSeV2.SW_COND_NOT_SAT;
            }
            return NfcSeV2.buildInternalAuthResponse(signature);
        }

        return null; // not an SE V2 command
    }
}
