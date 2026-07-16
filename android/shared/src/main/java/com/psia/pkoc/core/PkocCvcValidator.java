package com.psia.pkoc.core;

import androidx.annotation.Nullable;

import com.psia.pkoc.core.validations.SuccessResult;

/**
 * PKOC-CVC Validation process — NFC Transport Profile 2.0.1 §3.4 / §4.3, Core §5.8.
 *
 * <p>In Validated Mode the reader MUST: extract the IIR, select the configured
 * Issuer Key whose identifier matches, fail if none is configured, verify the CVC
 * signature with that key, SHOULD confirm conformance to the Core §5 profile, and
 * MAY verify the current date is within the validity period. A reader in Validated
 * Mode MUST NOT fall back to Standard Mode after validation fails (that policy is
 * enforced by the caller).</p>
 */
public final class PkocCvcValidator
{
    private PkocCvcValidator() { }

    /**
     * Run the Validation process.
     *
     * @param cvc            the parsed certificate (from GET DATA (PKOC-CVC))
     * @param issuerKeys     the reader's configured Issuer Keys
     * @param nowYyyymmdd    current date as e.g. 20260709, or &lt;= 0 to skip the date check
     * @param requireValidity whether to enforce the validity window (§3.4 "MAY")
     * @return a {@link SuccessResult} when the certificate validates; otherwise a
     *         failing {@link ValidationResult} whose message states the reason
     */
    public static ValidationResult validate(
            @Nullable PkocCvc cvc,
            IssuerKeyStore issuerKeys,
            int nowYyyymmdd,
            boolean requireValidity)
    {
        if (cvc == null)
        {
            return fail("PKOC-CVC could not be parsed.");
        }
        if (cvc.getProfileId() != PkocCvc.PROFILE_V1)
        {
            return fail("Unsupported PKOC-CVC profile identifier: " + cvc.getProfileId());
        }
        if (!cvc.isIirWellFormed())
        {
            return fail("PKOC-CVC IIR is not a well-formed 16-character reference.");
        }

        if (issuerKeys == null)
        {
            return fail("No Issuer Keys configured for Validated Mode.");
        }
        IssuerKey key = issuerKeys.get(cvc.getIir());
        if (key == null)
        {
            return fail("No configured Issuer Key matches IIR " + cvc.getIir() + ".");
        }

        if (!key.verify(cvc.getCertificateBody(), cvc.getSignature()))
        {
            return fail("PKOC-CVC signature did not verify against Issuer Key " + cvc.getIir() + ".");
        }

        if (requireValidity && nowYyyymmdd > 0 && !cvc.isWithinValidity(nowYyyymmdd))
        {
            return fail("PKOC-CVC is outside its validity period ("
                    + cvc.getValidFromYyyymmdd() + ".." + cvc.getValidToYyyymmdd() + ").");
        }

        return new SuccessResult();
    }

    private static ValidationResult fail(String message)
    {
        return new ValidationResult(true, false, message);
    }
}
