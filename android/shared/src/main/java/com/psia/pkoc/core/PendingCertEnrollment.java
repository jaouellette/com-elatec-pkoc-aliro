package com.psia.pkoc.core;

import org.bouncycastle.util.encoders.Hex;

/**
 * Single-slot state holder for Aliro Flow #2 cert-based enrollment.
 *
 * Background. Flow #2 uses a two-phase wire protocol:
 *   1. INS 0xE2 (submit) — reader hands over its pub key + reader_id, the
 *      App side stages a confirmation prompt, returns 9000.
 *   2. INS 0xE3 (fetch)  — reader polls for the signed result. App side
 *      returns 6985 while user is deciding, 9000 + data once approved,
 *      6A82 if denied or expired.
 *
 * The submit handler runs on the HCE service's binder thread; the user's
 * Approve/Deny decision happens on the main thread inside
 * {@code CertEnrollConfirmActivity}; the fetch handler runs on the binder
 * thread again. All three need a shared place to coordinate.
 *
 * That place is this class. One pending request at a time (per Gate 2
 * decision on "single slot, no handle"). A fresh 0xE2 always replaces any
 * prior pending or staged-result state.
 *
 * Phase transitions:
 * <pre>
 *   NONE        ──submit()──────────►  AWAITING_USER
 *   AWAITING_USER ──recordApprove()──►  RESULT_READY
 *   AWAITING_USER ──recordDeny()─────►  DENIED
 *   AWAITING_USER ──pending timeout──►  NONE          (set by tickAndMaybeExpire)
 *   RESULT_READY  ──peekResult()─────►  RESULT_READY  (marks firstFetchAtMs)
 *   RESULT_READY  ──grace timeout────►  NONE          (set by tickAndMaybeExpire)
 *   DENIED        ──tickAndMaybeExpire──►  NONE       (cleared on next tick)
 * </pre>
 *
 * Threading. Every public method is {@code static synchronized}. The
 * binder-thread reads (getPhase, peekResult, tickAndMaybeExpire) and the
 * UI-thread writes (recordApprove, recordDeny) are serialised. The
 * critical sections are tiny so contention is not a concern.
 *
 * Note on the 0xE2/0xE3 state machine. Because 0xE3 needs to be poll-able
 * across many APDUs without re-SELECT between each poll, the HCE service
 * leaves its session state in ENROLLMENT_SELECTED across 0xE2 and 0xE3.
 * This differs from the existing 0xE0 handler which resets state after
 * returning 9000. The wire spec §3 documents this as "post-SELECT, after
 * 0xE2" — meaning the session stays selected.
 */
public final class PendingCertEnrollment
{
    private static final String TAG = "PendingCertEnroll";

    public enum Phase { NONE, AWAITING_USER, RESULT_READY, DENIED }

    // -------------------------------------------------------------------------
    // State (single slot)
    // -------------------------------------------------------------------------
    private static Phase  phase             = Phase.NONE;

    // Submit-time inputs (from 0xE2 payload)
    private static byte[] readerPub         = null;   // 65 bytes uncompressed
    private static byte[] readerId          = null;   // 32 bytes (group(16) || subGroup(16))
    private static long   submitAtMs        = 0L;

    // Approve-time outputs (set by CertEnrollConfirmActivity on Approve)
    private static byte[] responsePayload   = null;   // TLV-encoded: 0x90 <len> <cert> 0x85 0x41 <caPub>
    private static long   resultReadyAtMs   = 0L;

    // First successful fetch — anchors the re-fetch grace window
    private static long   firstFetchAtMs    = 0L;

    private PendingCertEnrollment() { /* no instances */ }

    // =========================================================================
    // Mutators
    // =========================================================================

    /**
     * Store a fresh 0xE2 submit. Overwrites any prior state (per Gate 2
     * "single slot, no handle" decision — a new submit always wins).
     */
    public static synchronized void submit(byte[] readerPubArg, byte[] readerIdArg)
    {
        if (readerPubArg == null || readerPubArg.length != 65 || readerPubArg[0] != 0x04)
        {
            throw new IllegalArgumentException("readerPub must be 65-byte uncompressed (0x04 || X || Y)");
        }
        if (readerIdArg == null || readerIdArg.length != 32)
        {
            throw new IllegalArgumentException("readerId must be 32 bytes (group(16) || subGroup(16))");
        }

        phase             = Phase.AWAITING_USER;
        readerPub         = readerPubArg.clone();
        readerId          = readerIdArg.clone();
        submitAtMs        = System.currentTimeMillis();
        responsePayload   = null;
        resultReadyAtMs   = 0L;
        firstFetchAtMs    = 0L;

        AliroDiagnosticLog.i(TAG, "submit: staged request groupId="
                + Hex.toHexString(readerId, 0, 16) + ", subGroupId="
                + Hex.toHexString(readerId, 16, 16));
    }

    /**
     * Called from the confirmation activity on user Approve, after the cert
     * has been signed and the TLV response payload assembled.
     *
     * @param tlvResponsePayload assembled bytes: 0x90 &lt;len&gt; &lt;cert&gt; 0x85 0x41 &lt;caPub&gt;.
     *                           See wire spec §5.2 Case A.
     */
    public static synchronized void recordApprove(byte[] tlvResponsePayload)
    {
        if (phase != Phase.AWAITING_USER)
        {
            AliroDiagnosticLog.w(TAG, "recordApprove: phase=" + phase
                    + " (expected AWAITING_USER); ignoring");
            return;
        }
        if (tlvResponsePayload == null || tlvResponsePayload.length == 0)
        {
            AliroDiagnosticLog.e(TAG, "recordApprove: response payload null/empty; treating as deny");
            phase = Phase.DENIED;
            return;
        }
        phase             = Phase.RESULT_READY;
        responsePayload   = tlvResponsePayload.clone();
        resultReadyAtMs   = System.currentTimeMillis();
        firstFetchAtMs    = 0L;
        AliroDiagnosticLog.i(TAG, "recordApprove: staged " + responsePayload.length + "-byte response");
    }

    /**
     * Called from the confirmation activity on user Deny.
     *
     * Wipes the staged reader pub/id so the rejected submitter's data
     * doesn't linger in memory beyond the user decision. Phase transitions
     * AWAITING_USER -> DENIED so that the next 0xE3 fetch sees DENIED and
     * tickAndMaybeExpire clears it to NONE for subsequent fetches.
     */
    public static synchronized void recordDeny()
    {
        if (phase != Phase.AWAITING_USER)
        {
            AliroDiagnosticLog.w(TAG, "recordDeny: phase=" + phase
                    + " (expected AWAITING_USER); ignoring");
            return;
        }
        phase             = Phase.DENIED;
        readerPub         = null;
        readerId          = null;
        submitAtMs        = 0L;
        AliroDiagnosticLog.i(TAG, "recordDeny: user denied enrollment");
    }

    /**
     * Wipe state back to NONE. Called when starting over or on app shutdown.
     */
    public static synchronized void clear()
    {
        if (phase != Phase.NONE)
        {
            AliroDiagnosticLog.d(TAG, "clear: phase=" + phase + " -> NONE");
        }
        phase             = Phase.NONE;
        readerPub         = null;
        readerId          = null;
        submitAtMs        = 0L;
        responsePayload   = null;
        resultReadyAtMs   = 0L;
        firstFetchAtMs    = 0L;
    }

    // =========================================================================
    // Accessors (for the confirmation activity)
    // =========================================================================

    /**
     * Returns the reader's 65-byte pub key from the most recent submit, or
     * null if there is no AWAITING_USER request. Defensive copy.
     */
    public static synchronized byte[] readerPub()
    {
        return (readerPub != null) ? readerPub.clone() : null;
    }

    /**
     * Returns the 32-byte reader_id (group(16) || subGroup(16)) from the
     * most recent submit, or null if there is no AWAITING_USER request.
     * Defensive copy.
     */
    public static synchronized byte[] readerId()
    {
        return (readerId != null) ? readerId.clone() : null;
    }

    /**
     * Returns just the first 16 bytes of readerId — the
     * reader_group_identifier — or null. Convenience for the CA keystore
     * lookup. Defensive copy.
     */
    public static synchronized byte[] readerGroupId()
    {
        if (readerId == null) return null;
        byte[] out = new byte[16];
        System.arraycopy(readerId, 0, out, 0, 16);
        return out;
    }

    // =========================================================================
    // Fetch-side API (for the HCE service 0xE3 handler)
    // =========================================================================

    /**
     * Returns the current phase. Call {@link #tickAndMaybeExpire} first if
     * you want the phase to reflect timeout transitions.
     */
    public static synchronized Phase getPhase()
    {
        return phase;
    }

    /**
     * Returns the staged response payload if {@code phase == RESULT_READY},
     * or null otherwise. The first call after approval records the first-
     * fetch timestamp, which anchors the re-fetch grace window. Subsequent
     * calls within the grace window return the same bytes. Defensive copy.
     *
     * Does NOT clear state — the result remains available for re-fetch
     * until the grace window expires (handled by tickAndMaybeExpire).
     */
    public static synchronized byte[] peekResult()
    {
        if (phase != Phase.RESULT_READY || responsePayload == null) return null;
        if (firstFetchAtMs == 0L)
        {
            firstFetchAtMs = System.currentTimeMillis();
            AliroDiagnosticLog.d(TAG, "peekResult: first fetch at "
                    + firstFetchAtMs + ", grace window starts");
        }
        return responsePayload.clone();
    }

    /**
     * Apply timeout transitions based on elapsed wall-clock time. Called
     * by the 0xE3 handler before consulting {@link #getPhase} or
     * {@link #peekResult}, so that expired requests / results are converted
     * to NONE and the handler returns 6A82.
     *
     * Transitions applied:
     *   AWAITING_USER: if (now - submitAtMs) > pendingTimeoutMs -> NONE
     *   RESULT_READY:  if (now - firstFetchAtMs) > graceMs && firstFetchAtMs > 0 -> NONE
     *   DENIED:        unconditional clear on next tick (so a subsequent 0xE2
     *                  starts fresh and a duplicate 0xE3 doesn't keep
     *                  reporting "denied" forever).
     *
     * @param pendingTimeoutMs how long AWAITING_USER lives without a decision.
     * @param graceMs how long RESULT_READY lives after the first fetch.
     */
    public static synchronized void tickAndMaybeExpire(long pendingTimeoutMs, long graceMs)
    {
        long now = System.currentTimeMillis();

        if (phase == Phase.AWAITING_USER)
        {
            long elapsed = now - submitAtMs;
            if (elapsed > pendingTimeoutMs)
            {
                AliroDiagnosticLog.i(TAG, "tickAndMaybeExpire: AWAITING_USER expired after "
                        + elapsed + "ms (timeout=" + pendingTimeoutMs + "ms); clearing");
                clearLocked();
            }
            return;
        }

        if (phase == Phase.RESULT_READY)
        {
            // Only start the grace clock after the first fetch — the result
            // is allowed to sit forever (within reason) waiting for the
            // reader to come back and read it once, then we start the
            // re-fetch grace window.
            if (firstFetchAtMs > 0L)
            {
                long elapsed = now - firstFetchAtMs;
                if (elapsed > graceMs)
                {
                    AliroDiagnosticLog.i(TAG, "tickAndMaybeExpire: RESULT_READY grace expired after "
                            + elapsed + "ms (grace=" + graceMs + "ms); clearing");
                    clearLocked();
                }
            }
            return;
        }

        if (phase == Phase.DENIED)
        {
            // One-shot: convey "denied" via one 0xE3 returning 6A82, then
            // wipe so the slot is free for a new submit. The 0xE3 handler
            // calls tickAndMaybeExpire before reading phase, so this is
            // observed once by the handler (phase reads as DENIED, then it
            // transitions to NONE for next time). Actually — the handler
            // checks phase AFTER this tick, so by the time it reads it
            // will already be NONE and return 6A82. That's fine; both
            // map to the same SW per wire spec §5.2 Case C.
            AliroDiagnosticLog.d(TAG, "tickAndMaybeExpire: DENIED -> NONE");
            clearLocked();
            return;
        }

        // phase == NONE: nothing to do.
    }

    // =========================================================================
    // Internal
    // =========================================================================

    /** Caller must already hold the class monitor. */
    private static void clearLocked()
    {
        phase             = Phase.NONE;
        readerPub         = null;
        readerId          = null;
        submitAtMs        = 0L;
        responsePayload   = null;
        resultReadyAtMs   = 0L;
        firstFetchAtMs    = 0L;
    }
}
