package com.psia.pkoc.core;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Application-layer fragmentation/reassembly for the PKOC BLE Transport
 * Profile 2.0.1 §5.5. Each fragment is prefixed with a 1-byte indicator:
 * 0x00 = first, 0x01 = continuation, 0x02 = last. A message that fits in a
 * single fragment uses 0x02 directly (no preceding 0x00).
 *
 * <p>Both peers apply this framing unconditionally, with chunk size driven
 * by the live negotiated MTU, so there is never ambiguity between framed
 * and unframed bytes on the wire.</p>
 */
public class BleFragmenter
{
    private static final byte FRAG_FIRST = 0x00;
    private static final byte FRAG_CONTINUATION = 0x01;
    private static final byte FRAG_LAST = 0x02;

    private BleFragmenter()
    {
    }

    /**
     * Split a payload into indicator-prefixed fragments sized to fit the
     * negotiated ATT MTU.
     * @param payload full message to fragment
     * @param mtu negotiated ATT_MTU (including the 3-byte ATT header)
     * @return ordered list of fragments, each ready to write/notify as-is
     */
    public static List<byte[]> fragment(byte[] payload, int mtu)
    {
        int chunkSize = Math.max(1, mtu - 4); // ATT_MTU - 3 (ATT overhead) - 1 (indicator byte)
        List<byte[]> fragments = new ArrayList<>();
        int offset = 0;
        boolean first = true;
        do
        {
            int len = Math.min(chunkSize, payload.length - offset);
            boolean isLast = offset + len >= payload.length;
            byte indicator = isLast ? FRAG_LAST : (first ? FRAG_FIRST : FRAG_CONTINUATION);

            byte[] frag = new byte[len + 1];
            frag[0] = indicator;
            System.arraycopy(payload, offset, frag, 1, len);
            fragments.add(frag);

            offset += len;
            first = false;
        } while (offset < payload.length);

        return fragments;
    }

    /** Reassembles a stream of indicator-prefixed fragments back into complete messages. */
    public static class Reassembler
    {
        private ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        /**
         * Feed one received fragment into the reassembler.
         * @return the complete reassembled payload once the last fragment
         *         arrives, or {@code null} if more fragments are still expected.
         */
        public synchronized byte[] onFragment(byte[] fragment)
        {
            if (fragment == null || fragment.length == 0)
            {
                return null;
            }

            byte indicator = fragment[0];
            if (indicator == FRAG_FIRST)
            {
                buffer = new ByteArrayOutputStream();
            }

            buffer.write(fragment, 1, fragment.length - 1);

            if (indicator == FRAG_LAST)
            {
                byte[] complete = buffer.toByteArray();
                buffer = new ByteArrayOutputStream();
                return complete;
            }

            return null;
        }
    }
}
