package com.psia.pkoc.core;

import android.util.Log;

import java.text.SimpleDateFormat;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Date;
import java.util.Deque;
import java.util.List;
import java.util.Locale;

/**
 * In-memory diagnostic log for the Aliro credential.
 *
 * Mirrors every entry to logcat (so adb continues to work for those who want it)
 * AND keeps a fixed-size ring buffer of recent entries in process memory, viewable
 * via the Credential app's UI. The intent is to let firmware engineers and other
 * external testers capture the same diagnostic information that Anthropic developers
 * would normally pull with {@code adb logcat}, without having to install or
 * configure the Android SDK.
 *
 * <p>Usage from any class in the app:
 * <pre>
 *     AliroDiagnosticLog.d("AliroHCE", "APDU: " + Hex.toHexString(apdu));
 *     AliroDiagnosticLog.w("AliroHCE", "AUTH1: signature INVALID");
 *     AliroDiagnosticLog.e("AliroHCE", "AUTH1 error", e);
 * </pre>
 *
 * <p>The ring buffer holds the most recent {@link #CAPACITY} entries. When full,
 * the oldest entry is evicted. Memory footprint is bounded at roughly
 * CAPACITY × (avg entry size + ~80 bytes overhead).
 *
 * <p>Thread-safe: all public methods are synchronized on the shared deque.
 */
public final class AliroDiagnosticLog
{
    /** Maximum number of entries retained. Older entries are evicted FIFO. */
    public static final int CAPACITY = 2000;

    /** Log level constants — values match android.util.Log conventions. */
    public static final int VERBOSE = 2;
    public static final int DEBUG   = 3;
    public static final int INFO    = 4;
    public static final int WARN    = 5;
    public static final int ERROR   = 6;

    /** Single global deque protected by its own monitor. */
    private static final Deque<Entry> BUFFER = new ArrayDeque<>(CAPACITY);

    /** Whether to mirror entries to logcat in addition to the in-memory buffer. */
    private static volatile boolean mirrorToLogcat = true;

    /** Minimum level retained. Entries below this are discarded entirely. */
    private static volatile int minLevel = VERBOSE;

    /** Optional change listener — UI registers here to refresh when entries arrive. */
    private static volatile Listener listener = null;

    private AliroDiagnosticLog() { /* no instances */ }

    // -------------------------------------------------------------------------
    // Public logging API
    // -------------------------------------------------------------------------

    public static void v(String tag, String message)               { log(VERBOSE, tag, message, null); }
    public static void d(String tag, String message)               { log(DEBUG,   tag, message, null); }
    public static void i(String tag, String message)               { log(INFO,    tag, message, null); }
    public static void w(String tag, String message)               { log(WARN,    tag, message, null); }
    public static void w(String tag, String message, Throwable t)  { log(WARN,    tag, message, t);    }
    public static void e(String tag, String message)               { log(ERROR,   tag, message, null); }
    public static void e(String tag, String message, Throwable t)  { log(ERROR,   tag, message, t);    }

    // -------------------------------------------------------------------------
    // Buffer management
    // -------------------------------------------------------------------------

    /** Discard all buffered entries. */
    public static void clear()
    {
        synchronized (BUFFER) { BUFFER.clear(); }
        notifyListener();
    }

    /** Return a snapshot of current entries in chronological order. */
    public static List<Entry> snapshot()
    {
        synchronized (BUFFER) { return new ArrayList<>(BUFFER); }
    }

    /** Total number of entries currently buffered. */
    public static int size()
    {
        synchronized (BUFFER) { return BUFFER.size(); }
    }

    /** Format the entire buffer as one shareable text blob. */
    public static String toShareableText()
    {
        List<Entry> snap = snapshot();
        StringBuilder sb = new StringBuilder(snap.size() * 100);
        sb.append("Aliro diagnostic log\n")
          .append("=====================\n")
          .append("entries: ").append(snap.size()).append(" (capacity ").append(CAPACITY).append(")\n")
          .append("level filter: ").append(levelName(minLevel)).append("\n\n");
        for (Entry e : snap) sb.append(e.formatForShare()).append('\n');
        return sb.toString();
    }

    /** Enable / disable logcat mirror. Default true. */
    public static void setMirrorToLogcat(boolean enabled) { mirrorToLogcat = enabled; }

    /** Set minimum captured level. Entries below this are dropped. */
    public static void setMinLevel(int level) { minLevel = level; }

    /** Get current min-level filter. */
    public static int getMinLevel() { return minLevel; }

    /** Register a change listener; pass null to unregister. */
    public static void setListener(Listener l) { listener = l; }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    private static void log(int level, String tag, String message, Throwable t)
    {
        if (level < minLevel) return;

        if (mirrorToLogcat)
        {
            switch (level)
            {
                case VERBOSE: Log.v(tag, message, t); break;
                case DEBUG:   Log.d(tag, message, t); break;
                case INFO:    Log.i(tag, message, t); break;
                case WARN:    Log.w(tag, message, t); break;
                case ERROR:
                default:      Log.e(tag, message, t); break;
            }
        }

        String fullMessage = message;
        if (t != null) fullMessage = message + " | " + t.getClass().getSimpleName()
                + ": " + t.getMessage();

        Entry entry = new Entry(System.currentTimeMillis(), level, tag, fullMessage);
        synchronized (BUFFER)
        {
            if (BUFFER.size() >= CAPACITY) BUFFER.pollFirst();
            BUFFER.addLast(entry);
        }
        notifyListener();
    }

    private static void notifyListener()
    {
        Listener l = listener;
        if (l != null)
        {
            try { l.onLogChanged(); }
            catch (Exception ignored) { /* listener exceptions don't propagate */ }
        }
    }

    private static String levelName(int level)
    {
        switch (level)
        {
            case VERBOSE: return "V";
            case DEBUG:   return "D";
            case INFO:    return "I";
            case WARN:    return "W";
            case ERROR:   return "E";
            default:      return "?";
        }
    }

    // -------------------------------------------------------------------------
    // Nested types
    // -------------------------------------------------------------------------

    public static final class Entry
    {
        public final long   timestampMs;
        public final int    level;
        public final String tag;
        public final String message;

        Entry(long timestampMs, int level, String tag, String message)
        {
            this.timestampMs = timestampMs;
            this.level       = level;
            this.tag         = tag;
            this.message     = message;
        }

        /** Format as a single line suitable for share/copy. */
        public String formatForShare()
        {
            SimpleDateFormat fmt = new SimpleDateFormat("HH:mm:ss.SSS", Locale.US);
            return fmt.format(new Date(timestampMs))
                    + " " + levelName(level)
                    + "/" + tag
                    + ": " + message;
        }

        /** Compact UI label for this entry's level. */
        public String levelChar()
        {
            return levelName(level);
        }
    }

    public interface Listener
    {
        /** Called on any thread after an entry is added or the buffer cleared. */
        void onLogChanged();
    }
}
