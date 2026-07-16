package com.psia.pkoc.core;

import androidx.annotation.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A store of PKOC-CVC Issuer Keys keyed by IIR (NFC Transport Profile 2.0.1 §5.3).
 * Supports add / replace / remove / lookup, and hex (de)serialization so a
 * deployment can persist the configured trust anchors. In-memory and cheap to
 * construct; a process-wide singleton is available via {@link #shared()}.
 */
public final class IssuerKeyStore
{
    private final Map<String, IssuerKey> byIir = new LinkedHashMap<>();

    private static final IssuerKeyStore SHARED = new IssuerKeyStore();

    /** Process-wide store, convenient for the reader's configured Issuer Keys. */
    public static IssuerKeyStore shared() { return SHARED; }

    /** Add or replace the key for its IIR. */
    public void put(IssuerKey key)
    {
        if (key != null && key.getIir() != null) byIir.put(key.getIir(), key);
    }

    public void remove(String iir) { byIir.remove(iir); }

    /** Look up the Issuer Key whose identifier matches the CVC's IIR (tag 42). */
    @Nullable
    public IssuerKey get(String iir) { return iir == null ? null : byIir.get(iir); }

    public boolean isEmpty() { return byIir.isEmpty(); }
    public int size() { return byIir.size(); }
    public void clear() { byIir.clear(); }
    public Collection<IssuerKey> all() { return byIir.values(); }

    /** Serialize all keys to a list of storage strings (one per key). */
    public List<String> toStorage()
    {
        List<String> out = new ArrayList<>(byIir.size());
        for (IssuerKey k : byIir.values()) out.add(k.toStorage());
        return out;
    }

    /** Load keys from storage strings; malformed entries are skipped. */
    public void loadFromStorage(Collection<String> entries)
    {
        if (entries == null) return;
        for (String s : entries)
        {
            IssuerKey k = IssuerKey.fromStorage(s);
            if (k != null) put(k);
        }
    }
}
