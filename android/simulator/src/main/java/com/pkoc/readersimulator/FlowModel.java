package com.pkoc.readersimulator;

import android.bluetooth.BluetoothDevice;

import com.psia.pkoc.core.BleFragmenter;
import com.psia.pkoc.core.PKOC_ConnectionType;

import java.security.KeyPair;
import java.util.LinkedList;
import java.util.Queue;

public class FlowModel
{
    BluetoothDevice connectedDevice;
    PKOC_ConnectionType connectionType = PKOC_ConnectionType.Uncompressed;
    byte[] publicKey;
    KeyPair transientKeyPair;
    byte[] receivedTransientPublicKey;
    byte[] protocolVersion;
    byte[] sharedSecret;
    byte[] signature;
    int counter = 1;
    int creationTime = 0;

    // BLE Transport Profile 2.0.1 §5.5: per-connection application-layer
    // fragmentation state.
    int mtu = 23;
    final BleFragmenter.Reassembler incomingReassembler = new BleFragmenter.Reassembler();
    final Queue<byte[]> outgoingFragments = new LinkedList<>();
    boolean notifyInProgress = false;
}
