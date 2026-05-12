Wear OS HCE Routing Spike — Test Guide
=======================================

Goal
----
Definitively answer: does Wear OS route NFC APDUs to a third-party HCE
service registered with a custom AID?

If YES → the full PKOC/Aliro/LEAF credential-sender port to Wear OS is
viable, and we can plan that work properly.

If NO → routing is restricted (probably to Google Wallet only on this
device/OS version), and the port either needs a workaround or isn't
practical with the current OS state.


Module structure
----------------
  wear-spike/
    wear/
      build.gradle
      src/main/
        AndroidManifest.xml
        java/com/psia/pkoc/wearspike/
          TestHceService.java     (HCE service — the thing under test)
          MainActivity.java       (tiny launcher activity)
        res/
          xml/apduservice.xml     (AID group declaration)
          layout/activity_main.xml
          values/strings.xml


Adding to your existing Android Studio project
-----------------------------------------------
1. Copy the entire wear/ directory next to your existing app/ module
   in com-elatec-pkoc-aliro/android/.

2. In android/settings.gradle (or settings.gradle.kts), add:

     include ':wear'

3. Sync Gradle. Android Studio should detect the new module and offer
   to convert it.

4. If you don't already have a launcher icon at @mipmap/ic_launcher in
   the wear module, copy one in from your existing app or use Android
   Studio's "New Image Asset" wizard to generate one. Without an
   icon, the app will fail to install on the watch.


Pairing the Pixel Watch with your computer for adb
---------------------------------------------------
The watch must be in developer mode and accept adb over Wi-Fi.

1. On the watch:
     Settings → System → About → Versions → tap "Build number" 7 times
     until "You are now a developer" appears.

2. Settings → Developer Options:
     - Enable "ADB Debugging"
     - Enable "Debug over Wi-Fi"
     The Wi-Fi debugging screen shows an IP and port like 192.168.1.42:5555.

3. On your computer:
     adb connect 192.168.1.42:5555
     adb devices            # confirm the watch shows up

   First time only: the watch will show a fingerprint prompt — accept it.


Building and installing
-----------------------
From Android Studio: select the 'wear' run configuration and the connected
watch as target, click Run.

Or from the command line in the project root:

  ./gradlew :wear:installDebug

Verify install:
  Watch should show a new app icon labeled "HCE Spike". Tap it. The screen
  should display "Waiting for NFC tap…" with the test AID.


Running the test
----------------
From your reader simulator or another NFC-capable phone:

Option A — using the existing reader simulator
   The reader simulator's "Aliro" mode sends a SELECT for the Aliro AID,
   not our test AID, so it won't trigger the spike. Use Option B.

Option B — using a generic NFC test app
   Install "NFC TagInfo by NXP" or "NFC Tools" on a phone. These apps let
   you send arbitrary APDUs.

   APDU to send (Hex):
     00 A4 04 00 07 F0 01 02 03 04 05 06 00

     Breakdown:
       00 — CLA
       A4 — INS (SELECT)
       04 — P1 (by AID)
       00 — P2 (first occurrence, FCI)
       07 — Lc (AID length)
       F0 01 02 03 04 05 06 — the test AID
       00 — Le

   Hold the phone (sender) to the watch (receiver), with the watch's
   "HCE Spike" activity in the foreground. Wear OS routes APDUs to the
   foreground app's HCE service when one exists.

Option C — write a 30-line Android app
   Easiest if Options A and B aren't convenient. A reader-side activity
   that uses IsoDep.connect() and transceive() to send the APDU above.
   Take any HCE reader sample from the Android docs and change the AID.


Watching for results
--------------------
While the test is running, on your computer:

  adb -s <watch_id> logcat -s WearHCESpike

Expected SUCCESS output:

  WearHCESpike: processCommandApdu: len=13 hex=00A40400 07F0010203040506 00
  WearHCESpike: SELECT AID matched — returning 9000

If you see those lines → SPIKE PASSED. Wear OS HCE routing works for
third-party services on this watch + OS combination. The full port is
viable — proceed with planning.

The watch's MainActivity will also visually update to show the received
APDU hex, in case adb isn't attached.

Expected FAILURE indicators:
  - No log entries at all → no APDU ever reached the service
  - Reader-side error "Tag was lost" or "no application" → the framework
    rejected the SELECT before binding to our service
  - "Service not found for AID" in framework logs (adb logcat -s
    NfcCardEmulation, NfcService) → AID wasn't registered

If FAILURE: capture the framework-level NFC log for analysis:

  adb -s <watch_id> logcat -d | grep -iE "nfc|hce|cardemulation" > nfc-trace.txt


What "success" means concretely
-------------------------------
If the spike passes, that confirms:
  - Wear OS instantiates third-party HostApduService subclasses
  - The NFC HAL routes APDUs to those services when AIDs match
  - BIND_NFC_SERVICE permission grants are honored on the watch

It does NOT confirm:
  - That all transactions complete cleanly (the spike is a single APDU)
  - That long-running multi-APDU sessions work (Aliro AUTH0/AUTH1 round trip)
  - That the foreground service preferred-AID rules behave the same as
    on phones (the watch may have different rules)

Follow-up tests (if the basic spike passes):
  - Multi-APDU session: extend TestHceService to handle a SELECT followed
    by a READ BINARY, confirm both arrive
  - Background service: send the APDU when MainActivity is NOT in the
    foreground. Watches often only route to services when their activity
    is visible (battery optimization). This determines whether users would
    need to open the app first or it can passively receive taps.
  - Long-running auth: copy in the real Aliro_HostApduService and try a
    full SELECT → AUTH0 → AUTH1 round trip


Troubleshooting
---------------
"App not installed" / "Failed to install"
   Likely missing launcher icon. Generate one in Android Studio.

"adb connect" succeeds but "adb devices" shows watch as offline
   Watch went to sleep. Wake it, accept the auth prompt that appears.

"adb shell am start" reports activity launches but no UI appears
   Confirm the watch is awake during the test. Some Wear OS versions
   suspend HCE when the watch is wrist-down.

App installs but no APDU ever logged
   First check if the watch even knows about the AID:
     adb shell dumpsys nfc | grep -A 5 "Routing Table"
   You should see F0010203040506 in the routing table mapped to our
   service. If not, the AID registration didn't complete.

   If the AID is in the routing table but APDUs still don't arrive, the
   issue is at the OS routing layer — likely the spike answer is "no"
   for this device/OS combination.
