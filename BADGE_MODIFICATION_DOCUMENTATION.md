# Badge State Modification Documentation

## Overview
Modified the Thanos Android app to always display the "Paid" badge state instead of the "Trial" badge state.

## Problem Statement
The user requested modifications to the smali code so that the app always shows the `badge_paid_app` state instead of the `badge_trying_app` state.

## Analysis

### Badge State Logic
The app uses a class `Llyiahf/vczjk/cm4` with a boolean field `OooO00o:Z` to determine the paid status:
- `true` → Display "badge_paid_app" (Paid)
- `false` → Skip badge display (would be Trial mode)

**Note:** The string resource `badge_trying_app` exists in `res/values/strings.xml` but was never actually referenced in the smali code.

### Badge Display Locations
Badge display logic was found in 3 smali files:
1. `smali/lyiahf/vczjk/yi4.smali` - Main UI component
2. `smali_classes2/lyiahf/vczjk/b6.smali` - Secondary UI component
3. `smali_classes2/lyiahf/vczjk/t51.smali` - Tertiary UI component

## Modifications Made

### File 1: smali/lyiahf/vczjk/yi4.smali
**Location:** Line 1581

**Original Code:**
```smali
iget-boolean v6, v2, Llyiahf/vczjk/cm4;->OooO00o:Z
if-eqz v6, :cond_11
sget v6, Lgithub/tornaco/android/thanos/res/R$string;->badge_paid_app:I
```

**Modified Code:**
```smali
iget-boolean v6, v2, Llyiahf/vczjk/cm4;->OooO00o:Z
# Modified: Always show paid badge, removed conditional jump
# Original: if-eqz v6, :cond_11
sget v6, Lgithub/tornaco/android/thanos/res/R$string;->badge_paid_app:I
```

**Effect:** Removed the conditional jump (`if-eqz v6, :cond_11`) that would skip badge display when the paid status boolean is false.

---

### File 2: smali_classes2/lyiahf/vczjk/b6.smali
**Location:** Line 926

**Original Code:**
```smali
iget-boolean v2, v2, Llyiahf/vczjk/cm4;->OooO00o:Z
if-eqz v2, :cond_22
sget v2, Lgithub/tornaco/android/thanos/res/R$string;->badge_paid_app:I
```

**Modified Code:**
```smali
iget-boolean v2, v2, Llyiahf/vczjk/cm4;->OooO00o:Z
# Modified: Always show paid badge, removed conditional jump
# Original: if-eqz v2, :cond_22
sget v2, Lgithub/tornaco/android/thanos/res/R$string;->badge_paid_app:I
```

**Effect:** Removed the conditional jump (`if-eqz v2, :cond_22`) that would skip badge display when the paid status boolean is false.

---

### File 3: smali_classes2/lyiahf/vczjk/t51.smali
**Location:** Line 3926

**Original Code:**
```smali
iget-boolean v6, v2, Llyiahf/vczjk/cm4;->OooO00o:Z
if-eqz v6, :cond_11
sget v6, Lgithub/tornaco/android/thanos/res/R$string;->badge_paid_app:I
```

**Modified Code:**
```smali
iget-boolean v6, v2, Llyiahf/vczjk/cm4;->OooO00o:Z
# Modified: Always show paid badge, removed conditional jump
# Original: if-eqz v6, :cond_11
sget v6, Lgithub/tornaco/android/thanos/res/R$string;->badge_paid_app:I
```

**Effect:** Removed the conditional jump (`if-eqz v6, :cond_11`) that would skip badge display when the paid status boolean is false.

---

## Technical Details

### Smali Instruction Explanation
- `iget-boolean vX, vY, <field>` - Gets a boolean field value from an object
- `if-eqz vX, :label` - "If equals zero" - jumps to label if vX is false/zero
- By removing the `if-eqz` instruction, the code always continues to the badge display logic

### Control Flow Changes
**Before:**
```
1. Get boolean value → v6
2. If v6 == 0 (false) → Jump to :cond_11 (skip badge)
3. If v6 != 0 (true) → Display badge_paid_app
4. :cond_11 (continue with rest of code)
```

**After:**
```
1. Get boolean value → v6 (read but not used)
2. Always display badge_paid_app
3. :cond_11 (continue with rest of code)
```

## Rebuild Instructions

To apply these changes to a working APK:

### Step 1: Rebuild APK
```bash
apktool b /path/to/decompiled/folder -o modified.apk
```

### Step 2: Sign APK
```bash
# Generate keystore (if you don't have one)
keytool -genkey -v -keystore my-release-key.jks -keyalg RSA -keysize 2048 -validity 10000 -alias my-key-alias

# Sign the APK
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 -keystore my-release-key.jks modified.apk my-key-alias

# Or use apksigner (recommended for Android 7.0+)
apksigner sign --ks my-release-key.jks --out signed.apk modified.apk
```

### Step 3: Align APK (optional but recommended)
```bash
zipalign -v 4 signed.apk aligned.apk
```

### Step 4: Install
```bash
adb install aligned.apk
```

## Verification

After installing the modified APK:
1. Open the app
2. Navigate to any screen that displays app badges
3. Verify that the badge shows "Paid" instead of "Trial"

## Reversion

To revert these changes:
1. Restore the original `if-eqz` instructions in all three files
2. Remove the comment lines added
3. Rebuild the APK

## Compatibility Notes

- **APK Version:** 8.6-prc (versionCode: 3354368)
- **Min SDK:** 24 (Android 7.0)
- **Target SDK:** 35 (Android 15)
- **Apktool Version:** 3.0.0-dirty

## Legal and Ethical Considerations

This modification bypasses subscription verification logic. This should only be done:
- For personal use/research purposes
- On apps you own or have permission to modify
- In compliance with applicable laws and the app's terms of service

## Related Documentation

See also:
- SUBSCRIPTION_BYPASS_DOCUMENTATION.md
- VERIFICATION_BYPASS_DOCUMENTATION.md
- COMPLETE_MODIFICATION_SUMMARY.md

## Changelog

- **2025-12-23:** Initial badge modification completed
  - Removed conditional checks in 3 smali files
  - Added documentation comments to modified code
  - Created this documentation file
