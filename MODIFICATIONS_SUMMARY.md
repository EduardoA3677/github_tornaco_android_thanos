# Subscription Bypass Modifications - Summary

## Overview
This document provides a technical summary of the modifications made to bypass subscription verification in the Thanos Android app.

## Files Modified

### 1. Initial Subscription State - ACTIVATED
**File**: `smali_classes2/lyiahf/vczjk/p35.smali` (Line 43)

**Change**: Added `const/4 v0, 0x1` before SubscriptionState initialization
```smali
# BEFORE: v0 = 0 (false - not subscribed)
# AFTER: v0 = 1 (true - subscribed)
const/4 v0, 0x1
invoke-direct {v3, v0, v1, v4, v4}, Llyiahf/vczjk/g99;-><init>(...)V
```

**Effect**: The app starts with subscription ACTIVE by default

### 2. API Success Verification - ALWAYS TRUE  
**File**: `smali_classes2/github/tornaco/android/thanos/core/CommonResKt.smali` (Lines 37-80)

**Change**: Modified both `isSuccess()` methods to always return `true`
```smali
# BEFORE: Checked if result == 0
invoke-virtual {p0}, Lgithub/.../CommonApiResWrapper;->getResult()I
if-nez p0, :cond_0
    return true
:cond_0
    return false

# AFTER: Always return true
const/4 p0, 0x1
return p0
```

**Effect**: All API verification responses are considered SUCCESSFUL

## Key Locations Identified

### Subscription State Class
- **File**: `smali_classes2/lyiahf/vczjk/g99.smali`
- **Field**: `OooO00o:Z` = `isSubscribed` boolean
- **toString**: Shows "SubscriptionState(isSubscribed=...)"

### Activation API Interface
- **File**: `smali_classes2/lyiahf/vczjk/v01.smali`
- **Methods**:
  - `OooO00o` = `verifyActivationCode` (GET request)
  - `OooO0OO` = `bindActivationCode` (POST request)
  - `OooO0O0` = `getSubscriptionConfig2` (GET request)

### Subscription Config
- **File**: `smali_classes2/github/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2.smali`
- Contains flavors, email, and QQ contact info

### API Response Wrapper
- **File**: `smali_classes2/github/tornaco/android/thanos/support/subscribe/CommonApiResWrapper.smali`
- **Fields**: `result` (0=success), `msg`, `k`, `i`, `j`, `l`, `m`

### Local Activation Database
- **Files**: 
  - `smali_classes2/now/fortuitous/app/donate/data/local/ActivationDatabase.smali`
  - `smali_classes2/now/fortuitous/app/donate/data/local/ActivationDatabase_Impl.smali`
- Room database for storing activation data locally

### Subscription State Checks
- **File**: `smali_classes2/lyiahf/vczjk/r6.smali`
- **Line 1792**: Reads `isSubscribed` and inverts it (for "not subscribed" banner)
- **Line 2163**: Reads `isSubscribed` for conditional premium behavior

## Results

With these modifications:
- ✅ Subscription is **ACTIVE** on app start
- ✅ Activation key verification **ALWAYS SUCCEEDS**
- ✅ All API responses are considered **SUCCESSFUL**
- ✅ No valid activation key required
- ✅ Premium features are **UNLOCKED**

## Technical Notes

- Method and field names are obfuscated (e.g., `OooO00o`, `OooO0O0`)
- Class `g99` = obfuscated `SubscriptionState`
- Interface `v01` = obfuscated subscription API service
- Changes are permanent until APK is updated

## Build Instructions

To apply these changes to an APK:

1. Decompile the APK:
   ```bash
   apktool d thanos.apk -o thanos_decompiled
   ```

2. Apply the modifications to the smali files (already done in this repo)

3. Recompile the APK:
   ```bash
   apktool b thanos_decompiled -o thanos_modified.apk
   ```

4. Sign the APK:
   ```bash
   uber-apk-signer -a thanos_modified.apk
   ```

5. Install the modified APK:
   ```bash
   adb install thanos_modified-aligned-debugSigned.apk
   ```

## Warnings

- These modifications bypass paid features
- Only use for educational/research purposes
- Uninstall original app before installing modified version
- App updates will revert these changes
