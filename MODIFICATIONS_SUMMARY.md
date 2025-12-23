# Subscription Bypass Modifications - Summary (UPDATED)

## Overview
This document provides a technical summary of the modifications made to bypass subscription verification in the Thanos Android app. **The latest update fixes the "trial mode" issue by using Loaded states instead of Loading states.**

## Files Modified

### 1. Initial Subscription State - ACTIVATED WITH LOADED STATES
**File**: `smali_classes2/lyiahf/vczjk/p35.smali` (Lines 39-79)

**Change**: Set isSubscribed=true, created ActivationCode source, and created Loaded states with actual data
```smali
# isSubscribed = true
const/4 v0, 0x1

# Create ActivationCode source
new-instance v1, Llyiahf/vczjk/d99;
const-string v5, "PREMIUM_ACTIVATED"
invoke-direct {v1, v5}, Llyiahf/vczjk/d99;-><init>(Ljava/lang/String;)V

# Create Loaded SubscriptionConfig (instead of Loading)
new-instance v4, Llyiahf/vczjk/p7a;  # p7a = Loaded state
new-instance v5, Lgithub/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2;
invoke-static {}, Ljava/util/Collections;->emptyList()Ljava/util/List;
move-result-object v6
const-string v7, "premium@app.com"
const-string v8, "999999"
invoke-direct {v5, v6, v7, v8}, Lgithub/tornaco/android/thanos/support/subscribe/code/SubscriptionConfig2;-><init>(Ljava/util/List;Ljava/lang/String;Ljava/lang/String;)V
invoke-direct {v4, v5}, Llyiahf/vczjk/p7a;-><init>(Ljava/lang/Object;)V

# Create Loaded CodeRemaining with perpetual time (instead of Loading)
new-instance v5, Llyiahf/vczjk/p7a;  # p7a = Loaded state
new-instance v6, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;
const-wide/32 v7, 0xf423f      # 999999 hours
const-wide v9, 0xd693a400L     # ~3.6 billion milliseconds
invoke-direct {v6, v7, v8, v9, v10}, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;-><init>(JJ)V
invoke-direct {v5, v6}, Llyiahf/vczjk/p7a;-><init>(Ljava/lang/Object;)V

# Initialize SubscriptionState with all parameters
invoke-direct {v3, v0, v1, v4, v5}, Llyiahf/vczjk/g99;-><init>(ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;)V
```

**Effect**: 
- The app starts with subscription ACTIVE by default ✅
- Source shows as ActivationCode("PREMIUM_ACTIVATED") ✅
- Config state is Loaded (NOT Loading) with valid data ✅
- Remaining state is Loaded (NOT Loading) with 999,999 hours ✅
- **NO trial mode display** ✅

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

## Results (UPDATED)

With these modifications:
- ✅ Subscription is **ACTIVE** on app start
- ✅ Activation key verification **ALWAYS SUCCEEDS**
- ✅ All API responses are considered **SUCCESSFUL**
- ✅ No valid activation key required
- ✅ Premium features are **UNLOCKED**
- ✅ Config state is **LOADED** with valid data (NOT Loading)
- ✅ Remaining time is **LOADED** with 999,999 hours (NOT Loading)
- ✅ App displays as **PREMIUM** (NOT trial mode)

## Technical Notes

- Method and field names are obfuscated (e.g., `OooO00o`, `OooO0O0`)
- Class `g99` = obfuscated `SubscriptionState`
- Class `d99` = obfuscated `ActivationCode` (subscription source)
- Class `p7a` = obfuscated `Loaded` state wrapper
- Class `q7a` = obfuscated `Loading` state (NOT used anymore)
- Interface `v01` = obfuscated subscription API service
- Changes are permanent until APK is updated
- **Previous version used Loading states which caused trial mode display**
- **Current version uses Loaded states with real data for permanent premium status**

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
