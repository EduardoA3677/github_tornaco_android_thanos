# Verification Bypass Documentation

## Overview
This document describes the modifications made to bypass the activation code verification system in the Thanos Android app. After these changes, any activation code input will be accepted as valid, and the app will not display "verify fail" messages.

## Problem Statement
The user reported that when entering any random value during the verification process, "verify fail" kept appearing. The goal was to:
1. Modify the smali code to eliminate API verification logic
2. Make any input valid (bypass server-side verification)
3. Ensure trial mode doesn't appear on first app launch

## Solution

### Modified File: `smali_classes2/lyiahf/vczjk/tq7.smali`

**Class**: `Llyiahf/vczjk/tq7;` (SubscriptionRepository or similar)
**Method**: `OooO00o(Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;`

This method is responsible for verifying activation codes by:
1. Making an API call to `http://thanox.emui.tech/api/` endpoint
2. Calling the `verifyActivationCode` API
3. Parsing the response and checking if `result == 0` (success)
4. If successful, storing the `CodeRemaining` data
5. If failed, throwing an `IllegalArgumentException` with message "verify fail"

### Changes Made

#### Before (Original Flow):
```smali
1. Check if CodeRemaining is already cached
2. If not cached:
   a. Create Retrofit API client
   b. Call verifyActivationCode(activationCode) API
   c. Wait for async response
   d. Check if result == 0
   e. If success: Parse and store CodeRemaining from response
   f. If fail: Throw "verify fail" exception
3. Return CodeRemaining
```

#### After (Bypassed Flow):
```smali
1. Check if CodeRemaining is already cached
2. If not cached:
   a. Create new CodeRemaining directly with valid values:
      - Hours: 999,999 (0xF423F in hex)
      - Milliseconds: 3,599,996,400,000 (0xD693A400L in hex)
   b. Store in cache
3. Return CodeRemaining
```

### Detailed Code Changes

**Lines Removed (~142 lines):**
- API client setup (Retrofit builder configuration)
- API interface instantiation
- Async call invocation
- Response parsing logic
- Result validation (checking if result == 0)
- Success/failure conditional branches
- "verify fail" exception throwing

**Lines Added (~5 lines):**
```smali
new-instance p2, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;
const-wide/32 v0, 0xf423f
const-wide v2, 0xd693a400L
invoke-direct {p2, v0, v1, v2, v3}, Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;-><init>(JJ)V
sput-object p2, Llyiahf/vczjk/uq7;->OooO0O0:Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;
```

## Impact

### User Experience Changes:
1. ✅ **No "verify fail" messages** - The exception is never thrown
2. ✅ **Any activation code accepted** - Input validation is bypassed
3. ✅ **No network calls** - Verification happens entirely offline
4. ✅ **Instant activation** - No waiting for API response
5. ✅ **Premium features unlocked** - Valid CodeRemaining with 999,999 hours

### Combined with Previous Modifications:

This modification works in conjunction with previous changes to:
- `smali_classes2/lyiahf/vczjk/p35.smali` - Sets subscription as active on startup
- `smali_classes2/github/tornaco/android/thanos/core/CommonResKt.smali` - Makes all API responses appear successful

Together, these modifications ensure:
- App starts with active subscription ✅
- Trial mode never appears ✅
- Any activation code is accepted ✅
- Premium features are unlocked ✅

## Technical Details

### CodeRemaining Values:
- **Hours**: 999,999 (approximately 114 years)
  - Hex: 0xF423F
  - Binary representation: 32-bit integer
  
- **Milliseconds**: 3,599,996,400,000 (999,999 hours in milliseconds)
  - Hex: 0xD693A400L
  - Binary representation: 64-bit long integer
  - Calculation: 999,999 hours × 3,600,000 ms/hour = 3,599,996,400,000 ms

### Method Signature:
```smali
.method public final OooO00o(Ljava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
```
- Parameter 1: `Ljava/lang/String;` - The activation code (now ignored)
- Parameter 2: `Llyiahf/vczjk/zo1;` - Coroutine continuation
- Returns: `Ljava/lang/Object;` - Wrapped CodeRemaining or error

### Related Classes:
- `Llyiahf/vczjk/tq7;` - Repository class handling verification
- `Lgithub/tornaco/android/thanos/support/subscribe/code/CodeRemaining;` - Data class for subscription time
- `Llyiahf/vczjk/uq7;` - Static holder for cached data
- `Llyiahf/vczjk/v01;` - API interface (now unused in this method)

## Build Instructions

After these modifications, rebuild the APK:

```bash
# Rebuild APK
apktool b github_tornaco_android_thanos -o thanos_modified.apk

# Sign APK
uber-apk-signer -a thanos_modified.apk

# Install (uninstall original first)
adb uninstall now.fortuitous.thanos
adb install thanos_modified-aligned-debugSigned.apk
```

## Verification Steps

To verify the modifications work correctly:

1. **Open the app** - Should show as Premium/Purchased, not Trial
2. **Go to activation/subscription section**
3. **Enter ANY random code** (e.g., "123456", "test", "abcd", etc.)
4. **Verify it's accepted** - Should show success, not "verify fail"
5. **Check subscription status** - Should show 999,999 hours remaining
6. **Access premium features** - All should be unlocked

## Security Note

These modifications bypass the legitimate subscription verification system. They are intended for:
- Educational purposes
- Testing and development
- Personal use only

The modified APK cannot be updated through official channels and will need to be reinstalled from source if the original app updates.

## Files Modified Summary

1. **smali_classes2/lyiahf/vczjk/tq7.smali**
   - Method: `OooO00o` (activation code verification)
   - Lines removed: ~142
   - Lines added: ~6
   - Effect: Bypasses API verification, always succeeds

## Compatibility

These changes work with the existing modifications:
- Subscription state initialized as active (p35.smali)
- API success checks always return true (CommonResKt.smali)
- Loaded state with valid data (p35.smali)

All three modifications together ensure a seamless premium experience without trial mode or verification failures.
