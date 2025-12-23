.class public final Llyiahf/vczjk/ul4;
.super Llyiahf/vczjk/dha;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

.field public final OooO0OO:Llyiahf/vczjk/s29;

.field public final OooO0Oo:Llyiahf/vczjk/s29;


# direct methods
.method public constructor <init>()V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    new-instance v0, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v1, "ShortXApp"

    invoke-direct {v0, v1}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object v0, p0, Llyiahf/vczjk/ul4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance v0, Llyiahf/vczjk/lm4;

    sget-object v1, Llyiahf/vczjk/xu0;->OooOOO0:Llyiahf/vczjk/xu0;

    invoke-direct {v0, v1}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    iput-object v0, p0, Llyiahf/vczjk/ul4;->OooO0Oo:Llyiahf/vczjk/s29;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Landroid/content/Context;)V
    .locals 12

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/lm4;

    sget-object v2, Llyiahf/vczjk/xu0;->OooOOO0:Llyiahf/vczjk/xu0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/lm4;

    invoke-direct {v1, v2}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v2, 0x0

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    new-instance v0, Llyiahf/vczjk/tl4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/tl4;-><init>(Llyiahf/vczjk/ul4;)V

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v1

    const-string v3, "39M5DC32-B17D-4370-AB98-A9L809256685"

    invoke-virtual {v1, v3}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_0

    new-instance v3, Llyiahf/vczjk/zx4;

    new-instance v4, Llyiahf/vczjk/vg8;

    new-instance v5, Llyiahf/vczjk/n62;

    sget-object v6, Llyiahf/vczjk/os9;->OooO0Oo:[B

    invoke-virtual {p1}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v7

    const-string v8, "AES/CBC/PKCS5Padding"

    const/4 v9, 0x1

    const/4 v10, 0x0

    invoke-direct {v5, v9, v10}, Llyiahf/vczjk/n62;-><init>(IZ)V

    :try_start_0
    const-string v9, "PBEWITHSHAAND256BITAES-CBC-BC"

    invoke-static {v9}, Ljavax/crypto/SecretKeyFactory;->getInstance(Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;

    move-result-object v9

    new-instance v10, Ljavax/crypto/spec/PBEKeySpec;

    new-instance v11, Ljava/lang/StringBuilder;

    invoke-direct {v11}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v11, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v11, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v11}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/String;->toCharArray()[C

    move-result-object v1

    const/16 v7, 0x400

    const/16 v11, 0x100

    invoke-direct {v10, v1, v6, v7, v11}, Ljavax/crypto/spec/PBEKeySpec;-><init>([C[BII)V

    invoke-virtual {v9, v10}, Ljavax/crypto/SecretKeyFactory;->generateSecret(Ljava/security/spec/KeySpec;)Ljavax/crypto/SecretKey;

    move-result-object v1

    new-instance v6, Ljavax/crypto/spec/SecretKeySpec;

    invoke-interface {v1}, Ljava/security/Key;->getEncoded()[B

    move-result-object v1

    const-string v7, "AES"

    invoke-direct {v6, v1, v7}, Ljavax/crypto/spec/SecretKeySpec;-><init>([BLjava/lang/String;)V

    invoke-static {v8}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object v1

    iput-object v1, v5, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    new-instance v7, Ljavax/crypto/spec/IvParameterSpec;

    sget-object v9, Llyiahf/vczjk/n62;->OooOOOo:[B

    invoke-direct {v7, v9}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    const/4 v10, 0x1

    invoke-virtual {v1, v10, v6, v7}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V

    invoke-static {v8}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    move-result-object v1

    iput-object v1, v5, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    new-instance v7, Ljavax/crypto/spec/IvParameterSpec;

    invoke-direct {v7, v9}, Ljavax/crypto/spec/IvParameterSpec;-><init>([B)V

    const/4 v8, 0x2

    invoke-virtual {v1, v8, v6, v7}, Ljavax/crypto/Cipher;->init(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V
    :try_end_0
    .catch Ljava/security/GeneralSecurityException; {:try_start_0 .. :try_end_0} :catch_0

    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    const-wide/16 v6, 0x0

    iput-wide v6, v4, Llyiahf/vczjk/vg8;->OooO0o0:J

    const-string v1, "com.google.android.vending.licensing.ServerManagedPolicy"

    const/4 v6, 0x0

    invoke-virtual {p1, v1, v6}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/ed5;

    invoke-direct {v6, v1, v5}, Llyiahf/vczjk/ed5;-><init>(Landroid/content/SharedPreferences;Llyiahf/vczjk/n62;)V

    iput-object v6, v4, Llyiahf/vczjk/vg8;->OooO0oO:Llyiahf/vczjk/ed5;

    const/16 v1, 0x123

    invoke-static {v1}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    move-result-object v1

    const-string v5, "lastResponse"

    invoke-virtual {v6, v5, v1}, Llyiahf/vczjk/ed5;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v1

    iput v1, v4, Llyiahf/vczjk/vg8;->OooO0o:I

    const-string v1, "validityTimestamp"

    const-string v5, "0"

    invoke-virtual {v6, v1, v5}, Llyiahf/vczjk/ed5;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v7

    iput-wide v7, v4, Llyiahf/vczjk/vg8;->OooO00o:J

    const-string v1, "retryUntil"

    invoke-virtual {v6, v1, v5}, Llyiahf/vczjk/ed5;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v7

    iput-wide v7, v4, Llyiahf/vczjk/vg8;->OooO0O0:J

    const-string v1, "maxRetries"

    invoke-virtual {v6, v1, v5}, Llyiahf/vczjk/ed5;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v7

    iput-wide v7, v4, Llyiahf/vczjk/vg8;->OooO0OO:J

    const-string v1, "retryCount"

    invoke-virtual {v6, v1, v5}, Llyiahf/vczjk/ed5;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v7

    iput-wide v7, v4, Llyiahf/vczjk/vg8;->OooO0Oo:J

    const-string v1, "licensingUrl"

    invoke-virtual {v6, v1, v2}, Llyiahf/vczjk/ed5;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/zx4;-><init>(Landroid/content/Context;Llyiahf/vczjk/vg8;)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/sl4;

    invoke-direct {v1, v3, v0, v2}, Llyiahf/vczjk/sl4;-><init>(Llyiahf/vczjk/zx4;Llyiahf/vczjk/tl4;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {p1, v2, v2, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    :catch_0
    move-exception p1

    new-instance v0, Ljava/lang/RuntimeException;

    const-string v1, "Invalid environment"

    invoke-direct {v0, v1, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    throw v0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Required value was null."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
