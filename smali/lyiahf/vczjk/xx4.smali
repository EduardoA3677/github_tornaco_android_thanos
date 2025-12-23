.class public final Llyiahf/vczjk/xx4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/String;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/String;

.field public final synthetic OooOOOo:Llyiahf/vczjk/yx4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yx4;ILjava/lang/String;Ljava/lang/String;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xx4;->OooOOOo:Llyiahf/vczjk/yx4;

    iput p2, p0, Llyiahf/vczjk/xx4;->OooOOO0:I

    iput-object p3, p0, Llyiahf/vczjk/xx4;->OooOOO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/xx4;->OooOOOO:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 12

    const-string v0, "Received response."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "LicenseChecker %s"

    invoke-static {v1, v0}, Llyiahf/vczjk/zsa;->OooooO0(Ljava/lang/String;[Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/xx4;->OooOOOo:Llyiahf/vczjk/yx4;

    iget-object v2, v0, Llyiahf/vczjk/yx4;->OooO0oO:Llyiahf/vczjk/zx4;

    iget-object v3, v2, Llyiahf/vczjk/zx4;->OooO0oo:Ljava/util/HashSet;

    iget-object v4, v0, Llyiahf/vczjk/yx4;->OooO0o0:Llyiahf/vczjk/ay4;

    invoke-virtual {v3, v4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_e

    const-string v3, "Clearing timeout."

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v3}, Llyiahf/vczjk/zsa;->OooooO0(Ljava/lang/String;[Ljava/lang/Object;)V

    iget-object v1, v2, Llyiahf/vczjk/zx4;->OooO0o0:Landroid/os/Handler;

    iget-object v0, v0, Llyiahf/vczjk/yx4;->OooO0o:Llyiahf/vczjk/ra;

    invoke-virtual {v1, v0}, Landroid/os/Handler;->removeCallbacks(Ljava/lang/Runnable;)V

    iget-object v0, v2, Llyiahf/vczjk/zx4;->OooO0O0:Ljava/security/PublicKey;

    iget-object v1, p0, Llyiahf/vczjk/xx4;->OooOOO:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/xx4;->OooOOOO:Ljava/lang/String;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v5, 0x0

    iget-object v6, v4, Llyiahf/vczjk/ay4;->OooO0O0:Llyiahf/vczjk/tl4;

    iget v7, p0, Llyiahf/vczjk/xx4;->OooOOO0:I

    const/4 v8, 0x2

    const/4 v9, 0x1

    const-string v10, "LicenseValidator %s"

    if-eqz v7, :cond_1

    if-eq v7, v9, :cond_1

    if-ne v7, v8, :cond_0

    goto :goto_0

    :cond_0
    move-object v0, v5

    goto/16 :goto_1

    :cond_1
    :goto_0
    :try_start_0
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v11

    if-eqz v11, :cond_2

    const-string v0, "Signature verification failed: signedData is empty. (Device not signed-in to any Google accounts?)"

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto/16 :goto_3

    :catch_0
    move-exception v0

    goto/16 :goto_2

    :catch_1
    move-exception v0

    goto/16 :goto_4

    :cond_2
    const-string v11, "SHA1withRSA"

    invoke-static {v11}, Ljava/security/Signature;->getInstance(Ljava/lang/String;)Ljava/security/Signature;

    move-result-object v11

    invoke-virtual {v11, v0}, Ljava/security/Signature;->initVerify(Ljava/security/PublicKey;)V

    invoke-virtual {v1}, Ljava/lang/String;->getBytes()[B

    move-result-object v0

    invoke-virtual {v11, v0}, Ljava/security/Signature;->update([B)V

    invoke-static {v3}, Llyiahf/vczjk/os9;->OooOo0(Ljava/lang/String;)[B

    move-result-object v0

    invoke-virtual {v11, v0}, Ljava/security/Signature;->verify([B)Z

    move-result v0

    if-nez v0, :cond_3

    const-string v0, "Signature verification failed."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V
    :try_end_0
    .catch Ljava/security/NoSuchAlgorithmException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/security/InvalidKeyException; {:try_start_0 .. :try_end_0} :catch_4
    .catch Ljava/security/SignatureException; {:try_start_0 .. :try_end_0} :catch_0
    .catch Llyiahf/vczjk/y50; {:try_start_0 .. :try_end_0} :catch_3

    goto/16 :goto_3

    :cond_3
    :try_start_1
    invoke-static {v1}, Llyiahf/vczjk/ls7;->OooO00o(Ljava/lang/String;)Llyiahf/vczjk/ls7;

    move-result-object v0
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_2

    iget v1, v0, Llyiahf/vczjk/ls7;->OooO00o:I

    if-eq v1, v7, :cond_4

    const-string v0, "Response codes don\'t match."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto/16 :goto_3

    :cond_4
    iget v1, v0, Llyiahf/vczjk/ls7;->OooO0O0:I

    iget v3, v4, Llyiahf/vczjk/ay4;->OooO0OO:I

    if-eq v1, v3, :cond_5

    const-string v0, "Nonce doesn\'t match."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto/16 :goto_3

    :cond_5
    iget-object v1, v0, Llyiahf/vczjk/ls7;->OooO0OO:Ljava/lang/String;

    iget-object v3, v4, Llyiahf/vczjk/ay4;->OooO0Oo:Ljava/lang/String;

    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_6

    const-string v0, "Package name doesn\'t match."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto/16 :goto_3

    :cond_6
    iget-object v1, v0, Llyiahf/vczjk/ls7;->OooO0Oo:Ljava/lang/String;

    iget-object v3, v4, Llyiahf/vczjk/ay4;->OooO0o0:Ljava/lang/String;

    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_7

    const-string v0, "Version codes don\'t match."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto/16 :goto_3

    :cond_7
    iget-object v1, v0, Llyiahf/vczjk/ls7;->OooO0o0:Ljava/lang/String;

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_8

    const-string v0, "User identifier is empty."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto/16 :goto_3

    :cond_8
    :goto_1
    if-eqz v7, :cond_d

    if-eq v7, v9, :cond_c

    if-eq v7, v8, :cond_d

    const/4 v1, 0x3

    if-eq v7, v1, :cond_b

    const/4 v1, 0x4

    const/16 v3, 0x123

    if-eq v7, v1, :cond_a

    const/4 v1, 0x5

    if-eq v7, v1, :cond_9

    packed-switch v7, :pswitch_data_0

    const-string v0, "Unknown response code for license check."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto/16 :goto_3

    :pswitch_0
    iget-object v0, v6, Llyiahf/vczjk/tl4;->OooO00o:Llyiahf/vczjk/ul4;

    iget-object v1, v0, Llyiahf/vczjk/ul4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    iget-object v0, v0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/lm4;

    sget-object v3, Llyiahf/vczjk/xu0;->OooOOO:Llyiahf/vczjk/xu0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/lm4;

    invoke-direct {v1, v3}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0, v5, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    goto/16 :goto_3

    :pswitch_1
    iget-object v0, v6, Llyiahf/vczjk/tl4;->OooO00o:Llyiahf/vczjk/ul4;

    iget-object v1, v0, Llyiahf/vczjk/ul4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    iget-object v0, v0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/lm4;

    sget-object v3, Llyiahf/vczjk/xu0;->OooOOO:Llyiahf/vczjk/xu0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/lm4;

    invoke-direct {v1, v3}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0, v5, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    goto/16 :goto_3

    :pswitch_2
    const-string v1, "Error contacting licensing server."

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v10, v1}, Llyiahf/vczjk/zsa;->o0ooOoO(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4, v3, v0}, Llyiahf/vczjk/ay4;->OooO0O0(ILlyiahf/vczjk/ls7;)V

    goto/16 :goto_3

    :cond_9
    const-string v1, "Licensing server is refusing to talk to this device, over quota."

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v10, v1}, Llyiahf/vczjk/zsa;->o0ooOoO(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4, v3, v0}, Llyiahf/vczjk/ay4;->OooO0O0(ILlyiahf/vczjk/ls7;)V

    goto :goto_3

    :cond_a
    const-string v1, "An error has occurred on the licensing server."

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v10, v1}, Llyiahf/vczjk/zsa;->o0ooOoO(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4, v3, v0}, Llyiahf/vczjk/ay4;->OooO0O0(ILlyiahf/vczjk/ls7;)V

    goto :goto_3

    :cond_b
    iget-object v0, v6, Llyiahf/vczjk/tl4;->OooO00o:Llyiahf/vczjk/ul4;

    iget-object v1, v0, Llyiahf/vczjk/ul4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    iget-object v0, v0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/lm4;

    sget-object v3, Llyiahf/vczjk/xu0;->OooOOO:Llyiahf/vczjk/xu0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/lm4;

    invoke-direct {v1, v3}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0, v5, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    goto :goto_3

    :cond_c
    const/16 v1, 0x231

    invoke-virtual {v4, v1, v0}, Llyiahf/vczjk/ay4;->OooO0O0(ILlyiahf/vczjk/ls7;)V

    goto :goto_3

    :cond_d
    const/16 v1, 0x100

    invoke-virtual {v4, v1, v0}, Llyiahf/vczjk/ay4;->OooO0O0(ILlyiahf/vczjk/ls7;)V

    goto :goto_3

    :catch_2
    const-string v0, "Could not parse response."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto :goto_3

    :catch_3
    const-string v0, "Could not Base64-decode signature."

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10, v0}, Llyiahf/vczjk/zsa;->Oooo0o0(Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/ay4;->OooO00o()V

    goto :goto_3

    :goto_2
    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1

    :catch_4
    iget-object v0, v6, Llyiahf/vczjk/tl4;->OooO00o:Llyiahf/vczjk/ul4;

    iget-object v1, v0, Llyiahf/vczjk/ul4;->OooO0O0:Lgithub/tornaco/android/thanos/core/Logger;

    iget-object v0, v0, Llyiahf/vczjk/ul4;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/lm4;

    sget-object v3, Llyiahf/vczjk/xu0;->OooOOO:Llyiahf/vczjk/xu0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/lm4;

    invoke-direct {v1, v3}, Llyiahf/vczjk/lm4;-><init>(Llyiahf/vczjk/xu0;)V

    invoke-virtual {v0, v5, v1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    :goto_3
    invoke-static {v2, v4}, Llyiahf/vczjk/zx4;->OooO00o(Llyiahf/vczjk/zx4;Llyiahf/vczjk/ay4;)V

    goto :goto_5

    :goto_4
    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1

    :cond_e
    :goto_5
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x101
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
