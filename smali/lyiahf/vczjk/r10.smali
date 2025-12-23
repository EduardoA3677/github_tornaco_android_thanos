.class public final Llyiahf/vczjk/r10;
.super Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/rc0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rc0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r10;->OooO00o:Llyiahf/vczjk/rc0;

    invoke-direct {p0}, Landroid/hardware/biometrics/BiometricPrompt$AuthenticationCallback;-><init>()V

    return-void
.end method


# virtual methods
.method public final onAuthenticationError(ILjava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/r10;->OooO00o:Llyiahf/vczjk/rc0;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/rc0;->OooO00o(ILjava/lang/CharSequence;)V

    return-void
.end method

.method public final onAuthenticationFailed()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/r10;->OooO00o:Llyiahf/vczjk/rc0;

    iget-object v0, v0, Llyiahf/vczjk/rc0;->OooO00o:Ljava/lang/ref/WeakReference;

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/tc0;

    iget-boolean v1, v1, Llyiahf/vczjk/tc0;->OooOOO0:Z

    if-eqz v1, :cond_1

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/tc0;

    iget-object v1, v0, Llyiahf/vczjk/tc0;->OooOo0O:Llyiahf/vczjk/tr5;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/tr5;

    invoke-direct {v1}, Llyiahf/vczjk/m25;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/tc0;->OooOo0O:Llyiahf/vczjk/tr5;

    :cond_0
    iget-object v0, v0, Llyiahf/vczjk/tc0;->OooOo0O:Llyiahf/vczjk/tr5;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {v0, v1}, Llyiahf/vczjk/tc0;->OooOO0(Llyiahf/vczjk/tr5;Ljava/lang/Object;)V

    :cond_1
    return-void
.end method

.method public final onAuthenticationHelp(ILjava/lang/CharSequence;)V
    .locals 0

    return-void
.end method

.method public final onAuthenticationSucceeded(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)V
    .locals 6

    const/16 v0, 0x1e

    const/4 v1, 0x0

    if-eqz p1, :cond_6

    invoke-static {p1}, Llyiahf/vczjk/wo;->OooO0oO(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;

    move-result-object v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v2}, Llyiahf/vczjk/wo;->OooO0o(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Ljavax/crypto/Cipher;

    move-result-object v3

    if-eqz v3, :cond_1

    new-instance v1, Llyiahf/vczjk/nc0;

    invoke-direct {v1, v3}, Llyiahf/vczjk/nc0;-><init>(Ljavax/crypto/Cipher;)V

    goto :goto_0

    :cond_1
    invoke-static {v2}, Llyiahf/vczjk/wo;->OooOo00(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Ljava/security/Signature;

    move-result-object v3

    if-eqz v3, :cond_2

    new-instance v1, Llyiahf/vczjk/nc0;

    invoke-direct {v1, v3}, Llyiahf/vczjk/nc0;-><init>(Ljava/security/Signature;)V

    goto :goto_0

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/wo;->OooO(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Ljavax/crypto/Mac;

    move-result-object v3

    if-eqz v3, :cond_3

    new-instance v1, Llyiahf/vczjk/nc0;

    invoke-direct {v1, v3}, Llyiahf/vczjk/nc0;-><init>(Ljavax/crypto/Mac;)V

    goto :goto_0

    :cond_3
    sget v3, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v3, v0, :cond_4

    invoke-static {v2}, Llyiahf/vczjk/o0O0o00O;->OooO0o0(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Landroid/security/identity/IdentityCredential;

    move-result-object v4

    if-eqz v4, :cond_4

    new-instance v1, Llyiahf/vczjk/nc0;

    invoke-direct {v1, v4}, Llyiahf/vczjk/nc0;-><init>(Landroid/security/identity/IdentityCredential;)V

    goto :goto_0

    :cond_4
    const/16 v4, 0x21

    if-lt v3, v4, :cond_5

    invoke-static {v2}, Llyiahf/vczjk/o0O0o0;->OooO0oO(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)Landroid/security/identity/PresentationSession;

    move-result-object v4

    if-eqz v4, :cond_5

    new-instance v1, Llyiahf/vczjk/nc0;

    invoke-direct {v1, v4}, Llyiahf/vczjk/nc0;-><init>(Landroid/security/identity/PresentationSession;)V

    goto :goto_0

    :cond_5
    const/16 v4, 0x23

    if-lt v3, v4, :cond_6

    invoke-static {v2}, Llyiahf/vczjk/ct1;->OooO0O0(Landroid/hardware/biometrics/BiometricPrompt$CryptoObject;)J

    move-result-wide v2

    const-wide/16 v4, 0x0

    cmp-long v4, v2, v4

    if-eqz v4, :cond_6

    new-instance v1, Llyiahf/vczjk/nc0;

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/nc0;-><init>(J)V

    :cond_6
    :goto_0
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/4 v3, -0x1

    if-lt v2, v0, :cond_7

    if-eqz p1, :cond_9

    invoke-static {p1}, Llyiahf/vczjk/o0O0o00O;->OooO0OO(Landroid/hardware/biometrics/BiometricPrompt$AuthenticationResult;)I

    move-result v3

    goto :goto_1

    :cond_7
    const/16 p1, 0x1d

    if-ne v2, p1, :cond_8

    goto :goto_1

    :cond_8
    const/4 v3, 0x2

    :cond_9
    :goto_1
    new-instance p1, Llyiahf/vczjk/mc0;

    invoke-direct {p1, v1, v3}, Llyiahf/vczjk/mc0;-><init>(Llyiahf/vczjk/nc0;I)V

    iget-object v0, p0, Llyiahf/vczjk/r10;->OooO00o:Llyiahf/vczjk/rc0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/rc0;->OooO0O0(Llyiahf/vczjk/mc0;)V

    return-void
.end method
