.class public final Llyiahf/vczjk/n13;
.super Landroid/hardware/fingerprint/FingerprintManager$AuthenticationCallback;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/tg7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tg7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/n13;->OooO00o:Llyiahf/vczjk/tg7;

    invoke-direct {p0}, Landroid/hardware/fingerprint/FingerprintManager$AuthenticationCallback;-><init>()V

    return-void
.end method


# virtual methods
.method public final onAuthenticationError(ILjava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/n13;->OooO00o:Llyiahf/vczjk/tg7;

    iget-object v0, v0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uqa;

    iget-object v0, v0, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rc0;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/rc0;->OooO00o(ILjava/lang/CharSequence;)V

    return-void
.end method

.method public final onAuthenticationFailed()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/n13;->OooO00o:Llyiahf/vczjk/tg7;

    iget-object v0, v0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uqa;

    iget-object v0, v0, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rc0;

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
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/n13;->OooO00o:Llyiahf/vczjk/tg7;

    iget-object p1, p1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uqa;

    iget-object p1, p1, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/rc0;

    iget-object p1, p1, Llyiahf/vczjk/rc0;->OooO00o:Ljava/lang/ref/WeakReference;

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tc0;

    iget-object v0, p1, Llyiahf/vczjk/tc0;->OooOo0:Llyiahf/vczjk/tr5;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/tr5;

    invoke-direct {v0}, Llyiahf/vczjk/m25;-><init>()V

    iput-object v0, p1, Llyiahf/vczjk/tc0;->OooOo0:Llyiahf/vczjk/tr5;

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/tc0;->OooOo0:Llyiahf/vczjk/tr5;

    invoke-static {p1, p2}, Llyiahf/vczjk/tc0;->OooOO0(Llyiahf/vczjk/tr5;Ljava/lang/Object;)V

    :cond_1
    return-void
.end method

.method public final onAuthenticationSucceeded(Landroid/hardware/fingerprint/FingerprintManager$AuthenticationResult;)V
    .locals 3

    invoke-virtual {p1}, Landroid/hardware/fingerprint/FingerprintManager$AuthenticationResult;->getCryptoObject()Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;

    move-result-object p1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;->getCipher()Ljavax/crypto/Cipher;

    move-result-object v1

    if-eqz v1, :cond_1

    new-instance v1, Llyiahf/vczjk/uqa;

    invoke-virtual {p1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;->getCipher()Ljavax/crypto/Cipher;

    move-result-object p1

    invoke-direct {v1, p1}, Llyiahf/vczjk/uqa;-><init>(Ljavax/crypto/Cipher;)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;->getSignature()Ljava/security/Signature;

    move-result-object v1

    if-eqz v1, :cond_2

    new-instance v1, Llyiahf/vczjk/uqa;

    invoke-virtual {p1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;->getSignature()Ljava/security/Signature;

    move-result-object p1

    invoke-direct {v1, p1}, Llyiahf/vczjk/uqa;-><init>(Ljava/security/Signature;)V

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;->getMac()Ljavax/crypto/Mac;

    move-result-object v1

    if-eqz v1, :cond_3

    new-instance v1, Llyiahf/vczjk/uqa;

    invoke-virtual {p1}, Landroid/hardware/fingerprint/FingerprintManager$CryptoObject;->getMac()Ljavax/crypto/Mac;

    move-result-object p1

    invoke-direct {v1, p1}, Llyiahf/vczjk/uqa;-><init>(Ljavax/crypto/Mac;)V

    goto :goto_1

    :cond_3
    :goto_0
    move-object v1, v0

    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/n13;->OooO00o:Llyiahf/vczjk/tg7;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-nez v1, :cond_4

    goto :goto_2

    :cond_4
    iget-object v2, v1, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ljavax/crypto/Cipher;

    if-eqz v2, :cond_5

    new-instance v0, Llyiahf/vczjk/nc0;

    invoke-direct {v0, v2}, Llyiahf/vczjk/nc0;-><init>(Ljavax/crypto/Cipher;)V

    goto :goto_2

    :cond_5
    iget-object v2, v1, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v2, Ljava/security/Signature;

    if-eqz v2, :cond_6

    new-instance v0, Llyiahf/vczjk/nc0;

    invoke-direct {v0, v2}, Llyiahf/vczjk/nc0;-><init>(Ljava/security/Signature;)V

    goto :goto_2

    :cond_6
    iget-object v1, v1, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Ljavax/crypto/Mac;

    if-eqz v1, :cond_7

    new-instance v0, Llyiahf/vczjk/nc0;

    invoke-direct {v0, v1}, Llyiahf/vczjk/nc0;-><init>(Ljavax/crypto/Mac;)V

    :cond_7
    :goto_2
    new-instance v1, Llyiahf/vczjk/mc0;

    const/4 v2, 0x2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/mc0;-><init>(Llyiahf/vczjk/nc0;I)V

    iget-object p1, p1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uqa;

    iget-object p1, p1, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/rc0;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/rc0;->OooO0O0(Llyiahf/vczjk/mc0;)V

    return-void
.end method
