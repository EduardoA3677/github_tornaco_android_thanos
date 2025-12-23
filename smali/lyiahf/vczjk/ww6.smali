.class public final Llyiahf/vczjk/ww6;
.super Llyiahf/vczjk/g14;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3, p4}, Llyiahf/vczjk/g14;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;)V

    const/4 p2, 0x5

    iget p1, p1, Llyiahf/vczjk/dv7;->OooO0o0:I

    if-eq p1, p2, :cond_2

    const/4 p2, 0x6

    if-eq p1, p2, :cond_2

    if-eqz p3, :cond_1

    const/4 p2, 0x1

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "can\'t mix branchingness with result"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :goto_0
    return-void

    :cond_2
    new-instance p2, Ljava/lang/IllegalArgumentException;

    const-string p3, "opcode with invalid branchingness: "

    invoke-static {p1, p3}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p2
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/f14;)V
    .locals 0

    invoke-interface {p1, p0}, Llyiahf/vczjk/f14;->OooO0Oo(Llyiahf/vczjk/ww6;)V

    return-void
.end method

.method public final OooO0Oo()Llyiahf/vczjk/n4a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/d59;->OooOOOO:Llyiahf/vczjk/d59;

    return-object v0
.end method
