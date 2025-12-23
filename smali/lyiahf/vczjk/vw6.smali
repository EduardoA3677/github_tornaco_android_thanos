.class public final Llyiahf/vczjk/vw6;
.super Llyiahf/vczjk/nt1;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;Llyiahf/vczjk/t5a;)V
    .locals 0

    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/nt1;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;Llyiahf/vczjk/hj1;)V

    const/4 p2, 0x1

    iget p1, p1, Llyiahf/vczjk/dv7;->OooO0o0:I

    if-ne p1, p2, :cond_0

    return-void

    :cond_0
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

    invoke-interface {p1, p0}, Llyiahf/vczjk/f14;->OooOO0O(Llyiahf/vczjk/vw6;)V

    return-void
.end method

.method public final OooO0Oo()Llyiahf/vczjk/n4a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/d59;->OooOOOO:Llyiahf/vczjk/d59;

    return-object v0
.end method
