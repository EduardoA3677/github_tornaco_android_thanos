.class public final Llyiahf/vczjk/lr9;
.super Llyiahf/vczjk/nt1;
.source "SourceFile"


# instance fields
.field public final OooOOo:Llyiahf/vczjk/n4a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/tn7;Llyiahf/vczjk/n4a;Llyiahf/vczjk/hj1;)V
    .locals 6

    const/4 v3, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v4, p3

    move-object v5, p5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/nt1;-><init>(Llyiahf/vczjk/dv7;Llyiahf/vczjk/ay8;Llyiahf/vczjk/sn7;Llyiahf/vczjk/tn7;Llyiahf/vczjk/hj1;)V

    const/4 p1, 0x6

    iget p2, v1, Llyiahf/vczjk/dv7;->OooO0o0:I

    if-ne p2, p1, :cond_1

    if-eqz p4, :cond_0

    iput-object p4, v0, Llyiahf/vczjk/lr9;->OooOOo:Llyiahf/vczjk/n4a;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string p2, "catches == null"

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p3, "opcode with invalid branchingness: "

    invoke-static {p2, p3}, Llyiahf/vczjk/ii5;->OooO0o0(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/f14;)V
    .locals 0

    invoke-interface {p1, p0}, Llyiahf/vczjk/f14;->OooOOo0(Llyiahf/vczjk/lr9;)V

    return-void
.end method

.method public final OooO0Oo()Llyiahf/vczjk/n4a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/lr9;->OooOOo:Llyiahf/vczjk/n4a;

    return-object v0
.end method

.method public final OooO0o0()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/nt1;->OooOOo0:Llyiahf/vczjk/hj1;

    invoke-interface {v0}, Llyiahf/vczjk/ss9;->OooO00o()Ljava/lang/String;

    move-result-object v1

    instance-of v2, v0, Llyiahf/vczjk/zt1;

    if-eqz v2, :cond_0

    check-cast v0, Llyiahf/vczjk/zt1;

    invoke-virtual {v0}, Llyiahf/vczjk/zt1;->OooO0o()Ljava/lang/String;

    move-result-object v1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/lr9;->OooOOo:Llyiahf/vczjk/n4a;

    invoke-static {v0}, Llyiahf/vczjk/mr9;->OooO0o(Llyiahf/vczjk/n4a;)Ljava/lang/String;

    move-result-object v0

    const-string v2, " "

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/ix8;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
