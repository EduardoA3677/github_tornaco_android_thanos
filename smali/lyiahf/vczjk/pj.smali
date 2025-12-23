.class public final Llyiahf/vczjk/pj;
.super Llyiahf/vczjk/jo4;
.source "SourceFile"


# instance fields
.field public OooOoOO:Llyiahf/vczjk/oy9;

.field public OooOoo:Llyiahf/vczjk/uj;

.field public OooOoo0:Llyiahf/vczjk/qs5;

.field public OooOooO:J


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 7

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result p3

    const-wide v0, 0xffffffffL

    const/16 p4, 0x20

    if-eqz p3, :cond_0

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v2, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v3, p3

    shl-long/2addr v3, p4

    int-to-long v5, v2

    and-long/2addr v5, v0

    or-long v2, v3, v5

    goto :goto_0

    :cond_0
    iget-object p3, p0, Llyiahf/vczjk/pj;->OooOoOO:Llyiahf/vczjk/oy9;

    if-nez p3, :cond_1

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v2, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v3, p3

    shl-long/2addr v3, p4

    int-to-long v5, v2

    and-long/2addr v5, v0

    or-long v2, v3, v5

    iput-wide v2, p0, Llyiahf/vczjk/pj;->OooOooO:J

    goto :goto_0

    :cond_1
    iget v2, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v3, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v4, v2

    shl-long/2addr v4, p4

    int-to-long v2, v3

    and-long/2addr v2, v0

    or-long/2addr v2, v4

    new-instance v4, Llyiahf/vczjk/nj;

    invoke-direct {v4, p0, v2, v3}, Llyiahf/vczjk/nj;-><init>(Llyiahf/vczjk/pj;J)V

    new-instance v5, Llyiahf/vczjk/oj;

    invoke-direct {v5, p0, v2, v3}, Llyiahf/vczjk/oj;-><init>(Llyiahf/vczjk/pj;J)V

    invoke-virtual {p3, v4, v5}, Llyiahf/vczjk/oy9;->OooO00o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/ny9;

    move-result-object p3

    iget-object v2, p0, Llyiahf/vczjk/pj;->OooOoo:Llyiahf/vczjk/uj;

    iput-object p3, v2, Llyiahf/vczjk/uj;->OooO0o:Llyiahf/vczjk/ny9;

    invoke-virtual {p3}, Llyiahf/vczjk/ny9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/b24;

    iget-wide v2, v2, Llyiahf/vczjk/b24;->OooO00o:J

    invoke-virtual {p3}, Llyiahf/vczjk/ny9;->getValue()Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/b24;

    iget-wide v4, p3, Llyiahf/vczjk/b24;->OooO00o:J

    iput-wide v4, p0, Llyiahf/vczjk/pj;->OooOooO:J

    :goto_0
    shr-long p3, v2, p4

    long-to-int p3, p3

    and-long/2addr v0, v2

    long-to-int p4, v0

    new-instance v0, Llyiahf/vczjk/mj;

    invoke-direct {v0, p0, p2, v2, v3}, Llyiahf/vczjk/mj;-><init>(Llyiahf/vczjk/pj;Llyiahf/vczjk/ow6;J)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final o000000()V
    .locals 2

    sget-wide v0, Landroidx/compose/animation/OooO00o;->OooO00o:J

    iput-wide v0, p0, Llyiahf/vczjk/pj;->OooOooO:J

    return-void
.end method
