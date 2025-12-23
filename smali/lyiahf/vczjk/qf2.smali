.class public final Llyiahf/vczjk/qf2;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/c9;

.field public OooOoo:Llyiahf/vczjk/nf6;

.field public OooOoo0:Llyiahf/vczjk/ze3;

.field public OooOooO:Z


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 6

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/qf2;->OooOooO:Z

    if-nez v0, :cond_1

    :cond_0
    iget v0, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v1, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v2, v0

    const/16 v0, 0x20

    shl-long/2addr v2, v0

    int-to-long v0, v1

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    or-long/2addr v0, v2

    iget-object v2, p0, Llyiahf/vczjk/qf2;->OooOoo0:Llyiahf/vczjk/ze3;

    new-instance v3, Llyiahf/vczjk/b24;

    invoke-direct {v3, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    new-instance v0, Llyiahf/vczjk/rk1;

    invoke-direct {v0, p3, p4}, Llyiahf/vczjk/rk1;-><init>(J)V

    invoke-interface {v2, v3, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/xn6;

    iget-object p4, p0, Llyiahf/vczjk/qf2;->OooOoOO:Llyiahf/vczjk/c9;

    invoke-virtual {p3}, Llyiahf/vczjk/xn6;->OooO0OO()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/kb5;

    invoke-virtual {p3}, Llyiahf/vczjk/xn6;->OooO0Oo()Ljava/lang/Object;

    move-result-object p3

    invoke-virtual {p4, v0, p3}, Llyiahf/vczjk/c9;->OooOO0O(Llyiahf/vczjk/kb5;Ljava/lang/Object;)V

    :cond_1
    invoke-interface {p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result p3

    if-nez p3, :cond_3

    iget-boolean p3, p0, Llyiahf/vczjk/qf2;->OooOooO:Z

    if-eqz p3, :cond_2

    goto :goto_0

    :cond_2
    const/4 p3, 0x0

    goto :goto_1

    :cond_3
    :goto_0
    const/4 p3, 0x1

    :goto_1
    iput-boolean p3, p0, Llyiahf/vczjk/qf2;->OooOooO:Z

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/oo0ooO;

    const/16 v1, 0x9

    invoke-direct {v0, p1, p0, v1, p2}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final o000OOo()V
    .locals 1

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/qf2;->OooOooO:Z

    return-void
.end method
