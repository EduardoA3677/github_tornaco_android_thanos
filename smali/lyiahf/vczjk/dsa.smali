.class public final Llyiahf/vczjk/dsa;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/tb2;

.field public OooOoo0:Llyiahf/vczjk/rm4;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/dsa;->OooOoOO:Llyiahf/vczjk/tb2;

    sget-object v1, Llyiahf/vczjk/tb2;->OooOOO0:Llyiahf/vczjk/tb2;

    const/4 v2, 0x0

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/dsa;->OooOoOO:Llyiahf/vczjk/tb2;

    sget-object v3, Llyiahf/vczjk/tb2;->OooOOO:Llyiahf/vczjk/tb2;

    if-eq v1, v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v2

    :goto_1
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v1

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v3

    invoke-static {v0, v1, v2, v3}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide v0

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object v5

    iget p2, v5, Llyiahf/vczjk/ow6;->OooOOO0:I

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v1

    invoke-static {p2, v0, v1}, Llyiahf/vczjk/vt6;->OooOOo(III)I

    move-result v4

    iget p2, v5, Llyiahf/vczjk/ow6;->OooOOO:I

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    invoke-static {p2, v0, p3}, Llyiahf/vczjk/vt6;->OooOOo(III)I

    move-result v6

    new-instance v2, Llyiahf/vczjk/csa;

    move-object v3, p0

    move-object v7, p1

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/csa;-><init>(Llyiahf/vczjk/dsa;ILlyiahf/vczjk/ow6;ILlyiahf/vczjk/nf5;)V

    sget-object p1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {v7, v4, v6, p1, v2}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
