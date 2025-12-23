.class public final Llyiahf/vczjk/l03;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/tb2;

.field public OooOoo0:F


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 4

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0Oo(J)Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/l03;->OooOoOO:Llyiahf/vczjk/tb2;

    sget-object v1, Llyiahf/vczjk/tb2;->OooOOO0:Llyiahf/vczjk/tb2;

    if-eq v0, v1, :cond_2

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    int-to-float v0, v0

    iget v1, p0, Llyiahf/vczjk/l03;->OooOoo0:F

    mul-float/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    move-result v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v1

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v2

    if-ge v0, v1, :cond_0

    move v0, v1

    :cond_0
    if-le v0, v2, :cond_1

    goto :goto_0

    :cond_1
    move v2, v0

    :goto_0
    move v0, v2

    goto :goto_1

    :cond_2
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v2

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    :goto_1
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0OO(J)Z

    move-result v1

    if-eqz v1, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/l03;->OooOoOO:Llyiahf/vczjk/tb2;

    sget-object v3, Llyiahf/vczjk/tb2;->OooOOO:Llyiahf/vczjk/tb2;

    if-eq v1, v3, :cond_5

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v1

    int-to-float v1, v1

    iget v3, p0, Llyiahf/vczjk/l03;->OooOoo0:F

    mul-float/2addr v1, v3

    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    move-result v1

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v3

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    if-ge v1, v3, :cond_3

    move v1, v3

    :cond_3
    if-le v1, p3, :cond_4

    goto :goto_2

    :cond_4
    move p3, v1

    :goto_2
    move p4, p3

    goto :goto_3

    :cond_5
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v1

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    move p4, p3

    move p3, v1

    :goto_3
    invoke-static {v2, v0, p3, p4}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p3

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/k03;

    invoke-direct {v0, p2}, Llyiahf/vczjk/k03;-><init>(Llyiahf/vczjk/ow6;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
