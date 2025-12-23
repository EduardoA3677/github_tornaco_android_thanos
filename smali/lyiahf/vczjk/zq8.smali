.class public final Llyiahf/vczjk/zq8;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:F

.field public OooOoo:F

.field public OooOoo0:F

.field public OooOooO:F

.field public OooOooo:Z


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 6

    invoke-virtual {p0, p1}, Llyiahf/vczjk/zq8;->o00000OO(Llyiahf/vczjk/o34;)J

    move-result-wide v0

    iget-boolean v2, p0, Llyiahf/vczjk/zq8;->OooOooo:Z

    if-eqz v2, :cond_0

    invoke-static {p3, p4, v0, v1}, Llyiahf/vczjk/uk1;->OooO0o0(JJ)J

    move-result-wide p3

    goto :goto_4

    :cond_0
    iget v2, p0, Llyiahf/vczjk/zq8;->OooOoOO:F

    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    move-result v2

    if-nez v2, :cond_1

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v2

    goto :goto_0

    :cond_1
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v2

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v3

    if-le v2, v3, :cond_2

    move v2, v3

    :cond_2
    :goto_0
    iget v3, p0, Llyiahf/vczjk/zq8;->OooOoo:F

    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-nez v3, :cond_3

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v3

    goto :goto_1

    :cond_3
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v3

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v4

    if-ge v3, v4, :cond_4

    move v3, v4

    :cond_4
    :goto_1
    iget v4, p0, Llyiahf/vczjk/zq8;->OooOoo0:F

    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    move-result v4

    if-nez v4, :cond_5

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v4

    goto :goto_2

    :cond_5
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v4

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v5

    if-le v4, v5, :cond_6

    move v4, v5

    :cond_6
    :goto_2
    iget v5, p0, Llyiahf/vczjk/zq8;->OooOooO:F

    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    move-result v5

    if-nez v5, :cond_7

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    goto :goto_3

    :cond_7
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result p4

    if-ge p3, p4, :cond_8

    move p3, p4

    :cond_8
    :goto_3
    invoke-static {v2, v3, v4, p3}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide p3

    :goto_4
    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/yq8;

    invoke-direct {v0, p2}, Llyiahf/vczjk/yq8;-><init>(Llyiahf/vczjk/ow6;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo00(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/zq8;->o00000OO(Llyiahf/vczjk/o34;)J

    move-result-wide v0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0o0(J)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p1

    return p1

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/zq8;->OooOooo:Z

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {p3, v0, v1}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result p3

    :goto_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooooO0(I)I

    move-result p1

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p1

    return p1
.end method

.method public final OooOooO(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/zq8;->o00000OO(Llyiahf/vczjk/o34;)J

    move-result-wide v0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0o0(J)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p1

    return p1

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/zq8;->OooOooo:Z

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {p3, v0, v1}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result p3

    :goto_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result p1

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p1

    return p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/zq8;->o00000OO(Llyiahf/vczjk/o34;)J

    move-result-wide v0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0o(J)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result p1

    return p1

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/zq8;->OooOooo:Z

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {p3, v0, v1}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p3

    :goto_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0(I)I

    move-result p1

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result p1

    return p1
.end method

.method public final o00000OO(Llyiahf/vczjk/o34;)J
    .locals 6

    iget v0, p0, Llyiahf/vczjk/zq8;->OooOoo:F

    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    move-result v0

    const v1, 0x7fffffff

    const/4 v2, 0x0

    if-nez v0, :cond_0

    iget v0, p0, Llyiahf/vczjk/zq8;->OooOoo:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    if-gez v0, :cond_1

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :cond_1
    :goto_0
    iget v3, p0, Llyiahf/vczjk/zq8;->OooOooO:F

    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-nez v3, :cond_2

    iget v3, p0, Llyiahf/vczjk/zq8;->OooOooO:F

    invoke-interface {p1, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    if-gez v3, :cond_3

    move v3, v2

    goto :goto_1

    :cond_2
    move v3, v1

    :cond_3
    :goto_1
    iget v4, p0, Llyiahf/vczjk/zq8;->OooOoOO:F

    invoke-static {v4}, Ljava/lang/Float;->isNaN(F)Z

    move-result v4

    if-nez v4, :cond_6

    iget v4, p0, Llyiahf/vczjk/zq8;->OooOoOO:F

    invoke-interface {p1, v4}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v4

    if-gez v4, :cond_4

    move v4, v2

    :cond_4
    if-le v4, v0, :cond_5

    move v4, v0

    :cond_5
    if-eq v4, v1, :cond_6

    goto :goto_2

    :cond_6
    move v4, v2

    :goto_2
    iget v5, p0, Llyiahf/vczjk/zq8;->OooOoo0:F

    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    move-result v5

    if-nez v5, :cond_9

    iget v5, p0, Llyiahf/vczjk/zq8;->OooOoo0:F

    invoke-interface {p1, v5}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    if-gez p1, :cond_7

    move p1, v2

    :cond_7
    if-le p1, v3, :cond_8

    move p1, v3

    :cond_8
    if-eq p1, v1, :cond_9

    move v2, p1

    :cond_9
    invoke-static {v4, v0, v2, v3}, Llyiahf/vczjk/uk1;->OooO00o(IIII)J

    move-result-wide v0

    return-wide v0
.end method

.method public final o0OoOo0(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I
    .locals 2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/zq8;->o00000OO(Llyiahf/vczjk/o34;)J

    move-result-wide v0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0o(J)Z

    move-result p1

    if-eqz p1, :cond_0

    invoke-static {v0, v1}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result p1

    return p1

    :cond_0
    iget-boolean p1, p0, Llyiahf/vczjk/zq8;->OooOooo:Z

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-static {p3, v0, v1}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p3

    :goto_0
    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result p1

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result p1

    return p1
.end method
