.class public final Llyiahf/vczjk/gi6;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/bi6;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/gi6;->OooOoOO:Llyiahf/vczjk/bi6;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/bi6;->OooO0O0(Llyiahf/vczjk/yn4;)F

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/gi6;->OooOoOO:Llyiahf/vczjk/bi6;

    invoke-interface {v1}, Llyiahf/vczjk/bi6;->OooO0OO()F

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/gi6;->OooOoOO:Llyiahf/vczjk/bi6;

    invoke-interface {p1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v3

    invoke-interface {v2, v3}, Llyiahf/vczjk/bi6;->OooO0Oo(Llyiahf/vczjk/yn4;)F

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/gi6;->OooOoOO:Llyiahf/vczjk/bi6;

    invoke-interface {v3}, Llyiahf/vczjk/bi6;->OooO00o()F

    move-result v3

    const/4 v4, 0x0

    int-to-float v5, v4

    invoke-static {v0, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    const/4 v7, 0x1

    if-ltz v6, :cond_0

    move v6, v7

    goto :goto_0

    :cond_0
    move v6, v4

    :goto_0
    invoke-static {v1, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    if-ltz v8, :cond_1

    move v8, v7

    goto :goto_1

    :cond_1
    move v8, v4

    :goto_1
    and-int/2addr v6, v8

    invoke-static {v2, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v8

    if-ltz v8, :cond_2

    move v8, v7

    goto :goto_2

    :cond_2
    move v8, v4

    :goto_2
    and-int/2addr v6, v8

    invoke-static {v3, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v5

    if-ltz v5, :cond_3

    move v4, v7

    :cond_3
    and-int/2addr v4, v6

    if-nez v4, :cond_4

    const-string v4, "Padding must be non-negative"

    invoke-static {v4}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :cond_4
    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v0

    invoke-interface {p1, v2}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v2

    add-int/2addr v2, v0

    invoke-interface {p1, v1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v1

    invoke-interface {p1, v3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result v3

    add-int/2addr v3, v1

    neg-int v4, v2

    neg-int v5, v3

    invoke-static {v4, v5, p3, p4}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v4

    invoke-interface {p2, v4, v5}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget v4, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-int/2addr v4, v2

    invoke-static {v4, p3, p4}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result v2

    iget v4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    add-int/2addr v4, v3

    invoke-static {v4, p3, p4}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p3

    new-instance p4, Llyiahf/vczjk/fi6;

    invoke-direct {p4, p2, v0, v1}, Llyiahf/vczjk/fi6;-><init>(Llyiahf/vczjk/ow6;II)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v2, p3, p2, p4}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
