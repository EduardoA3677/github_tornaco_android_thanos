.class public final Llyiahf/vczjk/sr9;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/go4;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/rr5;

.field public OooOoo:Llyiahf/vczjk/p13;

.field public OooOoo0:Z

.field public OooOooO:Z

.field public OooOooo:Llyiahf/vczjk/gi;

.field public Oooo000:Llyiahf/vczjk/gi;

.field public Oooo00O:F

.field public Oooo00o:F


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 5

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v0

    invoke-interface {p2, v0}, Llyiahf/vczjk/ef5;->OooO0OO(I)I

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    invoke-interface {p2, p3}, Llyiahf/vczjk/ef5;->OooOo0o(I)I

    move-result p3

    if-eqz p3, :cond_0

    move p3, v2

    goto :goto_0

    :cond_0
    move p3, v1

    :goto_0
    iget-boolean p4, p0, Llyiahf/vczjk/sr9;->OooOooO:Z

    if-eqz p4, :cond_1

    sget p3, Llyiahf/vczjk/rc9;->OooOOO:F

    goto :goto_2

    :cond_1
    if-nez p3, :cond_3

    iget-boolean p3, p0, Llyiahf/vczjk/sr9;->OooOoo0:Z

    if-eqz p3, :cond_2

    goto :goto_1

    :cond_2
    sget p3, Landroidx/compose/material3/OooO0O0;->OooO0O0:F

    goto :goto_2

    :cond_3
    :goto_1
    sget p3, Landroidx/compose/material3/OooO0O0;->OooO00o:F

    :goto_2
    invoke-interface {p1, p3}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p3

    iget-object p4, p0, Llyiahf/vczjk/sr9;->Oooo000:Llyiahf/vczjk/gi;

    if-eqz p4, :cond_4

    invoke-virtual {p4}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p4

    check-cast p4, Ljava/lang/Number;

    invoke-virtual {p4}, Ljava/lang/Number;->floatValue()F

    move-result p4

    goto :goto_3

    :cond_4
    move p4, p3

    :goto_3
    float-to-int p4, p4

    if-ltz p4, :cond_5

    move v0, v2

    goto :goto_4

    :cond_5
    move v0, v1

    :goto_4
    if-ltz p4, :cond_6

    move v1, v2

    :cond_6
    and-int/2addr v0, v1

    if-nez v0, :cond_7

    const-string v0, "width and height must be >= 0"

    invoke-static {v0}, Llyiahf/vczjk/rz3;->OooO00o(Ljava/lang/String;)V

    :cond_7
    invoke-static {p4, p4, p4, p4}, Llyiahf/vczjk/uk1;->OooO0oo(IIII)J

    move-result-wide v0

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    sget v0, Landroidx/compose/material3/OooO0O0;->OooO0Oo:F

    invoke-interface {p1, p3}, Llyiahf/vczjk/f62;->Oooo0o(F)F

    move-result v1

    sub-float/2addr v0, v1

    const/high16 v1, 0x40000000    # 2.0f

    div-float/2addr v0, v1

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    sget v1, Landroidx/compose/material3/OooO0O0;->OooO0OO:F

    sget v2, Landroidx/compose/material3/OooO0O0;->OooO00o:F

    sub-float/2addr v1, v2

    sget v2, Landroidx/compose/material3/OooO0O0;->OooO0o0:F

    sub-float/2addr v1, v2

    invoke-interface {p1, v1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v1

    iget-boolean v2, p0, Llyiahf/vczjk/sr9;->OooOooO:Z

    if-eqz v2, :cond_8

    iget-boolean v3, p0, Llyiahf/vczjk/sr9;->OooOoo0:Z

    if-eqz v3, :cond_8

    sget v0, Llyiahf/vczjk/rc9;->OooOo0:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    sub-float v0, v1, v0

    goto :goto_5

    :cond_8
    if-eqz v2, :cond_9

    iget-boolean v2, p0, Llyiahf/vczjk/sr9;->OooOoo0:Z

    if-nez v2, :cond_9

    sget v0, Llyiahf/vczjk/rc9;->OooOo0:F

    invoke-interface {p1, v0}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v0

    goto :goto_5

    :cond_9
    iget-boolean v2, p0, Llyiahf/vczjk/sr9;->OooOoo0:Z

    if-eqz v2, :cond_a

    move v0, v1

    :cond_a
    :goto_5
    iget-object v1, p0, Llyiahf/vczjk/sr9;->Oooo000:Llyiahf/vczjk/gi;

    const/4 v2, 0x0

    if-eqz v1, :cond_b

    iget-object v1, v1, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Float;

    goto :goto_6

    :cond_b
    move-object v1, v2

    :goto_6
    const/4 v3, 0x3

    if-eqz v1, :cond_c

    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    move-result v1

    cmpl-float v1, v1, p3

    if-nez v1, :cond_c

    goto :goto_7

    :cond_c
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/pr9;

    invoke-direct {v4, p0, p3, v2}, Llyiahf/vczjk/pr9;-><init>(Llyiahf/vczjk/sr9;FLlyiahf/vczjk/yo1;)V

    invoke-static {v1, v2, v2, v4, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_7
    iget-object v1, p0, Llyiahf/vczjk/sr9;->OooOooo:Llyiahf/vczjk/gi;

    if-eqz v1, :cond_d

    iget-object v1, v1, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Float;

    goto :goto_8

    :cond_d
    move-object v1, v2

    :goto_8
    if-eqz v1, :cond_e

    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    move-result v1

    cmpl-float v1, v1, v0

    if-nez v1, :cond_e

    goto :goto_9

    :cond_e
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/qr9;

    invoke-direct {v4, p0, v0, v2}, Llyiahf/vczjk/qr9;-><init>(Llyiahf/vczjk/sr9;FLlyiahf/vczjk/yo1;)V

    invoke-static {v1, v2, v2, v4, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :goto_9
    iget v1, p0, Llyiahf/vczjk/sr9;->Oooo00o:F

    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    move-result v1

    if-eqz v1, :cond_f

    iget v1, p0, Llyiahf/vczjk/sr9;->Oooo00O:F

    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    move-result v1

    if-eqz v1, :cond_f

    iput p3, p0, Llyiahf/vczjk/sr9;->Oooo00o:F

    iput v0, p0, Llyiahf/vczjk/sr9;->Oooo00O:F

    :cond_f
    new-instance p3, Llyiahf/vczjk/or9;

    invoke-direct {p3, p2, p0, v0}, Llyiahf/vczjk/or9;-><init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/sr9;F)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p4, p4, p2, p3}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final o0O0O00()V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/rr9;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/rr9;-><init>(Llyiahf/vczjk/sr9;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
