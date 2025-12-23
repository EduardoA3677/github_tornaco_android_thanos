.class public final Llyiahf/vczjk/ej3;
.super Llyiahf/vczjk/y80;
.source "SourceFile"


# instance fields
.field public final OooOOo:Z

.field public final OooOOo0:Ljava/lang/String;

.field public final OooOOoo:Llyiahf/vczjk/i65;

.field public final OooOo:Llyiahf/vczjk/xi3;

.field public final OooOo0:Landroid/graphics/RectF;

.field public final OooOo00:Llyiahf/vczjk/i65;

.field public final OooOo0O:I

.field public final OooOo0o:I

.field public final OooOoO:Llyiahf/vczjk/xi3;

.field public final OooOoO0:Llyiahf/vczjk/xi3;

.field public OooOoOO:Llyiahf/vczjk/bca;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Llyiahf/vczjk/dj3;)V
    .locals 11

    iget v0, p3, Llyiahf/vczjk/dj3;->OooO0oo:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    if-eq v0, v1, :cond_0

    sget-object v0, Landroid/graphics/Paint$Cap;->SQUARE:Landroid/graphics/Paint$Cap;

    :goto_0
    move-object v3, v0

    goto :goto_1

    :cond_0
    sget-object v0, Landroid/graphics/Paint$Cap;->ROUND:Landroid/graphics/Paint$Cap;

    goto :goto_0

    :cond_1
    sget-object v0, Landroid/graphics/Paint$Cap;->BUTT:Landroid/graphics/Paint$Cap;

    goto :goto_0

    :goto_1
    iget v0, p3, Llyiahf/vczjk/dj3;->OooO:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    const/4 v10, 0x0

    if-eqz v0, :cond_4

    if-eq v0, v1, :cond_3

    const/4 v1, 0x2

    if-eq v0, v1, :cond_2

    move-object v4, v10

    goto :goto_3

    :cond_2
    sget-object v0, Landroid/graphics/Paint$Join;->BEVEL:Landroid/graphics/Paint$Join;

    :goto_2
    move-object v4, v0

    goto :goto_3

    :cond_3
    sget-object v0, Landroid/graphics/Paint$Join;->ROUND:Landroid/graphics/Paint$Join;

    goto :goto_2

    :cond_4
    sget-object v0, Landroid/graphics/Paint$Join;->MITER:Landroid/graphics/Paint$Join;

    goto :goto_2

    :goto_3
    iget-object v6, p3, Llyiahf/vczjk/dj3;->OooO0Oo:Llyiahf/vczjk/hi;

    iget-object v8, p3, Llyiahf/vczjk/dj3;->OooOO0O:Ljava/util/ArrayList;

    iget-object v9, p3, Llyiahf/vczjk/dj3;->OooOO0o:Llyiahf/vczjk/ii;

    iget v5, p3, Llyiahf/vczjk/dj3;->OooOO0:F

    iget-object v7, p3, Llyiahf/vczjk/dj3;->OooO0oO:Llyiahf/vczjk/ii;

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/y80;-><init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Landroid/graphics/Paint$Cap;Landroid/graphics/Paint$Join;FLlyiahf/vczjk/hi;Llyiahf/vczjk/ii;Ljava/util/ArrayList;Llyiahf/vczjk/ii;)V

    new-instance v1, Llyiahf/vczjk/i65;

    invoke-direct {v1, v10}, Llyiahf/vczjk/i65;-><init>(Ljava/lang/Object;)V

    iput-object v1, p0, Llyiahf/vczjk/ej3;->OooOOoo:Llyiahf/vczjk/i65;

    new-instance v1, Llyiahf/vczjk/i65;

    invoke-direct {v1, v10}, Llyiahf/vczjk/i65;-><init>(Ljava/lang/Object;)V

    iput-object v1, p0, Llyiahf/vczjk/ej3;->OooOo00:Llyiahf/vczjk/i65;

    new-instance v1, Landroid/graphics/RectF;

    invoke-direct {v1}, Landroid/graphics/RectF;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/ej3;->OooOo0:Landroid/graphics/RectF;

    iget-object v1, p3, Llyiahf/vczjk/dj3;->OooO00o:Ljava/lang/String;

    iput-object v1, p0, Llyiahf/vczjk/ej3;->OooOOo0:Ljava/lang/String;

    iget v1, p3, Llyiahf/vczjk/dj3;->OooO0O0:I

    iput v1, p0, Llyiahf/vczjk/ej3;->OooOo0O:I

    iget-boolean v1, p3, Llyiahf/vczjk/dj3;->OooOOO0:Z

    iput-boolean v1, p0, Llyiahf/vczjk/ej3;->OooOOo:Z

    iget-object v1, p1, Llyiahf/vczjk/v85;->OooOOO0:Llyiahf/vczjk/z75;

    invoke-virtual {v1}, Llyiahf/vczjk/z75;->OooO0O0()F

    move-result v1

    const/high16 v3, 0x42000000    # 32.0f

    div-float/2addr v1, v3

    float-to-int v1, v1

    iput v1, p0, Llyiahf/vczjk/ej3;->OooOo0o:I

    iget-object v1, p3, Llyiahf/vczjk/dj3;->OooO0OO:Llyiahf/vczjk/hi;

    invoke-virtual {v1}, Llyiahf/vczjk/hi;->o0OOO0o()Llyiahf/vczjk/d80;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/xi3;

    iput-object v3, p0, Llyiahf/vczjk/ej3;->OooOo:Llyiahf/vczjk/xi3;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    iget-object v1, p3, Llyiahf/vczjk/dj3;->OooO0o0:Llyiahf/vczjk/hi;

    invoke-virtual {v1}, Llyiahf/vczjk/hi;->o0OOO0o()Llyiahf/vczjk/d80;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/xi3;

    iput-object v3, p0, Llyiahf/vczjk/ej3;->OooOoO0:Llyiahf/vczjk/xi3;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    iget-object v1, p3, Llyiahf/vczjk/dj3;->OooO0o:Llyiahf/vczjk/hi;

    invoke-virtual {v1}, Llyiahf/vczjk/hi;->o0OOO0o()Llyiahf/vczjk/d80;

    move-result-object v1

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/xi3;

    iput-object v3, p0, Llyiahf/vczjk/ej3;->OooOoO:Llyiahf/vczjk/xi3;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    return-void
.end method


# virtual methods
.method public final OooO()I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ej3;->OooOoO0:Llyiahf/vczjk/xi3;

    iget v0, v0, Llyiahf/vczjk/d80;->OooO0Oo:F

    iget v1, p0, Llyiahf/vczjk/ej3;->OooOo0o:I

    int-to-float v1, v1

    mul-float/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Math;->round(F)I

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/ej3;->OooOoO:Llyiahf/vczjk/xi3;

    iget v2, v2, Llyiahf/vczjk/d80;->OooO0Oo:F

    mul-float/2addr v2, v1

    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/ej3;->OooOo:Llyiahf/vczjk/xi3;

    iget v3, v3, Llyiahf/vczjk/d80;->OooO0Oo:F

    mul-float/2addr v3, v1

    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    move-result v1

    if-eqz v0, :cond_0

    const/16 v3, 0x20f

    mul-int/2addr v3, v0

    goto :goto_0

    :cond_0
    const/16 v3, 0x11

    :goto_0
    if-eqz v2, :cond_1

    mul-int/lit8 v3, v3, 0x1f

    mul-int/2addr v3, v2

    :cond_1
    if-eqz v1, :cond_2

    mul-int/lit8 v3, v3, 0x1f

    mul-int/2addr v3, v1

    :cond_2
    return v3
.end method

.method public final OooO0OO(Landroid/graphics/ColorFilter;Llyiahf/vczjk/n62;)V
    .locals 2

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/y80;->OooO0OO(Landroid/graphics/ColorFilter;Llyiahf/vczjk/n62;)V

    sget-object v0, Llyiahf/vczjk/c95;->Oooo00O:[Ljava/lang/Integer;

    if-ne p1, v0, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/ej3;->OooOoOO:Llyiahf/vczjk/bca;

    iget-object v0, p0, Llyiahf/vczjk/y80;->OooO0o:Llyiahf/vczjk/f80;

    if-eqz p1, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/f80;->OooOOOO(Llyiahf/vczjk/d80;)V

    :cond_0
    new-instance p1, Llyiahf/vczjk/bca;

    const/4 v1, 0x0

    invoke-direct {p1, p2, v1}, Llyiahf/vczjk/bca;-><init>(Llyiahf/vczjk/n62;Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/ej3;->OooOoOO:Llyiahf/vczjk/bca;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    iget-object p1, p0, Llyiahf/vczjk/ej3;->OooOoOO:Llyiahf/vczjk/bca;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    :cond_1
    return-void
.end method

.method public final OooO0o(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILlyiahf/vczjk/bj2;)V
    .locals 17

    move-object/from16 v0, p0

    iget-boolean v1, v0, Llyiahf/vczjk/ej3;->OooOOo:Z

    if-eqz v1, :cond_0

    return-void

    :cond_0
    iget-object v1, v0, Llyiahf/vczjk/ej3;->OooOo0:Landroid/graphics/RectF;

    const/4 v2, 0x0

    move-object/from16 v3, p2

    invoke-virtual {v0, v1, v3, v2}, Llyiahf/vczjk/y80;->OooO0Oo(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    iget v1, v0, Llyiahf/vczjk/ej3;->OooOo0O:I

    const/4 v2, 0x1

    iget-object v4, v0, Llyiahf/vczjk/ej3;->OooOo:Llyiahf/vczjk/xi3;

    iget-object v5, v0, Llyiahf/vczjk/ej3;->OooOoO:Llyiahf/vczjk/xi3;

    iget-object v6, v0, Llyiahf/vczjk/ej3;->OooOoO0:Llyiahf/vczjk/xi3;

    if-ne v1, v2, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/ej3;->OooO()I

    move-result v1

    int-to-long v1, v1

    iget-object v7, v0, Llyiahf/vczjk/ej3;->OooOOoo:Llyiahf/vczjk/i65;

    invoke-virtual {v7, v1, v2}, Llyiahf/vczjk/i65;->OooO0O0(J)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Landroid/graphics/LinearGradient;

    if-eqz v8, :cond_1

    goto/16 :goto_1

    :cond_1
    invoke-virtual {v6}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/graphics/PointF;

    invoke-virtual {v5}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/graphics/PointF;

    invoke-virtual {v4}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/wi3;

    iget-object v8, v4, Llyiahf/vczjk/wi3;->OooO0O0:[I

    invoke-virtual {v0, v8}, Llyiahf/vczjk/ej3;->OooO0o0([I)[I

    move-result-object v14

    iget v10, v6, Landroid/graphics/PointF;->x:F

    iget v11, v6, Landroid/graphics/PointF;->y:F

    iget v12, v5, Landroid/graphics/PointF;->x:F

    iget v13, v5, Landroid/graphics/PointF;->y:F

    new-instance v9, Landroid/graphics/LinearGradient;

    sget-object v16, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    iget-object v15, v4, Llyiahf/vczjk/wi3;->OooO00o:[F

    invoke-direct/range {v9 .. v16}, Landroid/graphics/LinearGradient;-><init>(FFFF[I[FLandroid/graphics/Shader$TileMode;)V

    invoke-virtual {v7, v1, v2, v9}, Llyiahf/vczjk/i65;->OooO0o0(JLjava/lang/Object;)V

    :goto_0
    move-object v8, v9

    goto :goto_1

    :cond_2
    invoke-virtual {v0}, Llyiahf/vczjk/ej3;->OooO()I

    move-result v1

    int-to-long v1, v1

    iget-object v7, v0, Llyiahf/vczjk/ej3;->OooOo00:Llyiahf/vczjk/i65;

    invoke-virtual {v7, v1, v2}, Llyiahf/vczjk/i65;->OooO0O0(J)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Landroid/graphics/RadialGradient;

    if-eqz v8, :cond_3

    goto :goto_1

    :cond_3
    invoke-virtual {v6}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/graphics/PointF;

    invoke-virtual {v5}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/graphics/PointF;

    invoke-virtual {v4}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/wi3;

    iget-object v8, v4, Llyiahf/vczjk/wi3;->OooO0O0:[I

    invoke-virtual {v0, v8}, Llyiahf/vczjk/ej3;->OooO0o0([I)[I

    move-result-object v13

    iget v10, v6, Landroid/graphics/PointF;->x:F

    iget v11, v6, Landroid/graphics/PointF;->y:F

    iget v6, v5, Landroid/graphics/PointF;->x:F

    iget v5, v5, Landroid/graphics/PointF;->y:F

    sub-float/2addr v6, v10

    float-to-double v8, v6

    sub-float/2addr v5, v11

    float-to-double v5, v5

    invoke-static {v8, v9, v5, v6}, Ljava/lang/Math;->hypot(DD)D

    move-result-wide v5

    double-to-float v12, v5

    new-instance v9, Landroid/graphics/RadialGradient;

    sget-object v15, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    iget-object v14, v4, Llyiahf/vczjk/wi3;->OooO00o:[F

    invoke-direct/range {v9 .. v15}, Landroid/graphics/RadialGradient;-><init>(FFF[I[FLandroid/graphics/Shader$TileMode;)V

    invoke-virtual {v7, v1, v2, v9}, Llyiahf/vczjk/i65;->OooO0o0(JLjava/lang/Object;)V

    goto :goto_0

    :goto_1
    iget-object v1, v0, Llyiahf/vczjk/y80;->OooO:Llyiahf/vczjk/jl4;

    invoke-virtual {v1, v8}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    invoke-super/range {p0 .. p4}, Llyiahf/vczjk/y80;->OooO0o(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILlyiahf/vczjk/bj2;)V

    return-void
.end method

.method public final OooO0o0([I)[I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/ej3;->OooOoOO:Llyiahf/vczjk/bca;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/bca;->OooO0o0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, [Ljava/lang/Integer;

    array-length v1, p1

    array-length v2, v0

    const/4 v3, 0x0

    if-ne v1, v2, :cond_0

    :goto_0
    array-length v1, p1

    if-ge v3, v1, :cond_1

    aget-object v1, v0, v3

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    aput v1, p1, v3

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    array-length p1, v0

    new-array p1, p1, [I

    :goto_1
    array-length v1, v0

    if-ge v3, v1, :cond_1

    aget-object v1, v0, v3

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result v1

    aput v1, p1, v3

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_1
    return-object p1
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ej3;->OooOOo0:Ljava/lang/String;

    return-object v0
.end method
