.class public final Llyiahf/vczjk/gi9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $cursorAnimation:Llyiahf/vczjk/ou1;

.field final synthetic $cursorBrush:Llyiahf/vczjk/ri0;

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $value:Llyiahf/vczjk/gl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ou1;Llyiahf/vczjk/s86;Llyiahf/vczjk/gl9;Llyiahf/vczjk/lx4;Llyiahf/vczjk/ri0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gi9;->$cursorAnimation:Llyiahf/vczjk/ou1;

    iput-object p2, p0, Llyiahf/vczjk/gi9;->$offsetMapping:Llyiahf/vczjk/s86;

    iput-object p3, p0, Llyiahf/vczjk/gi9;->$value:Llyiahf/vczjk/gl9;

    iput-object p4, p0, Llyiahf/vczjk/gi9;->$state:Llyiahf/vczjk/lx4;

    iput-object p5, p0, Llyiahf/vczjk/gi9;->$cursorBrush:Llyiahf/vczjk/ri0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/mm1;

    check-cast v1, Llyiahf/vczjk/to4;

    invoke-virtual {v1}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-object v2, v0, Llyiahf/vczjk/gi9;->$cursorAnimation:Llyiahf/vczjk/ou1;

    iget-object v2, v2, Llyiahf/vczjk/ou1;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast v2, Llyiahf/vczjk/zv8;

    invoke-virtual {v2}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v2

    const/4 v3, 0x0

    cmpg-float v4, v2, v3

    if-nez v4, :cond_0

    goto/16 :goto_b

    :cond_0
    iget-object v4, v0, Llyiahf/vczjk/gi9;->$offsetMapping:Llyiahf/vczjk/s86;

    iget-object v5, v0, Llyiahf/vczjk/gi9;->$value:Llyiahf/vczjk/gl9;

    iget-wide v5, v5, Llyiahf/vczjk/gl9;->OooO0O0:J

    sget v7, Llyiahf/vczjk/gn9;->OooO0OO:I

    const/16 v7, 0x20

    shr-long/2addr v5, v7

    long-to-int v5, v5

    invoke-interface {v4, v5}, Llyiahf/vczjk/s86;->OooOO0(I)I

    move-result v4

    iget-object v5, v0, Llyiahf/vczjk/gi9;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v5}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v5

    if-eqz v5, :cond_1

    iget-object v5, v5, Llyiahf/vczjk/nm9;->OooO00o:Llyiahf/vczjk/mm9;

    if-eqz v5, :cond_1

    invoke-virtual {v5, v4}, Llyiahf/vczjk/mm9;->OooO0OO(I)Llyiahf/vczjk/wj7;

    move-result-object v3

    goto :goto_0

    :cond_1
    new-instance v4, Llyiahf/vczjk/wj7;

    invoke-direct {v4, v3, v3, v3, v3}, Llyiahf/vczjk/wj7;-><init>(FFFF)V

    move-object v3, v4

    :goto_0
    sget v4, Llyiahf/vczjk/ii9;->OooO00o:F

    invoke-virtual {v1, v4}, Llyiahf/vczjk/to4;->Ooooo00(F)F

    move-result v4

    float-to-double v4, v4

    invoke-static {v4, v5}, Ljava/lang/Math;->floor(D)D

    move-result-wide v4

    double-to-float v4, v4

    const/high16 v5, 0x3f800000    # 1.0f

    cmpg-float v6, v4, v5

    if-gez v6, :cond_2

    move v4, v5

    :cond_2
    const/4 v5, 0x2

    int-to-float v6, v5

    div-float v6, v4, v6

    iget v8, v3, Llyiahf/vczjk/wj7;->OooO00o:F

    add-float/2addr v8, v6

    iget-object v1, v1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v9

    shr-long/2addr v9, v7

    long-to-int v9, v9

    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v9

    sub-float/2addr v9, v6

    cmpl-float v10, v8, v9

    if-lez v10, :cond_3

    move v8, v9

    :cond_3
    cmpg-float v9, v8, v6

    if-gez v9, :cond_4

    goto :goto_1

    :cond_4
    move v6, v8

    :goto_1
    float-to-int v8, v4

    rem-int/2addr v8, v5

    const/4 v5, 0x1

    if-ne v8, v5, :cond_5

    float-to-double v8, v6

    invoke-static {v8, v9}, Ljava/lang/Math;->floor(D)D

    move-result-wide v8

    double-to-float v6, v8

    const/high16 v8, 0x3f000000    # 0.5f

    add-float/2addr v6, v8

    goto :goto_2

    :cond_5
    float-to-double v8, v6

    invoke-static {v8, v9}, Ljava/lang/Math;->rint(D)D

    move-result-wide v8

    double-to-float v6, v8

    :goto_2
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v8

    int-to-long v8, v8

    iget v10, v3, Llyiahf/vczjk/wj7;->OooO0O0:F

    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v10

    int-to-long v10, v10

    shl-long/2addr v8, v7

    const-wide v12, 0xffffffffL

    and-long/2addr v10, v12

    or-long v15, v8, v10

    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    int-to-long v8, v6

    iget v3, v3, Llyiahf/vczjk/wj7;->OooO0Oo:F

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v3

    int-to-long v10, v3

    shl-long v6, v8, v7

    and-long v8, v10, v12

    or-long v17, v6, v8

    iget-object v3, v0, Llyiahf/vczjk/gi9;->$cursorBrush:Llyiahf/vczjk/ri0;

    iget-object v6, v1, Llyiahf/vczjk/gq0;->OooOOO0:Llyiahf/vczjk/fq0;

    iget-object v14, v6, Llyiahf/vczjk/fq0;->OooO0OO:Llyiahf/vczjk/eq0;

    iget-object v6, v1, Llyiahf/vczjk/gq0;->OooOOOo:Llyiahf/vczjk/ie;

    if-nez v6, :cond_6

    invoke-static {}, Llyiahf/vczjk/c6a;->OooOOoo()Llyiahf/vczjk/ie;

    move-result-object v6

    invoke-virtual {v6, v5}, Llyiahf/vczjk/ie;->OooOo0o(I)V

    iput-object v6, v1, Llyiahf/vczjk/gq0;->OooOOOo:Llyiahf/vczjk/ie;

    :cond_6
    if-eqz v3, :cond_7

    invoke-interface {v1}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v7

    invoke-virtual {v3, v2, v7, v8, v6}, Llyiahf/vczjk/ri0;->OooO00o(FJLlyiahf/vczjk/ie;)V

    goto :goto_3

    :cond_7
    iget-object v1, v6, Llyiahf/vczjk/ie;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Landroid/graphics/Paint;

    invoke-virtual {v1}, Landroid/graphics/Paint;->getAlpha()I

    move-result v1

    int-to-float v1, v1

    const/high16 v3, 0x437f0000    # 255.0f

    div-float/2addr v1, v3

    cmpg-float v1, v1, v2

    if-nez v1, :cond_8

    goto :goto_3

    :cond_8
    invoke-virtual {v6, v2}, Llyiahf/vczjk/ie;->OooOOO(F)V

    :goto_3
    iget-object v1, v6, Llyiahf/vczjk/ie;->OooO0Oo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/p21;

    const/4 v2, 0x0

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_9

    invoke-virtual {v6, v2}, Llyiahf/vczjk/ie;->OooOOo0(Llyiahf/vczjk/p21;)V

    :cond_9
    iget v1, v6, Llyiahf/vczjk/ie;->OooO00o:I

    const/4 v2, 0x3

    if-ne v1, v2, :cond_a

    goto :goto_4

    :cond_a
    invoke-virtual {v6, v2}, Llyiahf/vczjk/ie;->OooOOOO(I)V

    :goto_4
    iget-object v1, v6, Llyiahf/vczjk/ie;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Landroid/graphics/Paint;

    invoke-virtual {v1}, Landroid/graphics/Paint;->getStrokeWidth()F

    move-result v2

    cmpg-float v2, v2, v4

    if-nez v2, :cond_b

    goto :goto_5

    :cond_b
    invoke-virtual {v6, v4}, Llyiahf/vczjk/ie;->OooOo0O(F)V

    :goto_5
    invoke-virtual {v1}, Landroid/graphics/Paint;->getStrokeMiter()F

    move-result v2

    const/high16 v3, 0x40800000    # 4.0f

    cmpg-float v2, v2, v3

    if-nez v2, :cond_c

    goto :goto_6

    :cond_c
    iget-object v2, v6, Llyiahf/vczjk/ie;->OooO0O0:Ljava/lang/Object;

    check-cast v2, Landroid/graphics/Paint;

    invoke-virtual {v2, v3}, Landroid/graphics/Paint;->setStrokeMiter(F)V

    :goto_6
    invoke-virtual {v6}, Llyiahf/vczjk/ie;->OooOO0()I

    move-result v2

    const/4 v3, 0x0

    if-nez v2, :cond_d

    goto :goto_7

    :cond_d
    invoke-virtual {v6, v3}, Llyiahf/vczjk/ie;->OooOo00(I)V

    :goto_7
    invoke-virtual {v6}, Llyiahf/vczjk/ie;->OooOO0O()I

    move-result v2

    if-nez v2, :cond_e

    goto :goto_8

    :cond_e
    invoke-virtual {v6, v3}, Llyiahf/vczjk/ie;->OooOo0(I)V

    :goto_8
    invoke-virtual {v1}, Landroid/graphics/Paint;->isFilterBitmap()Z

    move-result v1

    if-ne v1, v5, :cond_f

    :goto_9
    move-object/from16 v19, v6

    goto :goto_a

    :cond_f
    invoke-virtual {v6, v5}, Llyiahf/vczjk/ie;->OooOOo(I)V

    goto :goto_9

    :goto_a
    invoke-interface/range {v14 .. v19}, Llyiahf/vczjk/eq0;->OooOo00(JJLlyiahf/vczjk/ie;)V

    :goto_b
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
