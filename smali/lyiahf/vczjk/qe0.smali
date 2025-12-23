.class public final Llyiahf/vczjk/qe0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/re0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/re0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 45

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/tm0;

    iget-object v2, v1, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    iget v2, v2, Llyiahf/vczjk/re0;->OooOooO:F

    invoke-virtual {v0}, Llyiahf/vczjk/tm0;->OooO0O0()F

    move-result v3

    mul-float/2addr v3, v2

    const/4 v2, 0x0

    cmpl-float v3, v3, v2

    if-ltz v3, :cond_19

    iget-object v3, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v3}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v3

    invoke-static {v3, v4}, Llyiahf/vczjk/tq8;->OooO0OO(J)F

    move-result v3

    cmpl-float v3, v3, v2

    if-lez v3, :cond_19

    iget-object v3, v1, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    iget v3, v3, Llyiahf/vczjk/re0;->OooOooO:F

    invoke-static {v3, v2}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v2

    const/high16 v3, 0x3f800000    # 1.0f

    if-eqz v2, :cond_0

    move v2, v3

    goto :goto_0

    :cond_0
    iget-object v2, v1, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    iget v2, v2, Llyiahf/vczjk/re0;->OooOooO:F

    invoke-virtual {v0}, Llyiahf/vczjk/tm0;->OooO0O0()F

    move-result v4

    mul-float/2addr v4, v2

    float-to-double v4, v4

    invoke-static {v4, v5}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v4

    double-to-float v2, v4

    :goto_0
    iget-object v4, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v4}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v4

    invoke-static {v4, v5}, Llyiahf/vczjk/tq8;->OooO0OO(J)F

    move-result v4

    const/4 v5, 0x2

    int-to-float v5, v5

    div-float/2addr v4, v5

    float-to-double v6, v4

    invoke-static {v6, v7}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v6

    double-to-float v4, v6

    invoke-static {v2, v4}, Ljava/lang/Math;->min(FF)F

    move-result v7

    div-float v2, v7, v5

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    int-to-long v8, v4

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v4

    int-to-long v10, v4

    const/16 v4, 0x20

    shl-long/2addr v8, v4

    const-wide v12, 0xffffffffL

    and-long/2addr v10, v12

    or-long v14, v8, v10

    iget-object v6, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v6}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v8

    shr-long/2addr v8, v4

    long-to-int v6, v8

    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v6

    sub-float/2addr v6, v7

    iget-object v8, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v8}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v8

    and-long/2addr v8, v12

    long-to-int v8, v8

    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v8

    sub-float/2addr v8, v7

    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    int-to-long v9, v6

    invoke-static {v8}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    move/from16 p1, v4

    move v8, v5

    int-to-long v4, v6

    shl-long v9, v9, p1

    and-long/2addr v4, v12

    or-long/2addr v4, v9

    mul-float v17, v7, v8

    iget-object v6, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v6}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v8

    invoke-static {v8, v9}, Llyiahf/vczjk/tq8;->OooO0OO(J)F

    move-result v6

    cmpl-float v6, v17, v6

    const/4 v9, 0x0

    if-lez v6, :cond_1

    const/16 v16, 0x1

    goto :goto_1

    :cond_1
    move/from16 v16, v9

    :goto_1
    iget-object v6, v1, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    iget-object v6, v6, Llyiahf/vczjk/re0;->Oooo000:Llyiahf/vczjk/qj8;

    iget-object v10, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v10}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v10

    move-wide/from16 v22, v12

    iget-object v12, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v12}, Llyiahf/vczjk/qj0;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v12

    invoke-interface {v6, v10, v11, v12, v0}, Llyiahf/vczjk/qj8;->OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;

    move-result-object v6

    instance-of v10, v6, Llyiahf/vczjk/of6;

    if-eqz v10, :cond_f

    iget-object v2, v1, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    iget-object v12, v2, Llyiahf/vczjk/re0;->OooOooo:Llyiahf/vczjk/gx8;

    check-cast v6, Llyiahf/vczjk/of6;

    if-eqz v16, :cond_2

    new-instance v2, Llyiahf/vczjk/me0;

    invoke-direct {v2, v6, v12}, Llyiahf/vczjk/me0;-><init>(Llyiahf/vczjk/of6;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v0

    return-object v0

    :cond_2
    if-eqz v12, :cond_3

    iget-wide v10, v12, Llyiahf/vczjk/gx8;->OooO00o:J

    invoke-static {v3, v10, v11}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v10

    new-instance v3, Llyiahf/vczjk/fd0;

    const/4 v5, 0x5

    invoke-direct {v3, v5, v10, v11}, Llyiahf/vczjk/fd0;-><init>(IJ)V

    move-object/from16 v29, v3

    const/4 v3, 0x1

    goto :goto_2

    :cond_3
    move v3, v9

    const/16 v29, 0x0

    :goto_2
    iget-object v5, v6, Llyiahf/vczjk/of6;->OooO:Llyiahf/vczjk/qe;

    invoke-virtual {v5}, Llyiahf/vczjk/qe;->OooO0Oo()Llyiahf/vczjk/wj7;

    move-result-object v7

    iget-object v10, v2, Llyiahf/vczjk/re0;->OooOoo:Llyiahf/vczjk/ie0;

    if-nez v10, :cond_4

    new-instance v10, Llyiahf/vczjk/ie0;

    invoke-direct {v10}, Llyiahf/vczjk/ie0;-><init>()V

    iput-object v10, v2, Llyiahf/vczjk/re0;->OooOoo:Llyiahf/vczjk/ie0;

    :cond_4
    iget-object v10, v2, Llyiahf/vczjk/re0;->OooOoo:Llyiahf/vczjk/ie0;

    invoke-static {v10}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v11, v10, Llyiahf/vczjk/ie0;->OooO0Oo:Llyiahf/vczjk/qe;

    if-nez v11, :cond_5

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v11

    iput-object v11, v10, Llyiahf/vczjk/ie0;->OooO0Oo:Llyiahf/vczjk/qe;

    :cond_5
    move-object v10, v11

    invoke-virtual {v10}, Llyiahf/vczjk/qe;->OooO0oo()V

    invoke-static {v10, v7}, Llyiahf/vczjk/bq6;->OooO00o(Llyiahf/vczjk/bq6;Llyiahf/vczjk/wj7;)V

    invoke-virtual {v10, v10, v5, v9}, Llyiahf/vczjk/qe;->OooO0oO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/bq6;I)Z

    new-instance v5, Llyiahf/vczjk/hl7;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    iget v11, v7, Llyiahf/vczjk/wj7;->OooO0OO:F

    iget v13, v7, Llyiahf/vczjk/wj7;->OooO00o:F

    sub-float/2addr v11, v13

    float-to-double v14, v11

    invoke-static {v14, v15}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v14

    double-to-float v11, v14

    float-to-int v11, v11

    iget v14, v7, Llyiahf/vczjk/wj7;->OooO0Oo:F

    iget v15, v7, Llyiahf/vczjk/wj7;->OooO0O0:F

    sub-float/2addr v14, v15

    move-object/from16 v24, v10

    float-to-double v9, v14

    invoke-static {v9, v10}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v9

    double-to-float v9, v9

    float-to-int v9, v9

    int-to-long v10, v11

    shl-long v10, v10, p1

    move-object/from16 v26, v5

    int-to-long v4, v9

    and-long v4, v4, v22

    or-long v27, v10, v4

    iget-object v2, v2, Llyiahf/vczjk/re0;->OooOoo:Llyiahf/vczjk/ie0;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v4, v2, Llyiahf/vczjk/ie0;->OooO00o:Llyiahf/vczjk/kd;

    iget-object v5, v2, Llyiahf/vczjk/ie0;->OooO0O0:Llyiahf/vczjk/s9;

    if-eqz v4, :cond_6

    invoke-virtual {v4}, Llyiahf/vczjk/kd;->OooO00o()I

    move-result v9

    new-instance v10, Llyiahf/vczjk/mu3;

    invoke-direct {v10, v9}, Llyiahf/vczjk/mu3;-><init>(I)V

    goto :goto_3

    :cond_6
    const/4 v10, 0x0

    :goto_3
    if-nez v10, :cond_7

    goto :goto_4

    :cond_7
    iget v9, v10, Llyiahf/vczjk/mu3;->OooO00o:I

    if-nez v9, :cond_8

    goto :goto_7

    :cond_8
    :goto_4
    if-eqz v4, :cond_9

    invoke-virtual {v4}, Llyiahf/vczjk/kd;->OooO00o()I

    move-result v9

    new-instance v10, Llyiahf/vczjk/mu3;

    invoke-direct {v10, v9}, Llyiahf/vczjk/mu3;-><init>(I)V

    move-object v14, v10

    goto :goto_5

    :cond_9
    const/4 v14, 0x0

    :goto_5
    if-nez v14, :cond_a

    goto :goto_6

    :cond_a
    iget v9, v14, Llyiahf/vczjk/mu3;->OooO00o:I

    if-eq v3, v9, :cond_b

    :goto_6
    const/4 v9, 0x0

    goto :goto_8

    :cond_b
    :goto_7
    const/4 v9, 0x1

    :goto_8
    if-eqz v4, :cond_c

    if-eqz v5, :cond_c

    iget-object v10, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v10}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v10

    shr-long v10, v10, p1

    long-to-int v10, v10

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v10

    iget-object v11, v4, Llyiahf/vczjk/kd;->OooO00o:Landroid/graphics/Bitmap;

    invoke-virtual {v11}, Landroid/graphics/Bitmap;->getWidth()I

    move-result v14

    int-to-float v14, v14

    cmpl-float v10, v10, v14

    if-gtz v10, :cond_c

    iget-object v10, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v10}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v18

    move v10, v9

    and-long v8, v18, v22

    long-to-int v8, v8

    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v8

    invoke-virtual {v11}, Landroid/graphics/Bitmap;->getHeight()I

    move-result v9

    int-to-float v9, v9

    cmpl-float v8, v8, v9

    if-gtz v8, :cond_c

    if-nez v10, :cond_d

    :cond_c
    shr-long v4, v27, p1

    long-to-int v4, v4

    and-long v8, v27, v22

    long-to-int v5, v8

    invoke-static {v4, v5, v3}, Llyiahf/vczjk/os9;->OooOO0(III)Llyiahf/vczjk/kd;

    move-result-object v4

    iput-object v4, v2, Llyiahf/vczjk/ie0;->OooO00o:Llyiahf/vczjk/kd;

    invoke-static {v4}, Llyiahf/vczjk/e16;->OooO00o(Llyiahf/vczjk/kd;)Llyiahf/vczjk/s9;

    move-result-object v5

    iput-object v5, v2, Llyiahf/vczjk/ie0;->OooO0O0:Llyiahf/vczjk/s9;

    :cond_d
    iget-object v3, v2, Llyiahf/vczjk/ie0;->OooO0OO:Llyiahf/vczjk/gq0;

    if-nez v3, :cond_e

    new-instance v3, Llyiahf/vczjk/gq0;

    invoke-direct {v3}, Llyiahf/vczjk/gq0;-><init>()V

    iput-object v3, v2, Llyiahf/vczjk/ie0;->OooO0OO:Llyiahf/vczjk/gq0;

    :cond_e
    move-object v10, v3

    invoke-static/range {v27 .. v28}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v2

    iget-object v8, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v8}, Llyiahf/vczjk/qj0;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v8

    iget-object v9, v10, Llyiahf/vczjk/gq0;->OooOOO0:Llyiahf/vczjk/fq0;

    iget-object v11, v9, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iget-object v14, v9, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    move-object/from16 v41, v7

    iget-object v7, v9, Llyiahf/vczjk/fq0;->OooO0OO:Llyiahf/vczjk/eq0;

    move-object/from16 v30, v10

    move-object/from16 v42, v11

    iget-wide v10, v9, Llyiahf/vczjk/fq0;->OooO0Oo:J

    iput-object v0, v9, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iput-object v8, v9, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    iput-object v5, v9, Llyiahf/vczjk/fq0;->OooO0OO:Llyiahf/vczjk/eq0;

    iput-wide v2, v9, Llyiahf/vczjk/fq0;->OooO0Oo:J

    invoke-virtual {v5}, Llyiahf/vczjk/s9;->OooO0oO()V

    sget-wide v31, Llyiahf/vczjk/n21;->OooO0O0:J

    const/16 v38, 0x0

    const/16 v40, 0x3a

    const-wide/16 v33, 0x0

    const/16 v37, 0x0

    const/16 v39, 0x0

    move-wide/from16 v35, v2

    invoke-static/range {v30 .. v40}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    move-object/from16 v3, v30

    neg-float v2, v13

    neg-float v8, v15

    iget-object v13, v3, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v15, v13, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/vz5;

    invoke-virtual {v15, v2, v8}, Llyiahf/vczjk/vz5;->OooOOo(FF)V

    :try_start_0
    iget-object v6, v6, Llyiahf/vczjk/of6;->OooO:Llyiahf/vczjk/qe;

    new-instance v16, Llyiahf/vczjk/h79;

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x1e

    const/16 v18, 0x0

    invoke-direct/range {v16 .. v21}, Llyiahf/vczjk/h79;-><init>(FFIII)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_4

    const/16 v15, 0x34

    move-object/from16 v17, v13

    const/4 v13, 0x0

    move-object/from16 v19, v0

    move-wide v0, v10

    move-object v10, v3

    move-object v11, v6

    move-object v6, v14

    move-object/from16 v14, v16

    move-object/from16 v3, v42

    :try_start_1
    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/hg2;->OoooOOO(Llyiahf/vczjk/hg2;Llyiahf/vczjk/bq6;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/h79;I)V

    move-object/from16 v30, v10

    invoke-interface/range {v30 .. v30}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v10

    shr-long v10, v10, p1

    long-to-int v10, v10

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v10

    const/4 v11, 0x1

    int-to-float v11, v11

    add-float/2addr v10, v11

    invoke-interface/range {v30 .. v30}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v13

    shr-long v13, v13, p1

    long-to-int v13, v13

    invoke-static {v13}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v13

    div-float/2addr v10, v13

    invoke-interface/range {v30 .. v30}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v13

    and-long v13, v13, v22

    long-to-int v13, v13

    invoke-static {v13}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v13

    add-float/2addr v13, v11

    invoke-interface/range {v30 .. v30}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v14

    and-long v14, v14, v22

    long-to-int v11, v14

    invoke-static {v11}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v11

    div-float/2addr v13, v11

    invoke-interface/range {v30 .. v30}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v14

    move-object/from16 v16, v4

    move-object/from16 v18, v5

    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v4

    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v11

    invoke-interface {v11}, Llyiahf/vczjk/eq0;->OooO0oO()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    move-object/from16 p1, v12

    move-object/from16 v11, v17

    :try_start_2
    iget-object v12, v11, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/vz5;

    invoke-virtual {v12, v10, v13, v14, v15}, Llyiahf/vczjk/vz5;->OooOOo0(FFJ)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_3

    const/16 v15, 0x1c

    const/4 v13, 0x0

    const/4 v14, 0x0

    move-object/from16 v12, p1

    move-object/from16 v17, v11

    move-object/from16 v11, v24

    move-object/from16 v10, v30

    :try_start_3
    invoke-static/range {v10 .. v15}, Llyiahf/vczjk/hg2;->OoooOOO(Llyiahf/vczjk/hg2;Llyiahf/vczjk/bq6;Llyiahf/vczjk/ri0;FLlyiahf/vczjk/h79;I)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    :try_start_4
    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v10

    invoke-interface {v10}, Llyiahf/vczjk/eq0;->OooOOo0()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    move-object/from16 v11, v17

    :try_start_5
    invoke-virtual {v11, v4, v5}, Llyiahf/vczjk/uqa;->Oooo0(J)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    iget-object v4, v11, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/vz5;

    neg-float v2, v2

    neg-float v5, v8

    invoke-virtual {v4, v2, v5}, Llyiahf/vczjk/vz5;->OooOOo(FF)V

    invoke-virtual/range {v18 .. v18}, Llyiahf/vczjk/s9;->OooOOo0()V

    iput-object v3, v9, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iput-object v6, v9, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    iput-object v7, v9, Llyiahf/vczjk/fq0;->OooO0OO:Llyiahf/vczjk/eq0;

    iput-wide v0, v9, Llyiahf/vczjk/fq0;->OooO0Oo:J

    move-object/from16 v4, v16

    iget-object v0, v4, Llyiahf/vczjk/kd;->OooO00o:Landroid/graphics/Bitmap;

    invoke-virtual {v0}, Landroid/graphics/Bitmap;->prepareToDraw()V

    move-object/from16 v0, v26

    iput-object v4, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    new-instance v24, Llyiahf/vczjk/ne0;

    move-object/from16 v26, v0

    move-object/from16 v25, v41

    invoke-direct/range {v24 .. v29}, Llyiahf/vczjk/ne0;-><init>(Llyiahf/vczjk/wj7;Llyiahf/vczjk/hl7;JLlyiahf/vczjk/fd0;)V

    move-object/from16 v0, v19

    move-object/from16 v1, v24

    invoke-virtual {v0, v1}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v0

    return-object v0

    :catchall_0
    move-exception v0

    goto :goto_a

    :catchall_1
    move-exception v0

    move-object/from16 v11, v17

    goto :goto_a

    :catchall_2
    move-exception v0

    move-object/from16 v11, v17

    goto :goto_9

    :catchall_3
    move-exception v0

    :goto_9
    :try_start_6
    invoke-virtual {v11}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/eq0;->OooOOo0()V

    invoke-virtual {v11, v4, v5}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    :catchall_4
    move-exception v0

    move-object v11, v13

    :goto_a
    iget-object v1, v11, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/vz5;

    neg-float v2, v2

    neg-float v3, v8

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/vz5;->OooOOo(FF)V

    throw v0

    :cond_f
    instance-of v1, v6, Llyiahf/vczjk/qf6;

    if-eqz v1, :cond_14

    move-object/from16 v1, p0

    iget-object v3, v1, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    iget-object v12, v3, Llyiahf/vczjk/re0;->OooOooo:Llyiahf/vczjk/gx8;

    check-cast v6, Llyiahf/vczjk/qf6;

    iget-object v13, v6, Llyiahf/vczjk/qf6;->OooO:Llyiahf/vczjk/nv7;

    invoke-static {v13}, Llyiahf/vczjk/tn6;->OooOOOO(Llyiahf/vczjk/nv7;)Z

    move-result v6

    if-eqz v6, :cond_10

    new-instance v17, Llyiahf/vczjk/h79;

    const/4 v9, 0x0

    const/16 v11, 0x1e

    const/4 v8, 0x0

    const/4 v10, 0x0

    move-object/from16 v6, v17

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    new-instance v6, Llyiahf/vczjk/oe0;

    iget-wide v9, v13, Llyiahf/vczjk/nv7;->OooO0o0:J

    move v11, v2

    move-object v8, v12

    move-wide v13, v14

    move v12, v7

    move/from16 v7, v16

    move-wide v15, v4

    invoke-direct/range {v6 .. v17}, Llyiahf/vczjk/oe0;-><init>(ZLlyiahf/vczjk/gx8;JFFJJLlyiahf/vczjk/h79;)V

    invoke-virtual {v0, v6}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v0

    return-object v0

    :cond_10
    move-object v2, v12

    move/from16 v8, v16

    iget-object v4, v3, Llyiahf/vczjk/re0;->OooOoo:Llyiahf/vczjk/ie0;

    if-nez v4, :cond_11

    new-instance v4, Llyiahf/vczjk/ie0;

    invoke-direct {v4}, Llyiahf/vczjk/ie0;-><init>()V

    iput-object v4, v3, Llyiahf/vczjk/re0;->OooOoo:Llyiahf/vczjk/ie0;

    :cond_11
    iget-object v3, v3, Llyiahf/vczjk/re0;->OooOoo:Llyiahf/vczjk/ie0;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v4, v3, Llyiahf/vczjk/ie0;->OooO0Oo:Llyiahf/vczjk/qe;

    if-nez v4, :cond_12

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v4

    iput-object v4, v3, Llyiahf/vczjk/ie0;->OooO0Oo:Llyiahf/vczjk/qe;

    :cond_12
    invoke-virtual {v4}, Llyiahf/vczjk/qe;->OooO0oo()V

    invoke-static {v4, v13}, Llyiahf/vczjk/bq6;->OooO0O0(Llyiahf/vczjk/bq6;Llyiahf/vczjk/nv7;)V

    if-nez v8, :cond_13

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v3

    invoke-virtual {v13}, Llyiahf/vczjk/nv7;->OooO0O0()F

    move-result v5

    sub-float v9, v5, v7

    invoke-virtual {v13}, Llyiahf/vczjk/nv7;->OooO00o()F

    move-result v5

    sub-float v10, v5, v7

    iget-wide v5, v13, Llyiahf/vczjk/nv7;->OooO0o0:J

    invoke-static {v7, v5, v6}, Llyiahf/vczjk/e16;->Oooo0o0(FJ)J

    move-result-wide v11

    iget-wide v5, v13, Llyiahf/vczjk/nv7;->OooO0o:J

    invoke-static {v7, v5, v6}, Llyiahf/vczjk/e16;->Oooo0o0(FJ)J

    move-result-wide v5

    iget-wide v14, v13, Llyiahf/vczjk/nv7;->OooO0oo:J

    invoke-static {v7, v14, v15}, Llyiahf/vczjk/e16;->Oooo0o0(FJ)J

    move-result-wide v14

    move-wide/from16 v16, v5

    iget-wide v5, v13, Llyiahf/vczjk/nv7;->OooO0oO:J

    invoke-static {v7, v5, v6}, Llyiahf/vczjk/e16;->Oooo0o0(FJ)J

    move-result-wide v5

    move-wide/from16 v43, v16

    move-wide/from16 v17, v14

    move-wide/from16 v13, v43

    move-wide v15, v5

    const/4 v5, 0x0

    new-instance v6, Llyiahf/vczjk/nv7;

    move v8, v7

    invoke-direct/range {v6 .. v18}, Llyiahf/vczjk/nv7;-><init>(FFFFJJJJ)V

    invoke-static {v3, v6}, Llyiahf/vczjk/bq6;->OooO0O0(Llyiahf/vczjk/bq6;Llyiahf/vczjk/nv7;)V

    invoke-virtual {v4, v4, v3, v5}, Llyiahf/vczjk/qe;->OooO0oO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/bq6;I)Z

    :cond_13
    new-instance v3, Llyiahf/vczjk/pe0;

    invoke-direct {v3, v4, v2}, Llyiahf/vczjk/pe0;-><init>(Llyiahf/vczjk/qe;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v0

    return-object v0

    :cond_14
    move-object/from16 v1, p0

    move-wide v13, v14

    move/from16 v8, v16

    move-wide v15, v4

    instance-of v2, v6, Llyiahf/vczjk/pf6;

    if-eqz v2, :cond_18

    iget-object v2, v1, Llyiahf/vczjk/qe0;->this$0:Llyiahf/vczjk/re0;

    iget-object v2, v2, Llyiahf/vczjk/re0;->OooOooo:Llyiahf/vczjk/gx8;

    if-eqz v8, :cond_15

    const-wide/16 v3, 0x0

    move-wide/from16 v19, v3

    goto :goto_b

    :cond_15
    move-wide/from16 v19, v13

    :goto_b
    if-eqz v8, :cond_16

    iget-object v3, v0, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v3}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v4

    move-wide/from16 v21, v4

    goto :goto_c

    :cond_16
    move-wide/from16 v21, v15

    :goto_c
    if-eqz v8, :cond_17

    sget-object v3, Llyiahf/vczjk/i03;->OooO00o:Llyiahf/vczjk/i03;

    move-object/from16 v23, v3

    goto :goto_d

    :cond_17
    new-instance v6, Llyiahf/vczjk/h79;

    const/4 v9, 0x0

    const/16 v11, 0x1e

    const/4 v8, 0x0

    const/4 v10, 0x0

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    move-object/from16 v23, v6

    :goto_d
    new-instance v17, Llyiahf/vczjk/le0;

    move-object/from16 v18, v2

    invoke-direct/range {v17 .. v23}, Llyiahf/vczjk/le0;-><init>(Llyiahf/vczjk/gx8;JJLlyiahf/vczjk/ig2;)V

    move-object/from16 v2, v17

    invoke-virtual {v0, v2}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v0

    return-object v0

    :cond_18
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :cond_19
    sget-object v2, Llyiahf/vczjk/ke0;->OooOOO:Llyiahf/vczjk/ke0;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object v0

    return-object v0
.end method
