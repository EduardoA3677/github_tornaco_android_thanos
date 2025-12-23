.class public abstract Llyiahf/vczjk/vp;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F

.field public static final OooO0O0:F

.field public static final OooO0OO:Llyiahf/vczjk/r13;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    const/16 v0, 0x38

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/vp;->OooO00o:F

    const/4 v0, 0x4

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/vp;->OooO0O0:F

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v2, 0x10

    int-to-float v2, v2

    sub-float/2addr v2, v0

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/16 v2, 0x48

    int-to-float v2, v2

    sub-float/2addr v2, v0

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    const/4 v0, 0x0

    int-to-float v0, v0

    invoke-static {v0}, Llyiahf/vczjk/vl6;->OooO0Oo(F)Llyiahf/vczjk/r13;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/vp;->OooO0OO:Llyiahf/vczjk/r13;

    return-void
.end method

.method public static final OooO00o(JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/qj8;Llyiahf/vczjk/kna;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V
    .locals 25

    move-object/from16 v6, p5

    move-object/from16 v8, p7

    move-object/from16 v10, p9

    move/from16 v11, p11

    move/from16 v12, p12

    move-object/from16 v0, p10

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, -0x2a77f922

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v1, v12, 0x1

    if-eqz v1, :cond_0

    or-int/lit8 v1, v11, 0x6

    move v3, v1

    move-wide/from16 v1, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v1, v11, 0x6

    if-nez v1, :cond_2

    move-wide/from16 v1, p0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    goto :goto_0

    :cond_1
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v11

    goto :goto_1

    :cond_2
    move-wide/from16 v1, p0

    move v3, v11

    :goto_1
    and-int/lit8 v4, v12, 0x2

    if-eqz v4, :cond_4

    or-int/lit8 v3, v3, 0x30

    :cond_3
    move-wide/from16 v4, p2

    goto :goto_3

    :cond_4
    and-int/lit8 v4, v11, 0x30

    if-nez v4, :cond_3

    move-wide/from16 v4, p2

    invoke-virtual {v0, v4, v5}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v7

    if-eqz v7, :cond_5

    const/16 v7, 0x20

    goto :goto_2

    :cond_5
    const/16 v7, 0x10

    :goto_2
    or-int/2addr v3, v7

    :goto_3
    and-int/lit8 v7, v12, 0x4

    if-eqz v7, :cond_7

    or-int/lit16 v3, v3, 0x180

    :cond_6
    move/from16 v7, p4

    goto :goto_5

    :cond_7
    and-int/lit16 v7, v11, 0x180

    if-nez v7, :cond_6

    move/from16 v7, p4

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v9

    if-eqz v9, :cond_8

    const/16 v9, 0x100

    goto :goto_4

    :cond_8
    const/16 v9, 0x80

    :goto_4
    or-int/2addr v3, v9

    :goto_5
    and-int/lit8 v9, v12, 0x8

    if-eqz v9, :cond_9

    or-int/lit16 v3, v3, 0xc00

    goto :goto_7

    :cond_9
    and-int/lit16 v9, v11, 0xc00

    if-nez v9, :cond_b

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_a

    const/16 v9, 0x800

    goto :goto_6

    :cond_a
    const/16 v9, 0x400

    :goto_6
    or-int/2addr v3, v9

    :cond_b
    :goto_7
    and-int/lit8 v9, v12, 0x10

    if-eqz v9, :cond_c

    or-int/lit16 v3, v3, 0x6000

    move-object/from16 v14, p6

    goto :goto_9

    :cond_c
    and-int/lit16 v9, v11, 0x6000

    move-object/from16 v14, p6

    if-nez v9, :cond_e

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_d

    const/16 v9, 0x4000

    goto :goto_8

    :cond_d
    const/16 v9, 0x2000

    :goto_8
    or-int/2addr v3, v9

    :cond_e
    :goto_9
    and-int/lit8 v9, v12, 0x20

    const/high16 v13, 0x30000

    if-eqz v9, :cond_f

    or-int/2addr v3, v13

    goto :goto_b

    :cond_f
    and-int v9, v11, v13

    if-nez v9, :cond_11

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_10

    const/high16 v9, 0x20000

    goto :goto_a

    :cond_10
    const/high16 v9, 0x10000

    :goto_a
    or-int/2addr v3, v9

    :cond_11
    :goto_b
    and-int/lit8 v9, v12, 0x40

    const/high16 v13, 0x180000

    if-eqz v9, :cond_13

    or-int/2addr v3, v13

    :cond_12
    move-object/from16 v15, p8

    goto :goto_d

    :cond_13
    and-int v15, v11, v13

    if-nez v15, :cond_12

    move-object/from16 v15, p8

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_14

    const/high16 v16, 0x100000

    goto :goto_c

    :cond_14
    const/high16 v16, 0x80000

    :goto_c
    or-int v3, v3, v16

    :goto_d
    move/from16 p10, v13

    and-int/lit16 v13, v12, 0x80

    const/high16 v16, 0xc00000

    if-eqz v13, :cond_15

    or-int v3, v3, v16

    goto :goto_f

    :cond_15
    and-int v13, v11, v16

    if-nez v13, :cond_17

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_16

    const/high16 v13, 0x800000

    goto :goto_e

    :cond_16
    const/high16 v13, 0x400000

    :goto_e
    or-int/2addr v3, v13

    :cond_17
    :goto_f
    const v13, 0x492493

    and-int/2addr v13, v3

    const v1, 0x492492

    if-eq v13, v1, :cond_18

    const/4 v1, 0x1

    goto :goto_10

    :cond_18
    const/4 v1, 0x0

    :goto_10
    and-int/lit8 v2, v3, 0x1

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_1a

    if-eqz v9, :cond_19

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    move-object v13, v1

    goto :goto_11

    :cond_19
    move-object v13, v15

    :goto_11
    new-instance v1, Llyiahf/vczjk/qp;

    invoke-direct {v1, v8, v6, v10}, Llyiahf/vczjk/qp;-><init>(Llyiahf/vczjk/kna;Llyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;)V

    const v2, 0xcb64a1a

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v21

    shr-int/lit8 v1, v3, 0x12

    and-int/lit8 v1, v1, 0xe

    or-int v1, v1, p10

    shr-int/lit8 v2, v3, 0x9

    and-int/lit8 v2, v2, 0x70

    or-int/2addr v1, v2

    shl-int/lit8 v2, v3, 0x6

    and-int/lit16 v9, v2, 0x380

    or-int/2addr v1, v9

    and-int/lit16 v2, v2, 0x1c00

    or-int/2addr v1, v2

    const/high16 v2, 0x70000

    shl-int/lit8 v3, v3, 0x9

    and-int/2addr v2, v3

    or-int v23, v1, v2

    const/16 v24, 0x10

    const/16 v19, 0x0

    move-wide/from16 v15, p0

    move-object/from16 v22, v0

    move-wide/from16 v17, v4

    move/from16 v20, v7

    invoke-static/range {v13 .. v24}, Llyiahf/vczjk/rd3;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object v9, v13

    goto :goto_12

    :cond_1a
    move-object/from16 v22, v0

    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v9, v15

    :goto_12
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v13

    if-eqz v13, :cond_1b

    new-instance v0, Llyiahf/vczjk/rp;

    move-wide/from16 v1, p0

    move-wide/from16 v3, p2

    move/from16 v5, p4

    move-object/from16 v7, p6

    invoke-direct/range {v0 .. v12}, Llyiahf/vczjk/rp;-><init>(JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/qj8;Llyiahf/vczjk/kna;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;II)V

    iput-object v0, v13, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1b
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V
    .locals 23

    move/from16 v9, p9

    move-object/from16 v0, p8

    check-cast v0, Llyiahf/vczjk/zf1;

    const v1, 0x7112d116

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v1, p10, 0x1

    if-eqz v1, :cond_0

    or-int/lit8 v2, v9, 0x6

    move v3, v2

    move-object/from16 v2, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v2, v9, 0x6

    if-nez v2, :cond_2

    move-object/from16 v2, p0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    goto :goto_0

    :cond_1
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v9

    goto :goto_1

    :cond_2
    move-object/from16 v2, p0

    move v3, v9

    :goto_1
    and-int/lit8 v4, v9, 0x30

    if-nez v4, :cond_5

    and-int/lit8 v4, p10, 0x2

    if-nez v4, :cond_3

    move-wide/from16 v4, p1

    invoke-virtual {v0, v4, v5}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v6

    if-eqz v6, :cond_4

    const/16 v6, 0x20

    goto :goto_2

    :cond_3
    move-wide/from16 v4, p1

    :cond_4
    const/16 v6, 0x10

    :goto_2
    or-int/2addr v3, v6

    goto :goto_3

    :cond_5
    move-wide/from16 v4, p1

    :goto_3
    and-int/lit16 v6, v9, 0x180

    if-nez v6, :cond_8

    and-int/lit8 v6, p10, 0x4

    if-nez v6, :cond_6

    move-wide/from16 v6, p3

    invoke-virtual {v0, v6, v7}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v8

    if-eqz v8, :cond_7

    const/16 v8, 0x100

    goto :goto_4

    :cond_6
    move-wide/from16 v6, p3

    :cond_7
    const/16 v8, 0x80

    :goto_4
    or-int/2addr v3, v8

    goto :goto_5

    :cond_8
    move-wide/from16 v6, p3

    :goto_5
    and-int/lit8 v8, p10, 0x8

    if-eqz v8, :cond_a

    or-int/lit16 v3, v3, 0xc00

    :cond_9
    move/from16 v10, p5

    goto :goto_7

    :cond_a
    and-int/lit16 v10, v9, 0xc00

    if-nez v10, :cond_9

    move/from16 v10, p5

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v11

    if-eqz v11, :cond_b

    const/16 v11, 0x800

    goto :goto_6

    :cond_b
    const/16 v11, 0x400

    :goto_6
    or-int/2addr v3, v11

    :goto_7
    and-int/lit8 v11, p10, 0x10

    if-eqz v11, :cond_d

    or-int/lit16 v3, v3, 0x6000

    :cond_c
    move-object/from16 v12, p6

    goto :goto_9

    :cond_d
    and-int/lit16 v12, v9, 0x6000

    if-nez v12, :cond_c

    move-object/from16 v12, p6

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_e

    const/16 v13, 0x4000

    goto :goto_8

    :cond_e
    const/16 v13, 0x2000

    :goto_8
    or-int/2addr v3, v13

    :goto_9
    and-int/lit8 v13, p10, 0x20

    const/high16 v14, 0x30000

    if-eqz v13, :cond_10

    or-int/2addr v3, v14

    :cond_f
    move-object/from16 v13, p7

    goto :goto_b

    :cond_10
    and-int v13, v9, v14

    if-nez v13, :cond_f

    move-object/from16 v13, p7

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_11

    const/high16 v14, 0x20000

    goto :goto_a

    :cond_11
    const/high16 v14, 0x10000

    :goto_a
    or-int/2addr v3, v14

    :goto_b
    const v14, 0x12493

    and-int/2addr v14, v3

    const v15, 0x12492

    if-eq v14, v15, :cond_12

    const/4 v14, 0x1

    goto :goto_c

    :cond_12
    const/4 v14, 0x0

    :goto_c
    and-int/lit8 v15, v3, 0x1

    invoke-virtual {v0, v15, v14}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v14

    if-eqz v14, :cond_1d

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v14, v9, 0x1

    if-eqz v14, :cond_16

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v14

    if-eqz v14, :cond_13

    goto :goto_e

    :cond_13
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v1, p10, 0x2

    if-eqz v1, :cond_14

    and-int/lit8 v3, v3, -0x71

    :cond_14
    and-int/lit8 v1, p10, 0x4

    if-eqz v1, :cond_15

    and-int/lit16 v3, v3, -0x381

    :cond_15
    move-object/from16 v18, v2

    :goto_d
    move v14, v10

    move-object v15, v12

    move-wide v10, v4

    move-wide v12, v6

    goto :goto_11

    :cond_16
    :goto_e
    if-eqz v1, :cond_17

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_f

    :cond_17
    move-object v1, v2

    :goto_f
    and-int/lit8 v2, p10, 0x2

    if-eqz v2, :cond_19

    sget-object v2, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/k31;

    invoke-virtual {v2}, Llyiahf/vczjk/k31;->OooO0Oo()Z

    move-result v4

    if-eqz v4, :cond_18

    invoke-virtual {v2}, Llyiahf/vczjk/k31;->OooO0O0()J

    move-result-wide v4

    goto :goto_10

    :cond_18
    invoke-virtual {v2}, Llyiahf/vczjk/k31;->OooO0OO()J

    move-result-wide v4

    :goto_10
    and-int/lit8 v3, v3, -0x71

    :cond_19
    and-int/lit8 v2, p10, 0x4

    if-eqz v2, :cond_1a

    invoke-static {v4, v5, v0}, Llyiahf/vczjk/m31;->OooO00o(JLlyiahf/vczjk/rf1;)J

    move-result-wide v6

    and-int/lit16 v2, v3, -0x381

    move v3, v2

    :cond_1a
    if-eqz v8, :cond_1b

    sget v2, Llyiahf/vczjk/gp;->OooO00o:F

    move v10, v2

    :cond_1b
    if-eqz v11, :cond_1c

    sget-object v2, Llyiahf/vczjk/gp;->OooO0O0:Llyiahf/vczjk/di6;

    move-object/from16 v18, v1

    move-object v15, v2

    move-wide v12, v6

    move v14, v10

    move-wide v10, v4

    goto :goto_11

    :cond_1c
    move-object/from16 v18, v1

    goto :goto_d

    :goto_11
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget-object v16, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    shr-int/lit8 v1, v3, 0x3

    and-int/lit8 v2, v1, 0xe

    const v4, 0x36000

    or-int/2addr v2, v4

    and-int/lit8 v4, v1, 0x70

    or-int/2addr v2, v4

    and-int/lit16 v4, v1, 0x380

    or-int/2addr v2, v4

    and-int/lit16 v1, v1, 0x1c00

    or-int/2addr v1, v2

    shl-int/lit8 v2, v3, 0x12

    const/high16 v4, 0x380000

    and-int/2addr v2, v4

    or-int/2addr v1, v2

    const/high16 v2, 0x1c00000

    shl-int/lit8 v3, v3, 0x6

    and-int/2addr v2, v3

    or-int v21, v1, v2

    const/16 v22, 0x0

    sget-object v17, Llyiahf/vczjk/vp;->OooO0OO:Llyiahf/vczjk/r13;

    move-object/from16 v19, p7

    move-object/from16 v20, v0

    invoke-static/range {v10 .. v22}, Llyiahf/vczjk/vp;->OooO00o(JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/qj8;Llyiahf/vczjk/kna;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move-wide v2, v10

    move-wide v4, v12

    move v6, v14

    move-object v7, v15

    move-object/from16 v1, v18

    goto :goto_12

    :cond_1d
    move-object/from16 v20, v0

    invoke-virtual/range {v20 .. v20}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v1, v2

    move-wide v2, v4

    move-wide v4, v6

    move v6, v10

    move-object v7, v12

    :goto_12
    invoke-virtual/range {v20 .. v20}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v11

    if-eqz v11, :cond_1e

    new-instance v0, Llyiahf/vczjk/sp;

    move-object/from16 v8, p7

    move/from16 v10, p10

    invoke-direct/range {v0 .. v10}, Llyiahf/vczjk/sp;-><init>(Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/bi6;Llyiahf/vczjk/bf3;II)V

    iput-object v0, v11, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1e
    return-void
.end method
