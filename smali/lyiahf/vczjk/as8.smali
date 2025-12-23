.class public abstract Llyiahf/vczjk/as8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F

.field public static final OooO0O0:F

.field public static final OooO0OO:J

.field public static final OooO0Oo:F

.field public static final OooO0o:Llyiahf/vczjk/dfa;

.field public static final OooO0o0:F


# direct methods
.method static constructor <clinit>()V
    .locals 4

    sget v0, Llyiahf/vczjk/ds8;->OooOOO:F

    sput v0, Llyiahf/vczjk/as8;->OooO00o:F

    sget v0, Llyiahf/vczjk/ds8;->OooOO0o:F

    sput v0, Llyiahf/vczjk/as8;->OooO0O0:F

    sget v1, Llyiahf/vczjk/ds8;->OooOO0:F

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooO0oo(FF)J

    move-result-wide v2

    sput-wide v2, Llyiahf/vczjk/as8;->OooO0OO:J

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooO0oo(FF)J

    sget v0, Llyiahf/vczjk/ds8;->OooO00o:F

    sput v0, Llyiahf/vczjk/as8;->OooO0Oo:F

    const/4 v0, 0x2

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/as8;->OooO0o0:F

    new-instance v0, Llyiahf/vczjk/dfa;

    sget-object v1, Llyiahf/vczjk/tr8;->OooOOO:Llyiahf/vczjk/tr8;

    invoke-direct {v0, v1}, Llyiahf/vczjk/p4;-><init>(Llyiahf/vczjk/ze3;)V

    sput-object v0, Llyiahf/vczjk/as8;->OooO0o:Llyiahf/vczjk/dfa;

    return-void
.end method

.method public static final OooO00o(FLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/m01;ILlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/rf1;II)V
    .locals 25

    const/16 v0, 0x20

    const/4 v1, 0x1

    const/16 v2, 0x10

    move-object/from16 v13, p8

    check-cast v13, Llyiahf/vczjk/zf1;

    const v3, -0xc0af27b

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    move/from16 v15, p0

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int v3, p9, v3

    move-object/from16 v4, p1

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    move v5, v0

    goto :goto_1

    :cond_1
    move v5, v2

    :goto_1
    or-int/2addr v3, v5

    or-int/lit16 v3, v3, 0xd80

    and-int/lit8 v5, p10, 0x10

    if-nez v5, :cond_2

    move-object/from16 v5, p4

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3

    const/16 v6, 0x4000

    goto :goto_2

    :cond_2
    move-object/from16 v5, p4

    :cond_3
    const/16 v6, 0x2000

    :goto_2
    or-int/2addr v3, v6

    and-int/lit8 v0, p10, 0x20

    const/high16 v6, 0x30000

    if-eqz v0, :cond_5

    or-int/2addr v3, v6

    :cond_4
    move/from16 v6, p5

    goto :goto_4

    :cond_5
    and-int v6, p9, v6

    if-nez v6, :cond_4

    move/from16 v6, p5

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v7

    if-eqz v7, :cond_6

    const/high16 v7, 0x20000

    goto :goto_3

    :cond_6
    const/high16 v7, 0x10000

    :goto_3
    or-int/2addr v3, v7

    :goto_4
    const/high16 v7, 0x6580000

    or-int/2addr v3, v7

    const v7, 0x2492493

    and-int/2addr v7, v3

    const v8, 0x2492492

    const/4 v9, 0x0

    if-eq v7, v8, :cond_7

    move v7, v1

    goto :goto_5

    :cond_7
    move v7, v9

    :goto_5
    and-int/lit8 v8, v3, 0x1

    invoke-virtual {v13, v8, v7}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v7

    if-eqz v7, :cond_e

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v7, p9, 0x1

    const v8, -0x1c00001

    const v10, -0xe001

    if-eqz v7, :cond_a

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v7

    if-eqz v7, :cond_8

    goto :goto_6

    :cond_8
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v0, p10, 0x10

    if-eqz v0, :cond_9

    and-int/2addr v3, v10

    :cond_9
    and-int v0, v3, v8

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object v12, v5

    move v9, v6

    move-object/from16 v5, p2

    move/from16 v6, p3

    goto :goto_7

    :cond_a
    :goto_6
    sget-object v7, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    and-int/lit8 v2, p10, 0x10

    if-eqz v2, :cond_b

    new-instance v2, Llyiahf/vczjk/m01;

    const/4 v5, 0x0

    const/high16 v11, 0x3f800000    # 1.0f

    invoke-direct {v2, v5, v11}, Llyiahf/vczjk/m01;-><init>(FF)V

    and-int/2addr v3, v10

    move-object v5, v2

    :cond_b
    if-eqz v0, :cond_c

    move v6, v9

    :cond_c
    sget-object v0, Llyiahf/vczjk/pr8;->OooO00o:Llyiahf/vczjk/pr8;

    invoke-static {v13}, Llyiahf/vczjk/pr8;->OooO0Oo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/ir8;

    move-result-object v0

    and-int v2, v3, v8

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v8, :cond_d

    invoke-static {v13}, Llyiahf/vczjk/ix8;->OooOOo0(Llyiahf/vczjk/zf1;)Llyiahf/vczjk/sr5;

    move-result-object v3

    :cond_d
    check-cast v3, Llyiahf/vczjk/rr5;

    move-object v8, v3

    move-object v12, v5

    move v9, v6

    move-object v5, v7

    move-object v7, v0

    move v6, v1

    move v0, v2

    :goto_7
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo0()V

    new-instance v2, Llyiahf/vczjk/ur8;

    invoke-direct {v2, v8, v7, v6}, Llyiahf/vczjk/ur8;-><init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/ir8;Z)V

    const v3, 0x125f81c1

    invoke-static {v3, v2, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v10

    new-instance v2, Llyiahf/vczjk/gl0;

    invoke-direct {v2, v1, v7, v6}, Llyiahf/vczjk/gl0;-><init>(ILjava/lang/Object;Z)V

    const v1, -0x6ddd853e

    invoke-static {v1, v2, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v11

    and-int/lit8 v1, v0, 0xe

    const/high16 v2, 0x36000000

    or-int/2addr v1, v2

    and-int/lit8 v2, v0, 0x70

    or-int/2addr v1, v2

    const v2, 0x186d80

    or-int/2addr v1, v2

    shl-int/lit8 v2, v0, 0x6

    const/high16 v3, 0x1c00000

    and-int/2addr v2, v3

    or-int v14, v1, v2

    shr-int/lit8 v0, v0, 0xc

    and-int/lit8 v0, v0, 0xe

    move v3, v15

    move v15, v0

    invoke-static/range {v3 .. v15}, Llyiahf/vczjk/as8;->OooO0O0(FLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;ILlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/m01;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v17, v5

    move/from16 v18, v6

    move-object/from16 v21, v7

    move-object/from16 v22, v8

    move/from16 v20, v9

    move-object/from16 v19, v12

    goto :goto_8

    :cond_e
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v17, p2

    move/from16 v18, p3

    move-object/from16 v21, p6

    move-object/from16 v22, p7

    move-object/from16 v19, v5

    move/from16 v20, v6

    :goto_8
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_f

    new-instance v14, Llyiahf/vczjk/rr8;

    move/from16 v15, p0

    move-object/from16 v16, p1

    move/from16 v23, p9

    move/from16 v24, p10

    invoke-direct/range {v14 .. v24}, Llyiahf/vczjk/rr8;-><init>(FLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/m01;ILlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;II)V

    iput-object v14, v0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooO0O0(FLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;ILlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/m01;Llyiahf/vczjk/rf1;II)V
    .locals 21

    move/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v7, p6

    move-object/from16 v10, p9

    move/from16 v11, p11

    move-object/from16 v0, p10

    check-cast v0, Llyiahf/vczjk/zf1;

    const v3, 0x3ac3ab6f

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v3, v11, 0x6

    const/4 v4, 0x2

    if-nez v3, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v3, v11

    goto :goto_1

    :cond_1
    move v3, v11

    :goto_1
    and-int/lit8 v6, v11, 0x30

    if-nez v6, :cond_3

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    const/16 v6, 0x20

    goto :goto_2

    :cond_2
    const/16 v6, 0x10

    :goto_2
    or-int/2addr v3, v6

    :cond_3
    and-int/lit16 v6, v11, 0x180

    move-object/from16 v13, p2

    if-nez v6, :cond_5

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_4

    const/16 v6, 0x100

    goto :goto_3

    :cond_4
    const/16 v6, 0x80

    :goto_3
    or-int/2addr v3, v6

    :cond_5
    and-int/lit16 v6, v11, 0xc00

    move/from16 v14, p3

    if-nez v6, :cond_7

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v6

    if-eqz v6, :cond_6

    const/16 v6, 0x800

    goto :goto_4

    :cond_6
    const/16 v6, 0x400

    :goto_4
    or-int/2addr v3, v6

    :cond_7
    and-int/lit16 v6, v11, 0x6000

    if-nez v6, :cond_9

    const/4 v6, 0x0

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_8

    const/16 v6, 0x4000

    goto :goto_5

    :cond_8
    const/16 v6, 0x2000

    :goto_5
    or-int/2addr v3, v6

    :cond_9
    const/high16 v6, 0x30000

    and-int/2addr v6, v11

    if-nez v6, :cond_b

    move-object/from16 v6, p4

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_a

    const/high16 v8, 0x20000

    goto :goto_6

    :cond_a
    const/high16 v8, 0x10000

    :goto_6
    or-int/2addr v3, v8

    goto :goto_7

    :cond_b
    move-object/from16 v6, p4

    :goto_7
    const/high16 v8, 0x180000

    and-int/2addr v8, v11

    if-nez v8, :cond_d

    move-object/from16 v8, p5

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_c

    const/high16 v9, 0x100000

    goto :goto_8

    :cond_c
    const/high16 v9, 0x80000

    :goto_8
    or-int/2addr v3, v9

    goto :goto_9

    :cond_d
    move-object/from16 v8, p5

    :goto_9
    const/high16 v9, 0xc00000

    and-int/2addr v9, v11

    if-nez v9, :cond_f

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v9

    if-eqz v9, :cond_e

    const/high16 v9, 0x800000

    goto :goto_a

    :cond_e
    const/high16 v9, 0x400000

    :goto_a
    or-int/2addr v3, v9

    :cond_f
    const/high16 v9, 0x6000000

    and-int/2addr v9, v11

    if-nez v9, :cond_11

    move-object/from16 v9, p7

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_10

    const/high16 v15, 0x4000000

    goto :goto_b

    :cond_10
    const/high16 v15, 0x2000000

    :goto_b
    or-int/2addr v3, v15

    goto :goto_c

    :cond_11
    move-object/from16 v9, p7

    :goto_c
    const/high16 v15, 0x30000000

    and-int/2addr v15, v11

    if-nez v15, :cond_13

    move-object/from16 v15, p8

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_12

    const/high16 v16, 0x20000000

    goto :goto_d

    :cond_12
    const/high16 v16, 0x10000000

    :goto_d
    or-int v3, v3, v16

    goto :goto_e

    :cond_13
    move-object/from16 v15, p8

    :goto_e
    and-int/lit8 v16, p12, 0x6

    if-nez v16, :cond_15

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_14

    const/16 v16, 0x4

    goto :goto_f

    :cond_14
    move/from16 v16, v4

    :goto_f
    or-int v16, p12, v16

    goto :goto_10

    :cond_15
    move/from16 v16, p12

    :goto_10
    const v17, 0x12492493

    and-int v5, v3, v17

    const/16 v17, 0x1

    const v12, 0x12492492

    const/16 v19, 0x0

    if-ne v5, v12, :cond_17

    and-int/lit8 v5, v16, 0x3

    if-eq v5, v4, :cond_16

    goto :goto_11

    :cond_16
    move/from16 v4, v19

    goto :goto_12

    :cond_17
    :goto_11
    move/from16 v4, v17

    :goto_12
    and-int/lit8 v5, v3, 0x1

    invoke-virtual {v0, v5, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v4

    if-eqz v4, :cond_20

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v4, v11, 0x1

    if-eqz v4, :cond_19

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v4

    if-eqz v4, :cond_18

    goto :goto_13

    :cond_18
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_19
    :goto_13
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo0()V

    const/high16 v4, 0x1c00000

    and-int/2addr v4, v3

    const/high16 v5, 0x800000

    if-ne v4, v5, :cond_1a

    move/from16 v4, v17

    goto :goto_14

    :cond_1a
    move/from16 v4, v19

    :goto_14
    and-int/lit8 v5, v16, 0xe

    xor-int/lit8 v5, v5, 0x6

    const/4 v12, 0x4

    if-le v5, v12, :cond_1b

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_1d

    :cond_1b
    and-int/lit8 v5, v16, 0x6

    if-ne v5, v12, :cond_1c

    goto :goto_15

    :cond_1c
    move/from16 v17, v19

    :cond_1d
    :goto_15
    or-int v4, v4, v17

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_1e

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v4, :cond_1f

    :cond_1e
    new-instance v5, Llyiahf/vczjk/cs8;

    invoke-direct {v5, v1, v7, v10}, Llyiahf/vczjk/cs8;-><init>(FILlyiahf/vczjk/m01;)V

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1f
    move-object v12, v5

    check-cast v12, Llyiahf/vczjk/cs8;

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iput-object v2, v12, Llyiahf/vczjk/cs8;->OooO0Oo:Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/cs8;->OooO0o0(F)V

    shr-int/lit8 v4, v3, 0x3

    and-int/lit16 v4, v4, 0x3f0

    shr-int/lit8 v5, v3, 0x6

    const v16, 0xe000

    and-int v5, v5, v16

    or-int/2addr v4, v5

    shr-int/lit8 v3, v3, 0x9

    const/high16 v5, 0x70000

    and-int/2addr v5, v3

    or-int/2addr v4, v5

    const/high16 v5, 0x380000

    and-int/2addr v3, v5

    or-int v20, v4, v3

    const/4 v15, 0x0

    move-object/from16 v18, p8

    move-object/from16 v19, v0

    move-object/from16 v16, v8

    move-object/from16 v17, v9

    invoke-static/range {v12 .. v20}, Llyiahf/vczjk/as8;->OooO0OO(Llyiahf/vczjk/cs8;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    goto :goto_16

    :cond_20
    move-object/from16 v19, v0

    invoke-virtual/range {v19 .. v19}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_16
    invoke-virtual/range {v19 .. v19}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v13

    if-eqz v13, :cond_21

    new-instance v0, Llyiahf/vczjk/sr8;

    move-object/from16 v3, p2

    move/from16 v4, p3

    move-object/from16 v8, p7

    move-object/from16 v9, p8

    move/from16 v12, p12

    move-object v5, v6

    move-object/from16 v6, p5

    invoke-direct/range {v0 .. v12}, Llyiahf/vczjk/sr8;-><init>(FLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;ILlyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/m01;II)V

    iput-object v0, v13, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_21
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/cs8;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 13

    move/from16 v8, p8

    const/4 v0, 0x1

    move-object/from16 v6, p7

    check-cast v6, Llyiahf/vczjk/zf1;

    const v2, 0x186dff48

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v2, v8, 0x6

    if-nez v2, :cond_1

    invoke-virtual {v6, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    const/4 v2, 0x4

    goto :goto_0

    :cond_0
    const/4 v2, 0x2

    :goto_0
    or-int/2addr v2, v8

    goto :goto_1

    :cond_1
    move v2, v8

    :goto_1
    and-int/lit8 v3, v8, 0x30

    if-nez v3, :cond_3

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v2, v4

    :cond_3
    and-int/lit16 v4, v8, 0x180

    if-nez v4, :cond_5

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    if-eqz v5, :cond_4

    const/16 v5, 0x100

    goto :goto_3

    :cond_4
    const/16 v5, 0x80

    :goto_3
    or-int/2addr v2, v5

    :cond_5
    and-int/lit16 v5, v8, 0xc00

    if-nez v5, :cond_6

    or-int/lit16 v2, v2, 0x400

    :cond_6
    and-int/lit16 v5, v8, 0x6000

    if-nez v5, :cond_8

    move-object/from16 v5, p4

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_7

    const/16 v7, 0x4000

    goto :goto_4

    :cond_7
    const/16 v7, 0x2000

    :goto_4
    or-int/2addr v2, v7

    goto :goto_5

    :cond_8
    move-object/from16 v5, p4

    :goto_5
    const/high16 v7, 0x30000

    and-int/2addr v7, v8

    if-nez v7, :cond_a

    move-object/from16 v7, p5

    invoke-virtual {v6, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_9

    const/high16 v9, 0x20000

    goto :goto_6

    :cond_9
    const/high16 v9, 0x10000

    :goto_6
    or-int/2addr v2, v9

    goto :goto_7

    :cond_a
    move-object/from16 v7, p5

    :goto_7
    const/high16 v9, 0x180000

    and-int/2addr v9, v8

    if-nez v9, :cond_c

    move-object/from16 v9, p6

    invoke-virtual {v6, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_b

    const/high16 v10, 0x100000

    goto :goto_8

    :cond_b
    const/high16 v10, 0x80000

    :goto_8
    or-int/2addr v2, v10

    goto :goto_9

    :cond_c
    move-object/from16 v9, p6

    :goto_9
    const v10, 0x92493

    and-int/2addr v10, v2

    const v11, 0x92492

    if-eq v10, v11, :cond_d

    move v10, v0

    goto :goto_a

    :cond_d
    const/4 v10, 0x0

    :goto_a
    and-int/lit8 v11, v2, 0x1

    invoke-virtual {v6, v11, v10}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v10

    if-eqz v10, :cond_11

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/2addr v0, v8

    if-eqz v0, :cond_f

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_e

    goto :goto_b

    :cond_e
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit16 v0, v2, -0x1c01

    move-object/from16 v10, p3

    goto :goto_c

    :cond_f
    :goto_b
    sget-object v0, Llyiahf/vczjk/pr8;->OooO00o:Llyiahf/vczjk/pr8;

    invoke-static {v6}, Llyiahf/vczjk/pr8;->OooO0Oo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/ir8;

    move-result-object v0

    and-int/lit16 v2, v2, -0x1c01

    move-object v10, v0

    move v0, v2

    :goto_c
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo0()V

    iget v2, p0, Llyiahf/vczjk/cs8;->OooO00o:I

    if-ltz v2, :cond_10

    shr-int/lit8 v2, v0, 0x3

    and-int/lit8 v11, v2, 0xe

    shl-int/lit8 v12, v0, 0x3

    and-int/lit8 v12, v12, 0x70

    or-int/2addr v11, v12

    and-int/lit16 v0, v0, 0x380

    or-int/2addr v0, v11

    and-int/lit16 v11, v2, 0x1c00

    or-int/2addr v0, v11

    const v11, 0xe000

    and-int/2addr v11, v2

    or-int/2addr v0, v11

    const/high16 v11, 0x70000

    and-int/2addr v2, v11

    or-int/2addr v0, v2

    move-object v1, p0

    move v2, p2

    move-object v3, v5

    move-object v4, v7

    move-object v5, v9

    move v7, v0

    move-object v0, p1

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/as8;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/cs8;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    move-object v4, v10

    goto :goto_d

    :cond_10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "steps should be >= 0"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_11
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v4, p3

    :goto_d
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v9

    if-eqz v9, :cond_12

    new-instance v0, Llyiahf/vczjk/gv0;

    move-object v1, p0

    move-object v2, p1

    move v3, p2

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/gv0;-><init>(Llyiahf/vczjk/cs8;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/ir8;Llyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;I)V

    iput-object v0, v9, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/cs8;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 22

    move-object/from16 v1, p1

    move/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v9, p4

    move-object/from16 v10, p5

    move/from16 v11, p7

    const/4 v12, 0x1

    move-object/from16 v13, p6

    check-cast v13, Llyiahf/vczjk/zf1;

    const v0, 0x358907a3

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const/4 v0, 0x6

    and-int/lit8 v2, v11, 0x6

    const/4 v5, 0x4

    move-object/from16 v14, p0

    if-nez v2, :cond_1

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    move v2, v5

    goto :goto_0

    :cond_0
    const/4 v2, 0x2

    :goto_0
    or-int/2addr v2, v11

    goto :goto_1

    :cond_1
    move v2, v11

    :goto_1
    and-int/lit8 v6, v11, 0x30

    if-nez v6, :cond_3

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    const/16 v6, 0x20

    goto :goto_2

    :cond_2
    const/16 v6, 0x10

    :goto_2
    or-int/2addr v2, v6

    :cond_3
    and-int/lit16 v6, v11, 0x180

    if-nez v6, :cond_5

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v6

    if-eqz v6, :cond_4

    const/16 v6, 0x100

    goto :goto_3

    :cond_4
    const/16 v6, 0x80

    :goto_3
    or-int/2addr v2, v6

    :cond_5
    and-int/lit16 v6, v11, 0xc00

    if-nez v6, :cond_7

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_6

    const/16 v6, 0x800

    goto :goto_4

    :cond_6
    const/16 v6, 0x400

    :goto_4
    or-int/2addr v2, v6

    :cond_7
    and-int/lit16 v6, v11, 0x6000

    if-nez v6, :cond_9

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_8

    const/16 v6, 0x4000

    goto :goto_5

    :cond_8
    const/16 v6, 0x2000

    :goto_5
    or-int/2addr v2, v6

    :cond_9
    const/high16 v6, 0x30000

    and-int/2addr v6, v11

    if-nez v6, :cond_b

    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_a

    const/high16 v6, 0x20000

    goto :goto_6

    :cond_a
    const/high16 v6, 0x10000

    :goto_6
    or-int/2addr v2, v6

    :cond_b
    move v15, v2

    const v2, 0x12493

    and-int/2addr v2, v15

    const v6, 0x12492

    const/4 v7, 0x0

    if-eq v2, v6, :cond_c

    move v2, v12

    goto :goto_7

    :cond_c
    move v2, v7

    :goto_7
    and-int/lit8 v6, v15, 0x1

    invoke-virtual {v13, v6, v2}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_25

    sget-object v2, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    sget-object v6, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    if-ne v2, v6, :cond_d

    move v2, v12

    goto :goto_8

    :cond_d
    move v2, v7

    :goto_8
    iput-boolean v2, v1, Llyiahf/vczjk/cs8;->OooO:Z

    sget-object v6, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    iget-object v8, v1, Llyiahf/vczjk/cs8;->OooOO0o:Llyiahf/vczjk/nf6;

    if-ne v8, v6, :cond_f

    if-nez v2, :cond_e

    goto :goto_9

    :cond_e
    move v2, v7

    move v7, v12

    goto :goto_a

    :cond_f
    :goto_9
    move v2, v7

    :goto_a
    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    if-eqz v3, :cond_10

    new-instance v2, Llyiahf/vczjk/o0000O0;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/o0000O0;-><init>(Ljava/lang/Object;I)V

    sget-object v0, Llyiahf/vczjk/gb9;->OooO00o:Llyiahf/vczjk/ey6;

    new-instance v0, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;

    invoke-direct {v0, v1, v4, v2, v5}, Landroidx/compose/ui/input/pointer/SuspendPointerInputElement;-><init>(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;I)V

    goto :goto_b

    :cond_10
    move-object v0, v6

    :goto_b
    iget-object v2, v1, Llyiahf/vczjk/cs8;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v5

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    move-object/from16 v16, v8

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v2, :cond_11

    if-ne v12, v8, :cond_12

    :cond_11
    new-instance v12, Llyiahf/vczjk/xr8;

    const/4 v2, 0x0

    invoke-direct {v12, v1, v2}, Llyiahf/vczjk/xr8;-><init>(Llyiahf/vczjk/cs8;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v13, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_12
    check-cast v12, Llyiahf/vczjk/bf3;

    move-object v2, v8

    const/16 v8, 0x20

    move-object/from16 v17, v2

    iget-object v2, v1, Llyiahf/vczjk/cs8;->OooOO0o:Llyiahf/vczjk/nf6;

    move-object v11, v0

    move-object v0, v6

    move-object v6, v12

    move-object/from16 v12, v16

    move-object/from16 v14, v17

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/uf2;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ag2;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/bf3;ZI)Llyiahf/vczjk/kl5;

    move-result-object v8

    move v5, v7

    move-object v7, v1

    move-object v1, v0

    move-object v0, v4

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne v12, v2, :cond_13

    sget-object v4, Llyiahf/vczjk/jr8;->OooOOO0:Llyiahf/vczjk/jr8;

    invoke-static {v1, v4}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOoo(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    goto :goto_c

    :cond_13
    sget-object v4, Llyiahf/vczjk/jr8;->OooOOO0:Llyiahf/vczjk/jr8;

    invoke-static {v1, v4}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOo0(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    :goto_c
    sget-object v6, Llyiahf/vczjk/r24;->OooO00o:Llyiahf/vczjk/go3;

    sget-object v16, Landroidx/compose/material3/MinimumInteractiveModifier;->OooOOO0:Landroidx/compose/material3/MinimumInteractiveModifier;

    invoke-virtual/range {p0 .. p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v6, Llyiahf/vczjk/as8;->OooO0O0:F

    sget v17, Llyiahf/vczjk/as8;->OooO00o:F

    move/from16 v18, v17

    if-ne v12, v2, :cond_14

    goto :goto_d

    :cond_14
    move/from16 v17, v6

    :goto_d
    if-ne v12, v2, :cond_15

    move/from16 v18, v6

    :cond_15
    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0xc

    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0O(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v6

    move-object/from16 v16, v1

    new-instance v1, Llyiahf/vczjk/ow2;

    invoke-direct {v1, v3, v7}, Llyiahf/vczjk/ow2;-><init>(ZLlyiahf/vczjk/cs8;)V

    move-object/from16 v17, v4

    const/4 v4, 0x0

    invoke-static {v6, v4, v1}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    if-ne v12, v2, :cond_16

    sget-object v2, Llyiahf/vczjk/o0OO0o;->OooO0Oo:Llyiahf/vczjk/kl5;

    goto :goto_e

    :cond_16
    sget-object v2, Llyiahf/vczjk/o0OO0o;->OooO0OO:Llyiahf/vczjk/kl5;

    :goto_e
    invoke-interface {v1, v2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v7}, Llyiahf/vczjk/cs8;->OooO0Oo()F

    move-result v2

    iget-object v4, v7, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    iget v6, v4, Llyiahf/vczjk/m01;->OooO00o:F

    new-instance v12, Llyiahf/vczjk/m01;

    iget v4, v4, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-direct {v12, v6, v4}, Llyiahf/vczjk/m01;-><init>(FF)V

    new-instance v4, Llyiahf/vczjk/ha7;

    iget v6, v7, Llyiahf/vczjk/cs8;->OooO00o:I

    invoke-direct {v4, v2, v6, v12}, Llyiahf/vczjk/ha7;-><init>(FILlyiahf/vczjk/m01;)V

    const/4 v2, 0x1

    invoke-static {v1, v2, v4}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v3, v0}, Landroidx/compose/foundation/OooO00o;->OooO0oo(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;)Llyiahf/vczjk/kl5;

    move-result-object v12

    invoke-virtual {v7}, Llyiahf/vczjk/cs8;->OooO0Oo()F

    move-result v6

    iget-object v2, v7, Llyiahf/vczjk/cs8;->OooO0Oo:Llyiahf/vczjk/oe3;

    iget v4, v7, Llyiahf/vczjk/cs8;->OooO00o:I

    if-ltz v4, :cond_24

    new-instance v0, Llyiahf/vczjk/yr8;

    iget-object v3, v7, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    move-object/from16 v1, v16

    move/from16 v16, v15

    move-object v15, v1

    move/from16 v1, p2

    move-object/from16 v10, v17

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/yr8;-><init>(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/m01;IZF)V

    invoke-static {v12, v0}, Landroidx/compose/ui/input/key/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-interface {v0, v11}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-interface {v0, v8}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_17

    if-ne v2, v14, :cond_18

    :cond_17
    new-instance v2, Llyiahf/vczjk/wr8;

    invoke-direct {v2, v7}, Llyiahf/vczjk/wr8;-><init>(Llyiahf/vczjk/cs8;)V

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v2, Llyiahf/vczjk/lf5;

    iget v1, v13, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v13, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_19

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_f

    :cond_19
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_f
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v13, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v13, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_1a

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v6, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_1b

    :cond_1a
    invoke-static {v1, v13, v1, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1b
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, v13, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v13, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_1c

    if-ne v6, v14, :cond_1d

    :cond_1c
    new-instance v6, Llyiahf/vczjk/qr8;

    const/4 v0, 0x1

    invoke-direct {v6, v7, v0}, Llyiahf/vczjk/qr8;-><init>(Llyiahf/vczjk/cs8;I)V

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1d
    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-static {v10, v6}, Landroidx/compose/ui/layout/OooO00o;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v6, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v8, 0x0

    invoke-static {v6, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v8, v13, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v13, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_1e

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_1e
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    invoke-static {v10, v13, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v13, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v10, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_1f

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_20

    :cond_1f
    invoke-static {v8, v13, v8, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_20
    invoke-static {v0, v13, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    shr-int/lit8 v0, v16, 0x3

    and-int/lit8 v0, v0, 0xe

    shr-int/lit8 v8, v16, 0x9

    and-int/lit8 v8, v8, 0x70

    or-int/2addr v8, v0

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-virtual {v9, v7, v13, v8}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v8, 0x1

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v8, Llyiahf/vczjk/jr8;->OooOOO:Llyiahf/vczjk/jr8;

    invoke-static {v15, v8}, Landroidx/compose/ui/layout/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Ljava/lang/Object;)Llyiahf/vczjk/kl5;

    move-result-object v8

    const/4 v10, 0x0

    invoke-static {v6, v10}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v6

    iget v10, v13, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v13, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_21

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_11

    :cond_21
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_11
    invoke-static {v6, v13, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v13, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_22

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_23

    :cond_22
    invoke-static {v10, v13, v10, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_23
    invoke-static {v8, v13, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    shr-int/lit8 v1, v16, 0xc

    and-int/lit8 v1, v1, 0x70

    or-int/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    move-object/from16 v10, p5

    invoke-virtual {v10, v7, v13, v0}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v8, 0x1

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_12

    :cond_24
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "steps should be >= 0"

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_25
    move-object v7, v1

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_12
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_26

    new-instance v0, Llyiahf/vczjk/iv0;

    move-object/from16 v1, p0

    move/from16 v3, p2

    move-object/from16 v4, p3

    move-object v2, v7

    move-object v5, v9

    move-object v6, v10

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/iv0;-><init>(Llyiahf/vczjk/hl5;Llyiahf/vczjk/cs8;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_26
    return-void
.end method

.method public static final OooO0o0(FFF[F)F
    .locals 7

    array-length v0, p3

    if-nez v0, :cond_0

    const/4 p3, 0x0

    goto :goto_1

    :cond_0
    const/4 v0, 0x0

    aget v0, p3, v0

    array-length v1, p3

    const/4 v2, 0x1

    sub-int/2addr v1, v2

    if-nez v1, :cond_1

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p3

    goto :goto_1

    :cond_1
    invoke-static {p1, p2, v0}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result v3

    sub-float/2addr v3, p0

    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    move-result v3

    if-gt v2, v1, :cond_3

    :goto_0
    aget v4, p3, v2

    invoke-static {p1, p2, v4}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result v5

    sub-float/2addr v5, p0

    invoke-static {v5}, Ljava/lang/Math;->abs(F)F

    move-result v5

    invoke-static {v3, v5}, Ljava/lang/Float;->compare(FF)I

    move-result v6

    if-lez v6, :cond_2

    move v0, v4

    move v3, v5

    :cond_2
    if-eq v2, v1, :cond_3

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_3
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p3

    :goto_1
    if-eqz p3, :cond_4

    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    move-result p0

    invoke-static {p1, p2, p0}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result p0

    :cond_4
    return p0
.end method
