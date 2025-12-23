.class public abstract Llyiahf/vczjk/fa7;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F

.field public static final OooO0O0:F

.field public static final OooO0OO:F

.field public static final OooO0Oo:Llyiahf/vczjk/cu1;

.field public static final OooO0o:Llyiahf/vczjk/cu1;

.field public static final OooO0o0:Llyiahf/vczjk/cu1;

.field public static final OooO0oO:Llyiahf/vczjk/cu1;

.field public static final OooO0oo:Llyiahf/vczjk/cu1;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    sget v0, Llyiahf/vczjk/r97;->OooO00o:F

    sput v0, Llyiahf/vczjk/fa7;->OooO00o:F

    const/16 v0, 0xf0

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/fa7;->OooO0O0:F

    const/16 v0, 0x28

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/fa7;->OooO0OO:F

    new-instance v0, Llyiahf/vczjk/cu1;

    const v1, 0x3e4ccccd    # 0.2f

    const/4 v2, 0x0

    const v3, 0x3f4ccccd    # 0.8f

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/fa7;->OooO0Oo:Llyiahf/vczjk/cu1;

    new-instance v0, Llyiahf/vczjk/cu1;

    const v3, 0x3ecccccd    # 0.4f

    invoke-direct {v0, v3, v2, v4, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/fa7;->OooO0o0:Llyiahf/vczjk/cu1;

    new-instance v0, Llyiahf/vczjk/cu1;

    const v5, 0x3f266666    # 0.65f

    invoke-direct {v0, v2, v2, v5, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/fa7;->OooO0o:Llyiahf/vczjk/cu1;

    new-instance v0, Llyiahf/vczjk/cu1;

    const v5, 0x3dcccccd    # 0.1f

    const v6, 0x3ee66666    # 0.45f

    invoke-direct {v0, v5, v2, v6, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/fa7;->OooO0oO:Llyiahf/vczjk/cu1;

    new-instance v0, Llyiahf/vczjk/cu1;

    invoke-direct {v0, v3, v2, v1, v4}, Llyiahf/vczjk/cu1;-><init>(FFFF)V

    sput-object v0, Llyiahf/vczjk/fa7;->OooO0oo:Llyiahf/vczjk/cu1;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;JFJILlyiahf/vczjk/rf1;II)V
    .locals 31

    move/from16 v8, p8

    move-object/from16 v15, p7

    check-cast v15, Llyiahf/vczjk/zf1;

    const v0, -0x42b466e0

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p9, 0x1

    if-eqz v0, :cond_0

    or-int/lit8 v2, v8, 0x6

    move v3, v2

    move-object/from16 v2, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v2, v8, 0x6

    if-nez v2, :cond_2

    move-object/from16 v2, p0

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/4 v3, 0x4

    goto :goto_0

    :cond_1
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v8

    goto :goto_1

    :cond_2
    move-object/from16 v2, p0

    move v3, v8

    :goto_1
    and-int/lit8 v4, v8, 0x30

    if-nez v4, :cond_4

    and-int/lit8 v4, p9, 0x2

    move-wide/from16 v6, p1

    if-nez v4, :cond_3

    invoke-virtual {v15, v6, v7}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v4

    if-eqz v4, :cond_3

    const/16 v4, 0x20

    goto :goto_2

    :cond_3
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v3, v4

    goto :goto_3

    :cond_4
    move-wide/from16 v6, p1

    :goto_3
    and-int/lit8 v4, p9, 0x4

    if-eqz v4, :cond_6

    or-int/lit16 v3, v3, 0x180

    :cond_5
    move/from16 v10, p3

    goto :goto_5

    :cond_6
    and-int/lit16 v10, v8, 0x180

    if-nez v10, :cond_5

    move/from16 v10, p3

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v11

    if-eqz v11, :cond_7

    const/16 v11, 0x100

    goto :goto_4

    :cond_7
    const/16 v11, 0x80

    :goto_4
    or-int/2addr v3, v11

    :goto_5
    and-int/lit8 v11, p9, 0x8

    if-eqz v11, :cond_9

    or-int/lit16 v3, v3, 0xc00

    :cond_8
    move-wide/from16 v13, p4

    goto :goto_7

    :cond_9
    and-int/lit16 v13, v8, 0xc00

    if-nez v13, :cond_8

    move-wide/from16 v13, p4

    invoke-virtual {v15, v13, v14}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v16

    if-eqz v16, :cond_a

    const/16 v16, 0x800

    goto :goto_6

    :cond_a
    const/16 v16, 0x400

    :goto_6
    or-int v3, v3, v16

    :goto_7
    and-int/lit16 v9, v8, 0x6000

    if-nez v9, :cond_d

    and-int/lit8 v9, p9, 0x10

    if-nez v9, :cond_b

    move/from16 v9, p6

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v16

    if-eqz v16, :cond_c

    const/16 v16, 0x4000

    goto :goto_8

    :cond_b
    move/from16 v9, p6

    :cond_c
    const/16 v16, 0x2000

    :goto_8
    or-int v3, v3, v16

    goto :goto_9

    :cond_d
    move/from16 v9, p6

    :goto_9
    and-int/lit16 v12, v3, 0x2493

    const/4 v5, 0x1

    const/16 v1, 0x2492

    const/4 v14, 0x0

    if-eq v12, v1, :cond_e

    move v1, v5

    goto :goto_a

    :cond_e
    move v1, v14

    :goto_a
    and-int/lit8 v12, v3, 0x1

    invoke-virtual {v15, v12, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_1f

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v1, v8, 0x1

    const v12, -0xe001

    if-eqz v1, :cond_12

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v1

    if-eqz v1, :cond_f

    goto :goto_c

    :cond_f
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v0, p9, 0x2

    if-eqz v0, :cond_10

    and-int/lit8 v3, v3, -0x71

    :cond_10
    and-int/lit8 v0, p9, 0x10

    if-eqz v0, :cond_11

    and-int/2addr v3, v12

    :cond_11
    move-wide/from16 v20, p4

    move-object v0, v2

    :goto_b
    move v1, v10

    goto :goto_f

    :cond_12
    :goto_c
    if-eqz v0, :cond_13

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_d

    :cond_13
    move-object v0, v2

    :goto_d
    and-int/lit8 v1, p9, 0x2

    if-eqz v1, :cond_14

    sget-object v1, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/k31;

    invoke-virtual {v1}, Llyiahf/vczjk/k31;->OooO0O0()J

    move-result-wide v1

    and-int/lit8 v3, v3, -0x71

    move-wide v6, v1

    :cond_14
    if-eqz v4, :cond_15

    sget v1, Llyiahf/vczjk/r97;->OooO00o:F

    move v10, v1

    :cond_15
    if-eqz v11, :cond_16

    sget-wide v1, Llyiahf/vczjk/n21;->OooO:J

    goto :goto_e

    :cond_16
    move-wide/from16 v1, p4

    :goto_e
    and-int/lit8 v4, p9, 0x10

    if-eqz v4, :cond_17

    and-int/2addr v3, v12

    move-wide/from16 v20, v1

    move v1, v10

    const/4 v9, 0x2

    goto :goto_f

    :cond_17
    move-wide/from16 v20, v1

    goto :goto_b

    :goto_f
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget-object v2, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/f62;

    new-instance v22, Llyiahf/vczjk/h79;

    invoke-interface {v2, v1}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v2

    const/4 v4, 0x0

    const/4 v10, 0x0

    const/16 v11, 0x1a

    move/from16 p1, v2

    move/from16 p2, v4

    move/from16 p3, v9

    move/from16 p4, v10

    move/from16 p5, v11

    move-object/from16 p0, v22

    invoke-direct/range {p0 .. p5}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    move-object/from16 v4, p0

    move/from16 v2, p3

    invoke-static {v5, v15}, Llyiahf/vczjk/rs;->OoooOO0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/jy3;

    move-result-object v9

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    const/4 v11, 0x5

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/gda;->OooO0O0:Llyiahf/vczjk/n1a;

    sget-object v13, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    const/16 v5, 0x1a04

    move-object/from16 v30, v0

    const/4 v0, 0x2

    invoke-static {v5, v14, v13, v0}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v5

    const/4 v0, 0x6

    invoke-static {v5, v0}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v5

    const/16 v17, 0x10

    move/from16 v22, v14

    const/4 v14, 0x0

    const/16 v23, 0x800

    const v16, 0x81b8

    move-object v0, v13

    move-object v13, v5

    move/from16 v5, v22

    invoke-static/range {v9 .. v17}, Llyiahf/vczjk/rs;->OooO0o(Llyiahf/vczjk/jy3;Ljava/lang/Number;Ljava/lang/Number;Llyiahf/vczjk/n1a;Llyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v10

    const/16 v11, 0x534

    const/4 v12, 0x2

    invoke-static {v11, v5, v0, v12}, Llyiahf/vczjk/ng0;->OooooO0(IILlyiahf/vczjk/ik2;I)Llyiahf/vczjk/h1a;

    move-result-object v0

    const/4 v12, 0x6

    invoke-static {v0, v12}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v0

    const/4 v12, 0x0

    const/high16 v13, 0x438f0000    # 286.0f

    const/4 v14, 0x0

    const/16 v16, 0x11b8

    const/16 v17, 0x8

    move-object/from16 p3, v0

    move-object/from16 p0, v9

    move/from16 p1, v12

    move/from16 p2, v13

    move-object/from16 p4, v14

    move-object/from16 p5, v15

    move/from16 p6, v16

    move/from16 p7, v17

    invoke-static/range {p0 .. p7}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v0

    move/from16 v12, p6

    new-instance v13, Llyiahf/vczjk/vj4;

    new-instance v14, Llyiahf/vczjk/uj4;

    invoke-direct {v14}, Llyiahf/vczjk/uj4;-><init>()V

    iput v11, v14, Llyiahf/vczjk/uj4;->OooO00o:I

    const/16 v16, 0x0

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v12

    invoke-virtual {v14, v5, v12}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v12

    sget-object v5, Llyiahf/vczjk/fa7;->OooO0oo:Llyiahf/vczjk/cu1;

    iput-object v5, v12, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    const/high16 v18, 0x43910000    # 290.0f

    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v12

    const/16 v11, 0x29a

    invoke-virtual {v14, v11, v12}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v13, v14}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v12, 0x6

    invoke-static {v13, v12}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v13

    const/4 v12, 0x0

    const/high16 v14, 0x43910000    # 290.0f

    const/16 v24, 0x0

    const/16 v25, 0x8

    move-object/from16 p0, v9

    move/from16 p1, v12

    move-object/from16 p3, v13

    move/from16 p2, v14

    move-object/from16 p5, v15

    move-object/from16 p4, v24

    move/from16 p7, v25

    const/16 p6, 0x11b8

    invoke-static/range {p0 .. p7}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v9

    move-object/from16 v12, p0

    move/from16 v13, p6

    new-instance v14, Llyiahf/vczjk/vj4;

    new-instance v13, Llyiahf/vczjk/uj4;

    invoke-direct {v13}, Llyiahf/vczjk/uj4;-><init>()V

    const/16 v11, 0x534

    iput v11, v13, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v11

    move/from16 v23, v1

    const/16 v1, 0x29a

    invoke-virtual {v13, v1, v11}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v1

    iput-object v5, v1, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {v18 .. v18}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    iget v5, v13, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-virtual {v13, v5, v1}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v14, v13}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v1, 0x6

    invoke-static {v14, v1}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v1

    const/4 v5, 0x0

    const/high16 v11, 0x43910000    # 290.0f

    const/4 v13, 0x0

    const/16 v14, 0x8

    move-object/from16 p3, v1

    move/from16 p1, v5

    move/from16 p2, v11

    move-object/from16 p0, v12

    move-object/from16 p4, v13

    move/from16 p7, v14

    move-object/from16 p5, v15

    const/16 p6, 0x11b8

    invoke-static/range {p0 .. p7}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v1

    invoke-static/range {v30 .. v30}, Llyiahf/vczjk/rl6;->OooOo0o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget v11, Llyiahf/vczjk/fa7;->OooO0OO:F

    invoke-static {v5, v11}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    and-int/lit16 v11, v3, 0x1c00

    const/16 v12, 0x800

    if-ne v11, v12, :cond_18

    const/4 v14, 0x1

    goto :goto_10

    :cond_18
    const/4 v14, 0x0

    :goto_10
    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v11, v14

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    and-int/lit16 v12, v3, 0x380

    const/16 v13, 0x100

    if-ne v12, v13, :cond_19

    const/4 v14, 0x1

    goto :goto_11

    :cond_19
    const/4 v14, 0x0

    :goto_11
    or-int/2addr v11, v14

    and-int/lit8 v12, v3, 0x70

    xor-int/lit8 v12, v12, 0x30

    const/16 v13, 0x20

    if-le v12, v13, :cond_1a

    invoke-virtual {v15, v6, v7}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v12

    if-nez v12, :cond_1b

    :cond_1a
    and-int/lit8 v3, v3, 0x30

    if-ne v3, v13, :cond_1c

    :cond_1b
    const/16 v19, 0x1

    goto :goto_12

    :cond_1c
    const/16 v19, 0x0

    :goto_12
    or-int v3, v11, v19

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v3, :cond_1e

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v11, v3, :cond_1d

    goto :goto_13

    :cond_1d
    move-wide/from16 v24, v6

    goto :goto_14

    :cond_1e
    :goto_13
    new-instance v19, Llyiahf/vczjk/y97;

    move-object/from16 v29, v0

    move-object/from16 v28, v1

    move-object/from16 v22, v4

    move-wide/from16 v24, v6

    move-object/from16 v27, v9

    move-object/from16 v26, v10

    invoke-direct/range {v19 .. v29}, Llyiahf/vczjk/y97;-><init>(JLlyiahf/vczjk/h79;FJLlyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;)V

    move-object/from16 v11, v19

    invoke-virtual {v15, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_14
    check-cast v11, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-static {v5, v11, v15, v0}, Llyiahf/vczjk/vc6;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    move v7, v2

    move-wide/from16 v5, v20

    move/from16 v4, v23

    move-wide/from16 v2, v24

    move-object/from16 v1, v30

    goto :goto_15

    :cond_1f
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v1, v2

    move-wide v2, v6

    move v7, v9

    move v4, v10

    move-wide/from16 v5, p4

    :goto_15
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v10

    if-eqz v10, :cond_20

    new-instance v0, Llyiahf/vczjk/z97;

    move/from16 v9, p9

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/z97;-><init>(Llyiahf/vczjk/kl5;JFJIII)V

    iput-object v0, v10, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_20
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;JJILlyiahf/vczjk/rf1;II)V
    .locals 32

    move/from16 v7, p7

    move-object/from16 v13, p6

    check-cast v13, Llyiahf/vczjk/zf1;

    const v0, 0x598122d0

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p8, 0x1

    if-eqz v0, :cond_0

    or-int/lit8 v1, v7, 0x6

    move v2, v1

    move-object/from16 v1, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v1, v7, 0x6

    if-nez v1, :cond_2

    move-object/from16 v1, p0

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    const/4 v2, 0x4

    goto :goto_0

    :cond_1
    const/4 v2, 0x2

    :goto_0
    or-int/2addr v2, v7

    goto :goto_1

    :cond_2
    move-object/from16 v1, p0

    move v2, v7

    :goto_1
    and-int/lit8 v3, v7, 0x30

    if-nez v3, :cond_4

    and-int/lit8 v3, p8, 0x2

    move-wide/from16 v5, p1

    if-nez v3, :cond_3

    invoke-virtual {v13, v5, v6}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v3

    if-eqz v3, :cond_3

    const/16 v3, 0x20

    goto :goto_2

    :cond_3
    const/16 v3, 0x10

    :goto_2
    or-int/2addr v2, v3

    goto :goto_3

    :cond_4
    move-wide/from16 v5, p1

    :goto_3
    and-int/lit16 v3, v7, 0x180

    const/16 v8, 0x100

    if-nez v3, :cond_6

    and-int/lit8 v3, p8, 0x4

    move-wide/from16 v9, p3

    if-nez v3, :cond_5

    invoke-virtual {v13, v9, v10}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v3

    if-eqz v3, :cond_5

    move v3, v8

    goto :goto_4

    :cond_5
    const/16 v3, 0x80

    :goto_4
    or-int/2addr v2, v3

    goto :goto_5

    :cond_6
    move-wide/from16 v9, p3

    :goto_5
    and-int/lit16 v3, v7, 0xc00

    const/16 v11, 0x800

    if-nez v3, :cond_9

    and-int/lit8 v3, p8, 0x8

    if-nez v3, :cond_7

    move/from16 v3, p5

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v12

    if-eqz v12, :cond_8

    move v12, v11

    goto :goto_6

    :cond_7
    move/from16 v3, p5

    :cond_8
    const/16 v12, 0x400

    :goto_6
    or-int/2addr v2, v12

    goto :goto_7

    :cond_9
    move/from16 v3, p5

    :goto_7
    and-int/lit16 v12, v2, 0x493

    const/4 v14, 0x1

    const/16 v15, 0x492

    const/4 v4, 0x0

    if-eq v12, v15, :cond_a

    move v12, v14

    goto :goto_8

    :cond_a
    move v12, v4

    :goto_8
    and-int/lit8 v15, v2, 0x1

    invoke-virtual {v13, v15, v12}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v12

    if-eqz v12, :cond_1f

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v12, v7, 0x1

    if-eqz v12, :cond_10

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v12

    if-eqz v12, :cond_b

    goto :goto_9

    :cond_b
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit8 v0, p8, 0x2

    if-eqz v0, :cond_c

    and-int/lit8 v2, v2, -0x71

    :cond_c
    and-int/lit8 v0, p8, 0x4

    if-eqz v0, :cond_d

    and-int/lit16 v2, v2, -0x381

    :cond_d
    and-int/lit8 v0, p8, 0x8

    if-eqz v0, :cond_e

    and-int/lit16 v2, v2, -0x1c01

    :cond_e
    move-object v0, v1

    :cond_f
    move-wide/from16 v30, v9

    move v9, v2

    move-wide/from16 v1, v30

    goto :goto_b

    :cond_10
    :goto_9
    if-eqz v0, :cond_11

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_a

    :cond_11
    move-object v0, v1

    :goto_a
    and-int/lit8 v1, p8, 0x2

    if-eqz v1, :cond_12

    sget-object v1, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/k31;

    invoke-virtual {v1}, Llyiahf/vczjk/k31;->OooO0O0()J

    move-result-wide v5

    and-int/lit8 v2, v2, -0x71

    :cond_12
    and-int/lit8 v1, p8, 0x4

    if-eqz v1, :cond_13

    const v1, 0x3e75c28f    # 0.24f

    invoke-static {v1, v5, v6}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v9

    and-int/lit16 v1, v2, -0x381

    move v2, v1

    :cond_13
    and-int/lit8 v1, p8, 0x8

    if-eqz v1, :cond_f

    and-int/lit16 v2, v2, -0x1c01

    move-wide/from16 v30, v9

    move v9, v2

    move-wide/from16 v1, v30

    move v3, v4

    :goto_b
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo0()V

    move v10, v8

    invoke-static {v14, v13}, Llyiahf/vczjk/rs;->OoooOO0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/jy3;

    move-result-object v8

    new-instance v12, Llyiahf/vczjk/vj4;

    new-instance v15, Llyiahf/vczjk/uj4;

    invoke-direct {v15}, Llyiahf/vczjk/uj4;-><init>()V

    move/from16 p0, v9

    const/16 v9, 0x708

    iput v9, v15, Llyiahf/vczjk/uj4;->OooO00o:I

    const/16 p2, 0x0

    invoke-static/range {p2 .. p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v9

    invoke-virtual {v15, v4, v9}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/fa7;->OooO0Oo:Llyiahf/vczjk/cu1;

    iput-object v10, v9, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    const/high16 v16, 0x3f800000    # 1.0f

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v9

    const/16 v10, 0x2ee

    invoke-virtual {v15, v10, v9}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v12, v15}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v9, 0x6

    invoke-static {v12, v9}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v10

    move v12, v9

    const/4 v9, 0x0

    move v15, v11

    move-object v11, v10

    const/high16 v10, 0x3f800000    # 1.0f

    move/from16 v17, v12

    const/4 v12, 0x0

    move/from16 v18, v14

    const/16 v14, 0x11b8

    move/from16 v19, v15

    const/16 v15, 0x8

    const/16 v4, 0x708

    move/from16 v26, p0

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v21

    new-instance v9, Llyiahf/vczjk/vj4;

    new-instance v10, Llyiahf/vczjk/uj4;

    invoke-direct {v10}, Llyiahf/vczjk/uj4;-><init>()V

    iput v4, v10, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static/range {p2 .. p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v11

    const/16 v12, 0x14d

    invoke-virtual {v10, v12, v11}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/fa7;->OooO0o0:Llyiahf/vczjk/cu1;

    iput-object v12, v11, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v11

    const/16 v12, 0x49f

    invoke-virtual {v10, v12, v11}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v9, v10}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v10, 0x6

    invoke-static {v9, v10}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v11

    const/4 v9, 0x0

    move v12, v10

    const/high16 v10, 0x3f800000    # 1.0f

    move/from16 v27, v12

    const/4 v12, 0x0

    const/16 v15, 0x8

    move-object/from16 v28, v21

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v22

    new-instance v9, Llyiahf/vczjk/vj4;

    new-instance v10, Llyiahf/vczjk/uj4;

    invoke-direct {v10}, Llyiahf/vczjk/uj4;-><init>()V

    iput v4, v10, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static/range {p2 .. p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v11

    const/16 v12, 0x3e8

    invoke-virtual {v10, v12, v11}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/fa7;->OooO0o:Llyiahf/vczjk/cu1;

    iput-object v12, v11, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v11

    const/16 v12, 0x61f

    invoke-virtual {v10, v12, v11}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v9, v10}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v10, 0x6

    invoke-static {v9, v10}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v11

    const/4 v9, 0x0

    move v12, v10

    const/high16 v10, 0x3f800000    # 1.0f

    move/from16 v27, v12

    const/4 v12, 0x0

    const/16 v15, 0x8

    move-object/from16 v29, v22

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v23

    new-instance v9, Llyiahf/vczjk/vj4;

    new-instance v10, Llyiahf/vczjk/uj4;

    invoke-direct {v10}, Llyiahf/vczjk/uj4;-><init>()V

    iput v4, v10, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static/range {p2 .. p2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v11

    const/16 v12, 0x4f3

    invoke-virtual {v10, v12, v11}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v11

    sget-object v12, Llyiahf/vczjk/fa7;->OooO0oO:Llyiahf/vczjk/cu1;

    iput-object v12, v11, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static/range {v16 .. v16}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v11

    invoke-virtual {v10, v4, v11}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {v9, v10}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v12, 0x6

    invoke-static {v9, v12}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v11

    const/4 v9, 0x0

    const/high16 v10, 0x3f800000    # 1.0f

    const/4 v12, 0x0

    const/16 v15, 0x8

    move-object/from16 v4, v23

    invoke-static/range {v8 .. v15}, Llyiahf/vczjk/rs;->OooO0o0(Llyiahf/vczjk/jy3;FFLlyiahf/vczjk/cy3;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/dy3;

    move-result-object v8

    const/16 v9, 0xa

    int-to-float v9, v9

    new-instance v10, Llyiahf/vczjk/da7;

    invoke-direct {v10, v9}, Llyiahf/vczjk/da7;-><init>(F)V

    invoke-static {v0, v10}, Landroidx/compose/ui/layout/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/x77;->OooOOOO:Llyiahf/vczjk/x77;

    const/4 v12, 0x1

    invoke-static {v10, v12, v11}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v10

    move/from16 v11, p2

    invoke-static {v10, v11, v9, v12}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/rl6;->OooOo0o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget v10, Llyiahf/vczjk/fa7;->OooO0O0:F

    sget v11, Llyiahf/vczjk/fa7;->OooO00o:F

    invoke-static {v9, v10, v11}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOO0(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v9

    move/from16 v10, v26

    and-int/lit16 v11, v10, 0x380

    xor-int/lit16 v11, v11, 0x180

    const/16 v14, 0x100

    if-le v11, v14, :cond_14

    invoke-virtual {v13, v1, v2}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v11

    if-nez v11, :cond_15

    :cond_14
    and-int/lit16 v11, v10, 0x180

    if-ne v11, v14, :cond_16

    :cond_15
    move v14, v12

    goto :goto_c

    :cond_16
    const/4 v14, 0x0

    :goto_c
    and-int/lit16 v11, v10, 0x1c00

    xor-int/lit16 v11, v11, 0xc00

    const/16 v15, 0x800

    if-le v11, v15, :cond_17

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v11

    if-nez v11, :cond_18

    :cond_17
    and-int/lit16 v11, v10, 0xc00

    if-ne v11, v15, :cond_19

    :cond_18
    move v11, v12

    goto :goto_d

    :cond_19
    const/4 v11, 0x0

    :goto_d
    or-int/2addr v11, v14

    move-object/from16 v14, v28

    invoke-virtual {v13, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    or-int/2addr v11, v15

    move-object/from16 v15, v29

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v16

    or-int v11, v11, v16

    and-int/lit8 v16, v10, 0x70

    xor-int/lit8 v12, v16, 0x30

    move-object/from16 v25, v0

    const/16 v0, 0x20

    if-le v12, v0, :cond_1a

    invoke-virtual {v13, v5, v6}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v12

    if-nez v12, :cond_1b

    :cond_1a
    and-int/lit8 v10, v10, 0x30

    if-ne v10, v0, :cond_1c

    :cond_1b
    const/16 v18, 0x1

    goto :goto_e

    :cond_1c
    const/16 v18, 0x0

    :goto_e
    or-int v0, v11, v18

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v0, v10

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v0, v10

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v0, :cond_1d

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v10, v0, :cond_1e

    :cond_1d
    move-object/from16 v29, v15

    goto :goto_f

    :cond_1e
    move-wide/from16 v16, v1

    move/from16 v18, v3

    move-wide/from16 v19, v5

    goto :goto_10

    :goto_f
    new-instance v15, Llyiahf/vczjk/aa7;

    move-wide/from16 v16, v1

    move/from16 v18, v3

    move-object/from16 v23, v4

    move-wide/from16 v19, v5

    move-object/from16 v24, v8

    move-object/from16 v21, v14

    move-object/from16 v22, v29

    invoke-direct/range {v15 .. v24}, Llyiahf/vczjk/aa7;-><init>(JIJLlyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;)V

    invoke-virtual {v13, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v10, v15

    :goto_10
    check-cast v10, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-static {v9, v10, v13, v0}, Llyiahf/vczjk/vc6;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    move-wide/from16 v4, v16

    move/from16 v6, v18

    move-wide/from16 v2, v19

    move-object/from16 v1, v25

    goto :goto_11

    :cond_1f
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-wide/from16 v30, v5

    move v6, v3

    move-wide/from16 v2, v30

    move-wide v4, v9

    :goto_11
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v9

    if-eqz v9, :cond_20

    new-instance v0, Llyiahf/vczjk/ba7;

    move/from16 v8, p8

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/ba7;-><init>(Llyiahf/vczjk/kl5;JJIII)V

    iput-object v0, v9, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_20
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/hg2;FFJLlyiahf/vczjk/h79;)V
    .locals 12

    move-object/from16 v10, p5

    iget v0, v10, Llyiahf/vczjk/h79;->OooO00o:F

    const/4 v1, 0x2

    int-to-float v1, v1

    div-float/2addr v0, v1

    invoke-interface {p0}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v2

    invoke-static {v2, v3}, Llyiahf/vczjk/tq8;->OooO0Oo(J)F

    move-result v2

    mul-float/2addr v1, v0

    sub-float/2addr v2, v1

    invoke-static {v0, v0}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide v5

    invoke-static {v2, v2}, Llyiahf/vczjk/tn6;->OooO0O0(FF)J

    move-result-wide v7

    const/16 v11, 0x340

    const/4 v9, 0x0

    move-object v0, p0

    move v3, p1

    move v4, p2

    move-wide v1, p3

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/hg2;->OoooOoo(Llyiahf/vczjk/hg2;JFFJJFLlyiahf/vczjk/h79;I)V

    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/hg2;FFJFI)V
    .locals 17

    invoke-interface/range {p0 .. p0}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v0

    invoke-static {v0, v1}, Llyiahf/vczjk/tq8;->OooO0Oo(J)F

    move-result v0

    invoke-interface/range {p0 .. p0}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v1

    invoke-static {v1, v2}, Llyiahf/vczjk/tq8;->OooO0O0(J)F

    move-result v1

    const/4 v2, 0x2

    int-to-float v2, v2

    div-float v3, v1, v2

    invoke-interface/range {p0 .. p0}, Llyiahf/vczjk/hg2;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-ne v4, v5, :cond_0

    const/4 v4, 0x1

    goto :goto_0

    :cond_0
    const/4 v4, 0x0

    :goto_0
    const/high16 v5, 0x3f800000    # 1.0f

    if-eqz v4, :cond_1

    move/from16 v6, p1

    goto :goto_1

    :cond_1
    sub-float v6, v5, p2

    :goto_1
    mul-float/2addr v6, v0

    if-eqz v4, :cond_2

    move/from16 v5, p2

    goto :goto_2

    :cond_2
    sub-float v5, v5, p1

    :goto_2
    mul-float/2addr v5, v0

    if-nez p6, :cond_3

    goto :goto_3

    :cond_3
    cmpl-float v1, v1, v0

    if-lez v1, :cond_4

    :goto_3
    invoke-static {v6, v3}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide v10

    invoke-static {v5, v3}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide v12

    const/16 v16, 0x1f0

    const/4 v15, 0x0

    move-object/from16 v7, p0

    move-wide/from16 v8, p3

    move/from16 v14, p5

    invoke-static/range {v7 .. v16}, Llyiahf/vczjk/hg2;->OoooO(Llyiahf/vczjk/hg2;JJJFII)V

    return-void

    :cond_4
    div-float v1, p5, v2

    sub-float/2addr v0, v1

    new-instance v2, Llyiahf/vczjk/m01;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/m01;-><init>(FF)V

    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    invoke-static {v0, v2}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    invoke-static {v5}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    sub-float v2, p2, p1

    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    const/4 v4, 0x0

    cmpl-float v2, v2, v4

    if-lez v2, :cond_5

    invoke-static {v0, v3}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide v4

    invoke-static {v1, v3}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide v0

    const/16 v9, 0x1e0

    move/from16 v7, p5

    move/from16 v8, p6

    move-wide v3, v4

    move-wide v5, v0

    move-object/from16 v0, p0

    move-wide/from16 v1, p3

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/hg2;->OoooO(Llyiahf/vczjk/hg2;JJJFII)V

    :cond_5
    return-void
.end method
