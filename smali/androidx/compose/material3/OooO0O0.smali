.class public abstract Landroidx/compose/material3/OooO0O0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F

.field public static final OooO0O0:F

.field public static final OooO0OO:F

.field public static final OooO0Oo:F

.field public static final OooO0o:Llyiahf/vczjk/ev8;

.field public static final OooO0o0:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget v0, Llyiahf/vczjk/rc9;->OooOOOo:F

    sput v0, Landroidx/compose/material3/OooO0O0;->OooO00o:F

    sget v1, Llyiahf/vczjk/rc9;->OooOoO:F

    sput v1, Landroidx/compose/material3/OooO0O0;->OooO0O0:F

    sget v1, Llyiahf/vczjk/rc9;->OooOo0o:F

    sput v1, Landroidx/compose/material3/OooO0O0;->OooO0OO:F

    sget v1, Llyiahf/vczjk/rc9;->OooOo00:F

    sput v1, Landroidx/compose/material3/OooO0O0;->OooO0Oo:F

    sub-float/2addr v1, v0

    const/4 v0, 0x2

    int-to-float v0, v0

    div-float/2addr v1, v0

    sput v1, Landroidx/compose/material3/OooO0O0;->OooO0o0:F

    new-instance v0, Llyiahf/vczjk/ev8;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ev8;-><init>(I)V

    sput-object v0, Landroidx/compose/material3/OooO0O0;->OooO0o:Llyiahf/vczjk/ev8;

    return-void
.end method

.method public static final OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rf1;II)V
    .locals 48

    move-object/from16 v2, p1

    move/from16 v7, p6

    const/4 v0, 0x4

    const/4 v1, 0x1

    move-object/from16 v14, p5

    check-cast v14, Llyiahf/vczjk/zf1;

    const v3, -0xfb23c9f

    invoke-virtual {v14, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v3, v7, 0x6

    const/4 v8, 0x2

    move/from16 v9, p0

    if-nez v3, :cond_1

    invoke-virtual {v14, v9}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v3

    if-eqz v3, :cond_0

    move v3, v0

    goto :goto_0

    :cond_0
    move v3, v8

    :goto_0
    or-int/2addr v3, v7

    goto :goto_1

    :cond_1
    move v3, v7

    :goto_1
    and-int/lit8 v4, v7, 0x30

    if-nez v4, :cond_3

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v3, v4

    :cond_3
    and-int/lit8 v0, p7, 0x4

    if-eqz v0, :cond_5

    or-int/lit16 v3, v3, 0x180

    :cond_4
    move-object/from16 v4, p2

    goto :goto_4

    :cond_5
    and-int/lit16 v4, v7, 0x180

    if-nez v4, :cond_4

    move-object/from16 v4, p2

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_6

    const/16 v5, 0x100

    goto :goto_3

    :cond_6
    const/16 v5, 0x80

    :goto_3
    or-int/2addr v3, v5

    :goto_4
    or-int/lit16 v5, v3, 0x6c00

    const/high16 v6, 0x30000

    and-int/2addr v6, v7

    if-nez v6, :cond_7

    const v5, 0x16c00

    or-int/2addr v5, v3

    :cond_7
    const/high16 v3, 0x180000

    or-int/2addr v3, v5

    const v5, 0x92493

    and-int/2addr v5, v3

    const v6, 0x92492

    const/4 v10, 0x0

    if-eq v5, v6, :cond_8

    move v5, v1

    goto :goto_5

    :cond_8
    move v5, v10

    :goto_5
    and-int/lit8 v6, v3, 0x1

    invoke-virtual {v14, v6, v5}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v5

    if-eqz v5, :cond_f

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v5, v7, 0x1

    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v11, -0x70001

    if-eqz v5, :cond_a

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v5

    if-eqz v5, :cond_9

    goto :goto_7

    :cond_9
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int v0, v3, v11

    move-object/from16 v15, p4

    move-object v11, v4

    move/from16 v4, p3

    :goto_6
    move v12, v0

    goto/16 :goto_9

    :cond_a
    :goto_7
    if-eqz v0, :cond_b

    move-object v4, v6

    :cond_b
    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    iget-object v5, v0, Llyiahf/vczjk/x21;->o0OoOo0:Llyiahf/vczjk/nc9;

    if-nez v5, :cond_c

    new-instance v15, Llyiahf/vczjk/nc9;

    sget-object v5, Llyiahf/vczjk/rc9;->OooOOOO:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v16

    sget-object v5, Llyiahf/vczjk/rc9;->OooOOo:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v18

    sget-wide v20, Llyiahf/vczjk/n21;->OooO:J

    sget-object v5, Llyiahf/vczjk/rc9;->OooOOo0:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v22

    sget-object v5, Llyiahf/vczjk/rc9;->OooOoO0:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v24

    sget-object v5, Llyiahf/vczjk/rc9;->OooOoo0:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v26

    sget-object v5, Llyiahf/vczjk/rc9;->OooOo:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v28

    sget-object v5, Llyiahf/vczjk/rc9;->OooOoOO:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v30

    sget-object v5, Llyiahf/vczjk/rc9;->OooO00o:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v12

    sget v5, Llyiahf/vczjk/rc9;->OooO0O0:F

    invoke-static {v5, v12, v13}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v12

    iget-wide v1, v0, Llyiahf/vczjk/x21;->OooOOOo:J

    invoke-static {v12, v13, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v32

    sget-object v5, Llyiahf/vczjk/rc9;->OooO0o0:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v12

    sget v5, Llyiahf/vczjk/rc9;->OooO0o:F

    invoke-static {v5, v12, v13}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v12

    invoke-static {v12, v13, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v34

    sget-object v12, Llyiahf/vczjk/rc9;->OooO0OO:Llyiahf/vczjk/y21;

    invoke-static {v0, v12}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v12

    move/from16 p5, v11

    sget v11, Llyiahf/vczjk/rc9;->OooO0Oo:F

    invoke-static {v11, v12, v13}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v11

    invoke-static {v11, v12, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v38

    sget-object v11, Llyiahf/vczjk/rc9;->OooO0oO:Llyiahf/vczjk/y21;

    invoke-static {v0, v11}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v11

    sget v13, Llyiahf/vczjk/rc9;->OooO0oo:F

    invoke-static {v13, v11, v12}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v11

    invoke-static {v11, v12, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v40

    sget-object v11, Llyiahf/vczjk/rc9;->OooOO0O:Llyiahf/vczjk/y21;

    invoke-static {v0, v11}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v11

    invoke-static {v5, v11, v12}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v11

    invoke-static {v11, v12, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v42

    sget-object v11, Llyiahf/vczjk/rc9;->OooOO0o:Llyiahf/vczjk/y21;

    invoke-static {v0, v11}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v11

    invoke-static {v5, v11, v12}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v11

    invoke-static {v11, v12, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v44

    sget-object v5, Llyiahf/vczjk/rc9;->OooO:Llyiahf/vczjk/y21;

    invoke-static {v0, v5}, Llyiahf/vczjk/z21;->OooO0Oo(Llyiahf/vczjk/x21;Llyiahf/vczjk/y21;)J

    move-result-wide v11

    sget v5, Llyiahf/vczjk/rc9;->OooOO0:F

    invoke-static {v5, v11, v12}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v11

    invoke-static {v11, v12, v1, v2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide v46

    move-wide/from16 v36, v20

    invoke-direct/range {v15 .. v47}, Llyiahf/vczjk/nc9;-><init>(JJJJJJJJJJJJJJJJ)V

    iput-object v15, v0, Llyiahf/vczjk/x21;->o0OoOo0:Llyiahf/vczjk/nc9;

    goto :goto_8

    :cond_c
    move/from16 p5, v11

    move-object v15, v5

    :goto_8
    and-int v0, v3, p5

    move-object v11, v4

    const/4 v4, 0x1

    goto/16 :goto_6

    :goto_9
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOo0()V

    const v0, 0x696ac19a

    invoke-virtual {v14, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v0, v1, :cond_d

    invoke-static {v14}, Llyiahf/vczjk/ix8;->OooOOo0(Llyiahf/vczjk/zf1;)Llyiahf/vczjk/sr5;

    move-result-object v0

    :cond_d
    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/rr5;

    invoke-virtual {v14, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    if-eqz p1, :cond_e

    sget-object v0, Llyiahf/vczjk/r24;->OooO00o:Llyiahf/vczjk/go3;

    sget-object v0, Landroidx/compose/material3/MinimumInteractiveModifier;->OooOOO0:Landroidx/compose/material3/MinimumInteractiveModifier;

    new-instance v5, Llyiahf/vczjk/gu7;

    invoke-direct {v5, v8}, Llyiahf/vczjk/gu7;-><init>(I)V

    const/4 v3, 0x0

    move-object/from16 v6, p1

    move v1, v9

    invoke-static/range {v0 .. v6}, Landroidx/compose/foundation/selection/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/du7;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    move-object v6, v0

    :cond_e
    move v10, v4

    invoke-interface {v11, v6}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v0, v1, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooOo00(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ub0;I)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget v1, Landroidx/compose/material3/OooO0O0;->OooO0OO:F

    sget v3, Landroidx/compose/material3/OooO0O0;->OooO0Oo:F

    invoke-static {v0, v1, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v0, Llyiahf/vczjk/rc9;->OooOOO0:Llyiahf/vczjk/dk8;

    invoke-static {v0, v14}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v13

    shl-int/lit8 v0, v12, 0x3

    and-int/lit8 v1, v0, 0x70

    shr-int/lit8 v3, v12, 0x6

    and-int/lit16 v3, v3, 0x380

    or-int/2addr v1, v3

    const v3, 0xe000

    and-int/2addr v0, v3

    or-int/2addr v0, v1

    move/from16 v9, p0

    move-object v12, v2

    move-object v4, v11

    move-object v11, v15

    move v15, v0

    invoke-static/range {v8 .. v15}, Landroidx/compose/material3/OooO0O0;->OooO0O0(Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/qj8;Llyiahf/vczjk/rf1;I)V

    move-object v3, v4

    move v4, v10

    move-object v5, v11

    goto :goto_a

    :cond_f
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v5, p4

    move-object v3, v4

    move/from16 v4, p3

    :goto_a
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_10

    new-instance v0, Llyiahf/vczjk/pc9;

    move/from16 v1, p0

    move-object/from16 v2, p1

    move v6, v7

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/pc9;-><init>(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/nc9;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_10
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/qj8;Llyiahf/vczjk/rf1;I)V
    .locals 18

    move-object/from16 v1, p0

    move/from16 v2, p1

    move/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v7, p7

    move-object/from16 v0, p6

    check-cast v0, Llyiahf/vczjk/zf1;

    const v8, -0x27fd625d

    invoke-virtual {v0, v8}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v8, v7, 0x6

    if-nez v8, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_0

    const/4 v8, 0x4

    goto :goto_0

    :cond_0
    const/4 v8, 0x2

    :goto_0
    or-int/2addr v8, v7

    goto :goto_1

    :cond_1
    move v8, v7

    :goto_1
    and-int/lit8 v11, v7, 0x30

    if-nez v11, :cond_3

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v11

    if-eqz v11, :cond_2

    const/16 v11, 0x20

    goto :goto_2

    :cond_2
    const/16 v11, 0x10

    :goto_2
    or-int/2addr v8, v11

    :cond_3
    and-int/lit16 v11, v7, 0x180

    if-nez v11, :cond_5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v11

    if-eqz v11, :cond_4

    const/16 v11, 0x100

    goto :goto_3

    :cond_4
    const/16 v11, 0x80

    :goto_3
    or-int/2addr v8, v11

    :cond_5
    and-int/lit16 v11, v7, 0xc00

    if-nez v11, :cond_7

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_6

    const/16 v11, 0x800

    goto :goto_4

    :cond_6
    const/16 v11, 0x400

    :goto_4
    or-int/2addr v8, v11

    :cond_7
    and-int/lit16 v11, v7, 0x6000

    if-nez v11, :cond_9

    const/4 v11, 0x0

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_8

    const/16 v11, 0x4000

    goto :goto_5

    :cond_8
    const/16 v11, 0x2000

    :goto_5
    or-int/2addr v8, v11

    :cond_9
    const/high16 v11, 0x30000

    and-int/2addr v11, v7

    if-nez v11, :cond_b

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_a

    const/high16 v11, 0x20000

    goto :goto_6

    :cond_a
    const/high16 v11, 0x10000

    :goto_6
    or-int/2addr v8, v11

    :cond_b
    const/high16 v11, 0x180000

    and-int/2addr v11, v7

    if-nez v11, :cond_d

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_c

    const/high16 v11, 0x100000

    goto :goto_7

    :cond_c
    const/high16 v11, 0x80000

    :goto_7
    or-int/2addr v8, v11

    :cond_d
    const v11, 0x92493

    and-int/2addr v11, v8

    const v12, 0x92492

    const/4 v14, 0x1

    if-eq v11, v12, :cond_e

    move v11, v14

    goto :goto_8

    :cond_e
    const/4 v11, 0x0

    :goto_8
    and-int/2addr v8, v14

    invoke-virtual {v0, v8, v11}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v8

    if-eqz v8, :cond_1e

    if-eqz v3, :cond_10

    if-eqz v2, :cond_f

    iget-wide v11, v4, Llyiahf/vczjk/nc9;->OooO0O0:J

    goto :goto_9

    :cond_f
    iget-wide v11, v4, Llyiahf/vczjk/nc9;->OooO0o:J

    goto :goto_9

    :cond_10
    if-eqz v2, :cond_11

    iget-wide v11, v4, Llyiahf/vczjk/nc9;->OooOO0:J

    goto :goto_9

    :cond_11
    iget-wide v11, v4, Llyiahf/vczjk/nc9;->OooOOO:J

    :goto_9
    if-eqz v3, :cond_13

    if-eqz v2, :cond_12

    iget-wide v14, v4, Llyiahf/vczjk/nc9;->OooO00o:J

    goto :goto_a

    :cond_12
    iget-wide v14, v4, Llyiahf/vczjk/nc9;->OooO0o0:J

    goto :goto_a

    :cond_13
    if-eqz v2, :cond_14

    iget-wide v14, v4, Llyiahf/vczjk/nc9;->OooO:J

    goto :goto_a

    :cond_14
    iget-wide v14, v4, Llyiahf/vczjk/nc9;->OooOOO0:J

    :goto_a
    sget-object v8, Llyiahf/vczjk/rc9;->OooOo0O:Llyiahf/vczjk/dk8;

    invoke-static {v8, v0}, Llyiahf/vczjk/cl8;->OooO0O0(Llyiahf/vczjk/dk8;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qj8;

    move-result-object v8

    sget v9, Llyiahf/vczjk/rc9;->OooOo0:F

    if-eqz v3, :cond_16

    if-eqz v2, :cond_15

    move-wide/from16 v16, v14

    iget-wide v13, v4, Llyiahf/vczjk/nc9;->OooO0OO:J

    goto :goto_b

    :cond_15
    move-wide/from16 v16, v14

    iget-wide v13, v4, Llyiahf/vczjk/nc9;->OooO0oO:J

    goto :goto_b

    :cond_16
    move-wide/from16 v16, v14

    if-eqz v2, :cond_17

    iget-wide v13, v4, Llyiahf/vczjk/nc9;->OooOO0O:J

    goto :goto_b

    :cond_17
    iget-wide v13, v4, Llyiahf/vczjk/nc9;->OooOOOO:J

    :goto_b
    new-instance v15, Llyiahf/vczjk/gx8;

    invoke-direct {v15, v13, v14}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v13, Landroidx/compose/foundation/BorderModifierNodeElement;

    invoke-direct {v13, v9, v15, v8}, Landroidx/compose/foundation/BorderModifierNodeElement;-><init>(FLlyiahf/vczjk/gx8;Llyiahf/vczjk/qj8;)V

    invoke-interface {v1, v13}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-static {v9, v11, v12, v8}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v11, 0x0

    invoke-static {v9, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v9

    iget v11, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v0, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_18

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_c

    :cond_18
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_c
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v0, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v15, :cond_19

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v15, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_1a

    :cond_19
    invoke-static {v11, v0, v11, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1a
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v0, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    sget-object v11, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v15, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-virtual {v8, v11, v15}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v8

    new-instance v11, Landroidx/compose/material3/ThumbElement;

    sget-object v15, Llyiahf/vczjk/zo5;->OooOOO:Llyiahf/vczjk/zo5;

    invoke-static {v15, v0}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v15

    invoke-direct {v11, v5, v2, v15}, Landroidx/compose/material3/ThumbElement;-><init>(Llyiahf/vczjk/rr5;ZLlyiahf/vczjk/p13;)V

    invoke-interface {v8, v11}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget v11, Llyiahf/vczjk/rc9;->OooOOoo:F

    const/4 v15, 0x2

    int-to-float v15, v15

    div-float/2addr v11, v15

    const/4 v1, 0x0

    const/4 v15, 0x4

    invoke-static {v11, v15, v1}, Llyiahf/vczjk/zt7;->OooO00o(FIZ)Llyiahf/vczjk/du7;

    move-result-object v11

    invoke-static {v8, v5, v11}, Landroidx/compose/foundation/OooO0o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/n24;Llyiahf/vczjk/lx3;)Llyiahf/vczjk/kl5;

    move-result-object v8

    move-wide/from16 v1, v16

    invoke-static {v8, v1, v2, v6}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    const/4 v11, 0x0

    invoke-static {v2, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v2

    iget v8, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v0, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_1b

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_d

    :cond_1b
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_d
    invoke-static {v2, v0, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_1c

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v2, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1d

    :cond_1c
    invoke-static {v8, v0, v8, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1d
    invoke-static {v1, v0, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v1, 0x49acf013

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v11, 0x0

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_e

    :cond_1e
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_e
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_1f

    new-instance v0, Llyiahf/vczjk/qc9;

    move-object/from16 v1, p0

    move/from16 v2, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/qc9;-><init>(Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rr5;Llyiahf/vczjk/qj8;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1f
    return-void
.end method
