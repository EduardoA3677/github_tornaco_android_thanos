.class public abstract Llyiahf/vczjk/ut3;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/16 v0, 0x18

    int-to-float v0, v0

    sput v0, Llyiahf/vczjk/ut3;->OooO00o:F

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V
    .locals 17

    move-object/from16 v5, p4

    move/from16 v6, p6

    const/16 v0, 0x8

    const/16 v1, 0x10

    const/4 v2, 0x2

    move-object/from16 v3, p5

    check-cast v3, Llyiahf/vczjk/zf1;

    const v4, -0x69eb252

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const/4 v4, 0x1

    and-int/lit8 v7, p7, 0x1

    const/4 v8, 0x4

    if-eqz v7, :cond_0

    or-int/lit8 v7, v6, 0x6

    move-object/from16 v14, p0

    goto :goto_1

    :cond_0
    and-int/lit8 v7, v6, 0x6

    move-object/from16 v14, p0

    if-nez v7, :cond_2

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_1

    move v7, v8

    goto :goto_0

    :cond_1
    move v7, v2

    :goto_0
    or-int/2addr v7, v6

    goto :goto_1

    :cond_2
    move v7, v6

    :goto_1
    and-int/lit8 v2, p7, 0x2

    if-eqz v2, :cond_4

    or-int/lit8 v7, v7, 0x30

    :cond_3
    move-object/from16 v9, p1

    goto :goto_3

    :cond_4
    and-int/lit8 v9, v6, 0x30

    if-nez v9, :cond_3

    move-object/from16 v9, p1

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_5

    const/16 v10, 0x20

    goto :goto_2

    :cond_5
    move v10, v1

    :goto_2
    or-int/2addr v7, v10

    :goto_3
    and-int/lit8 v10, p7, 0x4

    if-eqz v10, :cond_7

    or-int/lit16 v7, v7, 0x180

    :cond_6
    move/from16 v11, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v11, v6, 0x180

    if-nez v11, :cond_6

    move/from16 v11, p2

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v12

    if-eqz v12, :cond_8

    const/16 v12, 0x100

    goto :goto_4

    :cond_8
    const/16 v12, 0x80

    :goto_4
    or-int/2addr v7, v12

    :goto_5
    and-int/lit8 v12, p7, 0x8

    if-eqz v12, :cond_a

    or-int/lit16 v7, v7, 0xc00

    :cond_9
    move-object/from16 v13, p3

    goto :goto_7

    :cond_a
    and-int/lit16 v13, v6, 0xc00

    if-nez v13, :cond_9

    move-object/from16 v13, p3

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_b

    const/16 v15, 0x800

    goto :goto_6

    :cond_b
    const/16 v15, 0x400

    :goto_6
    or-int/2addr v7, v15

    :goto_7
    and-int/lit8 v1, p7, 0x10

    if-eqz v1, :cond_c

    or-int/lit16 v7, v7, 0x6000

    goto :goto_9

    :cond_c
    and-int/lit16 v1, v6, 0x6000

    if-nez v1, :cond_e

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_d

    const/16 v1, 0x4000

    goto :goto_8

    :cond_d
    const/16 v1, 0x2000

    :goto_8
    or-int/2addr v7, v1

    :cond_e
    :goto_9
    and-int/lit16 v1, v7, 0x2493

    const/16 v15, 0x2492

    move/from16 v16, v0

    const/4 v0, 0x0

    if-eq v1, v15, :cond_f

    move v1, v4

    goto :goto_a

    :cond_f
    move v1, v0

    :goto_a
    and-int/lit8 v15, v7, 0x1

    invoke-virtual {v3, v15, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_18

    if-eqz v2, :cond_10

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_b

    :cond_10
    move-object v1, v9

    :goto_b
    move v2, v12

    if-eqz v10, :cond_11

    move v12, v4

    goto :goto_c

    :cond_11
    move v12, v11

    :goto_c
    if-eqz v2, :cond_12

    const/4 v2, 0x0

    move-object v10, v2

    goto :goto_d

    :cond_12
    move-object v10, v13

    :goto_d
    sget-object v2, Llyiahf/vczjk/s24;->OooO00o:Llyiahf/vczjk/l39;

    sget-object v2, Landroidx/compose/material/MinimumInteractiveModifier;->OooOOO0:Landroidx/compose/material/MinimumInteractiveModifier;

    invoke-interface {v1, v2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-static {v8, v0}, Llyiahf/vczjk/au7;->OooO00o(IZ)Llyiahf/vczjk/eu7;

    move-result-object v11

    new-instance v13, Llyiahf/vczjk/gu7;

    invoke-direct {v13, v0}, Llyiahf/vczjk/gu7;-><init>(I)V

    const/16 v15, 0x8

    invoke-static/range {v9 .. v15}, Landroidx/compose/foundation/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLlyiahf/vczjk/gu7;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v8, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v8, v0}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v8

    iget v9, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v3, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_13

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_e

    :cond_13
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_e
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v8, v3, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v11, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v11, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v11, :cond_14

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v11, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-nez v11, :cond_15

    :cond_14
    invoke-static {v9, v3, v9, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_15
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    if-eqz v12, :cond_16

    const v2, 0x7060d077

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/gm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_10

    :cond_16
    const v2, 0x7060d3b8

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/lm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n21;

    iget-wide v8, v2, Llyiahf/vczjk/n21;->OooO00o:J

    sget-object v2, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/k31;

    invoke-virtual {v2}, Llyiahf/vczjk/k31;->OooO0Oo()Z

    move-result v2

    if-eqz v2, :cond_17

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooooOO(J)F

    goto :goto_f

    :cond_17
    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooooOO(J)F

    :goto_f
    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, 0x3ec28f5c    # 0.38f

    :goto_10
    sget-object v0, Llyiahf/vczjk/gm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v0

    shr-int/lit8 v2, v7, 0x9

    and-int/lit8 v2, v2, 0x70

    or-int v2, v16, v2

    invoke-static {v0, v5, v3, v2}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v2, v1

    move-object v0, v3

    move-object v4, v10

    move v3, v12

    goto :goto_11

    :cond_18
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v0, v3

    move-object v2, v9

    move v3, v11

    move-object v4, v13

    :goto_11
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_19

    new-instance v0, Llyiahf/vczjk/tt3;

    move-object/from16 v1, p0

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/tt3;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/ze3;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_19
    return-void
.end method
