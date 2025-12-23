.class public abstract Llyiahf/vczjk/of;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/jh1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/u;->OooOo0o:Llyiahf/vczjk/u;

    new-instance v1, Llyiahf/vczjk/jh1;

    invoke-direct {v1, v0}, Llyiahf/vczjk/jh1;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Llyiahf/vczjk/of;->OooO00o:Llyiahf/vczjk/jh1;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V
    .locals 25

    move-object/from16 v1, p0

    move-object/from16 v8, p3

    move/from16 v9, p5

    move-object/from16 v5, p4

    check-cast v5, Llyiahf/vczjk/zf1;

    const v0, -0x317c909c

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p6, 0x1

    if-eqz v0, :cond_0

    or-int/lit8 v0, v9, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v0, v9, 0x6

    if-nez v0, :cond_2

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/4 v0, 0x4

    goto :goto_0

    :cond_1
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v9

    goto :goto_1

    :cond_2
    move v0, v9

    :goto_1
    and-int/lit8 v2, p6, 0x2

    if-eqz v2, :cond_4

    or-int/lit8 v0, v0, 0x30

    :cond_3
    move-object/from16 v3, p1

    goto :goto_3

    :cond_4
    and-int/lit8 v3, v9, 0x30

    if-nez v3, :cond_3

    move-object/from16 v3, p1

    invoke-virtual {v5, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_5

    const/16 v4, 0x20

    goto :goto_2

    :cond_5
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v0, v4

    :goto_3
    and-int/lit8 v4, p6, 0x4

    if-eqz v4, :cond_7

    or-int/lit16 v0, v0, 0x180

    :cond_6
    move-object/from16 v6, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v6, v9, 0x180

    if-nez v6, :cond_6

    move-object/from16 v6, p2

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_8

    const/16 v7, 0x100

    goto :goto_4

    :cond_8
    const/16 v7, 0x80

    :goto_4
    or-int/2addr v0, v7

    :goto_5
    and-int/lit8 v7, p6, 0x8

    if-eqz v7, :cond_a

    or-int/lit16 v0, v0, 0xc00

    :cond_9
    :goto_6
    move v13, v0

    goto :goto_8

    :cond_a
    and-int/lit16 v7, v9, 0xc00

    if-nez v7, :cond_9

    invoke-virtual {v5, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_b

    const/16 v7, 0x800

    goto :goto_7

    :cond_b
    const/16 v7, 0x400

    :goto_7
    or-int/2addr v0, v7

    goto :goto_6

    :goto_8
    and-int/lit16 v0, v13, 0x493

    const/4 v14, 0x1

    const/16 v7, 0x492

    const/4 v15, 0x0

    if-eq v0, v7, :cond_c

    move v0, v14

    goto :goto_9

    :cond_c
    move v0, v15

    :goto_9
    and-int/lit8 v7, v13, 0x1

    invoke-virtual {v5, v7, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_24

    const/4 v0, 0x0

    if-eqz v2, :cond_d

    move-object/from16 v18, v0

    goto :goto_a

    :cond_d
    move-object/from16 v18, v3

    :goto_a
    if-eqz v4, :cond_e

    new-instance v2, Llyiahf/vczjk/d07;

    const/16 v3, 0xf

    invoke-direct {v2, v3}, Llyiahf/vczjk/d07;-><init>(I)V

    move-object/from16 v19, v2

    goto :goto_b

    :cond_e
    move-object/from16 v19, v6

    :goto_b
    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0o:Llyiahf/vczjk/l39;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v16, v2

    check-cast v16, Landroid/view/View;

    sget-object v2, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v17, v2

    check-cast v17, Llyiahf/vczjk/f62;

    sget-object v2, Llyiahf/vczjk/of;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v20, v2

    check-cast v20, Ljava/lang/String;

    sget-object v2, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    move-object/from16 v21, v2

    check-cast v21, Llyiahf/vczjk/yn4;

    invoke-static {v5}, Llyiahf/vczjk/sb;->OoooO0(Llyiahf/vczjk/rf1;)Landroidx/compose/runtime/OooO00o;

    move-result-object v2

    invoke-static {v8, v5}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v3

    move-object v4, v2

    new-array v2, v15, [Ljava/lang/Object;

    move-object v6, v4

    sget-object v4, Llyiahf/vczjk/u;->OooOo:Llyiahf/vczjk/u;

    const/4 v7, 0x6

    move-object/from16 v22, v3

    const/4 v3, 0x0

    move-object/from16 v23, v6

    const/16 v6, 0xc00

    move-object/from16 v15, v21

    move-object/from16 v12, v22

    move-object/from16 v10, v23

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object v2

    move-object v7, v2

    check-cast v7, Ljava/util/UUID;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, v3, :cond_f

    move-object v4, v0

    new-instance v0, Llyiahf/vczjk/zz6;

    move-object v6, v1

    move-object/from16 v24, v3

    move-object v11, v5

    move-object/from16 v4, v16

    move-object/from16 v5, v17

    move-object/from16 v1, v18

    move-object/from16 v2, v19

    move-object/from16 v3, v20

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/zz6;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Ljava/lang/String;Landroid/view/View;Llyiahf/vczjk/f62;Llyiahf/vczjk/c07;Ljava/util/UUID;)V

    move-object v1, v6

    new-instance v2, Llyiahf/vczjk/lf;

    invoke-direct {v2, v0, v12}, Llyiahf/vczjk/lf;-><init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/qs5;)V

    new-instance v4, Llyiahf/vczjk/a91;

    const v5, 0x4da88f2f    # 3.53494496E8f

    invoke-direct {v4, v5, v2, v14}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-virtual {v0, v10, v4}, Llyiahf/vczjk/zz6;->OooOO0(Llyiahf/vczjk/lg1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v2, v0

    goto :goto_c

    :cond_f
    move-object/from16 v24, v3

    move-object v11, v5

    move-object/from16 v3, v20

    :goto_c
    check-cast v2, Llyiahf/vczjk/zz6;

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    and-int/lit8 v4, v13, 0x70

    const/16 v5, 0x20

    if-ne v4, v5, :cond_10

    move v5, v14

    goto :goto_d

    :cond_10
    const/4 v5, 0x0

    :goto_d
    or-int/2addr v0, v5

    and-int/lit16 v5, v13, 0x380

    const/16 v6, 0x100

    if-ne v5, v6, :cond_11

    move v6, v14

    goto :goto_e

    :cond_11
    const/4 v6, 0x0

    :goto_e
    or-int/2addr v0, v6

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_12

    move-object/from16 v0, v24

    if-ne v6, v0, :cond_13

    goto :goto_f

    :cond_12
    move-object/from16 v0, v24

    :goto_f
    new-instance v16, Llyiahf/vczjk/cf;

    move-object/from16 v17, v2

    move-object/from16 v20, v3

    move-object/from16 v21, v15

    invoke-direct/range {v16 .. v21}, Llyiahf/vczjk/cf;-><init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Ljava/lang/String;Llyiahf/vczjk/yn4;)V

    move-object/from16 v6, v16

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-static {v2, v6, v11}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    const/16 v7, 0x20

    if-ne v4, v7, :cond_14

    move v4, v14

    goto :goto_10

    :cond_14
    const/4 v4, 0x0

    :goto_10
    or-int/2addr v4, v6

    const/16 v6, 0x100

    if-ne v5, v6, :cond_15

    move v5, v14

    goto :goto_11

    :cond_15
    const/4 v5, 0x0

    :goto_11
    or-int/2addr v4, v5

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_16

    if-ne v5, v0, :cond_17

    :cond_16
    new-instance v16, Llyiahf/vczjk/df;

    move-object/from16 v17, v2

    move-object/from16 v20, v3

    move-object/from16 v21, v15

    invoke-direct/range {v16 .. v21}, Llyiahf/vczjk/df;-><init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Ljava/lang/String;Llyiahf/vczjk/yn4;)V

    move-object/from16 v5, v16

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    check-cast v5, Llyiahf/vczjk/le3;

    invoke-static {v5, v11}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    and-int/lit8 v4, v13, 0xe

    const/4 v5, 0x4

    if-ne v4, v5, :cond_18

    move v4, v14

    goto :goto_12

    :cond_18
    const/4 v4, 0x0

    :goto_12
    or-int/2addr v3, v4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_19

    if-ne v4, v0, :cond_1a

    :cond_19
    new-instance v4, Llyiahf/vczjk/ff;

    invoke-direct {v4, v2, v1}, Llyiahf/vczjk/ff;-><init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/c07;)V

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1a
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-static {v1, v4, v11}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_1b

    if-ne v4, v0, :cond_1c

    :cond_1b
    new-instance v4, Llyiahf/vczjk/gf;

    const/4 v3, 0x0

    invoke-direct {v4, v2, v3}, Llyiahf/vczjk/gf;-><init>(Llyiahf/vczjk/zz6;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1c
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-static {v2, v11, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_1d

    if-ne v5, v0, :cond_1e

    :cond_1d
    new-instance v5, Llyiahf/vczjk/hf;

    invoke-direct {v5, v2}, Llyiahf/vczjk/hf;-><init>(Llyiahf/vczjk/zz6;)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1e
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-static {v3, v5}, Landroidx/compose/ui/layout/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_1f

    if-ne v5, v0, :cond_20

    :cond_1f
    new-instance v5, Llyiahf/vczjk/if;

    const/4 v0, 0x0

    invoke-direct {v5, v0, v2, v15}, Llyiahf/vczjk/if;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_20
    check-cast v5, Llyiahf/vczjk/lf5;

    iget v0, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v2

    invoke-static {v11, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_21

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_13

    :cond_21
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_13
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v2, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_22

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_23

    :cond_22
    invoke-static {v0, v11, v0, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_23
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v11, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v2, v18

    move-object/from16 v3, v19

    goto :goto_14

    :cond_24
    move-object v11, v5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v2, v3

    move-object v3, v6

    :goto_14
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v7

    if-eqz v7, :cond_25

    new-instance v0, Llyiahf/vczjk/jf;

    move/from16 v6, p6

    move-object v4, v8

    move v5, v9

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/jf;-><init>(Llyiahf/vczjk/c07;Llyiahf/vczjk/le3;Llyiahf/vczjk/d07;Llyiahf/vczjk/ze3;II)V

    iput-object v0, v7, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_25
    return-void
.end method

.method public static final OooO0O0(Landroid/view/View;)Z
    .locals 1

    invoke-virtual {p0}, Landroid/view/View;->getRootView()Landroid/view/View;

    move-result-object p0

    invoke-virtual {p0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p0

    instance-of v0, p0, Landroid/view/WindowManager$LayoutParams;

    if-eqz v0, :cond_0

    check-cast p0, Landroid/view/WindowManager$LayoutParams;

    goto :goto_0

    :cond_0
    const/4 p0, 0x0

    :goto_0
    const/4 v0, 0x0

    if-eqz p0, :cond_1

    iget p0, p0, Landroid/view/WindowManager$LayoutParams;->flags:I

    and-int/lit16 p0, p0, 0x2000

    if-eqz p0, :cond_1

    const/4 p0, 0x1

    return p0

    :cond_1
    return v0
.end method
