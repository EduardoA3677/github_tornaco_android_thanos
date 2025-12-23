.class public final Llyiahf/vczjk/ha2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    iput p6, p0, Llyiahf/vczjk/ha2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ha2;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/ha2;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/ha2;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/ha2;->OooOOo0:Ljava/lang/Object;

    iput-object p5, p0, Llyiahf/vczjk/ha2;->OooOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 55

    move-object/from16 v0, p0

    const/16 v1, 0x10

    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v7, 0x0

    sget-object v8, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v9, v0, Llyiahf/vczjk/ha2;->OooOOo0:Ljava/lang/Object;

    iget-object v10, v0, Llyiahf/vczjk/ha2;->OooOOOo:Ljava/lang/Object;

    iget-object v11, v0, Llyiahf/vczjk/ha2;->OooOOo:Ljava/lang/Object;

    iget-object v12, v0, Llyiahf/vczjk/ha2;->OooOOOO:Ljava/lang/Object;

    const/4 v13, 0x2

    iget-object v14, v0, Llyiahf/vczjk/ha2;->OooOOO:Ljava/lang/Object;

    iget v15, v0, Llyiahf/vczjk/ha2;->OooOOO0:I

    packed-switch v15, :pswitch_data_0

    move-object/from16 v22, p1

    check-cast v22, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    if-ne v1, v13, :cond_1

    move-object/from16 v1, v22

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    move-object/from16 v16, v14

    check-cast v16, Llyiahf/vczjk/a91;

    move-object/from16 v17, v12

    check-cast v17, Llyiahf/vczjk/a91;

    move-object/from16 v21, v11

    check-cast v21, Llyiahf/vczjk/bo2;

    const/16 v18, 0x0

    move-object/from16 v19, v10

    check-cast v19, Llyiahf/vczjk/le3;

    move-object/from16 v20, v9

    check-cast v20, Llyiahf/vczjk/hb8;

    const/16 v23, 0x0

    const/16 v24, 0x4

    invoke-static/range {v16 .. v24}, Llyiahf/vczjk/xr6;->OooO0o(Llyiahf/vczjk/a91;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/hb8;Llyiahf/vczjk/jx9;Llyiahf/vczjk/rf1;II)V

    :goto_1
    return-object v8

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v15, p2

    check-cast v15, Ljava/lang/Number;

    invoke-virtual {v15}, Ljava/lang/Number;->intValue()I

    move-result v15

    and-int/lit8 v15, v15, 0x3

    if-ne v15, v13, :cond_3

    move-object v13, v1

    check-cast v13, Llyiahf/vczjk/zf1;

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v15

    if-nez v15, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v36, v8

    goto/16 :goto_9

    :cond_3
    :goto_2
    check-cast v1, Llyiahf/vczjk/zf1;

    const v13, 0x6e3c21fe

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-ne v13, v6, :cond_4

    new-instance v13, Llyiahf/vczjk/oOOO0OO0;

    const/16 v15, 0x16

    invoke-direct {v13, v15}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v13, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v15, 0x36

    const/4 v2, 0x0

    invoke-static {v2, v13, v1, v15}, Llyiahf/vczjk/ls6;->OooOOo(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/bf7;

    move-result-object v13

    sget-object v15, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v15, v13}, Llyiahf/vczjk/xr6;->OooOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf7;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v5, v7}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v7, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v18, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v36, v8

    iget-boolean v8, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_5

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_5
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move-object/from16 v37, v9

    iget-boolean v9, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_6

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    move-object/from16 v23, v10

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_7

    goto :goto_4

    :cond_6
    move-object/from16 v23, v10

    :goto_4
    invoke-static {v7, v1, v7, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/i28;

    iget-boolean v9, v9, Llyiahf/vczjk/i28;->OooO00o:Z

    const v10, 0x4c5de2

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v14, Llyiahf/vczjk/h48;

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    move/from16 p2, v10

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez p2, :cond_9

    if-ne v10, v6, :cond_8

    goto :goto_5

    :cond_8
    move-object/from16 v38, v11

    const/4 v11, 0x0

    goto :goto_6

    :cond_9
    :goto_5
    new-instance v10, Llyiahf/vczjk/l08;

    move-object/from16 v38, v11

    const/4 v11, 0x0

    invoke-direct {v10, v14, v11}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_6
    check-cast v10, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v10, v1, v11, v11}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object v9, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v10, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v11, 0x6

    invoke-static {v9, v10, v1, v11}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v9

    iget v10, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    move-object/from16 p2, v13

    invoke-static {v1, v15}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v13

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v39, v2

    iget-boolean v2, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_a

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_a
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v9, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v1, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_b

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_c

    :cond_b
    invoke-static {v10, v1, v10, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    invoke-static {v13, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    iget-object v2, v14, Llyiahf/vczjk/h48;->OooOOO:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/q29;

    invoke-static {v2, v1}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v2

    iget-object v3, v14, Llyiahf/vczjk/h48;->OooOO0O:Llyiahf/vczjk/gh7;

    invoke-static {v3, v1}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v3

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->pkg_set:I

    invoke-static {v5, v1}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    const v10, 0x4c5de2

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_d

    if-ne v8, v6, :cond_e

    :cond_d
    new-instance v8, Llyiahf/vczjk/pz7;

    const/4 v7, 0x1

    invoke-direct {v8, v14, v7}, Llyiahf/vczjk/pz7;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v8, Llyiahf/vczjk/oe3;

    const/4 v11, 0x0

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v7, 0x1c

    const/4 v9, 0x0

    invoke-static {v5, v9, v8, v1, v7}, Llyiahf/vczjk/ll6;->OooOOO(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/zl9;

    move-result-object v5

    invoke-static {v5, v1, v11}, Llyiahf/vczjk/ll6;->OooO0Oo(Llyiahf/vczjk/zl9;Llyiahf/vczjk/rf1;I)V

    const v10, 0x4c5de2

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_f

    if-ne v8, v6, :cond_10

    :cond_f
    new-instance v8, Llyiahf/vczjk/a67;

    const/4 v7, 0x7

    invoke-direct {v8, v2, v7}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v8, Llyiahf/vczjk/le3;

    const/4 v11, 0x0

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget v7, Llyiahf/vczjk/qm6;->OooO00o:F

    new-array v7, v11, [Ljava/lang/Object;

    sget-object v17, Llyiahf/vczjk/d32;->Oooo0:Llyiahf/vczjk/era;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v10

    const/4 v11, 0x0

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v11

    or-int/2addr v10, v11

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v10, v11

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v10, :cond_11

    if-ne v11, v6, :cond_12

    :cond_11
    new-instance v11, Llyiahf/vczjk/pm6;

    invoke-direct {v11, v8}, Llyiahf/vczjk/pm6;-><init>(Llyiahf/vczjk/le3;)V

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_12
    move-object/from16 v18, v11

    check-cast v18, Llyiahf/vczjk/le3;

    const/16 v20, 0x0

    const/16 v21, 0x4

    move-object/from16 v19, v1

    move-object/from16 v16, v7

    invoke-static/range {v16 .. v21}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v7, v19

    check-cast v1, Llyiahf/vczjk/d32;

    iget-object v10, v1, Llyiahf/vczjk/d32;->Oooo00o:Llyiahf/vczjk/qs5;

    check-cast v10, Llyiahf/vczjk/fw8;

    invoke-virtual {v10, v8}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    const v8, -0x6815fd56

    invoke-virtual {v7, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v10, v11

    invoke-virtual {v7, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v10, v11

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v10, :cond_13

    if-ne v11, v6, :cond_14

    :cond_13
    new-instance v11, Llyiahf/vczjk/n08;

    invoke-direct {v11, v1, v14, v2, v9}, Llyiahf/vczjk/n08;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/h48;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_14
    check-cast v11, Llyiahf/vczjk/ze3;

    const/4 v10, 0x0

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v7, v11}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/String;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Ljava/util/List;

    invoke-virtual {v7, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v8, v13

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v8, v13

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v8, :cond_15

    if-ne v13, v6, :cond_16

    :cond_15
    new-instance v13, Llyiahf/vczjk/o08;

    invoke-direct {v13, v1, v2, v3, v9}, Llyiahf/vczjk/o08;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/p29;Llyiahf/vczjk/p29;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    check-cast v13, Llyiahf/vczjk/ze3;

    const/4 v6, 0x0

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v10, v11, v13, v7}, Llyiahf/vczjk/c6a;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/high16 v6, 0x3f800000    # 1.0f

    float-to-double v8, v6

    const-wide/16 v10, 0x0

    cmpl-double v8, v8, v10

    if-lez v8, :cond_17

    goto :goto_8

    :cond_17
    const-string v8, "invalid weight; must be greater than zero"

    invoke-static {v8}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_8
    new-instance v8, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v11, 0x0

    invoke-direct {v8, v6, v11}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    invoke-interface {v15, v8}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v17

    new-instance v6, Llyiahf/vczjk/o60;

    move-object/from16 v10, v23

    check-cast v10, Llyiahf/vczjk/qs5;

    invoke-direct {v6, v12, v14, v10, v2}, Llyiahf/vczjk/o60;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;)V

    const v8, 0x1643d0a3

    invoke-static {v8, v6, v7}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v30

    const/16 v33, 0x6000

    const/16 v34, 0x3fec

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x1

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v32, 0x6000

    move-object/from16 v16, v1

    move-object/from16 v31, v7

    invoke-static/range {v16 .. v34}, Llyiahf/vczjk/cl6;->OooO0OO(Llyiahf/vczjk/lm6;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;Llyiahf/vczjk/uj6;IFLlyiahf/vczjk/n4;Llyiahf/vczjk/hg9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/bz5;Llyiahf/vczjk/dv8;Llyiahf/vczjk/qg6;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;III)V

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/i28;

    iget-boolean v1, v1, Llyiahf/vczjk/i28;->OooO00o:Z

    const/16 v35, 0x1

    xor-int/lit8 v17, v1, 0x1

    new-instance v24, Llyiahf/vczjk/a6;

    const/16 v29, 0xd

    move-object/from16 v26, v2

    move-object/from16 v27, v3

    move-object/from16 v28, v5

    move-object/from16 v25, v14

    invoke-direct/range {v24 .. v29}, Llyiahf/vczjk/a6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v1, v24

    move-object/from16 v30, v26

    move-object/from16 v29, v27

    move-object/from16 v26, v25

    const v2, -0x55297c54

    invoke-static {v2, v1, v7}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v22

    const/16 v25, 0x1e

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const v24, 0x180006

    move-object/from16 v16, v0

    move-object/from16 v23, v7

    invoke-static/range {v16 .. v25}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move/from16 v0, v24

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/i28;

    iget-boolean v1, v1, Llyiahf/vczjk/i28;->OooO00o:Z

    new-instance v24, Llyiahf/vczjk/u08;

    move-object/from16 v25, v37

    check-cast v25, Llyiahf/vczjk/xr1;

    move-object/from16 v28, v38

    check-cast v28, Landroid/content/Context;

    const/16 v31, 0x1

    move-object/from16 v27, v12

    invoke-direct/range {v24 .. v31}, Llyiahf/vczjk/u08;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/h48;Llyiahf/vczjk/qs5;Landroid/content/Context;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    move-object/from16 v2, v24

    const v3, 0x314b9a55

    invoke-static {v3, v2, v7}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v22

    const/16 v19, 0x0

    const/16 v25, 0x1e

    const/16 v18, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move/from16 v24, v0

    move/from16 v17, v1

    move-object/from16 v23, v7

    invoke-static/range {v16 .. v25}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    const/4 v0, 0x1

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v0, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    move-object/from16 v1, v39

    invoke-virtual {v1, v4, v0}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v18

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    iget-wide v0, v0, Llyiahf/vczjk/x21;->OooO0o:J

    const/16 v24, 0x46

    const/16 v25, 0x28

    const-wide/16 v19, 0x0

    move-object/from16 v17, p2

    move-wide/from16 v21, v0

    move-object/from16 v23, v7

    const/16 v16, 0x0

    invoke-static/range {v16 .. v25}, Llyiahf/vczjk/ue7;->OooO00o(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/rf1;II)V

    const/4 v0, 0x1

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    return-object v36

    :pswitch_1
    move-object/from16 v36, v8

    move-object/from16 v37, v9

    move-object/from16 v23, v10

    move-object/from16 v38, v11

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    if-ne v1, v13, :cond_19

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_18

    goto :goto_a

    :cond_18
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_b

    :cond_19
    :goto_a
    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-interface {v12}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v8, v1

    check-cast v8, Llyiahf/vczjk/j28;

    move-object/from16 v10, v23

    check-cast v10, Llyiahf/vczjk/qs5;

    invoke-interface {v10}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v9, v1

    check-cast v9, Llyiahf/vczjk/cm4;

    move-object/from16 v1, v37

    check-cast v1, Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v10, v1

    check-cast v10, Ljava/util/List;

    move-object/from16 v11, v38

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    if-nez v1, :cond_1a

    const-string v1, ""

    :cond_1a
    move-object v12, v1

    move-object v11, v14

    check-cast v11, Llyiahf/vczjk/i48;

    const/4 v14, 0x0

    move-object v13, v0

    invoke-static/range {v8 .. v14}, Llyiahf/vczjk/kh6;->OooO00o(Llyiahf/vczjk/j28;Llyiahf/vczjk/cm4;Ljava/util/List;Llyiahf/vczjk/i48;Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    :goto_b
    return-object v36

    :pswitch_2
    move-object/from16 v36, v8

    move-object/from16 v37, v9

    move-object/from16 v23, v10

    move-object/from16 v38, v11

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    and-int/lit8 v1, v1, 0x3

    if-ne v1, v13, :cond_1c

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_1b

    goto :goto_c

    :cond_1b
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_d

    :cond_1c
    :goto_c
    const v1, 0x3f2e147b    # 0.68f

    invoke-static {v4, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v41

    move-object v1, v14

    check-cast v1, Llyiahf/vczjk/qs5;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v39

    check-cast v0, Llyiahf/vczjk/zf1;

    const v10, 0x4c5de2

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_1d

    if-ne v3, v6, :cond_1e

    :cond_1d
    new-instance v3, Llyiahf/vczjk/o0oOOo;

    const/16 v2, 0x1a

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/o0oOOo;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1e
    move-object/from16 v40, v3

    check-cast v40, Llyiahf/vczjk/le3;

    const/4 v11, 0x0

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/z5;

    move-object/from16 v5, v37

    check-cast v5, Llyiahf/vczjk/ww2;

    move-object/from16 v6, v38

    check-cast v6, Landroidx/appcompat/app/AppCompatActivity;

    move-object v2, v12

    check-cast v2, Ljava/util/List;

    move-object v3, v14

    check-cast v3, Llyiahf/vczjk/qs5;

    move-object/from16 v4, v23

    check-cast v4, Llyiahf/vczjk/oe3;

    const/4 v7, 0x1

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/z5;-><init>(Ljava/util/List;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ww2;Landroidx/appcompat/app/AppCompatActivity;I)V

    const v2, 0x38fbe9cb    # 1.201216E-4f

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v51

    const/16 v50, 0x0

    const/16 v54, 0x7f8

    const-wide/16 v42, 0x0

    const/16 v44, 0x0

    const/16 v45, 0x0

    const/16 v46, 0x0

    const-wide/16 v47, 0x0

    const/16 v49, 0x0

    const/16 v53, 0x180

    move-object/from16 v52, v0

    invoke-static/range {v39 .. v54}, Llyiahf/vczjk/fe;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_d
    return-object v36

    :pswitch_3
    move-object/from16 v36, v8

    move-object/from16 v37, v9

    move-object/from16 v23, v10

    move-object/from16 v38, v11

    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v0, p2

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    and-int/lit8 v0, v0, 0x3

    if-ne v0, v13, :cond_20

    move-object v0, v5

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_1f

    goto :goto_e

    :cond_1f
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_10

    :cond_20
    :goto_e
    sget-object v0, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    check-cast v14, Llyiahf/vczjk/bi6;

    invoke-static {v0, v14}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v3, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v11, 0x0

    invoke-static {v2, v3, v5, v11}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    move-object v9, v5

    check-cast v9, Llyiahf/vczjk/zf1;

    iget v3, v9, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v5, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_21

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_f

    :cond_21
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_f
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v5, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v5, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_22

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_23

    :cond_22
    invoke-static {v3, v9, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_23
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, v5, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    int-to-float v0, v1

    const/4 v11, 0x0

    invoke-static {v4, v0, v11, v13}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v24

    const/16 v25, 0x0

    const/16 v29, 0xd

    const/16 v27, 0x0

    const/16 v28, 0x0

    move/from16 v26, v0

    invoke-static/range {v24 .. v29}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget v0, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OoooO0O:I

    move-object/from16 v11, v38

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/j55;

    iget-boolean v2, v0, Llyiahf/vczjk/j55;->OooO00o:Z

    const v10, 0x4c5de2

    invoke-virtual {v9, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v12, Llyiahf/vczjk/l55;

    invoke-virtual {v9, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v0, :cond_24

    if-ne v3, v6, :cond_25

    :cond_24
    new-instance v3, Llyiahf/vczjk/w45;

    const/4 v0, 0x1

    invoke-direct {v3, v12, v0}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_25
    check-cast v3, Llyiahf/vczjk/oe3;

    const/4 v6, 0x0

    invoke-virtual {v9, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v7, 0x186

    const/16 v8, 0x8

    move-object v6, v5

    move-object v5, v3

    const-string v3, "Logs"

    const/4 v4, 0x0

    invoke-static/range {v1 .. v8}, Llyiahf/vczjk/er8;->OooOO0(Llyiahf/vczjk/kl5;ZLjava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/j55;

    iget-boolean v2, v0, Llyiahf/vczjk/j55;->OooO0OO:Z

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/j55;

    sget v0, Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;->Oooo0oO:I

    move-object v5, v6

    const/16 v6, 0x1000

    move-object/from16 v1, v23

    check-cast v1, Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    move-object/from16 v3, v37

    check-cast v3, Llyiahf/vczjk/dw4;

    invoke-virtual/range {v1 .. v6}, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OooOoo(ZLlyiahf/vczjk/dw4;Llyiahf/vczjk/j55;Llyiahf/vczjk/rf1;I)V

    const/4 v0, 0x1

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_10
    return-object v36

    :pswitch_4
    move-object/from16 v36, v8

    move-object/from16 v37, v9

    move-object/from16 v23, v10

    move-object/from16 v38, v11

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v13, :cond_27

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_26

    goto :goto_11

    :cond_26
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_12

    :cond_27
    :goto_11
    check-cast v0, Llyiahf/vczjk/zf1;

    check-cast v14, Llyiahf/vczjk/ku5;

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    check-cast v12, Llyiahf/vczjk/za2;

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_28

    if-ne v3, v6, :cond_29

    :cond_28
    new-instance v3, Llyiahf/vczjk/oo0ooO;

    move-object/from16 v9, v37

    check-cast v9, Llyiahf/vczjk/tw8;

    const/16 v2, 0x8

    invoke-direct {v3, v9, v14, v2, v12}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_29
    check-cast v3, Llyiahf/vczjk/oe3;

    invoke-static {v14, v3, v0}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    new-instance v2, Llyiahf/vczjk/b6;

    move-object/from16 v11, v38

    check-cast v11, Llyiahf/vczjk/ya2;

    invoke-direct {v2, v1, v11, v14}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v1, -0x1da93fb4

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    const/16 v2, 0x180

    move-object/from16 v10, v23

    check-cast v10, Llyiahf/vczjk/r58;

    invoke-static {v14, v10, v1, v0, v2}, Llyiahf/vczjk/nqa;->OooO0Oo(Llyiahf/vczjk/ku5;Llyiahf/vczjk/r58;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_12
    return-object v36

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
