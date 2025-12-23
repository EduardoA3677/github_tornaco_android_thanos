.class public final Llyiahf/vczjk/qw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/qs5;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/qw0;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/qw0;->OooOOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/qw0;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/qw0;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/qw0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/qw0;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qw0;->OooOOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/qw0;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/bi6;Llyiahf/vczjk/dha;Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/qw0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/qw0;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qw0;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/qw0;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 43

    move-object/from16 v0, p0

    const/4 v1, 0x0

    const/4 v3, 0x0

    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v6, -0x615d173a

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    sget-object v9, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v10, v0, Llyiahf/vczjk/qw0;->OooOOOo:Ljava/lang/Object;

    iget-object v11, v0, Llyiahf/vczjk/qw0;->OooOOO:Ljava/lang/Object;

    iget-object v12, v0, Llyiahf/vczjk/qw0;->OooOOOO:Ljava/lang/Object;

    const/4 v13, 0x0

    const/4 v14, 0x2

    iget v15, v0, Llyiahf/vczjk/qw0;->OooOOO0:I

    packed-switch v15, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_1
    :goto_0
    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/jt2;->OooOOO0:Llyiahf/vczjk/jt2;

    if-ne v2, v3, :cond_2

    const/4 v8, 0x1

    goto :goto_1

    :cond_2
    move v8, v13

    :goto_1
    check-cast v12, Llyiahf/vczjk/uh6;

    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-static {v12, v8, v10, v1, v13}, Llyiahf/vczjk/xt6;->OooO0OO(Llyiahf/vczjk/uh6;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_2
    return-object v9

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p2

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    and-int/lit8 v6, v6, 0x3

    if-ne v6, v14, :cond_4

    move-object v6, v1

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v15

    if-nez v15, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_9

    :cond_4
    :goto_3
    sget-object v6, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    check-cast v12, Llyiahf/vczjk/bi6;

    invoke-static {v6, v12}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v12, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v15, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v12, v15, v1, v13}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v12

    move-object v15, v1

    check-cast v15, Llyiahf/vczjk/zf1;

    iget v8, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v2

    invoke-static {v1, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v4, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_5

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_5
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v12, v1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_6

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-static {v4, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_7

    :cond_6
    invoke-static {v8, v15, v8, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x10

    int-to-float v2, v2

    invoke-static {v5, v2, v3, v14}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v16

    const/16 v17, 0x0

    const/16 v21, 0xd

    const/16 v19, 0x0

    const/16 v20, 0x0

    move/from16 v18, v2

    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    move/from16 v4, v18

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/td0;

    iget-boolean v6, v6, Llyiahf/vczjk/td0;->OooO0O0:Z

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->feature_title_wakelock_blocker:I

    invoke-static {v8, v1}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v17

    const v8, 0x4c5de2

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v10, Llyiahf/vczjk/bla;

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v8, :cond_9

    if-ne v12, v7, :cond_8

    goto :goto_5

    :cond_8
    const/4 v8, 0x0

    goto :goto_6

    :cond_9
    :goto_5
    new-instance v12, Llyiahf/vczjk/tka;

    const/4 v8, 0x0

    invoke-direct {v12, v10, v8}, Llyiahf/vczjk/tka;-><init>(Llyiahf/vczjk/bla;I)V

    invoke-virtual {v15, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_6
    move-object/from16 v19, v12

    check-cast v19, Llyiahf/vczjk/oe3;

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v18, 0x0

    const/16 v21, 0x6

    const/16 v22, 0x8

    move-object/from16 v20, v1

    move/from16 v16, v6

    move-object v1, v15

    move-object v15, v2

    invoke-static/range {v15 .. v22}, Llyiahf/vczjk/er8;->OooOO0(Llyiahf/vczjk/kl5;ZLjava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v2, v20

    invoke-static {v5, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/4 v6, 0x6

    invoke-static {v5, v2, v6}, Llyiahf/vczjk/kh6;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V

    const/4 v5, 0x7

    invoke-static {v3, v3, v3, v4, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v3

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    move-object v15, v4

    check-cast v15, Llyiahf/vczjk/td0;

    const v8, 0x4c5de2

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_a

    if-ne v5, v7, :cond_b

    :cond_a
    new-instance v5, Llyiahf/vczjk/tka;

    const/4 v4, 0x1

    invoke-direct {v5, v10, v4}, Llyiahf/vczjk/tka;-><init>(Llyiahf/vczjk/bla;I)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object/from16 v16, v5

    check-cast v16, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x4c5de2

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_c

    if-ne v5, v7, :cond_d

    :cond_c
    new-instance v5, Llyiahf/vczjk/pka;

    invoke-direct {v5, v10, v14}, Llyiahf/vczjk/pka;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    move-object/from16 v17, v5

    check-cast v17, Llyiahf/vczjk/ze3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x4c5de2

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_e

    if-ne v5, v7, :cond_f

    :cond_e
    new-instance v5, Llyiahf/vczjk/tka;

    invoke-direct {v5, v10, v14}, Llyiahf/vczjk/tka;-><init>(Llyiahf/vczjk/bla;I)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    move-object/from16 v18, v5

    check-cast v18, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x4c5de2

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_11

    if-ne v5, v7, :cond_10

    goto :goto_7

    :cond_10
    const/4 v4, 0x1

    goto :goto_8

    :cond_11
    :goto_7
    new-instance v5, Llyiahf/vczjk/ska;

    const/4 v4, 0x1

    invoke-direct {v5, v10, v4}, Llyiahf/vczjk/ska;-><init>(Llyiahf/vczjk/bla;I)V

    invoke-virtual {v1, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_8
    move-object/from16 v19, v5

    check-cast v19, Llyiahf/vczjk/le3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v21, 0x6

    move-object/from16 v20, v2

    move-object v14, v3

    invoke-static/range {v14 .. v21}, Llyiahf/vczjk/xt6;->OooOOoo(Llyiahf/vczjk/di6;Llyiahf/vczjk/td0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    return-object v9

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_13

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_12

    goto :goto_a

    :cond_12
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_b

    :cond_13
    :goto_a
    sget-object v24, Llyiahf/vczjk/r6a;->OooO00o:Llyiahf/vczjk/n6a;

    new-instance v2, Llyiahf/vczjk/e4;

    check-cast v10, Llyiahf/vczjk/a91;

    const/16 v3, 0xe

    invoke-direct {v2, v10, v3}, Llyiahf/vczjk/e4;-><init>(Llyiahf/vczjk/a91;I)V

    const v3, 0x60058e7b

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v25

    move-object/from16 v23, v12

    check-cast v23, Llyiahf/vczjk/al8;

    move-object/from16 v22, v11

    check-cast v22, Llyiahf/vczjk/x21;

    const/16 v27, 0x6c00

    move-object/from16 v26, v1

    invoke-static/range {v22 .. v27}, Llyiahf/vczjk/we5;->OooO00o(Llyiahf/vczjk/x21;Llyiahf/vczjk/al8;Llyiahf/vczjk/n6a;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_b
    return-object v9

    :pswitch_2
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v14, :cond_15

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_14

    goto :goto_c

    :cond_14
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_d

    :cond_15
    :goto_c
    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/content/Context;

    sget-object v13, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v11, Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    check-cast v12, Ljava/util/ArrayList;

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_16

    if-ne v4, v7, :cond_17

    :cond_16
    new-instance v4, Llyiahf/vczjk/to9;

    invoke-direct {v4, v11, v12, v1}, Llyiahf/vczjk/to9;-><init>(Lgithub/tornaco/android/thanos/core/Logger;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    move-object v15, v4

    check-cast v15, Llyiahf/vczjk/ze3;

    const/4 v8, 0x0

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v14, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x1

    move-object/from16 v16, v2

    invoke-static/range {v13 .. v18}, Llyiahf/vczjk/so8;->OooOo0O(Llyiahf/vczjk/zl1;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_18

    if-ne v4, v7, :cond_19

    :cond_18
    new-instance v4, Llyiahf/vczjk/uo9;

    invoke-direct {v4, v11, v12, v1}, Llyiahf/vczjk/uo9;-><init>(Lgithub/tornaco/android/thanos/core/Logger;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_19
    check-cast v4, Llyiahf/vczjk/ze3;

    const/4 v8, 0x0

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v2, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v1, 0x52ab3ed8

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v1, Llyiahf/vczjk/z35;->OooO00o:Llyiahf/vczjk/l39;

    check-cast v10, Ltornaco/apps/thanox/ThanosShizukuMainActivity;

    iget-object v3, v10, Ltornaco/apps/thanox/ThanosShizukuMainActivity;->OoooO0O:Llyiahf/vczjk/cp8;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/l39;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    sget-object v3, Llyiahf/vczjk/jd1;->OooO00o:Llyiahf/vczjk/a91;

    const/16 v4, 0x38

    invoke-static {v1, v3, v2, v4}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    const/4 v8, 0x0

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_d
    return-object v9

    :pswitch_3
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_1b

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1a

    goto :goto_e

    :cond_1a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_10

    :cond_1b
    :goto_e
    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v12, Lnow/fortuitous/thanos/sf/SFActivity;

    invoke-virtual {v1, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_1c

    if-ne v3, v7, :cond_1d

    :cond_1c
    new-instance v3, Llyiahf/vczjk/w77;

    check-cast v11, Llyiahf/vczjk/qs5;

    const/4 v2, 0x5

    invoke-direct {v3, v2, v12, v11}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1d
    move-object v13, v3

    check-cast v13, Llyiahf/vczjk/le3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v10, Llyiahf/vczjk/qr5;

    move-object v2, v10

    check-cast v2, Llyiahf/vczjk/bw8;

    invoke-virtual {v2}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v2

    if-gtz v2, :cond_1e

    const/4 v15, 0x1

    goto :goto_f

    :cond_1e
    const/4 v15, 0x0

    :goto_f
    new-instance v2, Llyiahf/vczjk/jw5;

    const/4 v4, 0x1

    invoke-direct {v2, v10, v4}, Llyiahf/vczjk/jw5;-><init>(Llyiahf/vczjk/qr5;I)V

    const v3, 0x765a1b4c

    invoke-static {v3, v2, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v19

    const/high16 v21, 0x30000000

    const/16 v22, 0x1fa

    const/4 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    move-object/from16 v20, v1

    invoke-static/range {v13 .. v22}, Llyiahf/vczjk/bua;->OooOO0O(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    :goto_10
    return-object v9

    :pswitch_4
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_20

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1f

    goto :goto_11

    :cond_1f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_14

    :cond_20
    :goto_11
    sget v2, Lgithub/tornaco/thanos/android/module/profile/online/OnlineProfileActivity;->OoooO0O:I

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gc6;

    iget-object v2, v2, Llyiahf/vczjk/gc6;->OooO0O0:Ljava/util/List;

    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_21

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gc6;

    iget-boolean v2, v2, Llyiahf/vczjk/gc6;->OooO00o:Z

    if-nez v2, :cond_21

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, -0x84e74a4

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v12, Llyiahf/vczjk/bi6;

    invoke-static {v5, v12}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-interface {v2, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v8, 0x0

    invoke-static {v2, v1, v8}, Llyiahf/vczjk/os9;->OooOOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto/16 :goto_14

    :cond_21
    move-object v15, v1

    check-cast v15, Llyiahf/vczjk/zf1;

    const v1, -0x84b0cc4

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v11, v1

    check-cast v11, Llyiahf/vczjk/gc6;

    const v8, 0x4c5de2

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v10, Llyiahf/vczjk/nc6;

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_23

    if-ne v2, v7, :cond_22

    goto :goto_12

    :cond_22
    const/4 v8, 0x0

    goto :goto_13

    :cond_23
    :goto_12
    new-instance v2, Llyiahf/vczjk/xb6;

    const/4 v8, 0x0

    invoke-direct {v2, v10, v8}, Llyiahf/vczjk/xb6;-><init>(Llyiahf/vczjk/nc6;I)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_13
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x4c5de2

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_24

    if-ne v3, v7, :cond_25

    :cond_24
    new-instance v3, Llyiahf/vczjk/xb6;

    const/4 v4, 0x1

    invoke-direct {v3, v10, v4}, Llyiahf/vczjk/xb6;-><init>(Llyiahf/vczjk/nc6;I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_25
    move-object v13, v3

    check-cast v13, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x4c5de2

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_26

    if-ne v3, v7, :cond_27

    :cond_26
    new-instance v3, Llyiahf/vczjk/xb6;

    invoke-direct {v3, v10, v14}, Llyiahf/vczjk/xb6;-><init>(Llyiahf/vczjk/nc6;I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_27
    move-object v14, v3

    check-cast v14, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v10, v12

    check-cast v10, Llyiahf/vczjk/bi6;

    const/16 v16, 0x0

    move-object v12, v2

    invoke-static/range {v10 .. v16}, Llyiahf/vczjk/mc4;->OooOO0O(Llyiahf/vczjk/bi6;Llyiahf/vczjk/gc6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_14
    return-object v9

    :pswitch_5
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_29

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_28

    goto :goto_15

    :cond_28
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_17

    :cond_29
    :goto_15
    sget-object v2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    check-cast v12, Llyiahf/vczjk/qs5;

    invoke-virtual {v1, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_2a

    if-ne v4, v7, :cond_2b

    :cond_2a
    new-instance v4, Llyiahf/vczjk/bz0;

    invoke-direct {v4, v11, v12, v14}, Llyiahf/vczjk/bz0;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2b
    check-cast v4, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v4}, Landroidx/compose/ui/draw/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v3, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v4, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_2c

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_16

    :cond_2c
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_16
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_2d

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_2e

    :cond_2d
    invoke-static {v4, v1, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2e
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v25, 0x0

    invoke-static/range {v25 .. v25}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    check-cast v10, Llyiahf/vczjk/a91;

    invoke-virtual {v10, v1, v2}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v4, 0x1

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_17
    return-object v9

    :pswitch_6
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p2

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v14, :cond_30

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_2f

    goto :goto_18

    :cond_2f
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_1c

    :cond_30
    :goto_18
    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/content/Context;

    sget-object v13, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v11, Lgithub/tornaco/android/thanos/core/Logger;

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    check-cast v12, Ljava/util/ArrayList;

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_31

    if-ne v4, v7, :cond_32

    :cond_31
    new-instance v4, Llyiahf/vczjk/eu5;

    invoke-direct {v4, v11, v12, v1}, Llyiahf/vczjk/eu5;-><init>(Lgithub/tornaco/android/thanos/core/Logger;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_32
    move-object v15, v4

    check-cast v15, Llyiahf/vczjk/ze3;

    const/4 v8, 0x0

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v14, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x1

    move-object/from16 v16, v2

    invoke-static/range {v13 .. v18}, Llyiahf/vczjk/so8;->OooOo0O(Llyiahf/vczjk/zl1;Llyiahf/vczjk/jy4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_33

    if-ne v4, v7, :cond_34

    :cond_33
    new-instance v4, Llyiahf/vczjk/fu5;

    invoke-direct {v4, v11, v12, v1}, Llyiahf/vczjk/fu5;-><init>(Lgithub/tornaco/android/thanos/core/Logger;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_34
    check-cast v4, Llyiahf/vczjk/ze3;

    const/4 v8, 0x0

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v2, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v3, 0x56b8017f

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v3, 0x6e3c21fe

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v7, :cond_35

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_35
    check-cast v3, Llyiahf/vczjk/qs5;

    const/4 v8, 0x0

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v10, Landroid/app/Activity;

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_36

    if-ne v5, v7, :cond_37

    :cond_36
    new-instance v5, Llyiahf/vczjk/hu5;

    invoke-direct {v5, v10, v3, v1}, Llyiahf/vczjk/hu5;-><init>(Landroid/app/Activity;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_37
    check-cast v5, Llyiahf/vczjk/ze3;

    const/4 v8, 0x0

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v2, v5}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v1, -0x1e3bfb0c

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-nez v1, :cond_3a

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_39

    if-ne v4, v7, :cond_38

    goto :goto_19

    :cond_38
    const/4 v8, 0x0

    goto :goto_1a

    :cond_39
    :goto_19
    new-instance v4, Llyiahf/vczjk/o0O000;

    const/16 v1, 0x1a

    const/4 v8, 0x0

    invoke-direct {v4, v1, v10, v3, v8}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_1a
    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v2, v8}, Llyiahf/vczjk/yi4;->OooOOo0(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1b

    :cond_3a
    const/4 v8, 0x0

    :goto_1b
    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v8, v2}, Llyiahf/vczjk/so8;->OooOO0O(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1c
    return-object v9

    :pswitch_7
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v4, v2, 0x3

    if-eq v4, v14, :cond_3b

    const/4 v4, 0x1

    :goto_1d
    const/4 v5, 0x1

    goto :goto_1e

    :cond_3b
    const/4 v4, 0x0

    goto :goto_1d

    :goto_1e
    and-int/2addr v2, v5

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_3f

    sget v2, Llyiahf/vczjk/sh5;->OooO0Oo:F

    check-cast v11, Llyiahf/vczjk/kl5;

    invoke-static {v11, v3, v2, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/q34;->OooOOO0:Llyiahf/vczjk/q34;

    invoke-static {v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOOOO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    check-cast v12, Llyiahf/vczjk/z98;

    invoke-static {v2, v12, v5}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v4, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v8, 0x0

    invoke-static {v3, v4, v1, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v3

    iget v4, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v1, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_3c

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1f

    :cond_3c
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1f
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v1, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_3d

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_3e

    :cond_3d
    invoke-static {v4, v1, v4, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3e
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    const/16 v24, 0x6

    invoke-static/range {v24 .. v24}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    check-cast v10, Llyiahf/vczjk/a91;

    invoke-virtual {v10, v2, v1, v3}, Llyiahf/vczjk/a91;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v4, 0x1

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_20

    :cond_3f
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_20
    return-object v9

    :pswitch_8
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_41

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_40

    goto :goto_21

    :cond_40
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_22

    :cond_41
    :goto_21
    sget-object v2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    check-cast v12, Llyiahf/vczjk/bi6;

    invoke-static {v2, v12}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v26

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    check-cast v10, Llyiahf/vczjk/on4;

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_42

    if-ne v3, v7, :cond_43

    :cond_42
    new-instance v3, Llyiahf/vczjk/o0OO000o;

    const/16 v2, 0x13

    invoke-direct {v3, v2, v11, v10}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_43
    move-object/from16 v35, v3

    check-cast v35, Llyiahf/vczjk/oe3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v37, 0x0

    const/16 v38, 0x1fe

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    move-object/from16 v36, v1

    invoke-static/range {v26 .. v38}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_22
    return-object v9

    :pswitch_9
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_45

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_44

    goto :goto_23

    :cond_44
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_24

    :cond_45
    :goto_23
    sget-object v2, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/x21;

    iget-wide v2, v2, Llyiahf/vczjk/x21;->OooOOOo:J

    sget-object v4, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v5, v2, v3, v4}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v29

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v27

    const v8, 0x4c5de2

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_46

    if-ne v3, v7, :cond_47

    :cond_46
    new-instance v3, Llyiahf/vczjk/l5;

    const/16 v2, 0x11

    invoke-direct {v3, v11, v2}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_47
    move-object/from16 v28, v3

    check-cast v28, Llyiahf/vczjk/le3;

    const/4 v8, 0x0

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v13, Llyiahf/vczjk/n6;

    move-object v15, v12

    check-cast v15, Ljava/util/List;

    move-object/from16 v17, v10

    check-cast v17, Llyiahf/vczjk/oe3;

    const/16 v14, 0x9

    const/16 v18, 0x0

    move-object/from16 v16, v11

    invoke-direct/range {v13 .. v18}, Llyiahf/vczjk/n6;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V

    const v2, 0x639c1bbb

    invoke-static {v2, v13, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v39

    const/16 v38, 0x0

    const/16 v42, 0x7f8

    const-wide/16 v30, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const-wide/16 v35, 0x0

    const/16 v37, 0x0

    const/16 v41, 0x0

    move-object/from16 v40, v1

    invoke-static/range {v27 .. v42}, Llyiahf/vczjk/fe;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_24
    return-object v9

    :pswitch_a
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    if-ne v2, v14, :cond_49

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_48

    goto :goto_25

    :cond_48
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_26

    :cond_49
    :goto_25
    sget v2, Lnow/fortuitous/thanos/main/ChooserActivity;->OoooO0O:I

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/pw0;

    check-cast v12, Landroid/content/Context;

    check-cast v10, Lnow/fortuitous/thanos/main/ChooserActivity;

    invoke-direct {v3, v12, v10}, Llyiahf/vczjk/pw0;-><init>(Landroid/content/Context;Lnow/fortuitous/thanos/main/ChooserActivity;)V

    const v4, 0x7aec14c4

    invoke-static {v4, v3, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v16

    const/high16 v18, 0x180000

    const/16 v19, 0x3e

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    move-object/from16 v17, v1

    move-object v10, v2

    invoke-static/range {v10 .. v19}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    :goto_26
    return-object v9

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
