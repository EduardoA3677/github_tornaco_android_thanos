.class public final Llyiahf/vczjk/a6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;

.field public final synthetic OooOOo0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroid/os/Parcelable;Llyiahf/vczjk/fy4;Llyiahf/vczjk/oe3;Ljava/lang/Object;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/a6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/a6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final OooO0oO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 25

    move-object/from16 v0, p0

    const/4 v2, 0x0

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/bi6;

    move-object/from16 v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v6, "paddings"

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v6, v5, 0x6

    if-nez v6, :cond_1

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_0

    const/4 v6, 0x4

    goto :goto_0

    :cond_0
    const/4 v6, 0x2

    :goto_0
    or-int/2addr v5, v6

    :cond_1
    and-int/lit8 v5, v5, 0x13

    const/16 v6, 0x12

    if-ne v5, v6, :cond_3

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_b

    :cond_3
    :goto_1
    move-object v15, v4

    check-cast v15, Llyiahf/vczjk/zf1;

    const v4, -0x6815fd56

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/pu6;

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    iget-object v6, v0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Landroid/content/Context;

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v5, v8

    iget-object v8, v0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    check-cast v8, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v5, v9

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v5, :cond_4

    if-ne v9, v10, :cond_5

    :cond_4
    new-instance v9, Llyiahf/vczjk/hu6;

    const/4 v5, 0x0

    invoke-direct {v9, v4, v6, v8, v5}, Llyiahf/vczjk/hu6;-><init>(Llyiahf/vczjk/pu6;Landroid/content/Context;Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v9, Llyiahf/vczjk/ze3;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v15, v9}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v6, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v6, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v8, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    const/16 v9, 0x36

    invoke-static {v6, v8, v15, v9}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v6

    iget v8, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v15, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_6

    invoke-virtual {v15, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_6
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v6, v15, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v15, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_7

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_8

    :cond_7
    invoke-static {v8, v15, v8, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v15, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v3, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PinSettingsActivity;->OoooO0O:I

    iget-object v3, v0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/su6;

    iget-object v13, v13, Llyiahf/vczjk/su6;->OooO00o:Llyiahf/vczjk/wu6;

    sget-object v14, Llyiahf/vczjk/tu6;->OooO00o:Llyiahf/vczjk/tu6;

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_9

    const v13, -0x1fbfc0f5

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const-string v13, ""

    goto :goto_3

    :cond_9
    sget-object v14, Llyiahf/vczjk/uu6;->OooO00o:Llyiahf/vczjk/uu6;

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_a

    const v13, -0x1fbe5e27

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pin_settings_input_1:I

    invoke-static {v13, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_a
    sget-object v14, Llyiahf/vczjk/vu6;->OooO00o:Llyiahf/vczjk/vu6;

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_16

    const v13, -0x1fbbc3a7

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pin_settings_input_2:I

    invoke-static {v13, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    const v14, 0x20afa4f1

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v14, 0x6e3c21fe

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-ne v14, v10, :cond_b

    sget-object v14, Llyiahf/vczjk/iu6;->OooOOOO:Llyiahf/vczjk/iu6;

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    check-cast v14, Llyiahf/vczjk/oe3;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/k91;

    const/16 v7, 0xd

    invoke-direct {v1, v7}, Llyiahf/vczjk/k91;-><init>(I)V

    const v7, 0x72008807

    invoke-static {v7, v1, v15}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    const v16, 0x180180

    const/16 v17, 0x3a

    move-object v7, v9

    const/4 v9, 0x0

    move-object/from16 v18, v11

    const/4 v11, 0x0

    move-object/from16 v19, v12

    const/4 v12, 0x0

    move-object/from16 v20, v8

    move-object v8, v13

    const/4 v13, 0x0

    move-object/from16 v22, v14

    move-object v14, v1

    move-object v1, v10

    move-object/from16 v10, v22

    move-object/from16 v23, v7

    move-object/from16 v7, v18

    move-object/from16 v22, v19

    move-object/from16 v24, v20

    invoke-static/range {v8 .. v17}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v15}, Llyiahf/vczjk/ru6;->OooO0O0(ILlyiahf/vczjk/rf1;)V

    const/16 v8, 0x10

    int-to-float v8, v8

    const/4 v9, 0x0

    const/4 v10, 0x2

    invoke-static {v5, v8, v9, v10}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v9, v2}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v9

    iget v10, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v15, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_c

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_4
    move-object/from16 v12, v22

    goto :goto_5

    :cond_c
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_4

    :goto_5
    invoke-static {v9, v15, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v15, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v9, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_d

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_e

    :cond_d
    move-object/from16 v9, v23

    goto :goto_7

    :cond_e
    move-object/from16 v9, v23

    :goto_6
    move-object/from16 v10, v24

    goto :goto_8

    :goto_7
    invoke-static {v10, v15, v10, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_6

    :goto_8
    invoke-static {v8, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pin_settings_warn:I

    invoke-static {v8, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    invoke-static {v8, v15, v2}, Llyiahf/vczjk/br6;->OooO(Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    const/4 v8, 0x1

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v11, 0x40

    int-to-float v11, v11

    const/16 v17, 0x0

    const/16 v21, 0xd

    const/16 v19, 0x0

    const/16 v20, 0x0

    move-object/from16 v16, v5

    move/from16 v18, v11

    invoke-static/range {v16 .. v21}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v11, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v11, v2}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v11

    iget v13, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v15, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_f

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_f
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    invoke-static {v11, v15, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v15, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v6, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_10

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_11

    :cond_10
    invoke-static {v13, v15, v13, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_11
    invoke-static {v5, v15, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v5, -0x615d173a

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_12

    if-ne v6, v1, :cond_13

    :cond_12
    new-instance v6, Llyiahf/vczjk/gu6;

    invoke-direct {v6, v2, v4, v3}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    move-object v11, v6

    check-cast v11, Llyiahf/vczjk/oe3;

    const v3, 0x6e3c21fe

    invoke-static {v15, v2, v3}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v1, :cond_14

    new-instance v4, Llyiahf/vczjk/oOOO0OO0;

    const/16 v5, 0x16

    invoke-direct {v4, v5}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    goto :goto_a

    :cond_14
    const/16 v5, 0x16

    :goto_a
    move-object v12, v4

    check-cast v12, Llyiahf/vczjk/le3;

    invoke-static {v15, v2, v3}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v1, :cond_15

    new-instance v3, Llyiahf/vczjk/oOOO0OO0;

    invoke-direct {v3, v5}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    move-object v13, v3

    check-cast v13, Llyiahf/vczjk/le3;

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v16, 0x36006

    const/16 v17, 0xc6

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v14, 0x0

    const/4 v1, 0x1

    invoke-static/range {v8 .. v17}, Llyiahf/vczjk/fu6;->OooO0O0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_b
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :cond_16
    const v1, -0x4b58c988

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1
.end method

.method private final OooO0oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "contentPadding"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v4, v3, 0x6

    if-nez v4, :cond_1

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int/2addr v3, v4

    :cond_1
    and-int/lit8 v3, v3, 0x13

    const/16 v4, 0x12

    if-ne v3, v4, :cond_3

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_3
    :goto_1
    iget-object v3, v0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/t67;

    iget-boolean v4, v4, Llyiahf/vczjk/t67;->OooO00o:Z

    move-object v12, v2

    check-cast v12, Llyiahf/vczjk/zf1;

    const v2, 0x4c5de2

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/k77;

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v6, :cond_4

    if-ne v7, v8, :cond_5

    :cond_4
    new-instance v7, Llyiahf/vczjk/z57;

    const/4 v6, 0x1

    invoke-direct {v7, v5, v6}, Llyiahf/vczjk/z57;-><init>(Llyiahf/vczjk/k77;I)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v7, Llyiahf/vczjk/le3;

    const/4 v6, 0x0

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v7, v12, v6}, Llyiahf/vczjk/ls6;->OooOOo(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/bf7;

    move-result-object v4

    sget-object v15, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v7, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v7, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v4}, Llyiahf/vczjk/xr6;->OooOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf7;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v7, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v7, v6}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v9, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v12, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_6

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_6
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v12, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v12, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_8

    :cond_7
    invoke-static {v9, v12, v9, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v12, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    sget-object v7, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/content/Context;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/t67;

    const v10, -0x615d173a

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v10, v0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/wa5;

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v11, v13

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v11, :cond_9

    if-ne v13, v8, :cond_a

    :cond_9
    new-instance v13, Llyiahf/vczjk/gu6;

    const/4 v11, 0x2

    invoke-direct {v13, v11, v10, v7}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v12, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v13, Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v10, :cond_b

    if-ne v11, v8, :cond_c

    :cond_b
    new-instance v11, Llyiahf/vczjk/q71;

    const/4 v10, 0x3

    invoke-direct {v11, v7, v10}, Llyiahf/vczjk/q71;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v11, Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v7, :cond_d

    if-ne v10, v8, :cond_e

    :cond_d
    new-instance v10, Llyiahf/vczjk/i57;

    const/4 v7, 0x1

    invoke-direct {v10, v5, v7}, Llyiahf/vczjk/i57;-><init>(Llyiahf/vczjk/k77;I)V

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v7, :cond_f

    if-ne v14, v8, :cond_10

    :cond_f
    new-instance v14, Llyiahf/vczjk/i57;

    const/4 v7, 0x2

    invoke-direct {v14, v5, v7}, Llyiahf/vczjk/i57;-><init>(Llyiahf/vczjk/k77;I)V

    invoke-virtual {v12, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v14, Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v7, :cond_11

    if-ne v2, v8, :cond_12

    :cond_11
    new-instance v2, Llyiahf/vczjk/i57;

    const/4 v7, 0x3

    invoke-direct {v2, v5, v7}, Llyiahf/vczjk/i57;-><init>(Llyiahf/vczjk/k77;I)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_12
    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v7, 0x4c5de2

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v7, :cond_13

    if-ne v6, v8, :cond_14

    :cond_13
    new-instance v6, Llyiahf/vczjk/i57;

    const/4 v7, 0x4

    invoke-direct {v6, v5, v7}, Llyiahf/vczjk/i57;-><init>(Llyiahf/vczjk/k77;I)V

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_14
    check-cast v6, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object v5, v0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/dw4;

    move-object v7, v13

    move-object v13, v12

    move-object v12, v6

    move-object v6, v9

    move-object v9, v10

    move-object v10, v14

    const/4 v14, 0x6

    move-object v8, v11

    move-object v11, v2

    invoke-static/range {v5 .. v14}, Llyiahf/vczjk/xt6;->OooOOOO(Llyiahf/vczjk/dw4;Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/t67;

    iget-boolean v5, v2, Llyiahf/vczjk/t67;->OooO00o:Z

    sget-object v2, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {v1, v15, v2}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v7

    move-object v12, v13

    const/16 v13, 0x40

    const/16 v14, 0x38

    const-wide/16 v8, 0x0

    const-wide/16 v10, 0x0

    move-object v6, v4

    invoke-static/range {v5 .. v14}, Llyiahf/vczjk/ue7;->OooO00o(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/rf1;II)V

    move-object v13, v12

    const/4 v1, 0x1

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

.method private final OooOO0O(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    move-object/from16 v9, p2

    check-cast v9, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "paddingValues"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v2, 0x6

    if-nez v3, :cond_1

    move-object v3, v9

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v2, v3

    :cond_1
    and-int/lit8 v2, v2, 0x13

    const/16 v3, 0x12

    if-ne v2, v3, :cond_3

    move-object v2, v9

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_3
    :goto_1
    sget-object v2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v9}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v2

    const/4 v13, 0x1

    invoke-static {v1, v2, v13}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v3, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v12, 0x0

    invoke-static {v2, v3, v9, v12}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    move-object v14, v9

    check-cast v14, Llyiahf/vczjk/zf1;

    iget v3, v14, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v9, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_4

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v9, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v9, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_5

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_6

    :cond_5
    invoke-static {v3, v14, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v9, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    const v1, -0x1b2193dc

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v1, v0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    move-object v4, v1

    check-cast v4, Ltornaco/apps/thanox/running/RunningAppState;

    iget-object v1, v4, Ltornaco/apps/thanox/running/RunningAppState;->OooOOO:Ljava/util/List;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    iget-object v5, v0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    move-object v7, v5

    check-cast v7, Llyiahf/vczjk/ny7;

    if-eqz v3, :cond_7

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v5, v3

    check-cast v5, Ltornaco/apps/thanox/running/RunningProcessState;

    iget-object v3, v5, Ltornaco/apps/thanox/running/RunningProcessState;->OooOOo0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    xor-int/lit8 v10, v3, 0x1

    new-instance v3, Llyiahf/vczjk/zy7;

    iget-object v6, v0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ks1;

    const/4 v8, 0x1

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/zy7;-><init>(Ltornaco/apps/thanox/running/RunningAppState;Ltornaco/apps/thanox/running/RunningProcessState;Llyiahf/vczjk/ks1;Llyiahf/vczjk/ny7;I)V

    move-object v15, v4

    const v4, -0x77d8a6a9

    invoke-static {v4, v3, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    move v3, v10

    const v10, 0x180006

    const/16 v11, 0x1e

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-static/range {v2 .. v11}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move-object v4, v15

    goto :goto_3

    :cond_7
    move-object v15, v4

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/16 v2, 0x10

    int-to-float v2, v2

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    const v1, -0x6815fd56

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v14, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    iget-object v2, v0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v1, v4

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_8

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v1, :cond_9

    :cond_8
    new-instance v4, Llyiahf/vczjk/x5;

    const/16 v1, 0xe

    invoke-direct {v4, v7, v15, v1, v2}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    move-object v2, v4

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/u20;

    const/16 v4, 0x15

    invoke-direct {v1, v15, v4}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v4, 0x4166ba67

    invoke-static {v4, v1, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    const v11, 0x30000030

    const/16 v12, 0x1fc

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v10, v9

    move-object v9, v1

    invoke-static/range {v2 .. v12}, Llyiahf/vczjk/bua;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v14, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

.method private final OooOO0o(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    move-object/from16 v9, p2

    check-cast v9, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "it"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v2, 0x6

    if-nez v3, :cond_1

    move-object v3, v9

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v2, v3

    :cond_1
    and-int/lit8 v2, v2, 0x13

    const/16 v3, 0x12

    if-ne v2, v3, :cond_3

    move-object v2, v9

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_3
    :goto_1
    sget-object v2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v9}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v2

    const/4 v13, 0x1

    invoke-static {v1, v2, v13}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v3, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v12, 0x0

    invoke-static {v2, v3, v9, v12}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    move-object v14, v9

    check-cast v14, Llyiahf/vczjk/zf1;

    iget v3, v14, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v9, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v5, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_4

    invoke-virtual {v14, v5}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v9, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v9, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v14, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_5

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_6

    :cond_5
    invoke-static {v3, v14, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v9, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    const v1, 0x66561b22

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v1, v0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    move-object v4, v1

    check-cast v4, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    iget-object v1, v4, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO:Ljava/util/List;

    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    iget-object v5, v0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    move-object v7, v5

    check-cast v7, Llyiahf/vczjk/oy7;

    if-eqz v3, :cond_7

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    move-object v5, v3

    check-cast v5, Lnow/fortuitous/thanos/process/v2/RunningProcessState;

    iget-object v3, v5, Lnow/fortuitous/thanos/process/v2/RunningProcessState;->OooOOo:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    xor-int/lit8 v10, v3, 0x1

    new-instance v3, Llyiahf/vczjk/az7;

    iget-object v6, v0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/ls1;

    const/4 v8, 0x1

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/az7;-><init>(Lnow/fortuitous/thanos/process/v2/RunningAppState;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/ls1;Llyiahf/vczjk/oy7;I)V

    move-object v15, v4

    const v4, -0x48b918af

    invoke-static {v4, v3, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    move v3, v10

    const v10, 0x180006

    const/16 v11, 0x1e

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-static/range {v2 .. v11}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move-object v4, v15

    goto :goto_3

    :cond_7
    move-object v15, v4

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/16 v2, 0x10

    int-to-float v2, v2

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    const v1, -0x6815fd56

    invoke-virtual {v14, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v14, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v14, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    iget-object v2, v0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {v14, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v1, v4

    invoke-virtual {v14}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_8

    sget-object v1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v1, :cond_9

    :cond_8
    new-instance v4, Llyiahf/vczjk/x5;

    const/16 v1, 0xf

    invoke-direct {v4, v7, v15, v1, v2}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v14, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    move-object v2, v4

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-virtual {v14, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/u20;

    const/16 v4, 0x16

    invoke-direct {v1, v15, v4}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v4, -0x6ff4b39f

    invoke-static {v4, v1, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v1

    const v11, 0x30000030

    const/16 v12, 0x1fc

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v10, v9

    move-object v9, v1

    invoke-static/range {v2 .. v12}, Llyiahf/vczjk/bua;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v14, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

.method private final OooOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/ze3;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    and-int/lit8 v4, v3, 0x6

    if-nez v4, :cond_1

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int/2addr v3, v4

    :cond_1
    and-int/lit8 v4, v3, 0x13

    const/16 v5, 0x12

    const/4 v6, 0x0

    const/4 v7, 0x1

    if-eq v4, v5, :cond_2

    move v4, v7

    goto :goto_1

    :cond_2
    move v4, v6

    :goto_1
    and-int/lit8 v5, v3, 0x1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v5, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v4

    if-eqz v4, :cond_12

    iget-object v4, v0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/gt8;

    iget-object v5, v0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/gt8;

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    sget-object v4, Llyiahf/vczjk/zo5;->OooOOOo:Llyiahf/vczjk/zo5;

    invoke-static {v4, v2}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v11

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    iget-object v8, v0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/lv2;

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v4, v9

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    sget-object v14, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v4, :cond_3

    if-ne v9, v14, :cond_4

    :cond_3
    new-instance v9, Llyiahf/vczjk/w77;

    const/16 v4, 0xa

    invoke-direct {v9, v4, v5, v8}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    move-object v12, v9

    check-cast v12, Llyiahf/vczjk/le3;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    const/high16 v15, 0x3f800000    # 1.0f

    if-ne v4, v14, :cond_6

    if-nez v10, :cond_5

    move v4, v15

    goto :goto_2

    :cond_5
    const/4 v4, 0x0

    :goto_2
    invoke-static {v4}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v4

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/gi;

    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v4

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v13

    or-int/2addr v8, v13

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v8, v13

    invoke-virtual {v2, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v8, v13

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v8, :cond_7

    if-ne v13, v14, :cond_8

    :cond_7
    new-instance v8, Llyiahf/vczjk/vt8;

    const/4 v13, 0x0

    invoke-direct/range {v8 .. v13}, Llyiahf/vczjk/vt8;-><init>(Llyiahf/vczjk/gi;ZLlyiahf/vczjk/wl;Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v13, v8

    :cond_8
    check-cast v13, Llyiahf/vczjk/ze3;

    invoke-static {v4, v2, v13}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v4, v9, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    sget-object v8, Llyiahf/vczjk/zo5;->OooOOO:Llyiahf/vczjk/zo5;

    invoke-static {v8, v2}, Llyiahf/vczjk/so8;->OoooO0O(Llyiahf/vczjk/zo5;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p13;

    move-result-object v8

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-ne v9, v14, :cond_a

    if-nez v10, :cond_9

    goto :goto_3

    :cond_9
    const v15, 0x3f4ccccd    # 0.8f

    :goto_3
    invoke-static {v15}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v9

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v9, Llyiahf/vczjk/gi;

    invoke-static {v10}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v11

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v13

    or-int/2addr v12, v13

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v12, v13

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v12, :cond_b

    if-ne v13, v14, :cond_c

    :cond_b
    new-instance v13, Llyiahf/vczjk/xt8;

    const/4 v12, 0x0

    invoke-direct {v13, v9, v10, v8, v12}, Llyiahf/vczjk/xt8;-><init>(Llyiahf/vczjk/gi;ZLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v13, Llyiahf/vczjk/ze3;

    invoke-static {v11, v2, v13}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v8, v9, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    sget-object v15, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v9, v8, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v9, Llyiahf/vczjk/fw8;

    invoke-virtual {v9}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->floatValue()F

    move-result v16

    iget-object v8, v8, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v8, Llyiahf/vczjk/fw8;

    invoke-virtual {v8}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->floatValue()F

    move-result v17

    iget-object v4, v4, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    move-result v18

    const/16 v22, 0x0

    const v23, 0x1fff8

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    invoke-static/range {v15 .. v23}, Landroidx/compose/ui/graphics/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;FFFFFLlyiahf/vczjk/qj8;ZI)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v8

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    iget-object v9, v0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    check-cast v9, Ljava/lang/String;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v8, v11

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v8, :cond_d

    if-ne v11, v14, :cond_e

    :cond_d
    new-instance v11, Llyiahf/vczjk/fa2;

    invoke-direct {v11, v10, v9, v5}, Llyiahf/vczjk/fa2;-><init>(ZLjava/lang/String;Llyiahf/vczjk/gt8;)V

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v11, Llyiahf/vczjk/oe3;

    invoke-static {v4, v6, v11}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v5, v6}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v6, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v2, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_f

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v2, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_10

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_11

    :cond_10
    invoke-static {v6, v2, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_11
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    and-int/lit8 v3, v3, 0xe

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-interface {v1, v2, v3}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_5

    :cond_12
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

.method private final OooOOO0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 39

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/vk;

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    const-string v2, "$this$AnimatedVisibility"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v4, 0x10

    int-to-float v4, v4

    invoke-static {v3, v4, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v5, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    const/4 v6, 0x6

    invoke-static {v4, v5, v8, v6}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    move-object v7, v8

    check-cast v7, Llyiahf/vczjk/zf1;

    iget v9, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v8, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_0

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_0
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v8, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_1

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_2

    :cond_1
    invoke-static {v9, v7, v9, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v1, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    float-to-double v13, v2

    const-wide/16 v15, 0x0

    cmpl-double v13, v13, v15

    if-lez v13, :cond_3

    goto :goto_1

    :cond_3
    const-string v13, "invalid weight; must be greater than zero"

    invoke-static {v13}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_1
    new-instance v13, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v14, 0x0

    invoke-direct {v13, v2, v14}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    invoke-interface {v3, v13}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-static {v8}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v13

    invoke-static {v3, v13, v14}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v13, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v15, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v2, 0x36

    invoke-static {v13, v15, v8, v2}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v13, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v8, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_4

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    invoke-static {v2, v8, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v15, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_5

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_6

    :cond_5
    invoke-static {v13, v7, v13, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    invoke-static {v3, v8, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v2, v0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qs5;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    invoke-static {v2, v8}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v2

    const v3, 0x4c5de2

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/h48;

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v6, :cond_7

    if-ne v9, v10, :cond_8

    :cond_7
    new-instance v9, Llyiahf/vczjk/pz7;

    const/4 v6, 0x2

    invoke-direct {v9, v4, v6}, Llyiahf/vczjk/pz7;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v9, Llyiahf/vczjk/oe3;

    invoke-virtual {v7, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v9, v8}, Llyiahf/vczjk/so8;->Oooo0(Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/p51;

    move-result-object v6

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Ljava/util/List;

    new-instance v11, Ljava/util/ArrayList;

    const/16 v12, 0xa

    invoke-static {v9, v12}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v12

    invoke-direct {v11, v12}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v9

    move v12, v14

    :goto_3
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    move-result v13

    const/4 v15, 0x0

    if-eqz v13, :cond_a

    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    add-int/lit8 v16, v12, 0x1

    if-ltz v12, :cond_9

    check-cast v13, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    new-instance v3, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;

    invoke-virtual {v13}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getLabel()Ljava/lang/String;

    move-result-object v13

    const-string v14, "getLabel(...)"

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v3, v12, v13, v15, v15}, Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    invoke-virtual {v11, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move/from16 v12, v16

    const v3, 0x4c5de2

    const/4 v14, 0x0

    goto :goto_3

    :cond_9
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v15

    :cond_a
    move v3, v14

    invoke-static {v6, v11, v8, v3}, Llyiahf/vczjk/so8;->OooO0O0(Llyiahf/vczjk/p51;Ljava/util/ArrayList;Llyiahf/vczjk/rf1;I)V

    const v3, 0x6e6b8237

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v25

    :goto_4
    invoke-interface/range {v25 .. v25}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1b

    invoke-interface/range {v25 .. v25}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    invoke-static {v2, v8}, Landroidx/compose/runtime/OooO0o;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v9

    sget-object v11, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    const/4 v12, 0x0

    invoke-static {v11, v12}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v13

    iget v12, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v8, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v23, v5

    iget-boolean v5, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_b

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_b
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v13, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v14, v8, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move-object/from16 v17, v15

    iget-boolean v15, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v15, :cond_c

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    move-object/from16 v24, v13

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v15, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_d

    goto :goto_6

    :cond_c
    move-object/from16 v24, v13

    :goto_6
    invoke-static {v12, v7, v12, v14}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_d
    sget-object v12, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v3, 0x6e3c21fe

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v10, :cond_e

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v3

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v3, Llyiahf/vczjk/qs5;

    const/4 v13, 0x0

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->rename:I

    invoke-static {v13, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v13

    const v15, -0x615d173a

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v19

    or-int v18, v18, v19

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    if-nez v18, :cond_10

    if-ne v15, v10, :cond_f

    goto :goto_7

    :cond_f
    move-object/from16 v26, v12

    goto :goto_8

    :cond_10
    :goto_7
    new-instance v15, Llyiahf/vczjk/gu6;

    move-object/from16 v26, v12

    const/16 v12, 0xa

    invoke-direct {v15, v12, v4, v9}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_8
    check-cast v15, Llyiahf/vczjk/oe3;

    const/4 v12, 0x0

    invoke-virtual {v7, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v9, 0x1c

    move-object/from16 v27, v14

    const/4 v14, 0x0

    invoke-static {v13, v14, v15, v8, v9}, Llyiahf/vczjk/ll6;->OooOOO(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/zl9;

    move-result-object v9

    invoke-static {v9, v8, v12}, Llyiahf/vczjk/ll6;->OooO0Oo(Llyiahf/vczjk/zl9;Llyiahf/vczjk/rf1;I)V

    new-instance v12, Llyiahf/vczjk/ah5;

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->delete:I

    invoke-static {v13, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v13

    sget v15, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_delete_bin_2_line:I

    const-string v14, "delete"

    invoke-direct {v12, v14, v13, v15}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v13, Llyiahf/vczjk/ah5;

    sget v14, Lgithub/tornaco/android/thanos/res/R$string;->rename:I

    invoke-static {v14, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v14

    sget v15, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_edit_2_line:I

    move-object/from16 v28, v5

    const-string v5, "rename"

    invoke-direct {v13, v5, v14, v15}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v5, Llyiahf/vczjk/ah5;

    sget v14, Lgithub/tornaco/android/thanos/res/R$string;->sort:I

    invoke-static {v14, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v14

    sget v15, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_sort_asc:I

    move-object/from16 v29, v11

    const-string v11, "sort"

    invoke-direct {v5, v11, v14, v15}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    filled-new-array {v12, v13, v5}, [Llyiahf/vczjk/ah5;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    const v11, -0x48fade91

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v11, v12

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v11, :cond_12

    if-ne v12, v10, :cond_11

    goto :goto_9

    :cond_11
    move-object v9, v2

    move-object/from16 v31, v6

    move-object/from16 v2, v17

    const/16 v30, 0x0

    move-object v6, v4

    const v4, -0x615d173a

    goto :goto_a

    :cond_12
    :goto_9
    new-instance v15, Llyiahf/vczjk/m60;

    const/16 v20, 0xd

    move-object/from16 v16, v17

    move-object/from16 v17, v2

    move-object/from16 v2, v16

    move-object/from16 v16, v4

    move-object/from16 v19, v6

    move-object/from16 v18, v9

    const v4, -0x615d173a

    const/16 v30, 0x0

    invoke-direct/range {v15 .. v20}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v6, v16

    move-object/from16 v9, v17

    move-object/from16 v31, v19

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v12, v15

    :goto_a
    check-cast v12, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v11, 0x6

    invoke-static {v3, v5, v12, v8, v11}, Llyiahf/vczjk/so8;->OooO0o0(Llyiahf/vczjk/qs5;Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    const/high16 v5, 0x3f800000    # 1.0f

    invoke-static {v1, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v12

    const/16 v13, 0x18

    int-to-float v13, v13

    invoke-static {v13}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v13

    invoke-static {v12, v13}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v12

    const v13, 0xbc537b1

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v13, v0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/qs5;

    invoke-interface {v13}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Ljava/lang/String;

    invoke-virtual {v9}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getId()Ljava/lang/String;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-eqz v13, :cond_13

    sget-object v13, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object v14, v8

    check-cast v14, Llyiahf/vczjk/zf1;

    invoke-virtual {v14, v13}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/x21;

    iget-wide v13, v13, Llyiahf/vczjk/x21;->OooO0OO:J

    :goto_b
    const/4 v15, 0x0

    goto :goto_c

    :cond_13
    sget-wide v13, Llyiahf/vczjk/n21;->OooOO0:J

    goto :goto_b

    :goto_c
    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v15, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v12, v13, v14, v15}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v12

    const v13, 0x4c5de2

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-ne v14, v10, :cond_14

    new-instance v14, Llyiahf/vczjk/a67;

    const/16 v15, 0x8

    invoke-direct {v14, v3, v15}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v7, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_14
    check-cast v14, Llyiahf/vczjk/le3;

    const/4 v15, 0x0

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v3, v4

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_15

    if-ne v4, v10, :cond_16

    :cond_15
    new-instance v4, Llyiahf/vczjk/w77;

    const/16 v3, 0x8

    invoke-direct {v4, v3, v6, v9}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    check-cast v4, Llyiahf/vczjk/le3;

    const/4 v15, 0x0

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v12, v14, v4}, Landroidx/compose/foundation/OooO00o;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v4, 0xc

    int-to-float v4, v4

    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    move-object/from16 v4, v29

    invoke-static {v4, v15}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v4

    iget v12, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v8, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_17

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_d
    move-object/from16 v2, v28

    goto :goto_e

    :cond_17
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_d

    :goto_e
    invoke-static {v4, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v2, v24

    invoke-static {v14, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_18

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_19

    :cond_18
    move-object/from16 v2, v27

    goto :goto_10

    :cond_19
    :goto_f
    move-object/from16 v2, v26

    goto :goto_11

    :goto_10
    invoke-static {v12, v7, v12, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_f

    :goto_11
    invoke-static {v3, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v2, 0x1f5e5708

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {v9}, Llyiahf/vczjk/v18;->OooO00o(Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;)Z

    move-result v2

    if-eqz v2, :cond_1a

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->all:I

    invoke-static {v2, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    :goto_12
    const/4 v15, 0x0

    goto :goto_13

    :cond_1a
    invoke-virtual {v9}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getLabel()Ljava/lang/String;

    move-result-object v2

    goto :goto_12

    :goto_13
    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    move-object/from16 v3, v23

    const/16 v23, 0x6000

    const v24, 0x3bffe

    move-object v4, v3

    const/4 v3, 0x0

    move-object v12, v4

    move v9, v5

    const-wide/16 v4, 0x0

    move-object/from16 v16, v6

    move-object v14, v7

    const-wide/16 v6, 0x0

    move-object/from16 v21, v8

    const/4 v8, 0x0

    move/from16 v17, v9

    const/4 v9, 0x0

    move-object/from16 v19, v10

    move/from16 v18, v11

    const-wide/16 v10, 0x0

    move-object/from16 v20, v12

    const/4 v12, 0x0

    move/from16 v27, v13

    move-object/from16 v26, v14

    const-wide/16 v13, 0x0

    move/from16 v28, v15

    const/4 v15, 0x0

    move-object/from16 v29, v16

    const/16 v16, 0x0

    move/from16 v32, v17

    const/16 v17, 0x1

    move/from16 v33, v18

    const/16 v18, 0x0

    move-object/from16 v34, v19

    const/16 v19, 0x0

    move-object/from16 v35, v20

    const/16 v20, 0x0

    const/16 v36, 0x1

    const/16 v22, 0x0

    move-object/from16 p1, v1

    move-object/from16 v1, v26

    move-object/from16 v37, v29

    move-object/from16 v38, v34

    move/from16 v0, v36

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v8, v21

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v0, p0

    move-object v7, v1

    move-object/from16 v15, v30

    move-object/from16 v6, v31

    move-object/from16 v5, v35

    move-object/from16 v4, v37

    move-object/from16 v10, v38

    move-object/from16 v1, p1

    goto/16 :goto_4

    :cond_1b
    move-object/from16 p1, v1

    move-object/from16 v37, v4

    move-object/from16 v35, v5

    move-object v1, v7

    move-object/from16 v38, v10

    const/4 v0, 0x1

    const/4 v15, 0x0

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v2, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    move-object/from16 v12, v35

    invoke-static {v2, v12, v8, v15}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v3, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    move-object/from16 v5, p1

    invoke-static {v8, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_1c

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_14

    :cond_1c
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_14
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v8, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_1d

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1e

    :cond_1d
    invoke-static {v3, v1, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1e
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v13, 0x4c5de2

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v11, p0

    iget-object v2, v11, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/zl9;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    move-object/from16 v12, v38

    if-nez v3, :cond_1f

    if-ne v4, v12, :cond_20

    :cond_1f
    new-instance v4, Llyiahf/vczjk/fn4;

    const/4 v3, 0x1

    invoke-direct {v4, v2, v3}, Llyiahf/vczjk/fn4;-><init>(Llyiahf/vczjk/zl9;I)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_20
    move-object v2, v4

    check-cast v2, Llyiahf/vczjk/le3;

    const/4 v15, 0x0

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/xb1;->OooO0Oo:Llyiahf/vczjk/a91;

    const/high16 v9, 0x180000

    const/16 v10, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v6, v37

    invoke-virtual {v1, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_21

    if-ne v3, v12, :cond_22

    :cond_21
    new-instance v3, Llyiahf/vczjk/l08;

    const/4 v2, 0x1

    invoke-direct {v3, v6, v2}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_22
    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/le3;

    const/4 v15, 0x0

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v7, Llyiahf/vczjk/xb1;->OooO0o0:Llyiahf/vczjk/a91;

    const/high16 v9, 0x180000

    const/16 v10, 0x3e

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

.method private final OooOOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/bi6;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p1

    const-string p3, "paddings"

    invoke-static {v0, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 p3, p1, 0x6

    if-nez p3, :cond_1

    move-object p3, p2

    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    const/4 p3, 0x4

    goto :goto_0

    :cond_0
    const/4 p3, 0x2

    :goto_0
    or-int/2addr p1, p3

    :cond_1
    and-int/lit8 p3, p1, 0x13

    const/16 v1, 0x12

    if-ne p3, v1, :cond_3

    move-object p3, p2

    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_3
    :goto_1
    iget-object p3, p0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/qs5;

    invoke-interface {p3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p3

    move-object v1, p3

    check-cast v1, Llyiahf/vczjk/j19;

    move-object v5, p2

    check-cast v5, Llyiahf/vczjk/zf1;

    const p2, 0x4c5de2

    invoke-virtual {v5, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/n19;

    invoke-virtual {v5, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez p3, :cond_4

    sget-object p3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v2, p3, :cond_5

    :cond_4
    new-instance v2, Llyiahf/vczjk/w45;

    const/16 p3, 0x15

    invoke-direct {v2, p2, p3}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/oe3;

    const/4 p2, 0x0

    invoke-virtual {v5, p2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    and-int/lit8 v6, p1, 0xe

    iget-object p1, p0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/oe3;

    iget-object p1, p0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/le3;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/er8;->OooO0oo(Llyiahf/vczjk/bi6;Llyiahf/vczjk/j19;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 64

    move-object/from16 v0, p0

    const/16 v2, 0x30

    const v3, 0x6e3c21fe

    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v7, -0x6815fd56

    const/16 v8, 0x12

    const/4 v12, 0x4

    const/4 v13, 0x1

    sget-object v14, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/16 v15, 0x10

    sget-object v16, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/16 v17, 0x6

    iget-object v11, v0, Llyiahf/vczjk/a6;->OooOOo0:Ljava/lang/Object;

    const/16 v18, 0x13

    iget-object v9, v0, Llyiahf/vczjk/a6;->OooOOOo:Ljava/lang/Object;

    iget-object v4, v0, Llyiahf/vczjk/a6;->OooOOO:Ljava/lang/Object;

    iget-object v10, v0, Llyiahf/vczjk/a6;->OooOOOO:Ljava/lang/Object;

    const/4 v1, 0x0

    iget v5, v0, Llyiahf/vczjk/a6;->OooOOO0:I

    packed-switch v5, :pswitch_data_0

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/q31;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v6, "$this$ModalBottomSheet"

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v2, v5, 0x11

    if-ne v2, v15, :cond_1

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v4, Llyiahf/vczjk/xr1;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    check-cast v10, Llyiahf/vczjk/zl8;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v2, v5

    check-cast v9, Llyiahf/vczjk/yo9;

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v2, v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_2

    if-ne v5, v14, :cond_3

    :cond_2
    new-instance v5, Llyiahf/vczjk/x5;

    const/16 v2, 0x19

    invoke-direct {v5, v4, v10, v2, v9}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v5, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v5, v3, v1, v13}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/c45;->OooO00o:Llyiahf/vczjk/jh1;

    sget-object v1, Llyiahf/vczjk/zo9;->OooOOO0:Llyiahf/vczjk/zo9;

    sget-object v2, Llyiahf/vczjk/c45;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/py7;

    check-cast v11, Llyiahf/vczjk/a91;

    invoke-direct {v2, v12, v11, v9}, Llyiahf/vczjk/py7;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v4, -0x6e9efc03

    invoke-static {v4, v2, v3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    const/16 v4, 0x38

    invoke-static {v1, v2, v3, v4}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    return-object v16

    :pswitch_0
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/a6;->OooOOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_1
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/a6;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_2
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/a6;->OooOOO0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_3
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/a6;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_4
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/a6;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_5
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/a6;->OooO0oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_6
    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/bi6;

    move-object/from16 v7, p2

    check-cast v7, Llyiahf/vczjk/rf1;

    move-object/from16 v15, p3

    check-cast v15, Ljava/lang/Number;

    invoke-virtual {v15}, Ljava/lang/Number;->intValue()I

    move-result v15

    const-string v12, "it"

    invoke-static {v5, v12}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v12, v15, 0x6

    if-nez v12, :cond_5

    move-object v12, v7

    check-cast v12, Llyiahf/vczjk/zf1;

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v12

    if-eqz v12, :cond_4

    const/16 v20, 0x4

    goto :goto_2

    :cond_4
    const/16 v20, 0x2

    :goto_2
    or-int v15, v15, v20

    :cond_5
    and-int/lit8 v12, v15, 0x13

    if-ne v12, v8, :cond_7

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v12

    if-nez v12, :cond_6

    goto :goto_3

    :cond_6
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_7
    :goto_3
    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/ot6;

    iget-boolean v8, v8, Llyiahf/vczjk/ot6;->OooO00o:Z

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v14, :cond_8

    new-instance v3, Llyiahf/vczjk/oOOO0OO0;

    const/16 v12, 0x16

    invoke-direct {v3, v12}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v8, v3, v7, v2}, Llyiahf/vczjk/ls6;->OooOOo(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/bf7;

    move-result-object v2

    sget-object v3, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v3, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-static {v3, v2}, Llyiahf/vczjk/xr6;->OooOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf7;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v5, v1}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v12, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v7, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v1, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v1, :cond_9

    invoke-virtual {v7, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_9
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v7, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v15, v7, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_a

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v5, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_b

    :cond_a
    invoke-static {v12, v7, v12, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v7, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    const/16 v3, 0x60

    int-to-float v3, v3

    const/4 v5, 0x7

    const/4 v12, 0x0

    invoke-static {v12, v12, v12, v3, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v25

    const v3, -0x48fade91

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    check-cast v10, Llyiahf/vczjk/gw6;

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v3, v5

    check-cast v9, Llyiahf/vczjk/qs5;

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v3, v5

    check-cast v11, Ljava/util/List;

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v3, v5

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v3, :cond_c

    if-ne v5, v14, :cond_d

    :cond_c
    new-instance v5, Llyiahf/vczjk/m60;

    invoke-direct {v5, v10, v4, v9, v11}, Llyiahf/vczjk/m60;-><init>(Llyiahf/vczjk/gw6;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Ljava/util/List;)V

    invoke-virtual {v7, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    move-object/from16 v32, v5

    check-cast v32, Llyiahf/vczjk/oe3;

    const/4 v3, 0x0

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v34, 0x180

    const/16 v35, 0x1fb

    const/16 v23, 0x0

    const/16 v24, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    const/16 v31, 0x0

    move-object/from16 v33, v7

    invoke-static/range {v23 .. v35}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    sget-object v3, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {v1, v6, v3}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v25

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v3, v1, Llyiahf/vczjk/x21;->OooO0o:J

    const/16 v31, 0x40

    const/16 v32, 0x28

    const-wide/16 v26, 0x0

    move-object/from16 v24, v2

    move-wide/from16 v28, v3

    move-object/from16 v30, v7

    move/from16 v23, v8

    invoke-static/range {v23 .. v32}, Llyiahf/vczjk/ue7;->OooO00o(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_5
    return-object v16

    :pswitch_7
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/a6;->OooO0oO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_8
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v6, "paddings"

    invoke-static {v1, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v6, v5, 0x6

    if-nez v6, :cond_f

    move-object v6, v2

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_e

    const/4 v12, 0x4

    goto :goto_6

    :cond_e
    const/4 v12, 0x2

    :goto_6
    or-int/2addr v5, v12

    :cond_f
    and-int/lit8 v5, v5, 0x13

    if-ne v5, v8, :cond_11

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_10

    goto :goto_7

    :cond_10
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_c

    :cond_11
    :goto_7
    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v4, Llyiahf/vczjk/vr6;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    check-cast v10, Landroid/content/Context;

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    check-cast v9, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v5, v6

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_12

    if-ne v6, v14, :cond_13

    :cond_12
    new-instance v6, Llyiahf/vczjk/or6;

    const/4 v5, 0x0

    invoke-direct {v6, v4, v10, v9, v5}, Llyiahf/vczjk/or6;-><init>(Llyiahf/vczjk/vr6;Landroid/content/Context;Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v6, Llyiahf/vczjk/ze3;

    const/4 v5, 0x0

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v2, v6}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v6, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v6, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v7, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    const/16 v8, 0x36

    invoke-static {v6, v7, v2, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v6

    iget v7, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v2, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_14

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_14
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v6, v2, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v2, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v12, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v12, :cond_15

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v12, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v12

    if-nez v12, :cond_16

    :cond_15
    invoke-static {v7, v2, v7, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_16
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v2, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v1, Lgithub/tornaco/practice/honeycomb/locker/ui/verify/PatternSettingsActivity;->OoooO0O:I

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/yr6;

    iget-object v1, v1, Llyiahf/vczjk/yr6;->OooO00o:Llyiahf/vczjk/k59;

    sget-object v11, Llyiahf/vczjk/h59;->OooO00o:Llyiahf/vczjk/h59;

    invoke-static {v1, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_17

    const v1, 0x35f34761

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v1, 0x0

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const-string v1, ""

    :goto_9
    move-object/from16 v25, v1

    goto :goto_a

    :cond_17
    sget-object v11, Llyiahf/vczjk/i59;->OooO00o:Llyiahf/vczjk/i59;

    invoke-static {v1, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_18

    const v1, 0x35f49eec

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pattern_settings_draw_1:I

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v1

    const/4 v11, 0x0

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_9

    :cond_18
    const/4 v11, 0x0

    sget-object v12, Llyiahf/vczjk/j59;->OooO00o:Llyiahf/vczjk/j59;

    invoke-static {v1, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1d

    const v1, 0x35f7396c

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pattern_settings_draw_2:I

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v2, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_9

    :goto_a
    const v1, 0x20afa4f1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v14, :cond_19

    sget-object v1, Llyiahf/vczjk/g13;->Oooo:Llyiahf/vczjk/g13;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_19
    move-object/from16 v27, v1

    check-cast v27, Llyiahf/vczjk/oe3;

    const/4 v1, 0x0

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/k91;

    const/16 v3, 0xc

    invoke-direct {v1, v3}, Llyiahf/vczjk/k91;-><init>(I)V

    const v3, 0x72008807

    invoke-static {v3, v1, v2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v31

    const v33, 0x180180

    const/16 v34, 0x3a

    const/16 v26, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    const/16 v30, 0x0

    move-object/from16 v32, v2

    invoke-static/range {v25 .. v34}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x0

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v2}, Llyiahf/vczjk/ru6;->OooO0O0(ILlyiahf/vczjk/rf1;)V

    int-to-float v3, v15

    const/4 v11, 0x2

    const/4 v12, 0x0

    invoke-static {v5, v3, v12, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v11, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v11, v1}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v11

    iget v1, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v2, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_1a

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_b

    :cond_1a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_b
    invoke-static {v11, v2, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12, v2, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v6, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_1b

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_1c

    :cond_1b
    invoke-static {v1, v2, v1, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1c
    invoke-static {v3, v2, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_title_verify_custom_pattern_settings_warn:I

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v1

    const/4 v3, 0x0

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/br6;->OooO(Ljava/lang/String;Llyiahf/vczjk/rf1;I)V

    const/4 v1, 0x1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v1, 0x40

    int-to-float v1, v1

    const/16 v24, 0x0

    const/16 v28, 0xd

    const/16 v26, 0x0

    const/16 v27, 0x0

    move/from16 v25, v1

    move-object/from16 v23, v5

    invoke-static/range {v23 .. v28}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v25

    new-instance v1, Llyiahf/vczjk/u20;

    invoke-direct {v1, v4, v15}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v3, 0x39e2fa05

    invoke-static {v3, v1, v2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v28

    const/16 v30, 0xc06

    const/16 v31, 0x6

    const/16 v26, 0x0

    const/16 v27, 0x0

    move-object/from16 v29, v2

    invoke-static/range {v25 .. v31}, Llyiahf/vczjk/dn8;->OooOOOo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;ZLlyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_c
    return-object v16

    :cond_1d
    const v1, -0x59193441

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/4 v1, 0x0

    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :pswitch_9
    move-object/from16 v1, p1

    check-cast v1, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v7, "$this$item"

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v5, 0x11

    if-ne v1, v15, :cond_1f

    move-object v1, v3

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_1e

    goto :goto_d

    :cond_1e
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_19

    :cond_1f
    :goto_d
    int-to-float v1, v15

    const/4 v5, 0x2

    const/4 v12, 0x0

    invoke-static {v6, v1, v12, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v25

    const/16 v26, 0x0

    const/16 v30, 0xd

    const/16 v28, 0x0

    const/16 v29, 0x0

    move/from16 v27, v1

    invoke-static/range {v25 .. v30}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    move/from16 v5, v27

    const/high16 v7, 0x3f800000    # 1.0f

    invoke-static {v1, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    const/16 v12, 0x40

    int-to-float v12, v12

    const/4 v13, 0x2

    const/4 v15, 0x0

    invoke-static {v1, v12, v15, v13}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v13, Llyiahf/vczjk/uv7;->OooO00o:Llyiahf/vczjk/tv7;

    new-instance v13, Llyiahf/vczjk/hs6;

    const/16 v15, 0x14

    int-to-float v15, v15

    invoke-direct {v13, v15}, Llyiahf/vczjk/hs6;-><init>(F)V

    move/from16 v31, v8

    new-instance v8, Llyiahf/vczjk/tv7;

    invoke-direct {v8, v13, v13, v13, v13}, Llyiahf/vczjk/ir1;-><init>(Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;)V

    invoke-static {v1, v8}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v8, Llyiahf/vczjk/nq9;->OooO0OO:Llyiahf/vczjk/l39;

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/ap9;

    move-object/from16 p2, v8

    iget-wide v7, v13, Llyiahf/vczjk/ap9;->OooO00o:J

    sget-object v13, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v1, v7, v8, v13}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v1

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v4, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_20

    if-ne v8, v14, :cond_21

    :cond_20
    new-instance v8, Llyiahf/vczjk/a5;

    const/16 v7, 0x1b

    invoke-direct {v8, v7, v4}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_21
    check-cast v8, Llyiahf/vczjk/le3;

    const/4 v4, 0x0

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v8}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v7, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-static {v7, v4}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v8

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v2

    invoke-static {v3, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v25, v9

    iget-boolean v9, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_22

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_e

    :cond_22
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_e
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v8, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move-object/from16 v33, v10

    iget-boolean v10, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_23

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    move-object/from16 v34, v11

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_24

    goto :goto_f

    :cond_23
    move-object/from16 v34, v11

    :goto_f
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_24
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v10, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    move-object/from16 p3, v7

    const/16 v11, 0x30

    invoke-static {v10, v1, v3, v11}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v7

    iget v11, v3, Llyiahf/vczjk/zf1;->Oooo:I

    move-object/from16 v17, v1

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v1

    move-object/from16 v18, v10

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v10

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v35, v14

    iget-boolean v14, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_25

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_25
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    invoke-static {v7, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v1, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_26

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v1, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_27

    :cond_26
    invoke-static {v11, v3, v11, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_27
    invoke-static {v10, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v1, 0x26

    int-to-float v1, v1

    invoke-static {v6, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v10, Llyiahf/vczjk/uv7;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v7, v10}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-static {v3}, Llyiahf/vczjk/rk0;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qk0;

    move-result-object v11

    move-object v14, v10

    iget-wide v10, v11, Llyiahf/vczjk/qk0;->OooO00o:J

    invoke-static {v7, v10, v11, v13}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v10, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    move-object/from16 v23, v14

    const/4 v11, 0x0

    invoke-static {v10, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v14

    iget v11, v3, Llyiahf/vczjk/zf1;->Oooo:I

    move-object/from16 v60, v10

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v3, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v61, v1

    iget-boolean v1, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v1, :cond_28

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_11

    :cond_28
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_11
    invoke-static {v14, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v10, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_29

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v1, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2a

    :cond_29
    invoke-static {v11, v3, v11, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2a
    invoke-static {v7, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v15}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v39

    sget v1, Lgithub/tornaco/android/thanos/lite/app/R$drawable;->ic_snowflake_line:I

    invoke-static {v1, v3}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v37

    invoke-static {v3}, Llyiahf/vczjk/rk0;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qk0;

    move-result-object v1

    const/16 v43, 0x1b0

    const/16 v44, 0x0

    const-string v38, ""

    iget-wide v10, v1, Llyiahf/vczjk/qk0;->OooO0O0:J

    move-object/from16 v42, v3

    move-wide/from16 v40, v10

    invoke-static/range {v37 .. v44}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v1, 0x0

    invoke-static {v1, v3}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    sget-object v7, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v10, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v7, v10, v3, v1}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v11

    iget v1, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    move-object/from16 v62, v7

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v63, v10

    iget-boolean v10, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_2b

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_12

    :cond_2b
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_12
    invoke-static {v11, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v10, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_2c

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_2d

    :cond_2c
    invoke-static {v1, v3, v1, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2d
    invoke-static {v7, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->smart_freeze:I

    invoke-static {v1, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v37

    invoke-static/range {v31 .. v31}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v41

    sget-object v43, Llyiahf/vczjk/ib3;->OooOOOO:Llyiahf/vczjk/ib3;

    const/16 v58, 0x0

    const v59, 0x3ffae

    const/16 v38, 0x0

    const-wide/16 v39, 0x0

    const/16 v44, 0x0

    const-wide/16 v45, 0x0

    const/16 v47, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const/16 v52, 0x0

    const/16 v53, 0x0

    const/16 v54, 0x0

    const/16 v55, 0x0

    const v57, 0x186000

    move-object/from16 v56, v3

    invoke-static/range {v37 .. v59}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v1, v43

    move-object/from16 v7, v25

    check-cast v7, Llyiahf/vczjk/qs5;

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/w18;

    iget v10, v10, Llyiahf/vczjk/w18;->OooO00o:I

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/w18;

    iget v11, v11, Llyiahf/vczjk/w18;->OooO0O0:I

    if-ne v10, v11, :cond_2e

    const v10, -0x54f0e33e

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->sf_pkg_stats_all_freeze:I

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/w18;

    iget v7, v7, Llyiahf/vczjk/w18;->OooO00o:I

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    filled-new-array {v7}, [Ljava/lang/Object;

    move-result-object v7

    invoke-static {v10, v7, v3}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v7

    const/4 v11, 0x0

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_13
    move-object/from16 v37, v7

    const/16 v21, 0xc

    goto :goto_14

    :cond_2e
    const v10, -0x54eaf4d9

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->sf_pkg_stats:I

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/w18;

    iget v11, v11, Llyiahf/vczjk/w18;->OooO00o:I

    invoke-static {v11}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v11

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/w18;

    iget v14, v14, Llyiahf/vczjk/w18;->OooO0O0:I

    invoke-static {v14}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v14

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/w18;

    iget v7, v7, Llyiahf/vczjk/w18;->OooO0OO:I

    invoke-static {v7}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v7

    filled-new-array {v11, v14, v7}, [Ljava/lang/Object;

    move-result-object v7

    invoke-static {v10, v7, v3}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v7

    const/4 v11, 0x0

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_13

    :goto_14
    invoke-static/range {v21 .. v21}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v41

    const/16 v58, 0x0

    const v59, 0x3ffee

    const/16 v38, 0x0

    const-wide/16 v39, 0x0

    const/16 v43, 0x0

    const/16 v44, 0x0

    const-wide/16 v45, 0x0

    const/16 v47, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const/16 v52, 0x0

    const/16 v53, 0x0

    const/16 v54, 0x0

    const/16 v55, 0x0

    const/16 v57, 0x6000

    move-object/from16 v56, v3

    invoke-static/range {v37 .. v59}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v7, 0x1

    invoke-static {v3, v7, v7, v7}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    const/4 v7, 0x0

    const/4 v11, 0x2

    invoke-static {v6, v5, v7, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v25

    const/16 v26, 0x0

    const/16 v30, 0xd

    const/16 v28, 0x0

    const/16 v29, 0x0

    move/from16 v27, v5

    invoke-static/range {v25 .. v30}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    move/from16 v10, v27

    const/high16 v14, 0x3f800000    # 1.0f

    invoke-static {v5, v14}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v5, v12, v7, v11}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    new-instance v7, Llyiahf/vczjk/hs6;

    invoke-direct {v7, v15}, Llyiahf/vczjk/hs6;-><init>(F)V

    new-instance v11, Llyiahf/vczjk/tv7;

    invoke-direct {v11, v7, v7, v7, v7}, Llyiahf/vczjk/ir1;-><init>(Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;)V

    invoke-static {v5, v11}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    move-object/from16 v7, p2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/ap9;

    iget-wide v11, v7, Llyiahf/vczjk/ap9;->OooO00o:J

    invoke-static {v5, v11, v12, v13}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v7, v33

    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-nez v11, :cond_2f

    move-object/from16 v14, v35

    if-ne v12, v14, :cond_30

    :cond_2f
    new-instance v12, Llyiahf/vczjk/a5;

    const/16 v11, 0x1c

    invoke-direct {v12, v11, v7}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v3, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_30
    check-cast v12, Llyiahf/vczjk/le3;

    const/4 v11, 0x0

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v5, v12}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v5, v10}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    move-object/from16 v7, p3

    invoke-static {v7, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v10, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v3, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_31

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_15

    :cond_31
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_15
    invoke-static {v7, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_32

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v7, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_33

    :cond_32
    invoke-static {v10, v3, v10, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_33
    invoke-static {v5, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v5, v17

    move-object/from16 v7, v18

    const/16 v11, 0x30

    invoke-static {v7, v5, v3, v11}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    iget v7, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_34

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_16

    :cond_34
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_16
    invoke-static {v5, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v10, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_35

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v5, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_36

    :cond_35
    invoke-static {v7, v3, v7, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_36
    invoke-static {v11, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move/from16 v5, v61

    invoke-static {v6, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    move-object/from16 v14, v23

    invoke-static {v5, v14}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v3}, Llyiahf/vczjk/rk0;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qk0;

    move-result-object v7

    iget-wide v10, v7, Llyiahf/vczjk/qk0;->OooO00o:J

    invoke-static {v5, v10, v11, v13}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    move-object/from16 v7, v60

    const/4 v11, 0x0

    invoke-static {v7, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v10, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v3, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_37

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_17

    :cond_37
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_17
    invoke-static {v7, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v11, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_38

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v7, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_39

    :cond_38
    invoke-static {v10, v3, v10, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_39
    invoke-static {v5, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v15}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v39

    sget v5, Lgithub/tornaco/android/thanos/lite/app/R$drawable;->ic_clear_bytedance:I

    invoke-static {v5, v3}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v37

    invoke-static {v3}, Llyiahf/vczjk/rk0;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qk0;

    move-result-object v5

    const/16 v43, 0x1b0

    const/16 v44, 0x0

    const-string v38, ""

    iget-wide v10, v5, Llyiahf/vczjk/qk0;->OooO0O0:J

    move-object/from16 v42, v3

    move-wide/from16 v40, v10

    invoke-static/range {v37 .. v44}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    const/4 v7, 0x1

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v11, 0x0

    invoke-static {v11, v3}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v5, v62

    move-object/from16 v7, v63

    invoke-static {v5, v7, v3, v11}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v7, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_3a

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_18

    :cond_3a
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_18
    invoke-static {v5, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v10, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_3b

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v0, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3c

    :cond_3b
    invoke-static {v7, v3, v7, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_3c
    invoke-static {v6, v3, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->bg_clean:I

    invoke-static {v0, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v37

    invoke-static/range {v31 .. v31}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v41

    const/16 v58, 0x0

    const v59, 0x3ffae

    const/16 v38, 0x0

    const-wide/16 v39, 0x0

    const/16 v44, 0x0

    const-wide/16 v45, 0x0

    const/16 v47, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const/16 v52, 0x0

    const/16 v53, 0x0

    const/16 v54, 0x0

    const/16 v55, 0x0

    const v57, 0x186000

    move-object/from16 v43, v1

    move-object/from16 v56, v3

    invoke-static/range {v37 .. v59}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->bg_clean_apps_count:I

    move-object/from16 v11, v34

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/m30;

    iget v1, v1, Llyiahf/vczjk/m30;->OooO00o:I

    invoke-static {v1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    invoke-static {v0, v1, v3}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v37

    const/16 v21, 0xc

    invoke-static/range {v21 .. v21}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v41

    const/16 v58, 0x0

    const v59, 0x3ffee

    const/16 v38, 0x0

    const-wide/16 v39, 0x0

    const/16 v43, 0x0

    const/16 v44, 0x0

    const-wide/16 v45, 0x0

    const/16 v47, 0x0

    const-wide/16 v48, 0x0

    const/16 v50, 0x0

    const/16 v51, 0x0

    const/16 v52, 0x0

    const/16 v53, 0x0

    const/16 v54, 0x0

    const/16 v55, 0x0

    const/16 v57, 0x6000

    move-object/from16 v56, v3

    invoke-static/range {v37 .. v59}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v1, 0x1

    invoke-static {v3, v1, v1, v1}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    :goto_19
    return-object v16

    :pswitch_a
    move/from16 v31, v8

    move-object/from16 v25, v9

    move-object/from16 v33, v10

    move-object/from16 v34, v11

    const/4 v11, 0x2

    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/bi6;

    move-object/from16 v0, p2

    check-cast v0, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p3

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    const-string v2, "contentPadding"

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v2, v1, 0x6

    if-nez v2, :cond_3e

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3d

    const/4 v10, 0x4

    goto :goto_1a

    :cond_3d
    move v10, v11

    :goto_1a
    or-int/2addr v1, v10

    :cond_3e
    and-int/lit8 v2, v1, 0x13

    move/from16 v3, v31

    if-ne v2, v3, :cond_40

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_3f

    goto :goto_1b

    :cond_3f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1c

    :cond_40
    :goto_1b
    sget v2, Lgithub/tornaco/thanos/android/module/profile/LogActivity;->OoooO0O:I

    move-object/from16 v10, v33

    check-cast v10, Llyiahf/vczjk/qs5;

    invoke-interface {v10}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/j55;

    iget-boolean v2, v2, Llyiahf/vczjk/j55;->OooO0O0:Z

    invoke-static {v2, v0}, Llyiahf/vczjk/tn6;->OooOOo0(ZLlyiahf/vczjk/rf1;)Llyiahf/vczjk/jc9;

    move-result-object v17

    check-cast v0, Llyiahf/vczjk/zf1;

    const v7, 0x4c5de2

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/l55;

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_41

    if-ne v3, v14, :cond_42

    :cond_41
    new-instance v3, Llyiahf/vczjk/z45;

    const/4 v7, 0x1

    invoke-direct {v3, v6, v7}, Llyiahf/vczjk/z45;-><init>(Llyiahf/vczjk/l55;I)V

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_42
    move-object/from16 v18, v3

    check-cast v18, Llyiahf/vczjk/le3;

    const/4 v11, 0x0

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v24, Llyiahf/vczjk/ta1;->OooO0O0:Llyiahf/vczjk/a91;

    new-instance v4, Llyiahf/vczjk/ha2;

    move-object/from16 v8, v34

    check-cast v8, Llyiahf/vczjk/dw4;

    move-object/from16 v9, v33

    check-cast v9, Llyiahf/vczjk/qs5;

    move-object/from16 v7, v25

    check-cast v7, Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    const/4 v10, 0x1

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/ha2;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v2, -0x45bf28c5

    invoke-static {v2, v4, v0}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v26

    const/high16 v2, 0x380000

    const/16 v31, 0x12

    shl-int/lit8 v1, v1, 0x12

    and-int/2addr v1, v2

    const/high16 v2, 0x36c00000

    or-int v28, v1, v2

    const/16 v21, 0x0

    const/16 v29, 0x3c

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v25, 0x0

    move-object/from16 v27, v0

    move-object/from16 v23, v5

    invoke-static/range {v17 .. v29}, Llyiahf/vczjk/tn6;->OooO0OO(Llyiahf/vczjk/jc9;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZFLlyiahf/vczjk/o4;Llyiahf/vczjk/bi6;Llyiahf/vczjk/df3;ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_1c
    return-object v16

    :pswitch_b
    move-object/from16 v25, v9

    move-object/from16 v33, v10

    move-object/from16 v34, v11

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/q31;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$DropdownMenu"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, v2, 0x11

    if-ne v0, v15, :cond_44

    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_43

    goto :goto_1d

    :cond_43
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1f

    :cond_44
    :goto_1d
    check-cast v4, Ljava/util/List;

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_1e
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_47

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/w03;

    new-instance v3, Llyiahf/vczjk/b6;

    move-object/from16 v9, v25

    check-cast v9, Landroid/content/Context;

    move/from16 v4, v18

    invoke-direct {v3, v4, v2, v9}, Llyiahf/vczjk/b6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v4, 0x61a85b4c

    invoke-static {v4, v3, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v35

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v10, v33

    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_45

    if-ne v5, v14, :cond_46

    :cond_45
    new-instance v5, Llyiahf/vczjk/x5;

    move-object/from16 v11, v34

    check-cast v11, Llyiahf/vczjk/qs5;

    const/16 v4, 0x8

    invoke-direct {v5, v10, v2, v4, v11}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_46
    move-object/from16 v36, v5

    check-cast v36, Llyiahf/vczjk/le3;

    const/4 v11, 0x0

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v42, 0x6

    const/16 v43, 0x1fc

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    const/16 v40, 0x0

    move-object/from16 v41, v3

    invoke-static/range {v35 .. v43}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    const/16 v18, 0x13

    goto :goto_1e

    :cond_47
    :goto_1f
    return-object v16

    :pswitch_c
    move-object/from16 v25, v9

    move-object/from16 v33, v10

    move-object/from16 v34, v11

    const/4 v11, 0x2

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/bi6;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "contentPadding"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v2, 0x6

    if-nez v3, :cond_49

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_48

    const/4 v10, 0x4

    goto :goto_20

    :cond_48
    move v10, v11

    :goto_20
    or-int/2addr v2, v10

    :cond_49
    const/16 v18, 0x13

    and-int/lit8 v2, v2, 0x13

    const/16 v3, 0x12

    if-ne v2, v3, :cond_4b

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_4a

    goto :goto_21

    :cond_4a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_23

    :cond_4b
    :goto_21
    sget-object v2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v2, v0}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v3, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v11, 0x0

    invoke-static {v2, v3, v1, v11}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/zf1;

    iget v5, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v1, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v7, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_4c

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_22

    :cond_4c
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_22
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_4d

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_4e

    :cond_4d
    invoke-static {v5, v3, v5, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4e
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v11, v34

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-interface {v11}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/m02;

    move-object/from16 v9, v25

    check-cast v9, Llyiahf/vczjk/k02;

    move-object/from16 v10, v33

    check-cast v10, Llyiahf/vczjk/ov5;

    const/4 v11, 0x0

    invoke-static {v10, v9, v0, v1, v11}, Llyiahf/vczjk/bua;->OooO(Llyiahf/vczjk/ov5;Llyiahf/vczjk/k02;Llyiahf/vczjk/m02;Llyiahf/vczjk/rf1;I)V

    const/4 v7, 0x1

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v4, Llyiahf/vczjk/n3;

    invoke-static {v4, v1, v11}, Llyiahf/vczjk/tg0;->OooO0O0(Llyiahf/vczjk/n3;Llyiahf/vczjk/rf1;I)V

    :goto_23
    return-object v16

    :pswitch_d
    move-object/from16 v25, v9

    move-object/from16 v33, v10

    move-object/from16 v34, v11

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/iw7;

    move-object/from16 v12, p2

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p3

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    const-string v2, "$this$ThanoxMediumAppBarScaffold"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, v1, 0x11

    if-ne v0, v15, :cond_50

    move-object v0, v12

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_4f

    goto :goto_24

    :cond_4f
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_25

    :cond_50
    :goto_24
    sget v0, Lgithub/tornaco/thanos/module/component/manager/redesign/ComponentsActivity;->OoooO0O:I

    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-interface {v4}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cr5;

    iget-boolean v0, v0, Llyiahf/vczjk/cr5;->OooO00o:Z

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    new-instance v0, Llyiahf/vczjk/y71;

    move-object/from16 v10, v33

    check-cast v10, Llyiahf/vczjk/t81;

    move-object/from16 v9, v25

    check-cast v9, Llyiahf/vczjk/hb8;

    move-object/from16 v11, v34

    check-cast v11, Llyiahf/vczjk/qs5;

    invoke-direct {v0, v10, v9, v11}, Llyiahf/vczjk/y71;-><init>(Llyiahf/vczjk/t81;Llyiahf/vczjk/hb8;Llyiahf/vczjk/qs5;)V

    const v1, 0x579dd5e3

    invoke-static {v1, v0, v12}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v11

    const/high16 v13, 0x180000

    const/16 v14, 0x3e

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    invoke-static/range {v5 .. v14}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    :goto_25
    return-object v16

    :pswitch_e
    move-object/from16 v25, v9

    move-object/from16 v33, v10

    move-object/from16 v34, v11

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/iw7;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$ThanoxBottomSheetScaffold"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, v2, 0x11

    if-ne v0, v15, :cond_52

    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_51

    goto :goto_26

    :cond_51
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2b

    :cond_52
    :goto_26
    check-cast v1, Llyiahf/vczjk/zf1;

    const v0, -0x615d173a

    invoke-virtual {v1, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    move-object/from16 v10, v33

    check-cast v10, Llyiahf/vczjk/hb8;

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v0, v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_54

    if-ne v2, v14, :cond_53

    goto :goto_27

    :cond_53
    const/4 v11, 0x0

    goto :goto_28

    :cond_54
    :goto_27
    new-instance v2, Llyiahf/vczjk/r20;

    const/4 v11, 0x0

    invoke-direct {v2, v10, v4, v11}, Llyiahf/vczjk/r20;-><init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_28
    move-object/from16 v35, v2

    check-cast v35, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v40, Llyiahf/vczjk/p91;->OooO0O0:Llyiahf/vczjk/a91;

    const/high16 v42, 0x180000

    const/16 v43, 0x3e

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    move-object/from16 v41, v1

    invoke-static/range {v35 .. v43}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v1, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    move-object/from16 v9, v25

    check-cast v9, Llyiahf/vczjk/xr1;

    invoke-virtual {v1, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v0, v2

    move-object/from16 v11, v34

    check-cast v11, Llyiahf/vczjk/lg0;

    invoke-virtual {v1, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v0, v2

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v0, :cond_56

    if-ne v2, v14, :cond_55

    goto :goto_29

    :cond_55
    const/4 v3, 0x0

    goto :goto_2a

    :cond_56
    :goto_29
    new-instance v2, Llyiahf/vczjk/s20;

    const/4 v3, 0x0

    invoke-direct {v2, v9, v4, v11, v3}, Llyiahf/vczjk/s20;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/qs5;Llyiahf/vczjk/lg0;I)V

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_2a
    move-object/from16 v35, v2

    check-cast v35, Llyiahf/vczjk/le3;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v40, Llyiahf/vczjk/p91;->OooO0OO:Llyiahf/vczjk/a91;

    const/high16 v42, 0x180000

    const/16 v43, 0x3e

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v39, 0x0

    move-object/from16 v41, v1

    invoke-static/range {v35 .. v43}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_2b
    return-object v16

    :pswitch_f
    move-object/from16 v25, v9

    move-object/from16 v33, v10

    move-object/from16 v34, v11

    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/w73;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$FlowRow"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, v2, 0x11

    if-ne v0, v15, :cond_58

    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_57

    goto :goto_2c

    :cond_57
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_31

    :cond_58
    :goto_2c
    check-cast v4, Llyiahf/vczjk/xw2;

    iget-object v0, v4, Llyiahf/vczjk/xw2;->OooO0O0:Ljava/util/List;

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_64

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/ww2;

    sget-object v2, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v3, 0x0

    invoke-static {v2, v3}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v2

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/zf1;

    iget v4, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v5

    invoke-static {v1, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_59

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2e

    :cond_59
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2e
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v5, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v5, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_5a

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_5b

    :cond_5a
    invoke-static {v4, v3, v4, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5b
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_5c

    if-ne v4, v14, :cond_5d

    :cond_5c
    sget-object v2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v4

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5d
    move-object v9, v4

    check-cast v9, Llyiahf/vczjk/qs5;

    const/4 v4, 0x0

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_5e

    if-ne v4, v14, :cond_5f

    :cond_5e
    iget-object v4, v11, Llyiahf/vczjk/ww2;->OooO0oO:Ljava/util/List;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5f
    move-object v8, v4

    check-cast v8, Ljava/util/List;

    const/4 v4, 0x0

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_60

    if-ne v5, v14, :cond_61

    :cond_60
    new-instance v5, Llyiahf/vczjk/w5;

    invoke-direct {v5, v9, v4}, Llyiahf/vczjk/w5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_61
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v10, v33

    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-static {v11, v10, v5, v1, v4}, Llyiahf/vczjk/t51;->OooO00o(Llyiahf/vczjk/ww2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    const v2, 0x3f2e147b    # 0.68f

    invoke-static {v6, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v39

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v37

    const v2, 0x4c5de2

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_63

    if-ne v5, v14, :cond_62

    goto :goto_2f

    :cond_62
    move/from16 v4, v17

    goto :goto_30

    :cond_63
    :goto_2f
    new-instance v5, Llyiahf/vczjk/l5;

    move/from16 v4, v17

    invoke-direct {v5, v9, v4}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_30
    move-object/from16 v38, v5

    check-cast v38, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v7, Llyiahf/vczjk/z5;

    move-object/from16 v12, v34

    check-cast v12, Landroidx/appcompat/app/AppCompatActivity;

    move-object/from16 v10, v25

    check-cast v10, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-direct/range {v7 .. v13}, Llyiahf/vczjk/z5;-><init>(Ljava/util/List;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ww2;Landroidx/appcompat/app/AppCompatActivity;I)V

    const v8, -0x57cbe77

    invoke-static {v8, v7, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v49

    const/16 v48, 0x0

    const/16 v52, 0x7f8

    const-wide/16 v40, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/16 v44, 0x0

    const-wide/16 v45, 0x0

    const/16 v47, 0x0

    const/16 v51, 0x180

    move-object/from16 v50, v1

    invoke-static/range {v37 .. v52}, Llyiahf/vczjk/fe;->OooO00o(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/z98;Llyiahf/vczjk/d07;Llyiahf/vczjk/qj8;JFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move/from16 v17, v4

    move-object/from16 v1, v50

    goto/16 :goto_2d

    :cond_64
    :goto_31
    return-object v16

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
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
