.class public final Llyiahf/vczjk/n6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;

.field public final synthetic OooOOOo:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Z)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/n6;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/n6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    iput-object p4, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/cf3;Llyiahf/vczjk/cf3;I)V
    .locals 0

    iput p4, p0, Llyiahf/vczjk/n6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method private final OooO0oO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 62

    move-object/from16 v0, p0

    const/16 v5, 0x9

    const/16 v6, 0x1a

    const/16 v7, 0x12

    const/4 v13, 0x0

    const/4 v14, 0x1

    move-object/from16 v15, p1

    check-cast v15, Llyiahf/vczjk/bi6;

    const/16 v16, 0x6

    move-object/from16 v8, p2

    check-cast v8, Llyiahf/vczjk/rf1;

    move-object/from16 v17, p3

    check-cast v17, Ljava/lang/Number;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Number;->intValue()I

    move-result v17

    const-string v1, "paddingValues"

    invoke-static {v15, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v17, 0x6

    if-nez v1, :cond_1

    move-object v1, v8

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x4

    goto :goto_0

    :cond_0
    const/4 v1, 0x2

    :goto_0
    or-int v17, v17, v1

    :cond_1
    and-int/lit8 v1, v17, 0x13

    if-ne v1, v7, :cond_3

    move-object v1, v8

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v17

    if-nez v17, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_1a

    :cond_3
    :goto_1
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v17, 0x5

    sget-object v9, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v2, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object v3, v8

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/x21;

    iget-wide v10, v2, Llyiahf/vczjk/x21;->OooOOO:J

    sget-object v2, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v9, v10, v11, v2}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v8}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v9

    invoke-static {v2, v9, v14}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2, v15}, Llyiahf/vczjk/uoa;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v18

    const/16 v2, 0x20

    int-to-float v2, v2

    const/16 v19, 0x0

    const/16 v23, 0x7

    const/16 v20, 0x0

    const/16 v21, 0x0

    move/from16 v22, v2

    invoke-static/range {v18 .. v23}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2}, Landroidx/compose/animation/OooO0OO;->OooO00o(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v9, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v10, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v9, v10, v8, v13}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v9

    iget v10, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v11

    invoke-static {v8, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v18, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move/from16 v31, v14

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_4

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v11, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v9, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_6

    :cond_5
    invoke-static {v10, v3, v10, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v8, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v2, Llyiahf/vczjk/im4;->OooO0OO:I

    invoke-static {v2, v8}, Llyiahf/vczjk/so8;->OooOo0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v2

    invoke-interface {v15}, Llyiahf/vczjk/bi6;->OooO0OO()F

    move-result v4

    invoke-static {v1, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v8, v4}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v4, 0x4bc23bb7    # 2.5458542E7f

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    iget-object v9, v0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/qs5;

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/mi8;

    const v11, -0x728bec69

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v11, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Landroid/content/Context;

    invoke-static {v3}, Llyiahf/vczjk/zsa;->ooOO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/zh1;

    move-result-object v19

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->nav_title_feedback:I

    invoke-static {v7, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v18

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->dialog_message_feedback:I

    invoke-static {v7, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->feedback_export_log:I

    invoke-static {v7, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v22

    const v7, 0x6e3c21fe

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v12, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v12, :cond_7

    new-instance v7, Llyiahf/vczjk/r07;

    invoke-direct {v7, v6}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    move-object/from16 v21, v7

    check-cast v21, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v6, v0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v23

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v23, :cond_8

    if-ne v7, v12, :cond_9

    :cond_8
    new-instance v7, Llyiahf/vczjk/hp;

    invoke-direct {v7, v5, v6}, Llyiahf/vczjk/hp;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    move-object/from16 v24, v7

    check-cast v24, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v27, 0x20

    const/16 v23, 0x0

    const/16 v26, 0xc00

    move-object/from16 v25, v3

    invoke-static/range {v18 .. v27}, Llyiahf/vczjk/zsa;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/zh1;Ljava/lang/Object;Llyiahf/vczjk/oe3;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v7, v19

    invoke-static {v14}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v5

    new-instance v13, Llyiahf/vczjk/q17;

    move-object/from16 p3, v2

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_general:I

    invoke-static {v2, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    invoke-direct {v13, v2}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v2, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_toggle_fill:I

    move/from16 v18, v2

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_feature_toggle:I

    invoke-static {v2, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    invoke-static/range {v18 .. v18}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v22

    const v2, 0x4c5de2

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    move/from16 v18, v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v18, :cond_b

    if-ne v2, v12, :cond_a

    goto :goto_3

    :cond_a
    move-object/from16 v39, v6

    goto :goto_4

    :cond_b
    :goto_3
    new-instance v2, Llyiahf/vczjk/kt;

    move-object/from16 v39, v6

    const/16 v6, 0xb

    invoke-direct {v2, v14, v6}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_4
    move-object/from16 v24, v2

    check-cast v24, Llyiahf/vczjk/le3;

    const/4 v2, 0x0

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v19, Llyiahf/vczjk/x17;

    const/16 v21, 0x0

    const/16 v23, 0x0

    const/16 v25, 0xb2

    invoke-direct/range {v19 .. v25}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    sget v2, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_battery_saver_fill:I

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_enable_power_save:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v21

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pref_summary_enable_power_save:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v22

    iget-boolean v6, v10, Llyiahf/vczjk/mi8;->OooO0o:Z

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v2, -0x615d173a

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    iget-object v2, v0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/dj8;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v20

    or-int v18, v18, v20

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez v18, :cond_d

    if-ne v0, v12, :cond_c

    goto :goto_5

    :cond_c
    move/from16 v25, v6

    goto :goto_6

    :cond_d
    :goto_5
    new-instance v0, Llyiahf/vczjk/bi8;

    move/from16 v25, v6

    const/4 v6, 0x2

    invoke-direct {v0, v5, v2, v6}, Llyiahf/vczjk/bi8;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_6
    move-object/from16 v26, v0

    check-cast v26, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v20, Llyiahf/vczjk/w17;

    const/16 v27, 0x150

    const/16 v23, 0x0

    invoke-direct/range {v20 .. v27}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_shield_cross_fill:I

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_app_stability_upkeep:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v42

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pref_summary_app_stability_upkeep:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v43

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v45

    const v0, -0x615d173a

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_e

    if-ne v6, v12, :cond_f

    :cond_e
    new-instance v6, Llyiahf/vczjk/bi8;

    const/4 v0, 0x3

    invoke-direct {v6, v5, v2, v0}, Llyiahf/vczjk/bi8;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    move-object/from16 v47, v6

    check-cast v47, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v41, Llyiahf/vczjk/w17;

    const/16 v44, 0x0

    iget-boolean v0, v10, Llyiahf/vczjk/mi8;->OooO0o0:Z

    const/16 v48, 0x150

    move/from16 v46, v0

    invoke-direct/range {v41 .. v48}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_file_list_3_fill:I

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_enable_global_white_list:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v43

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pref_summary_enable_global_white_list:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v44

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v46

    const v0, -0x615d173a

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v0, v6

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_10

    if-ne v6, v12, :cond_11

    :cond_10
    new-instance v6, Llyiahf/vczjk/bi8;

    const/4 v0, 0x4

    invoke-direct {v6, v5, v2, v0}, Llyiahf/vczjk/bi8;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    move-object/from16 v48, v6

    check-cast v48, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v42, Llyiahf/vczjk/w17;

    const/16 v45, 0x1

    iget-boolean v0, v10, Llyiahf/vczjk/mi8;->OooO0oO:Z

    const/16 v49, 0x150

    move/from16 v47, v0

    invoke-direct/range {v42 .. v49}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_device_recover_fill:I

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->feature_title_recovery_tools:I

    invoke-static {v5, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v22

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v0, 0x4c5de2

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v0, :cond_12

    if-ne v5, v12, :cond_13

    :cond_12
    new-instance v5, Llyiahf/vczjk/kt;

    const/16 v0, 0xc

    invoke-direct {v5, v14, v0}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    move-object/from16 v26, v5

    check-cast v26, Llyiahf/vczjk/le3;

    const/4 v0, 0x0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/x17;

    const/16 v23, 0x0

    const/16 v25, 0x0

    const/16 v27, 0xb2

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_feedback_fill:I

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->nav_title_feedback:I

    invoke-static {v5, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v44

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v46

    const v0, 0x4c5de2

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v0, :cond_14

    if-ne v5, v12, :cond_15

    :cond_14
    new-instance v5, Llyiahf/vczjk/na2;

    const/4 v0, 0x3

    invoke-direct {v5, v7, v0}, Llyiahf/vczjk/na2;-><init>(Llyiahf/vczjk/zh1;I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    move-object/from16 v48, v5

    check-cast v48, Llyiahf/vczjk/le3;

    const/4 v0, 0x0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v43, Llyiahf/vczjk/x17;

    const/16 v45, 0x0

    const/16 v47, 0x0

    const/16 v49, 0xb2

    invoke-direct/range {v43 .. v49}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    const/4 v5, 0x7

    new-array v5, v5, [Llyiahf/vczjk/y17;

    aput-object v13, v5, v0

    aput-object v19, v5, v31

    const/16 v33, 0x2

    aput-object v20, v5, v33

    const/16 v29, 0x3

    aput-object v41, v5, v29

    const/16 v30, 0x4

    aput-object v42, v5, v30

    aput-object v21, v5, v17

    aput-object v43, v5, v16

    invoke-static {v5}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-interface/range {p3 .. p3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/mi8;

    const v6, 0x3eec3137

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/content/Context;

    const v7, 0x34a4d9e4

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v7, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v7, :cond_16

    :goto_7
    const/4 v7, 0x0

    goto :goto_8

    :cond_16
    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available:I

    invoke-static {v7, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    goto :goto_7

    :goto_8
    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3}, Llyiahf/vczjk/wr6;->OooOo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/yo9;

    move-result-object v10

    invoke-static {v10, v3, v7}, Llyiahf/vczjk/dn8;->OooOOo(Llyiahf/vczjk/yo9;Llyiahf/vczjk/rf1;I)V

    invoke-static {v6}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v7

    iget-object v11, v5, Llyiahf/vczjk/mi8;->OooOOO0:Ljava/util/List;

    const v13, 0x4c5de2

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v13, :cond_17

    if-ne v14, v12, :cond_18

    :cond_17
    new-instance v14, Llyiahf/vczjk/q71;

    const/4 v13, 0x4

    invoke-direct {v14, v6, v13}, Llyiahf/vczjk/q71;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v14, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v13, Ljava/util/ArrayList;

    move-object/from16 v47, v9

    iget-object v9, v5, Llyiahf/vczjk/mi8;->OooOOO0:Ljava/util/List;

    move-object/from16 v48, v15

    const/16 v15, 0xa

    move-object/from16 v49, v1

    invoke-static {v9, v15}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {v13, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_9
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v18

    const-string v15, "getTitle(...)"

    if-eqz v18, :cond_19

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v18

    check-cast v18, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    new-instance v19, Llyiahf/vczjk/wg5;

    move-object/from16 v26, v1

    invoke-virtual/range {v18 .. v18}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getId()Ljava/lang/String;

    move-result-object v1

    move-object/from16 v50, v8

    const-string v8, "getId(...)"

    invoke-static {v1, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual/range {v18 .. v18}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getTitle()Ljava/lang/String;

    move-result-object v8

    invoke-static {v8, v15}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v22, 0x0

    const/16 v25, 0x1c

    const/16 v23, 0x0

    const/16 v24, 0x0

    move-object/from16 v20, v1

    move-object/from16 v21, v8

    invoke-direct/range {v19 .. v25}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    move-object/from16 v1, v19

    invoke-virtual {v13, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move-object/from16 v1, v26

    move-object/from16 v8, v50

    const/16 v15, 0xa

    goto :goto_9

    :cond_19
    move-object/from16 v50, v8

    const v1, -0x615d173a

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v1, v8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v1, :cond_1b

    if-ne v8, v12, :cond_1a

    goto :goto_a

    :cond_1a
    const/4 v1, 0x0

    goto :goto_b

    :cond_1b
    :goto_a
    new-instance v8, Llyiahf/vczjk/ai8;

    const/4 v1, 0x0

    invoke-direct {v8, v1, v7, v2}, Llyiahf/vczjk/ai8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_b
    check-cast v8, Llyiahf/vczjk/ze3;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const-string v1, "title"

    invoke-static {v14, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "onItemSelected"

    invoke-static {v8, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const v1, 0x4cd532ca    # 1.1177736E8f

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const v1, 0x4c5de2

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    move/from16 v18, v1

    const/4 v1, 0x0

    if-nez v18, :cond_1c

    if-ne v11, v12, :cond_1d

    :cond_1c
    new-instance v11, Llyiahf/vczjk/yg5;

    invoke-direct {v11, v14, v1, v13, v8}, Llyiahf/vczjk/yg5;-><init>(Llyiahf/vczjk/oe3;Ljava/lang/String;Ljava/util/List;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1d
    check-cast v11, Llyiahf/vczjk/yg5;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v8, 0x8

    invoke-static {v11, v3, v8}, Llyiahf/vczjk/rs;->OooO0Oo(Llyiahf/vczjk/yg5;Llyiahf/vczjk/rf1;I)V

    const v13, 0x6e3c21fe

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-ne v13, v12, :cond_1e

    new-instance v13, Llyiahf/vczjk/r07;

    const/16 v14, 0x18

    invoke-direct {v13, v14}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1e
    check-cast v13, Llyiahf/vczjk/oe3;

    const/4 v14, 0x0

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/wg5;

    sget v14, Lgithub/tornaco/android/thanos/res/R$string;->pref_action_edit_or_view_config_template:I

    invoke-static {v14, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    const/16 v21, 0x0

    const/16 v24, 0x1c

    const-string v19, "Edit"

    const/16 v22, 0x0

    const/16 v23, 0x0

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    move-object/from16 v14, v18

    new-instance v18, Llyiahf/vczjk/wg5;

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->pref_action_delete_config_template:I

    invoke-static {v1, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    const-string v19, "Delete"

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    move-object/from16 v1, v18

    filled-new-array {v14, v1}, [Llyiahf/vczjk/wg5;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    const v14, -0x6815fd56

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    or-int v18, v18, v19

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v19

    or-int v18, v18, v19

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v18, :cond_1f

    if-ne v14, v12, :cond_20

    :cond_1f
    new-instance v14, Llyiahf/vczjk/o0OO00OO;

    const/16 v8, 0x12

    invoke-direct {v14, v7, v6, v8, v2}, Llyiahf/vczjk/o0OO00OO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_20
    check-cast v14, Llyiahf/vczjk/ze3;

    const/4 v6, 0x0

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v1, v3, v13, v14}, Llyiahf/vczjk/rs;->o000oOoO(ILjava/util/List;Llyiahf/vczjk/rf1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yg5;

    move-result-object v1

    const/16 v6, 0x8

    invoke-static {v1, v3, v6}, Llyiahf/vczjk/rs;->OooO0Oo(Llyiahf/vczjk/yg5;Llyiahf/vczjk/rf1;I)V

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->common_fab_title_add:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    const v8, -0x615d173a

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v8, v13

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v8, :cond_22

    if-ne v13, v12, :cond_21

    goto :goto_c

    :cond_21
    const/4 v14, 0x0

    goto :goto_d

    :cond_22
    :goto_c
    new-instance v13, Llyiahf/vczjk/bi8;

    const/4 v14, 0x0

    invoke-direct {v13, v7, v2, v14}, Llyiahf/vczjk/bi8;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_d
    check-cast v13, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v32, v4

    const/16 v4, 0x1c

    const/4 v8, 0x0

    invoke-static {v6, v8, v13, v3, v4}, Llyiahf/vczjk/ll6;->OooOOO(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/zl9;

    move-result-object v6

    invoke-static {v6, v3, v14}, Llyiahf/vczjk/ll6;->OooO0Oo(Llyiahf/vczjk/zl9;Llyiahf/vczjk/rf1;I)V

    new-instance v4, Llyiahf/vczjk/q17;

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_strategy:I

    invoke-static {v8, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    invoke-direct {v4, v8}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v8, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_tools_fill:I

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_new_installed_apps_config_enabled:I

    invoke-static {v13, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v52

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->pref_summary_new_installed_apps_config_enabled:I

    invoke-static {v13, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v53

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v55

    const v8, -0x48fade91

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v13, v14

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v13, v14

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v13, v14

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v13, :cond_24

    if-ne v14, v12, :cond_23

    goto :goto_e

    :cond_23
    move-object/from16 v61, v10

    move-object v10, v7

    move-object/from16 v7, v61

    goto :goto_f

    :cond_24
    :goto_e
    new-instance v41, Llyiahf/vczjk/m60;

    const/16 v46, 0xe

    move-object/from16 v42, v0

    move-object/from16 v44, v2

    move-object/from16 v43, v7

    move-object/from16 v45, v10

    invoke-direct/range {v41 .. v46}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v14, v41

    move-object/from16 v10, v43

    move-object/from16 v7, v45

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_f
    move-object/from16 v57, v14

    check-cast v57, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v51, Llyiahf/vczjk/w17;

    const/16 v54, 0x0

    iget-boolean v13, v5, Llyiahf/vczjk/mi8;->OooOO0:Z

    const/16 v58, 0x150

    move/from16 v56, v13

    invoke-direct/range {v51 .. v58}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v13, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_notification_4_fill:I

    sget v14, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_new_installed_apps_config_notification_enabled:I

    invoke-static {v14, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v53

    sget v14, Lgithub/tornaco/android/thanos/res/R$string;->pref_summary_new_installed_apps_config_notification_enabled:I

    invoke-static {v14, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v54

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v56

    const v13, -0x615d173a

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v13, v14

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v13, :cond_25

    if-ne v14, v12, :cond_26

    :cond_25
    new-instance v14, Llyiahf/vczjk/bi8;

    move/from16 v13, v31

    invoke-direct {v14, v10, v2, v13}, Llyiahf/vczjk/bi8;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_26
    move-object/from16 v58, v14

    check-cast v58, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v52, Llyiahf/vczjk/w17;

    const/16 v55, 0x0

    iget-boolean v10, v5, Llyiahf/vczjk/mi8;->OooOO0O:Z

    const/16 v59, 0x150

    move/from16 v57, v10

    invoke-direct/range {v52 .. v59}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v10, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_file_code_fill:I

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_new_installed_apps_config:I

    invoke-static {v13, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v19

    iget-object v5, v5, Llyiahf/vczjk/mi8;->OooOO0o:Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    if-eqz v5, :cond_27

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getTitle()Ljava/lang/String;

    move-result-object v5

    goto :goto_10

    :cond_27
    const/4 v5, 0x0

    :goto_10
    const v13, 0x34a72d09

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez v5, :cond_28

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->common_text_value_not_set:I

    invoke-static {v5, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    :cond_28
    move-object/from16 v20, v5

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v21

    const v5, -0x6815fd56

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v5, v10

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v5, v10

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v5, :cond_29

    if-ne v10, v12, :cond_2a

    :cond_29
    new-instance v10, Llyiahf/vczjk/x5;

    const/16 v5, 0x15

    invoke-direct {v10, v0, v11, v5, v7}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2a
    move-object/from16 v23, v10

    check-cast v23, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/x17;

    const/16 v24, 0xb4

    const/16 v22, 0x0

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v5, v18

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_config_template_category:I

    invoke-static {v10, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v54

    const v10, 0x34a7764f

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance v10, Ljava/util/ArrayList;

    const/16 v11, 0xa

    invoke-static {v9, v11}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v13

    invoke-direct {v10, v13}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v9}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v9

    :goto_11
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    move-result v11

    if-eqz v11, :cond_2d

    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;->getTitle()Ljava/lang/String;

    move-result-object v13

    invoke-static {v13, v15}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    or-int v14, v14, v18

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    or-int v14, v14, v18

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    or-int v14, v14, v18

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v14, :cond_2b

    if-ne v8, v12, :cond_2c

    :cond_2b
    new-instance v18, Llyiahf/vczjk/c02;

    const/16 v23, 0x4

    move-object/from16 v19, v0

    move-object/from16 v20, v1

    move-object/from16 v22, v7

    move-object/from16 v21, v11

    invoke-direct/range {v18 .. v23}, Llyiahf/vczjk/c02;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v8, v18

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2c
    move-object/from16 v23, v8

    check-cast v23, Llyiahf/vczjk/le3;

    const/4 v14, 0x0

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/x17;

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v20, 0x0

    const/16 v24, 0xbe

    move-object/from16 v19, v13

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v8, v18

    invoke-virtual {v10, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const v8, -0x48fade91

    goto :goto_11

    :cond_2d
    const/4 v14, 0x0

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget v1, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_add_fill:I

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->common_fab_title_add:I

    invoke-static {v8, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v19

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v21

    const v1, -0x6815fd56

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v1, v8

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v1, v8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v1, :cond_2e

    if-ne v8, v12, :cond_2f

    :cond_2e
    new-instance v8, Llyiahf/vczjk/x5;

    const/16 v1, 0x16

    invoke-direct {v8, v0, v6, v1, v7}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2f
    move-object/from16 v23, v8

    check-cast v23, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/x17;

    const/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v24, 0xb6

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    invoke-static/range {v18 .. v18}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-static {v0, v10}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v58

    new-instance v53, Llyiahf/vczjk/r17;

    const/16 v57, 0x0

    const/16 v59, 0x0

    const/16 v55, 0x0

    const/16 v56, 0x0

    const/16 v60, 0xde

    invoke-direct/range {v53 .. v60}, Llyiahf/vczjk/r17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Llyiahf/vczjk/le3;I)V

    move/from16 v0, v17

    new-array v1, v0, [Llyiahf/vczjk/y17;

    const/4 v13, 0x0

    aput-object v4, v1, v13

    const/16 v31, 0x1

    aput-object v51, v1, v31

    const/16 v33, 0x2

    aput-object v52, v1, v33

    const/16 v29, 0x3

    aput-object v5, v1, v29

    const/16 v30, 0x4

    aput-object v53, v1, v30

    invoke-static {v1}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v1, v32

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-interface/range {p3 .. p3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    invoke-interface/range {v47 .. v47}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/mi8;

    const v4, 0x2c80d26e

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/content/Context;

    const v5, 0xf9608fb

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v5, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v5, :cond_30

    const/16 v55, 0x0

    :goto_12
    const/4 v13, 0x0

    goto :goto_13

    :cond_30
    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available:I

    invoke-static {v5, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    move-object/from16 v55, v8

    goto :goto_12

    :goto_13
    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3}, Llyiahf/vczjk/wr6;->OooOo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/yo9;

    move-result-object v5

    invoke-static {v5, v3, v13}, Llyiahf/vczjk/dn8;->OooOOo(Llyiahf/vczjk/yo9;Llyiahf/vczjk/rf1;I)V

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_backup:I

    invoke-static {v6, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    const v13, 0x6e3c21fe

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v12, :cond_31

    new-instance v7, Llyiahf/vczjk/r07;

    const/16 v8, 0x19

    invoke-direct {v7, v8}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_31
    check-cast v7, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v8, 0x0

    const/16 v9, 0x1a

    invoke-static {v6, v8, v7, v3, v9}, Llyiahf/vczjk/ll6;->OooOOO(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/zl9;

    move-result-object v6

    invoke-static {v6, v3, v13}, Llyiahf/vczjk/ll6;->OooO0Oo(Llyiahf/vczjk/zl9;Llyiahf/vczjk/rf1;I)V

    sget-object v6, Llyiahf/vczjk/z35;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/cp8;

    invoke-static {v3}, Llyiahf/vczjk/zsa;->ooOO(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/zh1;

    move-result-object v19

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_restore_default:I

    invoke-static {v7, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v18

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->pre_summary_restore_default:I

    invoke-static {v7, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    const v13, 0x6e3c21fe

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v12, :cond_32

    new-instance v7, Llyiahf/vczjk/r07;

    const/16 v8, 0x1b

    invoke-direct {v7, v8}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_32
    move-object/from16 v21, v7

    check-cast v21, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v7, 0x4c5de2

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_33

    if-ne v8, v12, :cond_34

    :cond_33
    new-instance v8, Llyiahf/vczjk/di8;

    invoke-direct {v8, v2, v13}, Llyiahf/vczjk/di8;-><init>(Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_34
    move-object/from16 v24, v8

    check-cast v24, Llyiahf/vczjk/oe3;

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v26, 0xc00

    const/16 v27, 0x30

    const/16 v22, 0x0

    const/16 v23, 0x0

    move-object/from16 v25, v3

    invoke-static/range {v18 .. v27}, Llyiahf/vczjk/zsa;->OooO0Oo(Ljava/lang/String;Llyiahf/vczjk/zh1;Ljava/lang/Object;Llyiahf/vczjk/oe3;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v7, v19

    new-instance v8, Llyiahf/vczjk/q17;

    sget v9, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_data:I

    invoke-static {v9, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v9

    invoke-direct {v8, v9}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v9, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_upload_cloud_2_fill:I

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_backup:I

    invoke-static {v10, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v19

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pre_summary_backup:I

    invoke-static {v10, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v21

    const v9, -0x6815fd56

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v9, v10

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v9, v10

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_36

    if-ne v10, v12, :cond_35

    goto :goto_14

    :cond_35
    const/4 v13, 0x0

    goto :goto_15

    :cond_36
    :goto_14
    new-instance v10, Llyiahf/vczjk/ei8;

    const/4 v13, 0x0

    invoke-direct {v10, v0, v6, v5, v13}, Llyiahf/vczjk/ei8;-><init>(Llyiahf/vczjk/cm4;Llyiahf/vczjk/cp8;Llyiahf/vczjk/yo9;I)V

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_15
    move-object/from16 v23, v10

    check-cast v23, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/x17;

    const/16 v24, 0xa4

    move-object/from16 v22, v55

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    sget v9, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_download_cloud_fill:I

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_restore:I

    invoke-static {v10, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v52

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pre_sumary_restore:I

    invoke-static {v10, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v53

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_restore_default:I

    invoke-static {v10, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pre_summary_restore_default:I

    invoke-static {v10, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v21

    const v13, 0x4c5de2

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v10, :cond_37

    if-ne v11, v12, :cond_38

    :cond_37
    new-instance v11, Llyiahf/vczjk/na2;

    const/4 v13, 0x4

    invoke-direct {v11, v7, v13}, Llyiahf/vczjk/na2;-><init>(Llyiahf/vczjk/zh1;I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_38
    move-object/from16 v24, v11

    check-cast v24, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v19, Llyiahf/vczjk/x17;

    const/16 v22, 0x0

    const/16 v23, 0x0

    const/16 v25, 0xbc

    invoke-direct/range {v19 .. v25}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    invoke-static/range {v19 .. v19}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v56

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v54

    const v9, -0x6815fd56

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v7, v9

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v7, v9

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v7, :cond_39

    if-ne v9, v12, :cond_3a

    :cond_39
    new-instance v9, Llyiahf/vczjk/ei8;

    const/4 v13, 0x1

    invoke-direct {v9, v0, v6, v5, v13}, Llyiahf/vczjk/ei8;-><init>(Llyiahf/vczjk/cm4;Llyiahf/vczjk/cp8;Llyiahf/vczjk/yo9;I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3a
    move-object/from16 v57, v9

    check-cast v57, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v51, Llyiahf/vczjk/r17;

    const/16 v58, 0x84

    invoke-direct/range {v51 .. v58}, Llyiahf/vczjk/r17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Llyiahf/vczjk/le3;I)V

    const/4 v0, 0x3

    new-array v5, v0, [Llyiahf/vczjk/y17;

    aput-object v8, v5, v13

    const/16 v31, 0x1

    aput-object v18, v5, v31

    const/16 v33, 0x2

    aput-object v51, v5, v33

    invoke-static {v5}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-interface/range {v47 .. v47}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mi8;

    const v5, -0x55bf42ed

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v12, :cond_3b

    invoke-static {v3}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v5

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3b
    check-cast v5, Llyiahf/vczjk/xr1;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/content/Context;

    new-instance v6, Llyiahf/vczjk/n17;

    invoke-direct {v6, v4}, Llyiahf/vczjk/n17;-><init>(Landroid/content/Context;)V

    sget-object v7, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v8, v6, Llyiahf/vczjk/n17;->OooO0OO:Llyiahf/vczjk/wh;

    invoke-static {v8, v7, v3}, Llyiahf/vczjk/cp7;->OooOO0O(Llyiahf/vczjk/f43;Ljava/lang/Object;Llyiahf/vczjk/zf1;)Llyiahf/vczjk/qs5;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/oq9;->OooOOO0:Llyiahf/vczjk/oq9;

    iget-object v9, v6, Llyiahf/vczjk/n17;->OooO0O0:Llyiahf/vczjk/wh;

    invoke-static {v9, v8, v3}, Llyiahf/vczjk/cp7;->OooOO0O(Llyiahf/vczjk/f43;Ljava/lang/Object;Llyiahf/vczjk/zf1;)Llyiahf/vczjk/qs5;

    move-result-object v8

    const v13, 0x6e3c21fe

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-ne v9, v12, :cond_3c

    new-instance v9, Llyiahf/vczjk/r07;

    const/16 v10, 0x1c

    invoke-direct {v9, v10}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3c
    check-cast v9, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v10, Llyiahf/vczjk/oq9;->OooOOOO:Llyiahf/vczjk/np2;

    new-instance v11, Ljava/util/ArrayList;

    const/16 v13, 0xa

    invoke-static {v10, v13}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v13

    invoke-direct {v11, v13}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/o00O00O;->iterator()Ljava/util/Iterator;

    move-result-object v10

    :goto_16
    invoke-interface {v10}, Ljava/util/Iterator;->hasNext()Z

    move-result v13

    if-eqz v13, :cond_3d

    invoke-interface {v10}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/oq9;

    new-instance v18, Llyiahf/vczjk/wg5;

    invoke-virtual {v13}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v19

    invoke-virtual {v13}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v20

    const/16 v21, 0x0

    const/16 v24, 0x1c

    const/16 v22, 0x0

    const/16 v23, 0x0

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/wg5;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Llyiahf/vczjk/xn6;I)V

    move-object/from16 v13, v18

    invoke-virtual {v11, v13}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_16

    :cond_3d
    const v13, -0x615d173a

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v10, v13

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v10, :cond_3e

    if-ne v13, v12, :cond_3f

    :cond_3e
    new-instance v13, Llyiahf/vczjk/ai8;

    const/4 v10, 0x1

    invoke-direct {v13, v10, v5, v6}, Llyiahf/vczjk/ai8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3f
    check-cast v13, Llyiahf/vczjk/ze3;

    const/4 v14, 0x0

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v10, 0x2

    invoke-static {v10, v11, v3, v9, v13}, Llyiahf/vczjk/rs;->o000oOoO(ILjava/util/List;Llyiahf/vczjk/rf1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/yg5;

    move-result-object v9

    const/16 v10, 0x8

    invoke-static {v9, v3, v10}, Llyiahf/vczjk/rs;->OooO0Oo(Llyiahf/vczjk/yg5;Llyiahf/vczjk/rf1;I)V

    new-instance v10, Llyiahf/vczjk/q17;

    sget v11, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_ui:I

    invoke-static {v11, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v11

    invoke-direct {v10, v11}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v11, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_number_9:I

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_app_list_item_show_version:I

    invoke-static {v13, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v19

    iget-boolean v13, v0, Llyiahf/vczjk/mi8;->OooO0oo:Z

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v22

    const v11, -0x615d173a

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v11, v14

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v11, :cond_40

    if-ne v14, v12, :cond_41

    :cond_40
    new-instance v14, Llyiahf/vczjk/zh8;

    const/4 v11, 0x1

    invoke-direct {v14, v4, v2, v11}, Llyiahf/vczjk/zh8;-><init>(Landroid/content/Context;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_41
    move-object/from16 v24, v14

    check-cast v24, Llyiahf/vczjk/oe3;

    const/4 v14, 0x0

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/w17;

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v25, 0x156

    move/from16 v23, v13

    invoke-direct/range {v18 .. v25}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v11, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_more_fill:I

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->pre_title_app_list_item_show_pkg:I

    invoke-static {v13, v3}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v23

    const v13, -0x615d173a

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v11, v13

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v11, :cond_42

    if-ne v13, v12, :cond_43

    :cond_42
    new-instance v13, Llyiahf/vczjk/zh8;

    const/4 v11, 0x2

    invoke-direct {v13, v4, v2, v11}, Llyiahf/vczjk/zh8;-><init>(Landroid/content/Context;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_43
    move-object/from16 v25, v13

    check-cast v25, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v19, Llyiahf/vczjk/w17;

    const/16 v22, 0x0

    iget-boolean v0, v0, Llyiahf/vczjk/mi8;->OooO:Z

    const/16 v21, 0x0

    const/16 v26, 0x156

    move/from16 v24, v0

    invoke-direct/range {v19 .. v26}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_palette_fill:I

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v25

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v13, -0x615d173a

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v0, v4

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v0, :cond_44

    if-ne v4, v12, :cond_45

    :cond_44
    new-instance v4, Llyiahf/vczjk/gu6;

    const/16 v0, 0xd

    invoke-direct {v4, v0, v5, v6}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_45
    move-object/from16 v26, v4

    check-cast v26, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v20, Llyiahf/vczjk/w17;

    const/16 v22, 0x0

    const/16 v23, 0x0

    const-string v21, "Dynamic color schema"

    const/16 v27, 0x156

    invoke-direct/range {v20 .. v27}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_moon_fill:I

    invoke-interface {v8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/oq9;

    invoke-virtual {v4}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v23

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v13, 0x4c5de2

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v0, :cond_46

    if-ne v4, v12, :cond_47

    :cond_46
    new-instance v4, Llyiahf/vczjk/xg5;

    const/4 v6, 0x2

    invoke-direct {v4, v9, v6}, Llyiahf/vczjk/xg5;-><init>(Llyiahf/vczjk/yg5;I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_47
    move-object/from16 v26, v4

    check-cast v26, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/x17;

    const-string v22, "Dark mode"

    const/16 v25, 0x0

    const/16 v27, 0xb4

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    const/4 v0, 0x5

    new-array v4, v0, [Llyiahf/vczjk/y17;

    aput-object v10, v4, v13

    const/16 v31, 0x1

    aput-object v18, v4, v31

    const/16 v33, 0x2

    aput-object v19, v4, v33

    const/16 v29, 0x3

    aput-object v20, v4, v29

    const/16 v30, 0x4

    aput-object v21, v4, v30

    invoke-static {v4}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-interface/range {v47 .. v47}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mi8;

    move-object/from16 v8, v50

    check-cast v8, Llyiahf/vczjk/zf1;

    const v4, 0x15088344

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/content/Context;

    invoke-static {v5}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v6

    new-instance v7, Llyiahf/vczjk/q17;

    sget v9, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_dev_tools:I

    invoke-static {v9, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v9

    invoke-direct {v7, v9}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v9, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_code_box_line:I

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_show_current_activity:I

    invoke-static {v10, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v19

    iget-boolean v10, v0, Llyiahf/vczjk/mi8;->OooOOO:Z

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v22

    const v13, -0x615d173a

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v9, v11

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v9, :cond_48

    if-ne v11, v12, :cond_49

    :cond_48
    new-instance v11, Llyiahf/vczjk/bi8;

    const/4 v9, 0x5

    invoke-direct {v11, v6, v2, v9}, Llyiahf/vczjk/bi8;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v8, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_49
    move-object/from16 v24, v11

    check-cast v24, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/w17;

    const/16 v21, 0x0

    const/16 v25, 0x156

    const/16 v20, 0x0

    move/from16 v23, v10

    invoke-direct/range {v18 .. v25}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v9, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_earth_fill:I

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->title_net_stats:I

    invoke-static {v10, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v23

    const v13, -0x615d173a

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v9, v10

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_4a

    if-ne v10, v12, :cond_4b

    :cond_4a
    new-instance v10, Llyiahf/vczjk/bi8;

    move/from16 v9, v16

    invoke-direct {v10, v6, v2, v9}, Llyiahf/vczjk/bi8;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4b
    move-object/from16 v25, v10

    check-cast v25, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v19, Llyiahf/vczjk/w17;

    const/16 v21, 0x0

    const/16 v26, 0x156

    const/16 v22, 0x0

    iget-boolean v9, v0, Llyiahf/vczjk/mi8;->OooOOOO:Z

    move/from16 v24, v9

    invoke-direct/range {v19 .. v26}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v9, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_task_fill:I

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->new_ops_feature:I

    invoke-static {v10, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v21

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->new_ops_feature_summary:I

    invoke-static {v10, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v22

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v9, -0x6815fd56

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v9, v10

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    or-int/2addr v9, v10

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_4c

    if-ne v10, v12, :cond_4d

    :cond_4c
    new-instance v10, Llyiahf/vczjk/oo0ooO;

    const/16 v9, 0x15

    invoke-direct {v10, v5, v6, v9, v2}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4d
    move-object/from16 v26, v10

    check-cast v26, Llyiahf/vczjk/oe3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v20, Llyiahf/vczjk/w17;

    iget-boolean v6, v0, Llyiahf/vczjk/mi8;->OooOOOo:Z

    const/16 v27, 0x154

    const/16 v23, 0x0

    move/from16 v25, v6

    invoke-direct/range {v20 .. v27}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v6, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_home_fill:I

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v25

    const v13, -0x615d173a

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v6, v9

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v6, :cond_4f

    if-ne v9, v12, :cond_4e

    goto :goto_17

    :cond_4e
    const/4 v13, 0x0

    goto :goto_18

    :cond_4f
    :goto_17
    new-instance v9, Llyiahf/vczjk/zh8;

    const/4 v13, 0x0

    invoke-direct {v9, v5, v2, v13}, Llyiahf/vczjk/zh8;-><init>(Landroid/content/Context;Llyiahf/vczjk/dj8;I)V

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_18
    move-object/from16 v27, v9

    check-cast v27, Llyiahf/vczjk/oe3;

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/w17;

    const/16 v23, 0x0

    const/16 v28, 0x156

    const-string v22, "Test New home screen"

    const/16 v24, 0x0

    iget-boolean v0, v0, Llyiahf/vczjk/mi8;->OooOOo0:Z

    move/from16 v26, v0

    invoke-direct/range {v21 .. v28}, Llyiahf/vczjk/w17;-><init>(Ljava/lang/String;Ljava/lang/String;ZLjava/lang/Integer;ZLlyiahf/vczjk/oe3;I)V

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_save_fill:I

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->feedback_export_log:I

    invoke-static {v2, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v35

    new-instance v34, Llyiahf/vczjk/x17;

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v37

    const/16 v40, 0xb6

    const/16 v36, 0x0

    const/16 v38, 0x0

    invoke-direct/range {v34 .. v40}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    const/4 v9, 0x6

    new-array v0, v9, [Llyiahf/vczjk/y17;

    const/4 v13, 0x0

    aput-object v7, v0, v13

    const/16 v31, 0x1

    aput-object v18, v0, v31

    const/16 v33, 0x2

    aput-object v19, v0, v33

    const/16 v29, 0x3

    aput-object v20, v0, v29

    const/16 v30, 0x4

    aput-object v21, v0, v30

    const/16 v17, 0x5

    aput-object v34, v0, v17

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-interface/range {v47 .. v47}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mi8;

    const v0, -0x15577b10

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v0, Llyiahf/vczjk/n35;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/Activity;

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/content/Context;

    const v13, 0x6e3c21fe

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v12, :cond_50

    const/4 v13, 0x0

    invoke-static {v13}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object v4

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    goto :goto_19

    :cond_50
    const/4 v13, 0x0

    :goto_19
    check-cast v4, Llyiahf/vczjk/qr5;

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    new-instance v5, Llyiahf/vczjk/q17;

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_about:I

    invoke-static {v6, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    invoke-direct {v5, v6}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v6, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_information_fill:I

    sget v7, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_app_feature_info:I

    invoke-static {v7, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v19

    const v7, 0x332f00

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    const-string v9, "8.6"

    const-string v10, "thanox@tornaco:f919506c-e8fd-4a35-b88e-e193d2725db5"

    const-string v11, "Wed Oct 01 16:05:37 CST 2025"

    const-string v13, "Built on: Mac OS X"

    filled-new-array {v9, v7, v10, v11, v13}, [Ljava/lang/Object;

    move-result-object v7

    invoke-static {v7}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v20

    const/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v21, 0x0

    const/16 v23, 0x0

    const/16 v25, 0x3f

    invoke-static/range {v20 .. v25}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v20

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v21

    const v13, -0x615d173a

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_51

    if-ne v7, v12, :cond_52

    :cond_51
    new-instance v7, Llyiahf/vczjk/w77;

    const/16 v6, 0x9

    invoke-direct {v7, v6, v2, v4}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v8, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_52
    move-object/from16 v23, v7

    check-cast v23, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v18, Llyiahf/vczjk/x17;

    const/16 v24, 0xb4

    const/16 v22, 0x0

    invoke-direct/range {v18 .. v24}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    sget v4, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_group_fill:I

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_rss_e:I

    invoke-static {v6, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v20

    sget v6, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_qq_fill:I

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v13, 0x4c5de2

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_53

    if-ne v7, v12, :cond_54

    :cond_53
    new-instance v7, Llyiahf/vczjk/kt;

    const/16 v6, 0xd

    invoke-direct {v7, v2, v6}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v8, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_54
    move-object/from16 v26, v7

    check-cast v26, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/x17;

    const-string v22, "QQ"

    const/16 v27, 0xb6

    const/16 v23, 0x0

    const/16 v25, 0x0

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v6, v21

    sget v7, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_telegram_fill:I

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v13, 0x4c5de2

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v7, :cond_55

    if-ne v9, v12, :cond_56

    :cond_55
    new-instance v9, Llyiahf/vczjk/kt;

    const/16 v7, 0xe

    invoke-direct {v9, v2, v7}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_56
    move-object/from16 v26, v9

    check-cast v26, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/x17;

    const-string v22, "Telegram"

    const/16 v27, 0xb6

    const/16 v23, 0x0

    const/16 v25, 0x0

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v7, v21

    sget v9, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_mail_fill:I

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v13, 0x4c5de2

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_57

    if-ne v10, v12, :cond_58

    :cond_57
    new-instance v10, Llyiahf/vczjk/kt;

    const/16 v9, 0xf

    invoke-direct {v10, v2, v9}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_58
    move-object/from16 v26, v10

    check-cast v26, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/x17;

    const-string v22, "Email"

    const/16 v27, 0xb6

    const/16 v23, 0x0

    const/16 v25, 0x0

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v9, v21

    sget v10, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_github_fill:I

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v13, 0x6e3c21fe

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-ne v10, v12, :cond_59

    new-instance v10, Llyiahf/vczjk/oOOO0OO0;

    const/16 v11, 0x16

    invoke-direct {v10, v11}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_59
    move-object/from16 v26, v10

    check-cast v26, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/x17;

    const-string v22, "Github"

    const/16 v27, 0xb4

    const-string v23, "Tornaco/Thanox"

    const/16 v25, 0x0

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v10, v21

    filled-new-array {v6, v7, v9, v10}, [Llyiahf/vczjk/x17;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v24

    new-instance v19, Llyiahf/vczjk/r17;

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v22

    const/16 v21, 0x0

    const/16 v23, 0x0

    const/16 v26, 0xd6

    invoke-direct/range {v19 .. v26}, Llyiahf/vczjk/r17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Llyiahf/vczjk/le3;I)V

    sget v4, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_history_fill:I

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->settings_history_versions_title:I

    invoke-static {v6, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v21

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->settings_history_versions_summary:I

    invoke-static {v6, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v22

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v23

    const v13, 0x4c5de2

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_5a

    if-ne v6, v12, :cond_5b

    :cond_5a
    new-instance v6, Llyiahf/vczjk/kt;

    const/16 v4, 0x10

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5b
    move-object/from16 v25, v6

    check-cast v25, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v20, Llyiahf/vczjk/x17;

    const/16 v26, 0xb4

    const/16 v24, 0x0

    invoke-direct/range {v20 .. v26}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    sget v2, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_open_source_fill:I

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_open_source_license:I

    invoke-static {v4, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v22

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v24

    const v13, 0x4c5de2

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_5c

    if-ne v4, v12, :cond_5d

    :cond_5c
    new-instance v4, Llyiahf/vczjk/cv5;

    const/4 v13, 0x1

    invoke-direct {v4, v0, v13}, Llyiahf/vczjk/cv5;-><init>(Landroid/app/Activity;I)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5d
    move-object/from16 v26, v4

    check-cast v26, Llyiahf/vczjk/le3;

    const/4 v13, 0x0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v21, Llyiahf/vczjk/x17;

    const/16 v25, 0x0

    const/16 v27, 0xb6

    const/16 v23, 0x0

    invoke-direct/range {v21 .. v27}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    const/4 v0, 0x5

    new-array v0, v0, [Llyiahf/vczjk/y17;

    aput-object v5, v0, v13

    const/16 v31, 0x1

    aput-object v18, v0, v31

    const/16 v33, 0x2

    aput-object v19, v0, v33

    const/16 v29, 0x3

    aput-object v20, v0, v29

    const/16 v30, 0x4

    aput-object v21, v0, v30

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v0, v50

    invoke-static {v1, v0, v13}, Llyiahf/vczjk/wr6;->OooO0o0(Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    invoke-static {v13, v0}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    invoke-interface/range {p3 .. p3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/cm4;

    invoke-static {v1, v0, v13}, Llyiahf/vczjk/hi8;->OooO0OO(Llyiahf/vczjk/cm4;Llyiahf/vczjk/rf1;I)V

    invoke-static {v13, v0}, Llyiahf/vczjk/ru6;->OooO00o(ILlyiahf/vczjk/rf1;)V

    invoke-static {v13, v0}, Llyiahf/vczjk/hi8;->OooO00o(ILlyiahf/vczjk/rf1;)V

    invoke-interface/range {v48 .. v48}, Llyiahf/vczjk/bi6;->OooO00o()F

    move-result v1

    move-object/from16 v2, v49

    invoke-static {v2, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v13, 0x1

    invoke-virtual {v3, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1a
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

.method private final OooO0oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 58

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/q31;

    move-object/from16 v7, p2

    check-cast v7, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p3

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    const-string v3, "$this$ThanoxCard"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v2, 0x11

    const/16 v2, 0x10

    if-ne v1, v2, :cond_1

    move-object v1, v7

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v11, v0

    goto/16 :goto_16

    :cond_1
    :goto_0
    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v6, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v8, 0x0

    invoke-static {v5, v6, v7, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v9

    move-object v10, v7

    check-cast v10, Llyiahf/vczjk/zf1;

    iget v11, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v7, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_2

    invoke-virtual {v10, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v7, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v7, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v15, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v15, :cond_3

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v15, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_4

    :cond_3
    invoke-static {v11, v10, v11, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v7, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    int-to-float v2, v2

    invoke-static {v4, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v11, 0x40

    int-to-float v11, v11

    const/4 v15, 0x2

    const/4 v3, 0x0

    invoke-static {v4, v11, v3, v15}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v11, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    const/16 v15, 0x36

    invoke-static {v11, v4, v7, v15}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v11

    iget v15, v10, Llyiahf/vczjk/zf1;->Oooo:I

    move/from16 v18, v2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v2

    invoke-static {v7, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 p3, v4

    iget-boolean v4, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_5

    invoke-virtual {v10, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_5
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    invoke-static {v11, v7, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v2, v7, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_6

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v15}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_7

    :cond_6
    invoke-static {v15, v10, v15, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    invoke-static {v3, v7, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v2, 0x3f800000    # 1.0f

    float-to-double v3, v2

    const-wide/16 v15, 0x0

    cmpl-double v3, v3, v15

    if-lez v3, :cond_8

    goto :goto_3

    :cond_8
    const-string v3, "invalid weight; must be greater than zero"

    invoke-static {v3}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_3
    new-instance v3, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v4, 0x0

    invoke-direct {v3, v2, v4}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    invoke-static {v5, v6, v7, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v4, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v7, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_9

    invoke-virtual {v10, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_9
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    invoke-static {v5, v7, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v7, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_a

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_b

    :cond_a
    invoke-static {v4, v10, v4, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    invoke-static {v3, v7, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_date_time_alarm:I

    invoke-static {v3, v7}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    const v4, -0x34192044    # -3.0261112E7f

    invoke-virtual {v10, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast v4, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/Alarm;->getRepeat()Lgithub/tornaco/android/thanos/core/alarm/Repeat;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/Repeat;->isNo()Z

    move-result v5

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-eqz v5, :cond_c

    const-string v5, "No repeat"

    :goto_5
    move-object v11, v5

    const/4 v5, 0x0

    goto :goto_6

    :cond_c
    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/Alarm;->getRepeat()Lgithub/tornaco/android/thanos/core/alarm/Repeat;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/Repeat;->isEveryDay()Z

    move-result v5

    if-eqz v5, :cond_d

    const-string v5, "Repeat every day"

    goto :goto_5

    :cond_d
    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/Alarm;->getRepeat()Lgithub/tornaco/android/thanos/core/alarm/Repeat;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/Repeat;->getDays()Ljava/util/List;

    move-result-object v19

    const v5, 0x6e3c21fe

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v6, :cond_e

    sget-object v5, Llyiahf/vczjk/tn;->OooOoO:Llyiahf/vczjk/tn;

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    move-object/from16 v23, v5

    check-cast v23, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v22, 0x0

    const/16 v24, 0x1e

    const-string v20, " "

    const/16 v21, 0x0

    invoke-static/range {v19 .. v24}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v11

    const-string v15, "Repeat at "

    invoke-static {v15, v11}, Llyiahf/vczjk/u81;->OooOo(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    :goto_6
    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/Alarm;->getTriggerAt()Lgithub/tornaco/android/thanos/core/alarm/TimeOfADay;

    move-result-object v5

    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    move-result-object v15

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/TimeOfADay;->getHour()I

    move-result v2

    move-object/from16 v16, v3

    const/16 v3, 0xb

    invoke-virtual {v15, v3, v2}, Ljava/util/Calendar;->set(II)V

    const/16 v2, 0xc

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/alarm/TimeOfADay;->getMinutes()I

    move-result v3

    invoke-virtual {v15, v2, v3}, Ljava/util/Calendar;->set(II)V

    const/16 v2, 0xd

    const/4 v5, 0x0

    invoke-virtual {v15, v2, v5}, Ljava/util/Calendar;->set(II)V

    invoke-virtual {v15}, Ljava/util/Calendar;->getTime()Ljava/util/Date;

    move-result-object v2

    invoke-virtual {v2}, Ljava/util/Date;->getTime()J

    move-result-wide v2

    invoke-static {v2, v3}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatShortForMessageTime(J)Ljava/lang/String;

    move-result-object v2

    const-string v3, "formatShortForMessageTime(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "\n"

    invoke-static {v2, v3, v11}, Llyiahf/vczjk/ix8;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v25

    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    move-object v3, v7

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/n6a;

    iget-object v11, v11, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v23, 0x6000

    const v24, 0x1bffe

    move-object v15, v3

    const/4 v3, 0x0

    move-object/from16 v19, v4

    move/from16 v17, v5

    const-wide/16 v4, 0x0

    move-object/from16 v20, v6

    move-object/from16 v21, v7

    const-wide/16 v6, 0x0

    move-object/from16 v22, v8

    const/4 v8, 0x0

    move-object/from16 v26, v9

    const/4 v9, 0x0

    move-object/from16 v27, v10

    move-object/from16 v28, v20

    move-object/from16 v20, v11

    const-wide/16 v10, 0x0

    move-object/from16 v29, v12

    const/4 v12, 0x0

    move-object/from16 v30, v13

    move-object/from16 v31, v14

    const-wide/16 v13, 0x0

    move-object/from16 v32, v15

    const/4 v15, 0x0

    move-object/from16 v33, v2

    move-object/from16 v2, v16

    const/16 v16, 0x0

    move/from16 v34, v17

    const/16 v17, 0x1

    move/from16 v35, v18

    const/16 v18, 0x0

    move-object/from16 v36, v19

    const/16 v19, 0x0

    move-object/from16 v37, v22

    const/16 v22, 0x0

    move-object/from16 p1, v1

    move-object/from16 v40, v26

    move-object/from16 v43, v28

    move-object/from16 v41, v29

    move-object/from16 v38, v30

    move-object/from16 v39, v31

    move-object/from16 v45, v32

    move-object/from16 v44, v33

    move/from16 v0, v34

    move-object/from16 v42, v37

    move-object/from16 v1, p3

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v7, v21

    invoke-static {v0, v7}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    sget-object v10, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v11, 0x30

    invoke-static {v10, v1, v7, v11}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object/from16 v12, v27

    iget v3, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    move-object/from16 v13, p1

    invoke-static {v7, v13}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_f

    move-object/from16 v14, v38

    invoke-virtual {v12, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_7
    move-object/from16 v15, v39

    goto :goto_8

    :cond_f
    move-object/from16 v14, v38

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_7

    :goto_8
    invoke-static {v2, v7, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v2, v40

    invoke-static {v4, v7, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_10

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_11

    :cond_10
    move-object/from16 v4, v41

    goto :goto_a

    :cond_11
    move-object/from16 v4, v41

    :goto_9
    move-object/from16 v3, v42

    goto :goto_b

    :goto_a
    invoke-static {v3, v12, v3, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_9

    :goto_b
    invoke-static {v5, v7, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v40, v2

    invoke-static {}, Llyiahf/vczjk/wr6;->OooOOOO()Llyiahf/vczjk/qv3;

    move-result-object v2

    const/16 v8, 0x30

    const/16 v9, 0xc

    move-object/from16 v37, v3

    const-string v3, "tag"

    move-object/from16 v29, v4

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    move-object/from16 v47, v29

    move-object/from16 v48, v37

    move-object/from16 v46, v40

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    invoke-static {v0, v7}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    invoke-virtual/range {v36 .. v36}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/alarm/Alarm;->getLabel()Ljava/lang/String;

    move-result-object v2

    invoke-virtual/range {v36 .. v36}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->getAlarm()Lgithub/tornaco/android/thanos/core/alarm/Alarm;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/alarm/Alarm;->getLabel()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v3

    const/16 v4, 0x12

    invoke-static {v4, v3}, Ljava/lang/Math;->min(II)I

    move-result v3

    invoke-virtual {v2, v0, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v2

    const-string v3, "substring(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v3, v44

    move-object/from16 v4, v45

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/n6a;

    iget-object v5, v5, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v23, 0x6000

    const v24, 0x1bffe

    move-object/from16 v44, v3

    const/4 v3, 0x0

    move-object/from16 v45, v4

    move-object/from16 v20, v5

    const-wide/16 v4, 0x0

    move-object/from16 v21, v7

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    move-object/from16 v16, v10

    move/from16 v17, v11

    const-wide/16 v10, 0x0

    move-object/from16 v27, v12

    const/4 v12, 0x0

    move-object/from16 v18, v13

    move-object/from16 v30, v14

    const-wide/16 v13, 0x0

    move-object/from16 v31, v15

    const/4 v15, 0x0

    move-object/from16 v19, v16

    const/16 v16, 0x0

    move/from16 v22, v17

    const/16 v17, 0x1

    move-object/from16 v26, v18

    const/16 v18, 0x0

    move-object/from16 v28, v19

    const/16 v19, 0x0

    move/from16 v29, v22

    const/16 v22, 0x0

    move-object/from16 v49, v26

    move-object/from16 v0, v27

    move-object/from16 v54, v28

    move-object/from16 v50, v30

    move-object/from16 v51, v31

    move-object/from16 v52, v44

    move-object/from16 v53, v45

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v7, v21

    const/4 v10, 0x1

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v5, 0x0

    invoke-static {v5, v7}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v2, v54

    const/16 v3, 0x30

    invoke-static {v2, v1, v7, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v1

    iget v2, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    move-object/from16 v11, v49

    invoke-static {v7, v11}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_12

    move-object/from16 v12, v50

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_c
    move-object/from16 v13, v51

    goto :goto_d

    :cond_12
    move-object/from16 v12, v50

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_c

    :goto_d
    invoke-static {v1, v7, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v1, v46

    invoke-static {v3, v7, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_13

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_14

    :cond_13
    move-object/from16 v14, v47

    goto :goto_f

    :cond_14
    move-object/from16 v14, v47

    :goto_e
    move-object/from16 v15, v48

    goto :goto_10

    :goto_f
    invoke-static {v2, v0, v2, v14}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_e

    :goto_10
    invoke-static {v4, v7, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {}, Llyiahf/vczjk/qu6;->OooOOO0()Llyiahf/vczjk/qv3;

    move-result-object v2

    const/16 v8, 0x30

    const/16 v9, 0xc

    const-string v3, "Time"

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    const/4 v5, 0x0

    invoke-static {v5, v7}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v3, v52

    move-object/from16 v4, v53

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v23, 0x0

    const v24, 0x1fffe

    const/4 v3, 0x0

    const-wide/16 v4, 0x0

    move-object/from16 v21, v7

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    move/from16 v16, v10

    move-object/from16 v18, v11

    const-wide/16 v10, 0x0

    move-object/from16 v30, v12

    const/4 v12, 0x0

    move-object/from16 v31, v13

    move-object/from16 v29, v14

    const-wide/16 v13, 0x0

    move-object/from16 v37, v15

    const/4 v15, 0x0

    move/from16 v17, v16

    const/16 v16, 0x0

    move/from16 v19, v17

    const/16 v17, 0x0

    move-object/from16 v49, v18

    const/16 v18, 0x0

    move/from16 v20, v19

    const/16 v19, 0x0

    const/16 v22, 0x0

    move-object/from16 v26, v1

    move/from16 v1, v20

    move-object/from16 v56, v29

    move-object/from16 v55, v31

    move-object/from16 v57, v37

    move-object/from16 v20, v2

    move-object/from16 v2, v25

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v7, v21

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual/range {v36 .. v36}, Lgithub/tornaco/android/thanos/core/alarm/AlarmRecord;->isEnabled()Z

    move-result v2

    const v10, -0x615d173a

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v11, p0

    iget-object v3, v11, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ze3;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    move-object/from16 v12, v36

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    move-object/from16 v13, v43

    if-nez v4, :cond_15

    if-ne v5, v13, :cond_16

    :cond_15
    new-instance v5, Llyiahf/vczjk/o0oOO;

    const/4 v4, 0x5

    invoke-direct {v5, v4, v3, v12}, Llyiahf/vczjk/o0oOO;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    move-object v3, v5

    check-cast v3, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v8, 0x180

    const/16 v9, 0x78

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object/from16 v4, v49

    invoke-static/range {v2 .. v9}, Landroidx/compose/material3/OooO0O0;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/nc9;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static {v4, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v14

    const/4 v2, 0x6

    int-to-float v2, v2

    const/4 v15, 0x0

    const/16 v19, 0xd

    const/16 v17, 0x0

    const/16 v18, 0x0

    move/from16 v16, v2

    invoke-static/range {v14 .. v19}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v5, 0x0

    invoke-static {v3, v5}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v3

    iget v5, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v7, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v8, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_17

    move-object/from16 v14, v30

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_11
    move-object/from16 v15, v55

    goto :goto_12

    :cond_17
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_11

    :goto_12
    invoke-static {v3, v7, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v3, v26

    invoke-static {v6, v7, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_18

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_19

    :cond_18
    move-object/from16 v14, v56

    goto :goto_14

    :cond_19
    :goto_13
    move-object/from16 v15, v57

    goto :goto_15

    :goto_14
    invoke-static {v5, v0, v5, v14}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_13

    :goto_15
    invoke-static {v2, v7, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    sget-object v3, Llyiahf/vczjk/op3;->OooOOoo:Llyiahf/vczjk/ub0;

    invoke-virtual {v2, v4, v3}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v15

    const/16 v16, 0x0

    const/16 v20, 0xb

    const/16 v17, 0x0

    const/16 v19, 0x0

    move/from16 v18, v35

    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v2, v11, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v0, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v4, :cond_1a

    if-ne v5, v13, :cond_1b

    :cond_1a
    new-instance v5, Llyiahf/vczjk/o0O000;

    const/16 v4, 0x8

    const/4 v6, 0x0

    invoke-direct {v5, v4, v2, v12, v6}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1b
    move-object v2, v5

    check-cast v2, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v21, v7

    sget-object v7, Llyiahf/vczjk/fa1;->OooO0o:Llyiahf/vczjk/a91;

    const/high16 v9, 0x180000

    const/16 v10, 0x3c

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object/from16 v8, v21

    invoke-static/range {v2 .. v10}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_16
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

.method private final OooOO0O(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p1

    const-string p3, "padding"

    invoke-static {v1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 p3, p1, 0x6

    if-nez p3, :cond_1

    move-object p3, p2

    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    const/4 p3, 0x4

    goto :goto_0

    :cond_0
    const/4 p3, 0x2

    :goto_0
    or-int/2addr p1, p3

    :cond_1
    and-int/lit8 p1, p1, 0x13

    const/16 p3, 0x12

    if-ne p1, p3, :cond_3

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p3

    if-nez p3, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_3
    :goto_1
    sget-object p1, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    new-instance v0, Llyiahf/vczjk/hq;

    iget-object p3, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    move-object v2, p3

    check-cast v2, Llyiahf/vczjk/km6;

    iget-object p3, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    move-object v3, p3

    check-cast v3, Llyiahf/vczjk/xr1;

    iget-object p3, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    move-object v4, p3

    check-cast v4, Llyiahf/vczjk/le3;

    const/16 v5, 0xa

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/hq;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const p3, -0x8602ea8

    invoke-static {p3, v0, p2}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object p3

    const/4 v0, 0x0

    const/16 v1, 0x186

    invoke-static {p1, v0, p3, p2, v1}, Llyiahf/vczjk/jp8;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/yi3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOO0o(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Llyiahf/vczjk/iw7;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p3

    const-string v0, "$this$ThanoxMediumAppBarScaffold"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 p1, p3, 0x11

    const/16 p3, 0x10

    if-ne p1, p3, :cond_1

    move-object p1, p2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p3

    if-nez p3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    move-object v6, p2

    check-cast v6, Llyiahf/vczjk/zf1;

    const p1, 0x4c5de2

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/hb8;

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p3

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p2, :cond_2

    if-ne p3, v9, :cond_3

    :cond_2
    new-instance p3, Llyiahf/vczjk/n20;

    const/16 p2, 0x9

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v6, p3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v5, Llyiahf/vczjk/nb1;->OooO0O0:Llyiahf/vczjk/a91;

    const/high16 v7, 0x180000

    const/16 v8, 0x3e

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    const p2, -0x615d173a

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p2, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p3

    iget-object v0, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr p3, v1

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez p3, :cond_4

    if-ne v1, v9, :cond_5

    :cond_4
    new-instance v1, Llyiahf/vczjk/oo0oO0;

    const/16 p3, 0x19

    invoke-direct {v1, p3, p2, v0}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    move-object v0, v1

    check-cast v0, Llyiahf/vczjk/le3;

    invoke-virtual {v6, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v5, Llyiahf/vczjk/nb1;->OooO0OO:Llyiahf/vczjk/a91;

    const/high16 v7, 0x180000

    const/16 v8, 0x3e

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    invoke-static/range {v0 .. v8}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/vk;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    const-string p3, "$this$AnimatedVisibility"

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/oy7;

    const/4 p3, 0x0

    iget-object v0, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;

    iget-object v1, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Lnow/fortuitous/thanos/process/v2/RunningService;

    invoke-static {v0, v1, p1, p2, p3}, Llyiahf/vczjk/mt6;->OooO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/oy7;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOOO0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "paddingValues"

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
    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    move-object v11, v2

    check-cast v11, Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/content/Context;

    iget-object v3, v0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/s67;

    iget-boolean v13, v4, Llyiahf/vczjk/s67;->OooO00o:Z

    const v4, 0x4c5de2

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/a77;

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v6, :cond_4

    if-ne v7, v8, :cond_5

    :cond_4
    new-instance v7, Llyiahf/vczjk/fz3;

    const/16 v6, 0x1b

    invoke-direct {v7, v5, v6}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v7, Llyiahf/vczjk/le3;

    const/4 v6, 0x0

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v13, v7, v11, v6}, Llyiahf/vczjk/ls6;->OooOOo(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/bf7;

    move-result-object v14

    new-instance v7, Llyiahf/vczjk/n;

    const/4 v9, 0x1

    invoke-direct {v7, v9}, Llyiahf/vczjk/n;-><init>(I)V

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_6

    if-ne v10, v8, :cond_7

    :cond_6
    new-instance v10, Llyiahf/vczjk/b67;

    const/4 v9, 0x0

    invoke-direct {v10, v5, v9}, Llyiahf/vczjk/b67;-><init>(Llyiahf/vczjk/a77;I)V

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v7, v10, v11}, Llyiahf/vczjk/zsa;->o00O0O(Llyiahf/vczjk/n;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/wa5;

    move-result-object v7

    sget-object v15, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v9, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v9, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v14}, Llyiahf/vczjk/xr6;->OooOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf7;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v9, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v9, v6}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v9

    iget v10, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v11, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_8

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_8
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v6, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_a

    :cond_9
    invoke-static {v10, v11, v10, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/s67;

    const v4, -0x6815fd56

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qs5;

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v6, v9

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v6, v9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v6, :cond_b

    if-ne v9, v8, :cond_c

    :cond_b
    new-instance v9, Llyiahf/vczjk/oo0ooO;

    const/16 v6, 0xf

    invoke-direct {v9, v7, v2, v6, v4}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    move-object v6, v9

    check-cast v6, Llyiahf/vczjk/oe3;

    const v2, 0x6e3c21fe

    const/4 v4, 0x0

    invoke-static {v11, v4, v2}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v8, :cond_d

    new-instance v2, Llyiahf/vczjk/r07;

    const/4 v4, 0x5

    invoke-direct {v2, v4}, Llyiahf/vczjk/r07;-><init>(I)V

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_d
    move-object v7, v2

    check-cast v7, Llyiahf/vczjk/oe3;

    const/4 v4, 0x0

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, 0x4c5de2

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_e

    if-ne v4, v8, :cond_f

    :cond_e
    new-instance v4, Llyiahf/vczjk/b67;

    const/4 v2, 0x1

    invoke-direct {v4, v5, v2}, Llyiahf/vczjk/b67;-><init>(Llyiahf/vczjk/a77;I)V

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    check-cast v4, Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, 0x4c5de2

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v2, :cond_10

    if-ne v9, v8, :cond_11

    :cond_10
    new-instance v9, Llyiahf/vczjk/b67;

    const/4 v2, 0x2

    invoke-direct {v9, v5, v2}, Llyiahf/vczjk/b67;-><init>(Llyiahf/vczjk/a77;I)V

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v9, Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v2, 0x4c5de2

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v2, :cond_12

    if-ne v10, v8, :cond_13

    :cond_12
    new-instance v10, Llyiahf/vczjk/b67;

    const/4 v2, 0x3

    invoke-direct {v10, v5, v2}, Llyiahf/vczjk/b67;-><init>(Llyiahf/vczjk/a77;I)V

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v10, Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v8, v4

    const/4 v4, 0x0

    const/16 v12, 0x6006

    move-object v5, v3

    invoke-static/range {v4 .. v12}, Llyiahf/vczjk/vt6;->OooOO0o(Llyiahf/vczjk/dw4;Llyiahf/vczjk/s67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object v2, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {v1, v15, v2}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v9, v1, Llyiahf/vczjk/x21;->OooO0o:J

    const/16 v12, 0x40

    move v4, v13

    const/16 v13, 0x28

    const-wide/16 v7, 0x0

    move-object v5, v14

    invoke-static/range {v4 .. v13}, Llyiahf/vczjk/ue7;->OooO00o(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

.method private final OooOOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/vk;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    const-string p3, "$this$AnimatedVisibility"

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ny7;

    const/4 p3, 0x0

    iget-object v0, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ltornaco/apps/thanox/running/RunningAppState;

    iget-object v1, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ltornaco/apps/thanox/running/RunningService;

    invoke-static {v0, v1, p1, p2, p3}, Llyiahf/vczjk/ht6;->OooO0oo(Ltornaco/apps/thanox/running/RunningAppState;Ltornaco/apps/thanox/running/RunningService;Llyiahf/vczjk/ny7;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method private final OooOOOo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/bi6;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v3, p3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    const-string v4, "paddingValues"

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
    iget-object v3, v0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qs5;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/j28;

    iget-boolean v5, v4, Llyiahf/vczjk/j28;->OooO00o:Z

    move-object v12, v2

    check-cast v12, Llyiahf/vczjk/zf1;

    const v2, 0x4c5de2

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/i48;

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v6, :cond_4

    if-ne v7, v8, :cond_5

    :cond_4
    new-instance v7, Llyiahf/vczjk/tz7;

    const/4 v6, 0x6

    invoke-direct {v7, v4, v6}, Llyiahf/vczjk/tz7;-><init>(Llyiahf/vczjk/i48;I)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v7, Llyiahf/vczjk/le3;

    const/4 v6, 0x0

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v5, v7, v12, v6}, Llyiahf/vczjk/ls6;->OooOOo(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/bf7;

    move-result-object v7

    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v10, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v10, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v1, v7}, Llyiahf/vczjk/xr6;->OooOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf7;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v11, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v11, v6}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v11

    iget v13, v12, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v12, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v15, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_6

    invoke-virtual {v12, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_6
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v11, v12, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v14, v12, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v11, v12, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v11, :cond_7

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v11, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-nez v11, :cond_8

    :cond_7
    invoke-static {v13, v12, v13, v6}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, v12, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    invoke-interface {v3}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/j28;

    iget-boolean v6, v6, Llyiahf/vczjk/j28;->OooO0OO:Z

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v2, :cond_9

    if-ne v11, v8, :cond_a

    :cond_9
    new-instance v11, Llyiahf/vczjk/tz7;

    const/4 v2, 0x7

    invoke-direct {v11, v4, v2}, Llyiahf/vczjk/tz7;-><init>(Llyiahf/vczjk/i48;I)V

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v11, Llyiahf/vczjk/le3;

    const/4 v2, 0x0

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v11, v12, v2, v2}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    new-instance v6, Llyiahf/vczjk/yj3;

    const/16 v2, 0x50

    int-to-float v2, v2

    invoke-direct {v6, v2}, Llyiahf/vczjk/yj3;-><init>(F)V

    const/16 v2, 0x40

    int-to-float v2, v2

    const/4 v11, 0x7

    const/4 v13, 0x0

    invoke-static {v13, v13, v13, v2, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v2

    const v11, -0x6815fd56

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v11, v0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast v11, Ljava/util/List;

    invoke-virtual {v12, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v13, v14

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v13, v14

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v13, :cond_b

    if-ne v14, v8, :cond_c

    :cond_b
    new-instance v14, Llyiahf/vczjk/oo0ooO;

    const/16 v8, 0x12

    invoke-direct {v14, v11, v3, v8, v4}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v12, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    move-object/from16 v16, v14

    check-cast v16, Llyiahf/vczjk/oe3;

    const/4 v3, 0x0

    invoke-virtual {v12, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v19, 0x0

    const/16 v20, 0x3f4

    const/4 v8, 0x0

    move-object v3, v7

    move-object v7, v10

    const/4 v10, 0x0

    const/4 v11, 0x0

    move-object/from16 v17, v12

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v18, 0xc30

    move-object/from16 v21, v9

    move-object v9, v2

    move-object/from16 v2, v21

    invoke-static/range {v6 .. v20}, Llyiahf/vczjk/yi4;->OooOOO0(Llyiahf/vczjk/ak3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v12, v17

    sget-object v4, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {v1, v2, v4}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v10, v1, Llyiahf/vczjk/x21;->OooO0o:J

    const/16 v13, 0x40

    const/16 v14, 0x28

    const-wide/16 v8, 0x0

    move-object v6, v3

    invoke-static/range {v5 .. v14}, Llyiahf/vczjk/ue7;->OooO00o(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

.method private final OooOOo0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/bi6;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    move-result p3

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v0, p3, 0x6

    if-nez v0, :cond_1

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr p3, v0

    :cond_1
    and-int/lit8 p3, p3, 0x13

    const/16 v0, 0x12

    if-ne p3, v0, :cond_3

    move-object p3, p2

    check-cast p3, Llyiahf/vczjk/zf1;

    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {p3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_1
    sget-object p3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-static {p3, p1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object p3, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    const/4 v0, 0x0

    invoke-static {p3, v0}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object p3

    move-object v1, p2

    check-cast v1, Llyiahf/vczjk/zf1;

    iget v2, v1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {p2, p1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p1

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_4

    invoke-virtual {v1, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {p3, p2, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p3, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, p2, p3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object p3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_6

    :cond_5
    invoke-static {v2, v1, v2, p3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object p3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {p1, p2, p3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object p1, p0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r39;

    iget-object p3, p0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/le3;

    invoke-static {p1, p3, v2, p2, v0}, Llyiahf/vczjk/tp6;->OooO0o(Llyiahf/vczjk/r39;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    const/4 p1, 0x1

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 52

    move-object/from16 v0, p0

    const-string v4, "$this$Card"

    const/16 v5, 0x8

    const/16 v6, 0x12

    const/4 v8, 0x6

    const/high16 v10, 0x3f800000    # 1.0f

    sget-object v12, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v13, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/16 v15, 0x10

    sget-object v16, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v7, v0, Llyiahf/vczjk/n6;->OooOOOo:Ljava/lang/Object;

    iget-object v1, v0, Llyiahf/vczjk/n6;->OooOOOO:Ljava/lang/Object;

    iget-object v11, v0, Llyiahf/vczjk/n6;->OooOOO:Ljava/lang/Object;

    const/4 v2, 0x0

    iget v3, v0, Llyiahf/vczjk/n6;->OooOOO0:I

    packed-switch v3, :pswitch_data_0

    move-object/from16 v3, p1

    check-cast v3, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p3

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    const-string v8, "$this$item"

    invoke-static {v3, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v6, 0x11

    if-ne v3, v15, :cond_1

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_3

    :cond_1
    :goto_0
    invoke-static {v12, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v6, v15

    int-to-float v5, v5

    invoke-static {v3, v6, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v8, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    invoke-static {v5, v8, v4, v2}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    move-object v8, v4

    check-cast v8, Llyiahf/vczjk/zf1;

    iget v10, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v4, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_2

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v4, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v15, v4, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v9, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_4

    :cond_3
    invoke-static {v10, v8, v10, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_4
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v4, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    check-cast v11, Llyiahf/vczjk/td0;

    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-static {v11, v1, v4, v2}, Llyiahf/vczjk/xt6;->OooO00o(Llyiahf/vczjk/td0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-static {v12, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v4, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v1, 0x4c5de2

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_5

    if-ne v3, v13, :cond_6

    :cond_5
    new-instance v3, Llyiahf/vczjk/ok5;

    const/16 v1, 0x19

    invoke-direct {v3, v1, v7}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object/from16 v17, v3

    check-cast v17, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget v1, Llyiahf/vczjk/rk0;->OooO00o:F

    const v1, -0x3836343

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v1, v11, Llyiahf/vczjk/td0;->OooO0o:Z

    if-eqz v1, :cond_7

    sget-object v1, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/x21;

    iget-wide v5, v1, Llyiahf/vczjk/x21;->OooO0oo:J

    goto :goto_2

    :cond_7
    sget-wide v5, Llyiahf/vczjk/n21;->OooO0o0:J

    :goto_2
    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v5, v6, v4}, Llyiahf/vczjk/rk0;->OooO0OO(JLlyiahf/vczjk/rf1;)Llyiahf/vczjk/qk0;

    move-result-object v21

    new-instance v1, Llyiahf/vczjk/u20;

    const/16 v2, 0x1a

    invoke-direct {v1, v11, v2}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v2, 0x2daa1424

    invoke-static {v2, v1, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v24

    const/high16 v26, 0x30000000

    const/16 v27, 0x1ee

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    move-object/from16 v25, v4

    invoke-static/range {v17 .. v27}, Llyiahf/vczjk/bua;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/vk0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    const/4 v1, 0x1

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    return-object v16

    :pswitch_0
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_1
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_2
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_3
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooOOOO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_4
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooOOO0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_5
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_6
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooOO0O(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_7
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/q31;

    move-object/from16 v6, p2

    check-cast v6, Llyiahf/vczjk/rf1;

    move-object/from16 v8, p3

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    move-result v8

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v8, 0x11

    if-ne v3, v15, :cond_9

    move-object v3, v6

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_8

    goto :goto_4

    :cond_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_9
    :goto_4
    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/content/Context;

    invoke-static {v3}, Llyiahf/vczjk/zsa;->o00ooo(Landroid/content/Context;)Landroidx/appcompat/app/AppCompatActivity;

    move-result-object v3

    int-to-float v4, v5

    invoke-static {v12, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v4, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    const/16 v5, 0x3e8

    int-to-float v5, v5

    const/4 v8, 0x0

    const/4 v9, 0x1

    invoke-static {v4, v8, v5, v9}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const v8, -0x48fade91

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, v9}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v8

    check-cast v11, Llyiahf/vczjk/xw2;

    invoke-virtual {v6, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    check-cast v7, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v8, :cond_a

    if-ne v9, v13, :cond_b

    :cond_a
    new-instance v17, Llyiahf/vczjk/m60;

    const/16 v22, 0x5

    move-object/from16 v19, v1

    move-object/from16 v21, v3

    move-object/from16 v20, v7

    move-object/from16 v18, v11

    invoke-direct/range {v17 .. v22}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v9, v17

    invoke-virtual {v6, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_b
    move-object/from16 v24, v9

    check-cast v24, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v21, 0x0

    const/16 v26, 0x6c06

    const/16 v18, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x0

    move-object/from16 v20, v5

    move-object/from16 v17, v4

    move-object/from16 v19, v5

    move-object/from16 v25, v6

    invoke-static/range {v17 .. v26}, Llyiahf/vczjk/jp8;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/f22;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_5
    return-object v16

    :pswitch_8
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/q31;

    move-object/from16 v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v6, "$this$NavHeaderContainer"

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v5, 0x11

    if-ne v3, v15, :cond_d

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_c

    goto :goto_6

    :cond_c
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_7

    :cond_d
    :goto_6
    check-cast v1, Llyiahf/vczjk/x39;

    check-cast v7, Llyiahf/vczjk/le3;

    check-cast v11, Llyiahf/vczjk/kl5;

    invoke-static {v11, v1, v7, v4, v2}, Llyiahf/vczjk/tg0;->OooOO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/x39;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_7
    return-object v16

    :pswitch_9
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/b24;

    iget-wide v3, v3, Llyiahf/vczjk/b24;->OooO00o:J

    move-object/from16 v5, p2

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v9, p3

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    move-result v9

    and-int/2addr v8, v9

    if-nez v8, :cond_f

    move-object v8, v5

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, v3, v4}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v8

    if-eqz v8, :cond_e

    const/16 v17, 0x4

    goto :goto_8

    :cond_e
    const/16 v17, 0x2

    :goto_8
    or-int v9, v9, v17

    :cond_f
    and-int/lit8 v8, v9, 0x13

    if-ne v8, v6, :cond_11

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/zf1;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_10

    goto :goto_9

    :cond_10
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_a

    :cond_11
    :goto_9
    new-instance v6, Llyiahf/vczjk/h09;

    check-cast v11, Llyiahf/vczjk/le3;

    invoke-interface {v11}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v8

    invoke-direct {v6, v8}, Llyiahf/vczjk/h09;-><init>(Ljava/lang/Object;)V

    new-instance v8, Llyiahf/vczjk/h09;

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    check-cast v7, Llyiahf/vczjk/ze3;

    invoke-interface {v7, v5, v2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/bumptech/glide/RequestBuilder;

    invoke-interface {v11}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v7

    invoke-virtual {v2, v7}, Lcom/bumptech/glide/RequestBuilder;->load(Ljava/lang/Object;)Lcom/bumptech/glide/RequestBuilder;

    move-result-object v2

    const-string v7, "null cannot be cast to non-null type com.bumptech.glide.RequestBuilder<kotlin.Any>"

    invoke-static {v2, v7}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v8, v2}, Llyiahf/vczjk/h09;-><init>(Ljava/lang/Object;)V

    and-int/lit8 v26, v9, 0xe

    move-object/from16 v23, v1

    check-cast v23, Llyiahf/vczjk/hv3;

    move-wide/from16 v20, v3

    move-object/from16 v25, v5

    move-object/from16 v22, v6

    move-object/from16 v24, v8

    invoke-static/range {v20 .. v26}, Llyiahf/vczjk/os9;->OooO(JLlyiahf/vczjk/h09;Llyiahf/vczjk/hv3;Llyiahf/vczjk/h09;Llyiahf/vczjk/rf1;I)V

    :goto_a
    return-object v16

    :pswitch_a
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/q31;

    move-object/from16 v5, p2

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v9, p3

    check-cast v9, Ljava/lang/Number;

    invoke-virtual {v9}, Ljava/lang/Number;->intValue()I

    move-result v9

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v9, 0x11

    if-ne v3, v15, :cond_13

    move-object v3, v5

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_12

    goto :goto_b

    :cond_12
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_e

    :cond_13
    :goto_b
    invoke-static {v12, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    check-cast v5, Llyiahf/vczjk/zf1;

    const v4, 0x4c5de2

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v7, Llyiahf/vczjk/qs5;

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v4, :cond_14

    if-ne v9, v13, :cond_15

    :cond_14
    new-instance v9, Llyiahf/vczjk/l5;

    invoke-direct {v9, v7, v6}, Llyiahf/vczjk/l5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v9}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v6, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v4, v6, v5, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    iget v6, v5, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v5, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v9, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_16

    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_c

    :cond_16
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_c
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v5, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v5, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v5, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_17

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_18

    :cond_17
    invoke-static {v6, v5, v6, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_18
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v5, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v29, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    check-cast v11, Llyiahf/vczjk/a91;

    invoke-virtual {v11, v5, v3}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/jt2;->OooOOO0:Llyiahf/vczjk/jt2;

    if-ne v3, v4, :cond_19

    const/16 v30, 0x1

    goto :goto_d

    :cond_19
    move/from16 v30, v2

    :goto_d
    new-instance v2, Llyiahf/vczjk/ra2;

    check-cast v1, Llyiahf/vczjk/a91;

    const/4 v9, 0x1

    invoke-direct {v2, v1, v9}, Llyiahf/vczjk/ra2;-><init>(Llyiahf/vczjk/a91;I)V

    const v1, 0x94e0ed4

    invoke-static {v1, v2, v5}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v35

    const v37, 0x180006

    const/16 v38, 0x1e

    const/16 v31, 0x0

    const/16 v32, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    move-object/from16 v36, v5

    invoke-static/range {v29 .. v38}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_e
    return-object v16

    :pswitch_b
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/q31;

    move-object/from16 v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v6, "$this$DropdownMenu"

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v5, 0x11

    if-ne v3, v15, :cond_1b

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_1a

    goto :goto_f

    :cond_1a
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_11

    :cond_1b
    :goto_f
    check-cast v11, Ljava/util/List;

    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_10
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_1e

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/gj2;

    sget-object v6, Llyiahf/vczjk/el8;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v12, v6}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v24

    new-instance v6, Llyiahf/vczjk/f5;

    const/16 v8, 0xf

    invoke-direct {v6, v5, v8}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v8, 0xb3da9df

    invoke-static {v8, v6, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v22

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/zf1;

    const v8, -0x6815fd56

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object v8, v1

    check-cast v8, Llyiahf/vczjk/oj2;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    move-object v10, v7

    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v9, v11

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v9, v11

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v9, :cond_1c

    if-ne v11, v13, :cond_1d

    :cond_1c
    new-instance v11, Llyiahf/vczjk/x5;

    const/4 v9, 0x7

    invoke-direct {v11, v8, v10, v9, v5}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v6, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1d
    move-object/from16 v23, v11

    check-cast v23, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v29, 0x186

    const/16 v30, 0x1f8

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    move-object/from16 v28, v6

    invoke-static/range {v22 .. v30}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    goto :goto_10

    :cond_1e
    :goto_11
    return-object v16

    :pswitch_c
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/q31;

    move-object/from16 v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v6, "$this$DropdownMenu"

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v5, 0x11

    if-ne v3, v15, :cond_20

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_1f

    goto :goto_12

    :cond_1f
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_14

    :cond_20
    :goto_12
    check-cast v11, Ljava/util/List;

    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_13
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_23

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ah5;

    new-instance v6, Llyiahf/vczjk/f5;

    const/16 v8, 0xe

    invoke-direct {v6, v5, v8}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v8, 0x53fdc6fc

    invoke-static {v8, v6, v4}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v22

    move-object v6, v4

    check-cast v6, Llyiahf/vczjk/zf1;

    const v8, -0x6815fd56

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/qs5;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    move-object v10, v1

    check-cast v10, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v9, v11

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v9, v11

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v9, :cond_21

    if-ne v11, v13, :cond_22

    :cond_21
    new-instance v11, Llyiahf/vczjk/x5;

    invoke-direct {v11, v8, v10, v5}, Llyiahf/vczjk/x5;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ah5;)V

    invoke-virtual {v6, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_22
    move-object/from16 v23, v11

    check-cast v23, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v29, 0x6

    const/16 v30, 0x1fc

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    move-object/from16 v28, v6

    invoke-static/range {v22 .. v30}, Llyiahf/vczjk/fe;->OooO0O0(Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/bh5;Llyiahf/vczjk/di6;Llyiahf/vczjk/rf1;II)V

    goto :goto_13

    :cond_23
    :goto_14
    return-object v16

    :pswitch_d
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooO0oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_e
    invoke-direct/range {p0 .. p3}, Llyiahf/vczjk/n6;->OooO0oO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    return-object v1

    :pswitch_f
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/q31;

    move-object/from16 v5, p2

    check-cast v5, Llyiahf/vczjk/rf1;

    move-object/from16 v6, p3

    check-cast v6, Ljava/lang/Number;

    invoke-virtual {v6}, Ljava/lang/Number;->intValue()I

    move-result v6

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v3, v6, 0x11

    if-ne v3, v15, :cond_25

    move-object v3, v5

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_24

    goto :goto_15

    :cond_24
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_18

    :cond_25
    :goto_15
    int-to-float v3, v15

    invoke-static {v12, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v6, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v4, v6, v5, v2}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/zf1;

    iget v8, v6, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v5, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v10, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_26

    invoke-virtual {v6, v10}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_16

    :cond_26
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_16
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v4, v5, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v5, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_27

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_28

    :cond_27
    invoke-static {v8, v6, v8, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_28
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v5, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v3, 0x18

    invoke-static {v3}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v33

    sget-object v35, Llyiahf/vczjk/ib3;->OooOo0O:Llyiahf/vczjk/ib3;

    move-object/from16 v29, v11

    check-cast v29, Ljava/lang/String;

    const/16 v50, 0x0

    const v51, 0x3ffae

    const/16 v30, 0x0

    const-wide/16 v31, 0x0

    const/16 v36, 0x0

    const-wide/16 v37, 0x0

    const/16 v39, 0x0

    const-wide/16 v40, 0x0

    const/16 v42, 0x0

    const/16 v43, 0x0

    const/16 v44, 0x0

    const/16 v45, 0x0

    const/16 v46, 0x0

    const/16 v47, 0x0

    const v49, 0x186000

    move-object/from16 v48, v5

    invoke-static/range {v29 .. v51}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v3, v48

    invoke-static {v2, v3}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    const v51, 0x3fffe

    move-object/from16 v29, v1

    check-cast v29, Ljava/lang/String;

    const-wide/16 v33, 0x0

    const/16 v35, 0x0

    const/16 v49, 0x0

    invoke-static/range {v29 .. v51}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const v1, 0x1c328fe4

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v7, Ljava/lang/String;

    if-nez v7, :cond_29

    goto :goto_17

    :cond_29
    invoke-static {v2, v3}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    const/4 v1, 0x2

    const/4 v4, 0x0

    invoke-static {v2, v1, v7, v3, v4}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    :goto_17
    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v9, 0x1

    invoke-virtual {v6, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_18
    return-object v16

    :pswitch_10
    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/bi6;

    move-object/from16 v4, p2

    check-cast v4, Llyiahf/vczjk/rf1;

    move-object/from16 v5, p3

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    const-string v9, "paddings"

    invoke-static {v3, v9}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/2addr v8, v5

    if-nez v8, :cond_2b

    move-object v8, v4

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_2a

    const/4 v8, 0x4

    goto :goto_19

    :cond_2a
    const/4 v8, 0x2

    :goto_19
    or-int/2addr v5, v8

    :cond_2b
    and-int/lit8 v5, v5, 0x13

    if-ne v5, v6, :cond_2d

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_2c

    goto :goto_1a

    :cond_2c
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_21

    :cond_2d
    :goto_1a
    check-cast v11, Llyiahf/vczjk/g70;

    iget-object v5, v11, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    invoke-virtual {v5}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v5

    invoke-static {v5, v4}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/yu;

    iget-boolean v6, v6, Llyiahf/vczjk/yu;->OooO0O0:Z

    check-cast v4, Llyiahf/vczjk/zf1;

    const v8, 0x4c5de2

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v8, :cond_2e

    if-ne v9, v13, :cond_2f

    :cond_2e
    new-instance v9, Llyiahf/vczjk/l60;

    invoke-direct {v9, v11, v2}, Llyiahf/vczjk/l60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2f
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v6, v9, v4, v2}, Llyiahf/vczjk/ls6;->OooOOo(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/bf7;

    move-result-object v6

    sget-object v8, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-static {v8, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-static {v3, v6}, Llyiahf/vczjk/xr6;->OooOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf7;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v9, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v9, v2}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v9

    iget v14, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v4, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v21, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v21 .. v21}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v2, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_30

    invoke-virtual {v4, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_1b

    :cond_30
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_1b
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v4, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v4, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_31

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_32

    :cond_31
    invoke-static {v14, v4, v14, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_32
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v4, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    new-instance v3, Llyiahf/vczjk/yj3;

    const/16 v9, 0x10e

    int-to-float v9, v9

    invoke-direct {v3, v9}, Llyiahf/vczjk/yj3;-><init>(F)V

    check-cast v7, Llyiahf/vczjk/e60;

    iget-object v9, v7, Llyiahf/vczjk/e60;->OooO0o0:Ljava/util/List;

    invoke-interface {v9}, Ljava/util/List;->isEmpty()Z

    move-result v9

    if-eqz v9, :cond_33

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/yu;

    iget-boolean v9, v9, Llyiahf/vczjk/yu;->OooOO0O:Z

    if-nez v9, :cond_33

    const/4 v9, 0x0

    :goto_1c
    int-to-float v10, v9

    goto :goto_1d

    :cond_33
    const/16 v9, 0xc8

    goto :goto_1c

    :goto_1d
    const/4 v9, 0x0

    const/4 v14, 0x7

    invoke-static {v9, v9, v9, v10, v14}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v9

    const v10, -0x48fade91

    invoke-virtual {v4, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    check-cast v1, Landroid/content/Context;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v10, v14

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v10, v14

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v14

    or-int/2addr v10, v14

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v10, :cond_35

    if-ne v14, v13, :cond_34

    goto :goto_1e

    :cond_34
    move-object v1, v5

    goto :goto_1f

    :cond_35
    :goto_1e
    new-instance v29, Llyiahf/vczjk/m60;

    const/16 v34, 0x0

    move-object/from16 v31, v1

    move-object/from16 v33, v5

    move-object/from16 v30, v7

    move-object/from16 v32, v11

    invoke-direct/range {v29 .. v34}, Llyiahf/vczjk/m60;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    move-object/from16 v14, v29

    move-object/from16 v1, v33

    invoke-virtual {v4, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_1f
    move-object/from16 v39, v14

    check-cast v39, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v42, 0x0

    const/16 v43, 0x3f4

    const/16 v31, 0x0

    const/16 v33, 0x0

    const/16 v34, 0x0

    const/16 v35, 0x0

    const/16 v36, 0x0

    const/16 v37, 0x0

    const/16 v38, 0x0

    const/16 v41, 0x30

    move-object/from16 v29, v3

    move-object/from16 v40, v4

    move-object/from16 v30, v8

    move-object/from16 v32, v9

    invoke-static/range {v29 .. v43}, Llyiahf/vczjk/yi4;->OooOOO0(Llyiahf/vczjk/ak3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v35, v40

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/yu;

    iget-boolean v3, v3, Llyiahf/vczjk/yu;->OooO0O0:Z

    sget-object v4, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {v2, v12, v4}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v31

    const/16 v37, 0x40

    const/16 v38, 0x38

    const-wide/16 v32, 0x0

    move-object/from16 v36, v35

    const-wide/16 v34, 0x0

    move/from16 v29, v3

    move-object/from16 v30, v6

    invoke-static/range {v29 .. v38}, Llyiahf/vczjk/ue7;->OooO00o(ZLlyiahf/vczjk/bf7;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/rf1;II)V

    move-object/from16 v4, v36

    const v3, -0x1a0b4c08

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v7, Llyiahf/vczjk/e60;->OooO0oO:Llyiahf/vczjk/ma0;

    if-eqz v3, :cond_3e

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v5

    move-object/from16 v30, v5

    check-cast v30, Llyiahf/vczjk/yu;

    const/16 v5, 0x10

    int-to-float v5, v5

    invoke-static {v12, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/high16 v6, 0x3f800000    # 1.0f

    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/op3;->OooOo0:Llyiahf/vczjk/ub0;

    invoke-virtual {v2, v5, v6}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v31

    const v8, 0x4c5de2

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_36

    if-ne v5, v13, :cond_37

    :cond_36
    new-instance v5, Llyiahf/vczjk/l60;

    const/4 v9, 0x1

    invoke-direct {v5, v11, v9}, Llyiahf/vczjk/l60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_37
    move-object/from16 v32, v5

    check-cast v32, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x4c5de2

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_38

    if-ne v5, v13, :cond_39

    :cond_38
    new-instance v5, Llyiahf/vczjk/l60;

    const/4 v2, 0x2

    invoke-direct {v5, v11, v2}, Llyiahf/vczjk/l60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_39
    move-object/from16 v33, v5

    check-cast v33, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v8, 0x4c5de2

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_3a

    if-ne v5, v13, :cond_3b

    :cond_3a
    new-instance v5, Llyiahf/vczjk/l60;

    const/4 v2, 0x3

    invoke-direct {v5, v11, v2}, Llyiahf/vczjk/l60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3b
    move-object/from16 v34, v5

    check-cast v34, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v36, 0x0

    move-object/from16 v29, v3

    move-object/from16 v35, v4

    invoke-static/range {v29 .. v36}, Llyiahf/vczjk/qqa;->OooO(Llyiahf/vczjk/ma0;Llyiahf/vczjk/yu;Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/yu;

    iget-boolean v1, v1, Llyiahf/vczjk/yu;->OooOO0O:Z

    const v8, 0x4c5de2

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v4, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_3c

    if-ne v3, v13, :cond_3d

    :cond_3c
    new-instance v3, Llyiahf/vczjk/l60;

    const/4 v2, 0x4

    invoke-direct {v3, v11, v2}, Llyiahf/vczjk/l60;-><init>(Llyiahf/vczjk/g70;I)V

    invoke-virtual {v4, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3d
    check-cast v3, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v1, v3, v4, v5, v5}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    goto :goto_20

    :cond_3e
    const/4 v5, 0x0

    :goto_20
    invoke-virtual {v4, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v9, 0x1

    invoke-virtual {v4, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_21
    return-object v16

    :pswitch_11
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/iw7;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p3

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    const-string v5, "$this$ThanoxMediumAppBarScaffold"

    invoke-static {v2, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v2, v4, 0x11

    const/16 v5, 0x10

    if-ne v2, v5, :cond_40

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_3f

    goto :goto_22

    :cond_3f
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_2f

    :cond_40
    :goto_22
    check-cast v11, Llyiahf/vczjk/e60;

    iget-object v2, v11, Llyiahf/vczjk/e60;->OooO0O0:Llyiahf/vczjk/fp;

    check-cast v3, Llyiahf/vczjk/zf1;

    const v8, 0x4c5de2

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_41

    if-ne v4, v13, :cond_42

    :cond_41
    iget-object v2, v11, Llyiahf/vczjk/e60;->OooO0O0:Llyiahf/vczjk/fp;

    iget-object v2, v2, Llyiahf/vczjk/fp;->OooO0O0:Llyiahf/vczjk/oe3;

    check-cast v1, Landroid/content/Context;

    invoke-interface {v2, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    move-object v4, v1

    check-cast v4, Ljava/util/List;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_42
    check-cast v4, Ljava/util/List;

    const/4 v5, 0x0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v1, 0x10bd0ce8

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v1, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/f62;

    sget-object v2, Llyiahf/vczjk/ch1;->OooOo00:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/bna;

    check-cast v2, Llyiahf/vczjk/yw4;

    iget-object v5, v2, Llyiahf/vczjk/yw4;->OooO0O0:Llyiahf/vczjk/qs5;

    if-nez v5, :cond_44

    iget-object v5, v2, Llyiahf/vczjk/yw4;->OooO00o:Llyiahf/vczjk/ma;

    if-eqz v5, :cond_43

    invoke-virtual {v5}, Llyiahf/vczjk/ma;->OooO00o()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/b24;

    iget-wide v5, v5, Llyiahf/vczjk/b24;->OooO00o:J

    goto :goto_23

    :cond_43
    const-wide/16 v5, 0x0

    :goto_23
    new-instance v8, Llyiahf/vczjk/b24;

    invoke-direct {v8, v5, v6}, Llyiahf/vczjk/b24;-><init>(J)V

    invoke-static {v8}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v5

    iput-object v5, v2, Llyiahf/vczjk/yw4;->OooO0O0:Llyiahf/vczjk/qs5;

    const/4 v5, 0x0

    iput-object v5, v2, Llyiahf/vczjk/yw4;->OooO00o:Llyiahf/vczjk/ma;

    :cond_44
    iget-object v2, v2, Llyiahf/vczjk/yw4;->OooO0O0:Llyiahf/vczjk/qs5;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/b24;

    iget-wide v5, v2, Llyiahf/vczjk/b24;->OooO00o:J

    invoke-static {v5, v6}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v5

    invoke-interface {v1, v5, v6}, Llyiahf/vczjk/f62;->OooOOOO(J)J

    move-result-wide v1

    const/4 v5, 0x0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v5, Llyiahf/vczjk/lpa;->OooO0OO:Ljava/util/List;

    sget-object v5, Llyiahf/vczjk/ce2;->OooO00o:Ljava/util/Set;

    sget-object v6, Llyiahf/vczjk/yd2;->OooO00o:Ljava/util/Set;

    check-cast v5, Ljava/lang/Iterable;

    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_45
    :goto_24
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_46

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    move-object v10, v9

    check-cast v10, Llyiahf/vczjk/wd2;

    iget v10, v10, Llyiahf/vczjk/wd2;->OooOOO0:F

    invoke-static {v1, v2}, Llyiahf/vczjk/ae2;->OooO0O0(J)F

    move-result v11

    invoke-static {v11, v10}, Ljava/lang/Float;->compare(FF)I

    move-result v10

    if-ltz v10, :cond_45

    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_24

    :cond_46
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_57

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/wd2;

    iget v8, v8, Llyiahf/vczjk/wd2;->OooOOO0:F

    :goto_25
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_47

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/wd2;

    iget v9, v9, Llyiahf/vczjk/wd2;->OooOOO0:F

    invoke-static {v8, v9}, Ljava/lang/Math;->max(FF)F

    move-result v8

    goto :goto_25

    :cond_47
    check-cast v6, Ljava/lang/Iterable;

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :cond_48
    :goto_26
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_49

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    move-object v10, v9

    check-cast v10, Llyiahf/vczjk/wd2;

    iget v10, v10, Llyiahf/vczjk/wd2;->OooOOO0:F

    invoke-static {v1, v2}, Llyiahf/vczjk/ae2;->OooO00o(J)F

    move-result v11

    invoke-static {v11, v10}, Ljava/lang/Float;->compare(FF)I

    move-result v10

    if-ltz v10, :cond_48

    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_26

    :cond_49
    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_56

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/wd2;

    iget v2, v2, Llyiahf/vczjk/wd2;->OooOOO0:F

    :goto_27
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_4a

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/wd2;

    iget v5, v5, Llyiahf/vczjk/wd2;->OooOOO0:F

    invoke-static {v2, v5}, Ljava/lang/Math;->max(FF)F

    move-result v2

    goto :goto_27

    :cond_4a
    new-instance v1, Llyiahf/vczjk/lpa;

    float-to-int v5, v8

    float-to-int v2, v2

    invoke-direct {v1, v5, v2}, Llyiahf/vczjk/lpa;-><init>(II)V

    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/content/Context;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v5, :cond_4b

    if-ne v6, v13, :cond_4c

    :cond_4b
    sget-object v5, Llyiahf/vczjk/ena;->OooO00o:Llyiahf/vczjk/dna;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v2}, Llyiahf/vczjk/dna;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/jna;

    move-result-object v5

    new-instance v6, Llyiahf/vczjk/gna;

    const/4 v8, 0x0

    invoke-direct {v6, v5, v2, v8}, Llyiahf/vczjk/gna;-><init>(Llyiahf/vczjk/jna;Landroid/content/Context;Llyiahf/vczjk/yo1;)V

    invoke-static {v6}, Llyiahf/vczjk/rs;->OooOO0O(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/lo0;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v5, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    invoke-static {v2, v5}, Llyiahf/vczjk/rs;->OooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/qr1;)Llyiahf/vczjk/f43;

    move-result-object v2

    new-instance v6, Llyiahf/vczjk/wh;

    const/4 v5, 0x0

    invoke-direct {v6, v2, v5}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4c
    move-object/from16 v25, v6

    check-cast v25, Llyiahf/vczjk/f43;

    sget-object v26, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/16 v30, 0x2

    const/16 v27, 0x0

    const/16 v29, 0x30

    move-object/from16 v28, v3

    invoke-static/range {v25 .. v30}, Landroidx/compose/runtime/OooO0o;->OooO00o(Llyiahf/vczjk/f43;Ljava/lang/Object;Llyiahf/vczjk/or1;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/qs5;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_28
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_52

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/nm3;

    iget-object v8, v6, Llyiahf/vczjk/nm3;->OooO00o:Llyiahf/vczjk/ug0;

    invoke-virtual {v8}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result v9

    invoke-virtual {v8}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result v8

    sget-object v10, Llyiahf/vczjk/q93;->OooOOOo:Llyiahf/vczjk/q93;

    sget-object v11, Llyiahf/vczjk/q93;->OooOOOO:Llyiahf/vczjk/q93;

    if-le v9, v8, :cond_4d

    move-object v8, v10

    goto :goto_29

    :cond_4d
    move-object v8, v11

    :goto_29
    invoke-virtual {v8, v10}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v8

    iget-object v9, v6, Llyiahf/vczjk/nm3;->OooO0OO:Llyiahf/vczjk/tqa;

    if-eqz v8, :cond_4e

    sget-object v8, Llyiahf/vczjk/tqa;->OooOOOo:Llyiahf/vczjk/tqa;

    invoke-virtual {v9, v8}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v8

    :cond_4e
    new-instance v18, Llyiahf/vczjk/vn3;

    iget-object v8, v6, Llyiahf/vczjk/nm3;->OooO00o:Llyiahf/vczjk/ug0;

    invoke-virtual {v8}, Llyiahf/vczjk/ug0;->OooO0OO()Landroid/graphics/Rect;

    move-result-object v12

    invoke-static {v12}, Llyiahf/vczjk/dl6;->OooOOOo(Landroid/graphics/Rect;)Llyiahf/vczjk/wj7;

    move-result-object v19

    sget-object v12, Llyiahf/vczjk/tqa;->OooOOOO:Llyiahf/vczjk/tqa;

    invoke-virtual {v9, v12}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v20

    invoke-virtual {v8}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result v9

    invoke-virtual {v8}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result v12

    if-le v9, v12, :cond_4f

    goto :goto_2a

    :cond_4f
    move-object v10, v11

    :goto_2a
    invoke-virtual {v10, v11}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v21

    invoke-virtual {v6}, Llyiahf/vczjk/nm3;->OooO00o()Z

    move-result v22

    invoke-virtual {v8}, Llyiahf/vczjk/ug0;->OooO0O0()I

    move-result v6

    sget-object v9, Llyiahf/vczjk/p93;->OooOOOo:Llyiahf/vczjk/p93;

    if-eqz v6, :cond_51

    invoke-virtual {v8}, Llyiahf/vczjk/ug0;->OooO00o()I

    move-result v6

    if-nez v6, :cond_50

    goto :goto_2b

    :cond_50
    move-object v6, v9

    goto :goto_2c

    :cond_51
    :goto_2b
    sget-object v6, Llyiahf/vczjk/p93;->OooOOOO:Llyiahf/vczjk/p93;

    :goto_2c
    invoke-virtual {v6, v9}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v23

    invoke-direct/range {v18 .. v23}, Llyiahf/vczjk/vn3;-><init>(Llyiahf/vczjk/wj7;ZZZZ)V

    move-object/from16 v6, v18

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_28

    :cond_52
    const/16 v2, 0x258

    iget v1, v1, Llyiahf/vczjk/lpa;->OooO00o:I

    if-lt v1, v2, :cond_53

    const/4 v1, 0x5

    :goto_2d
    move/from16 v27, v1

    goto :goto_2e

    :cond_53
    const/4 v1, 0x3

    goto :goto_2d

    :goto_2e
    sget-object v25, Llyiahf/vczjk/r91;->OooO0Oo:Llyiahf/vczjk/a91;

    const v1, -0x615d173a

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    check-cast v7, Llyiahf/vczjk/hb8;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    or-int/2addr v1, v2

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    if-nez v1, :cond_54

    if-ne v2, v13, :cond_55

    :cond_54
    new-instance v2, Llyiahf/vczjk/o0OO000o;

    const/4 v5, 0x4

    invoke-direct {v2, v5, v4, v7}, Llyiahf/vczjk/o0OO000o;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_55
    move-object/from16 v28, v2

    check-cast v28, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v26, 0x0

    const/16 v30, 0x6

    move-object/from16 v29, v3

    invoke-static/range {v25 .. v30}, Llyiahf/vczjk/ye5;->OooO00o(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;ILlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_2f
    return-object v16

    :cond_56
    new-instance v1, Ljava/util/NoSuchElementException;

    invoke-direct {v1}, Ljava/util/NoSuchElementException;-><init>()V

    throw v1

    :cond_57
    new-instance v1, Ljava/util/NoSuchElementException;

    invoke-direct {v1}, Ljava/util/NoSuchElementException;-><init>()V

    throw v1

    :pswitch_12
    move v2, v8

    const/4 v5, 0x4

    move-object/from16 v8, p1

    check-cast v8, Llyiahf/vczjk/bi6;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p3

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    const-string v9, "paddings"

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/2addr v2, v4

    if-nez v2, :cond_59

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_58

    goto :goto_30

    :cond_58
    const/4 v5, 0x2

    :goto_30
    or-int/2addr v4, v5

    :cond_59
    and-int/lit8 v2, v4, 0x13

    if-ne v2, v6, :cond_5b

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_5a

    goto :goto_31

    :cond_5a
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_34

    :cond_5b
    :goto_31
    check-cast v3, Llyiahf/vczjk/zf1;

    const v2, -0x615d173a

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v11, Llyiahf/vczjk/aw;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    move-object v10, v1

    check-cast v10, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v1, v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v1, :cond_5d

    if-ne v5, v13, :cond_5c

    goto :goto_32

    :cond_5c
    const/4 v9, 0x0

    goto :goto_33

    :cond_5d
    :goto_32
    new-instance v5, Llyiahf/vczjk/iv;

    const/4 v9, 0x0

    invoke-direct {v5, v11, v10, v9}, Llyiahf/vczjk/iv;-><init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_33
    check-cast v5, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v1, 0x2

    const/4 v12, 0x0

    invoke-static {v5, v12, v3, v9, v1}, Llyiahf/vczjk/rs;->OooO0O0(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v1, v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v1, :cond_5e

    if-ne v5, v13, :cond_5f

    :cond_5e
    new-instance v5, Llyiahf/vczjk/jv;

    const/4 v12, 0x0

    invoke-direct {v5, v11, v10, v12}, Llyiahf/vczjk/jv;-><init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5f
    check-cast v5, Llyiahf/vczjk/ze3;

    const/4 v9, 0x0

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v11, v3, v5}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v1, Lgithub/tornaco/thanos/android/ops2/byapp/AppOpsListActivity;->OoooO0O:I

    move-object v9, v7

    check-cast v9, Llyiahf/vczjk/qs5;

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ye6;

    iget-boolean v1, v1, Llyiahf/vczjk/ye6;->OooO00o:Z

    invoke-static {v1, v3}, Llyiahf/vczjk/tn6;->OooOOo0(ZLlyiahf/vczjk/rf1;)Llyiahf/vczjk/jc9;

    move-result-object v1

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v2, v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_60

    if-ne v5, v13, :cond_61

    :cond_60
    new-instance v5, Llyiahf/vczjk/iv;

    const/4 v2, 0x1

    invoke-direct {v5, v11, v10, v2}, Llyiahf/vczjk/iv;-><init>(Llyiahf/vczjk/aw;Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_61
    check-cast v5, Llyiahf/vczjk/le3;

    const/4 v2, 0x0

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v2, Llyiahf/vczjk/o91;->OooO0O0:Llyiahf/vczjk/a91;

    new-instance v7, Llyiahf/vczjk/hq;

    const/4 v12, 0x2

    invoke-direct/range {v7 .. v12}, Llyiahf/vczjk/hq;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v9, 0x81c22b0

    invoke-static {v9, v7, v3}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v11

    const/high16 v7, 0x380000

    shl-int/2addr v4, v6

    and-int/2addr v4, v7

    const/high16 v6, 0x36c00000

    or-int v13, v4, v6

    const/4 v6, 0x0

    const/16 v14, 0x3c

    const/4 v4, 0x0

    move-object v12, v3

    move-object v3, v5

    const/4 v5, 0x0

    const/4 v7, 0x0

    const/4 v10, 0x0

    move-object v9, v2

    move-object v2, v1

    invoke-static/range {v2 .. v14}, Llyiahf/vczjk/tn6;->OooO0OO(Llyiahf/vczjk/jc9;Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZFLlyiahf/vczjk/o4;Llyiahf/vczjk/bi6;Llyiahf/vczjk/df3;ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_34
    return-object v16

    :pswitch_13
    move-object/from16 v2, p1

    check-cast v2, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p3

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    const-string v6, "$this$item"

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v2, v4, 0x11

    const/16 v4, 0x10

    if-ne v2, v4, :cond_62

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_63

    :cond_62
    const/high16 v6, 0x3f800000    # 1.0f

    goto :goto_35

    :cond_63
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_37

    :goto_35
    invoke-static {v12, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    int-to-float v4, v4

    int-to-float v5, v5

    invoke-static {v2, v4, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v5, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    sget-object v6, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    const/4 v9, 0x0

    invoke-static {v5, v6, v3, v9}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    move-object v6, v3

    check-cast v6, Llyiahf/vczjk/zf1;

    iget v8, v6, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v3, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v10, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_64

    invoke-virtual {v6, v10}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_36

    :cond_64
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_36
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_65

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-nez v9, :cond_66

    :cond_65
    invoke-static {v8, v6, v8, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_66
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v2, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OoooO0O:I

    check-cast v7, Llyiahf/vczjk/qs5;

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/xu;

    const v8, 0x4c5de2

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v1, Llyiahf/vczjk/dv;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v5, :cond_67

    if-ne v7, v13, :cond_68

    :cond_67
    new-instance v7, Llyiahf/vczjk/o000OO;

    const/4 v14, 0x7

    invoke-direct {v7, v1, v14}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v6, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_68
    check-cast v7, Llyiahf/vczjk/oe3;

    const/4 v5, 0x0

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget v1, Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;->Oooo0oO:I

    check-cast v11, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;

    const/16 v1, 0x200

    invoke-virtual {v11, v2, v7, v3, v1}, Lgithub/tornaco/thanos/android/ops2/byop/AppListActivity;->OooOoo(Llyiahf/vczjk/xu;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-static {v12, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v3, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v9, 0x1

    invoke-virtual {v6, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_37
    return-object v16

    :pswitch_14
    move v2, v8

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/q31;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p3

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    and-int/lit8 v5, v4, 0x11

    const/16 v6, 0x10

    if-eq v5, v6, :cond_69

    const/4 v5, 0x1

    :goto_38
    const/16 v28, 0x1

    goto :goto_39

    :cond_69
    const/4 v5, 0x0

    goto :goto_38

    :goto_39
    and-int/lit8 v4, v4, 0x1

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v4, v5}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v4

    if-eqz v4, :cond_6a

    check-cast v1, Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/iq;

    iget-object v1, v1, Llyiahf/vczjk/iq;->OooO00o:Llyiahf/vczjk/jq;

    iget-object v1, v1, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    check-cast v11, Llyiahf/vczjk/eq;

    iget-object v4, v11, Llyiahf/vczjk/eq;->OooO0O0:Llyiahf/vczjk/qr5;

    check-cast v4, Llyiahf/vczjk/bw8;

    invoke-virtual {v4}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v4

    iget-object v5, v11, Llyiahf/vczjk/eq;->OooO00o:Llyiahf/vczjk/qr5;

    check-cast v5, Llyiahf/vczjk/bw8;

    invoke-virtual {v5}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v5

    invoke-virtual {v1, v4, v5}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v4

    const/4 v5, 0x0

    :goto_3a
    if-ge v5, v4, :cond_6b

    invoke-interface {v1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/qz0;

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/dq;

    invoke-virtual {v6, v8, v3, v2}, Llyiahf/vczjk/qz0;->OooO0O0(Llyiahf/vczjk/dq;Llyiahf/vczjk/rf1;I)V

    const/16 v28, 0x1

    add-int/lit8 v5, v5, 0x1

    goto :goto_3a

    :cond_6a
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_6b
    return-object v16

    :pswitch_15
    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/iw7;

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p3

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    const-string v5, "$this$ThanoxMediumAppBarScaffold"

    invoke-static {v2, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v2, v4, 0x11

    const/16 v5, 0x10

    if-ne v2, v5, :cond_6d

    move-object v2, v3

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_6c

    goto :goto_3b

    :cond_6c
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3c

    :cond_6d
    :goto_3b
    check-cast v3, Llyiahf/vczjk/zf1;

    const v8, -0x6815fd56

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    check-cast v11, Llyiahf/vczjk/wa5;

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    check-cast v1, Landroid/content/Context;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v2, v4

    check-cast v7, Llyiahf/vczjk/qs5;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v2, v4

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_6e

    if-ne v4, v13, :cond_6f

    :cond_6e
    new-instance v4, Llyiahf/vczjk/x5;

    const/4 v2, 0x2

    invoke-direct {v4, v11, v1, v2, v7}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6f
    move-object/from16 v25, v4

    check-cast v25, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v30, Llyiahf/vczjk/f91;->OooO00o:Llyiahf/vczjk/a91;

    const/high16 v32, 0x180000

    const/16 v33, 0x3e

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v29, 0x0

    move-object/from16 v31, v3

    invoke-static/range {v25 .. v33}, Llyiahf/vczjk/so8;->OooO0oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/pt3;Llyiahf/vczjk/qj8;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    :goto_3c
    return-object v16

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_15
        :pswitch_14
        :pswitch_13
        :pswitch_12
        :pswitch_11
        :pswitch_10
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
