.class public final Llyiahf/vczjk/ic1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/le3;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cj8;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;)V
    .locals 0

    const/4 p1, 0x0

    iput p1, p0, Llyiahf/vczjk/ic1;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/ic1;->OooOOO:Llyiahf/vczjk/le3;

    iput-object p3, p0, Llyiahf/vczjk/ic1;->OooOOOO:Llyiahf/vczjk/qs5;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/ic1;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ic1;->OooOOO:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/ic1;->OooOOOO:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 37

    move-object/from16 v0, p0

    const/16 v1, 0x12

    const/16 v2, 0x13

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const v5, 0x4c5de2

    iget-object v6, v0, Llyiahf/vczjk/ic1;->OooOOOO:Llyiahf/vczjk/qs5;

    sget-object v7, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v8, 0x1

    const/4 v9, 0x0

    const/4 v10, 0x2

    iget v11, v0, Llyiahf/vczjk/ic1;->OooOOO0:I

    packed-switch v11, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/rf1;

    move-object/from16 v8, p3

    check-cast v8, Ljava/lang/Number;

    invoke-virtual {v8}, Ljava/lang/Number;->intValue()I

    move-result v8

    const-string v11, "$this$item"

    invoke-static {v1, v11}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v1, v8, 0x11

    const/16 v8, 0x10

    if-ne v1, v8, :cond_1

    move-object v1, v2

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v11

    if-nez v11, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    int-to-float v14, v8

    const/4 v1, 0x0

    invoke-static {v7, v14, v1, v10}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v12

    const/4 v13, 0x0

    const/16 v17, 0xd

    const/4 v15, 0x0

    const/16 v16, 0x0

    invoke-static/range {v12 .. v17}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/nw5;

    iget-object v6, v6, Llyiahf/vczjk/nw5;->OooO0O0:Llyiahf/vczjk/x39;

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/ic1;->OooOOO:Llyiahf/vczjk/le3;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v7, :cond_2

    if-ne v8, v4, :cond_3

    :cond_2
    new-instance v8, Llyiahf/vczjk/a5;

    const/16 v4, 0x1a

    invoke-direct {v8, v4, v5}, Llyiahf/vczjk/a5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v4, 0x46

    invoke-static {v1, v6, v8, v2, v4}, Llyiahf/vczjk/tg0;->OooOOOO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/x39;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    return-object v3

    :pswitch_0
    move-object/from16 v11, p1

    check-cast v11, Llyiahf/vczjk/bi6;

    move-object/from16 v12, p2

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v13, p3

    check-cast v13, Ljava/lang/Number;

    invoke-virtual {v13}, Ljava/lang/Number;->intValue()I

    move-result v13

    const-string v14, "paddingValues"

    invoke-static {v11, v14}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    and-int/lit8 v14, v13, 0x6

    if-nez v14, :cond_5

    move-object v14, v12

    check-cast v14, Llyiahf/vczjk/zf1;

    invoke-virtual {v14, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_4

    const/4 v14, 0x4

    goto :goto_2

    :cond_4
    move v14, v10

    :goto_2
    or-int/2addr v13, v14

    :cond_5
    and-int/2addr v13, v2

    if-ne v13, v1, :cond_7

    move-object v13, v12

    check-cast v13, Llyiahf/vczjk/zf1;

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v14

    if-nez v14, :cond_6

    goto :goto_3

    :cond_6
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v16, v3

    goto/16 :goto_5

    :cond_7
    :goto_3
    sget-object v13, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v14, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    move-object v15, v12

    check-cast v15, Llyiahf/vczjk/zf1;

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v14

    check-cast v14, Llyiahf/vczjk/x21;

    move-object/from16 v16, v3

    iget-wide v2, v14, Llyiahf/vczjk/x21;->OooOOO:J

    sget-object v14, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v13, v2, v3, v14}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v12}, Llyiahf/vczjk/mt6;->OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;

    move-result-object v3

    invoke-static {v2, v3, v8}, Llyiahf/vczjk/mt6;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2, v11}, Llyiahf/vczjk/uoa;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

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

    sget-object v3, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v13, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v3, v13, v12, v9}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v3

    iget v13, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v12, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v18, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move/from16 v18, v8

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v1, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v1, :cond_8

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_8
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v3, v12, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v14, v12, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_9

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v3, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_a

    :cond_9
    invoke-static {v13, v15, v13, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v12, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v1, Llyiahf/vczjk/im4;->OooO0OO:I

    invoke-static {v1, v12}, Llyiahf/vczjk/so8;->OooOo0(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v1

    invoke-interface {v11}, Llyiahf/vczjk/bi6;->OooO0OO()F

    move-result v2

    invoke-static {v7, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v12, v2}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v2, -0x2757abdd

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ni8;

    const v3, -0x486d30f7

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance v3, Llyiahf/vczjk/q17;

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_dev_tools:I

    invoke-static {v8, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    invoke-direct {v3, v8}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v8, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_save_fill:I

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->feedback_export_log:I

    invoke-static {v13, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v21

    new-instance v20, Llyiahf/vczjk/x17;

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v23

    const/16 v24, 0x0

    const/16 v26, 0xb6

    const/16 v22, 0x0

    iget-object v8, v0, Llyiahf/vczjk/ic1;->OooOOO:Llyiahf/vczjk/le3;

    move-object/from16 v25, v8

    invoke-direct/range {v20 .. v26}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    new-array v8, v10, [Llyiahf/vczjk/y17;

    aput-object v3, v8, v9

    aput-object v20, v8, v18

    invoke-static {v8}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-interface {v6}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ni8;

    const v3, 0x1fcb71dd

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v3, Llyiahf/vczjk/n35;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/app/Activity;

    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/content/Context;

    new-instance v6, Llyiahf/vczjk/q17;

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_about:I

    invoke-static {v8, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v8

    invoke-direct {v6, v8}, Llyiahf/vczjk/q17;-><init>(Ljava/lang/String;)V

    sget v8, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_information_fill:I

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->pre_category_app_feature_info:I

    invoke-static {v13, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v21

    const v13, 0x332f00

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    const-string v14, "Wed Oct 01 16:05:37 CST 2025"

    move/from16 v27, v10

    const-string v10, "Built on: Mac OS X"

    const-string v9, "8.6"

    const-string v5, "thanox@tornaco:f919506c-e8fd-4a35-b88e-e193d2725db5"

    filled-new-array {v9, v13, v5, v14, v10}, [Ljava/lang/Object;

    move-result-object v5

    invoke-static {v5}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v28

    const/16 v31, 0x0

    const/16 v33, 0x3f

    const/16 v29, 0x0

    const/16 v30, 0x0

    const/16 v32, 0x0

    invoke-static/range {v28 .. v33}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v22

    new-instance v20, Llyiahf/vczjk/x17;

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v23

    const/16 v24, 0x0

    const/16 v26, 0xf4

    const/16 v25, 0x0

    invoke-direct/range {v20 .. v26}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    sget v5, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_group_fill:I

    sget v8, Lgithub/tornaco/android/thanos/res/R$string;->pref_title_rss_e:I

    invoke-static {v8, v15}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v29

    sget v8, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_qq_fill:I

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v33

    const v8, 0x4c5de2

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v8, :cond_b

    if-ne v9, v4, :cond_c

    :cond_b
    new-instance v9, Llyiahf/vczjk/kt;

    const/16 v8, 0x12

    invoke-direct {v9, v3, v8}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    move-object/from16 v35, v9

    check-cast v35, Llyiahf/vczjk/le3;

    const/4 v8, 0x0

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v30, Llyiahf/vczjk/x17;

    const/16 v32, 0x0

    const/16 v34, 0x0

    const-string v31, "QQ"

    const/16 v36, 0xb6

    invoke-direct/range {v30 .. v36}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v8, v30

    sget v9, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_telegram_fill:I

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v33

    const v9, 0x4c5de2

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v9, :cond_d

    if-ne v10, v4, :cond_e

    :cond_d
    new-instance v10, Llyiahf/vczjk/kt;

    const/16 v9, 0x13

    invoke-direct {v10, v3, v9}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    move-object/from16 v35, v10

    check-cast v35, Llyiahf/vczjk/le3;

    const/4 v9, 0x0

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v30, Llyiahf/vczjk/x17;

    const/16 v32, 0x0

    const/16 v34, 0x0

    const-string v31, "Telegram"

    const/16 v36, 0xb6

    invoke-direct/range {v30 .. v36}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v9, v30

    sget v10, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_mail_fill:I

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v33

    const v10, 0x4c5de2

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v10, :cond_f

    if-ne v13, v4, :cond_10

    :cond_f
    new-instance v13, Llyiahf/vczjk/kt;

    const/16 v10, 0x14

    invoke-direct {v13, v3, v10}, Llyiahf/vczjk/kt;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v15, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    move-object/from16 v35, v13

    check-cast v35, Llyiahf/vczjk/le3;

    const/4 v3, 0x0

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v30, Llyiahf/vczjk/x17;

    const/16 v32, 0x0

    const/16 v34, 0x0

    const-string v31, "Email"

    const/16 v36, 0xb6

    invoke-direct/range {v30 .. v36}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v3, v30

    sget v10, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_github_fill:I

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v33

    const v10, 0x6e3c21fe

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-ne v10, v4, :cond_11

    new-instance v10, Llyiahf/vczjk/oOOO0OO0;

    const/16 v4, 0x16

    invoke-direct {v10, v4}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    move-object/from16 v35, v10

    check-cast v35, Llyiahf/vczjk/le3;

    const/4 v4, 0x0

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v30, Llyiahf/vczjk/x17;

    const-string v32, "Tornaco/Thanox"

    const/16 v34, 0x0

    const-string v31, "Github"

    const/16 v36, 0xb4

    invoke-direct/range {v30 .. v36}, Llyiahf/vczjk/x17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Llyiahf/vczjk/le3;I)V

    move-object/from16 v4, v30

    filled-new-array {v8, v9, v3, v4}, [Llyiahf/vczjk/x17;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v33

    new-instance v28, Llyiahf/vczjk/r17;

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v31

    const/16 v32, 0x0

    const/16 v35, 0xd6

    const/16 v30, 0x0

    invoke-direct/range {v28 .. v35}, Llyiahf/vczjk/r17;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Integer;Ljava/lang/String;Ljava/util/List;Llyiahf/vczjk/le3;I)V

    const/4 v3, 0x3

    new-array v3, v3, [Llyiahf/vczjk/y17;

    const/4 v4, 0x0

    aput-object v6, v3, v4

    aput-object v20, v3, v18

    aput-object v28, v3, v27

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v12, v4}, Llyiahf/vczjk/wr6;->OooO0o0(Ljava/util/List;Llyiahf/vczjk/rf1;I)V

    invoke-static {v4, v12}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/cm4;

    invoke-static {v1, v12, v4}, Llyiahf/vczjk/dr6;->OooO0oO(Llyiahf/vczjk/cm4;Llyiahf/vczjk/rf1;I)V

    invoke-static {v4, v12}, Llyiahf/vczjk/ru6;->OooO00o(ILlyiahf/vczjk/rf1;)V

    invoke-static {v4, v12}, Llyiahf/vczjk/dr6;->OooO0OO(ILlyiahf/vczjk/rf1;)V

    invoke-interface {v11}, Llyiahf/vczjk/bi6;->OooO00o()F

    move-result v1

    invoke-static {v7, v1}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v12, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    move/from16 v1, v18

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_5
    return-object v16

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
