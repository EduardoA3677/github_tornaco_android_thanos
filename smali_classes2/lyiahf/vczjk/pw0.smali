.class public final Llyiahf/vczjk/pw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field public final synthetic OooOOO:Lnow/fortuitous/thanos/main/ChooserActivity;

.field public final synthetic OooOOO0:Landroid/content/Context;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lnow/fortuitous/thanos/main/ChooserActivity;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pw0;->OooOOO0:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/pw0;->OooOOO:Lnow/fortuitous/thanos/main/ChooserActivity;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 28

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/kj;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Boolean;

    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    move-object/from16 v3, p3

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    const-string v4, "$this$AnimatedContent"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x1

    const/4 v4, 0x0

    if-eqz v2, :cond_8

    move-object v9, v3

    check-cast v9, Llyiahf/vczjk/zf1;

    const v2, -0x68fa08f4

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v3, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    const/16 v5, 0x10

    int-to-float v5, v5

    invoke-static {v3, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v5, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v6, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    const/16 v7, 0x36

    invoke-static {v5, v6, v9, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v6, v9, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v9, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v10, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_0

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_0

    :cond_0
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_0
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v9, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v9, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v9, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_1

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_2

    :cond_1
    invoke-static {v6, v9, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_2
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v9, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->app_select_activate_method:I

    invoke-static {v2, v9}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    sget-object v2, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooO0o:Llyiahf/vczjk/rn9;

    new-instance v15, Llyiahf/vczjk/ch9;

    const/4 v3, 0x3

    invoke-direct {v15, v3}, Llyiahf/vczjk/ch9;-><init>(I)V

    const/16 v26, 0x0

    const v27, 0x1fbfc

    const-wide/16 v7, 0x0

    move-object/from16 v24, v9

    const-wide/16 v9, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const-wide/16 v16, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v25, 0x30

    move-object/from16 v23, v2

    invoke-static/range {v5 .. v27}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v9, v24

    const v2, -0x14ef561c

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move v2, v4

    :goto_1
    const/4 v3, 0x4

    if-ge v2, v3, :cond_3

    invoke-static {v4, v9}, Llyiahf/vczjk/ru6;->OooO00o(ILlyiahf/vczjk/rf1;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_3
    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->active_method_chooser_summary_shizuku:I

    invoke-static {v2, v9}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->common_badge_text_experiment:I

    invoke-static {v2, v9}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v7

    const v2, -0x615d173a

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v0, Llyiahf/vczjk/pw0;->OooOOO0:Landroid/content/Context;

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    iget-object v12, v0, Llyiahf/vczjk/pw0;->OooOOO:Lnow/fortuitous/thanos/main/ChooserActivity;

    invoke-virtual {v9, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v5, v8

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    sget-object v13, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v5, :cond_4

    if-ne v8, v13, :cond_5

    :cond_4
    new-instance v8, Llyiahf/vczjk/ow0;

    const/4 v5, 0x0

    invoke-direct {v8, v3, v12, v5}, Llyiahf/vczjk/ow0;-><init>(Landroid/content/Context;Lnow/fortuitous/thanos/main/ChooserActivity;I)V

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const-string v5, "Shizuku"

    const/4 v10, 0x6

    const/4 v11, 0x0

    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/dn8;->OooOo0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-static {v4, v9}, Llyiahf/vczjk/ru6;->OooO00o(ILlyiahf/vczjk/rf1;)V

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->active_method_chooser_summary_xposed_magisk:I

    invoke-static {v5, v9}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v9, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v2, v5

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v2, :cond_6

    if-ne v5, v13, :cond_7

    :cond_6
    new-instance v5, Llyiahf/vczjk/ow0;

    const/4 v2, 0x1

    invoke-direct {v5, v3, v12, v2}, Llyiahf/vczjk/ow0;-><init>(Landroid/content/Context;Lnow/fortuitous/thanos/main/ChooserActivity;I)V

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    move-object v8, v5

    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v10, 0x6

    const/4 v11, 0x4

    const-string v5, "Xposed"

    const/4 v7, 0x0

    invoke-static/range {v5 .. v11}, Llyiahf/vczjk/dn8;->OooOo0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v9, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_3

    :cond_8
    check-cast v3, Llyiahf/vczjk/zf1;

    const v2, -0x68d937b6

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    sget-object v5, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v5, v4}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v6, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v3, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_9

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_9
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_2
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v7, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_a

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_b

    :cond_a
    invoke-static {v6, v3, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v18, 0x0

    const/16 v19, 0x1f

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const-wide/16 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    move-object/from16 v17, v3

    invoke-static/range {v10 .. v19}, Llyiahf/vczjk/so8;->OooO0OO(Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/qj8;Ljava/util/List;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
