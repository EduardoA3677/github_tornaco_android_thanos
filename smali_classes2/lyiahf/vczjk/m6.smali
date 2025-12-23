.class public final Llyiahf/vczjk/m6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/m6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/m6;->OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 28

    move-object/from16 v0, p0

    iget v1, v0, Llyiahf/vczjk/m6;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v3, 0x26

    int-to-float v3, v3

    invoke-static {v2, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/m6;->OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v4, 0x6

    invoke-static {v2, v3, v1, v4}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_0
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_3

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_4

    :cond_3
    :goto_2
    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v5, 0x30

    invoke-static {v4, v2, v1, v5}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/zf1;

    iget v5, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v1, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_4

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_5

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v6, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_6

    :cond_5
    invoke-static {v5, v4, v5, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x20

    int-to-float v2, v2

    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v3, 0x6

    iget-object v5, v0, Llyiahf/vczjk/m6;->OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v2, v5, v1, v3}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/4 v2, 0x0

    invoke-static {v2, v1}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v3

    const-string v5, "getAppLabel(...)"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v5, v1

    check-cast v5, Llyiahf/vczjk/zf1;

    const v6, -0x4021aeb5

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v6, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    move-object/from16 v20, v6

    check-cast v20, Llyiahf/vczjk/rn9;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v23, 0x0

    const v24, 0x1fffe

    move-object v2, v3

    const/4 v3, 0x0

    move-object v6, v4

    const-wide/16 v4, 0x0

    move-object v8, v6

    const-wide/16 v6, 0x0

    move-object v9, v8

    const/4 v8, 0x0

    move-object v10, v9

    const/4 v9, 0x0

    move-object v12, v10

    const-wide/16 v10, 0x0

    move-object v13, v12

    const/4 v12, 0x0

    move-object v15, v13

    const-wide/16 v13, 0x0

    move-object/from16 v16, v15

    const/4 v15, 0x0

    move-object/from16 v17, v16

    const/16 v16, 0x0

    move-object/from16 v18, v17

    const/16 v17, 0x0

    move-object/from16 v19, v18

    const/16 v18, 0x0

    move-object/from16 v21, v19

    const/16 v19, 0x0

    const/16 v22, 0x0

    move-object/from16 v27, v21

    move-object/from16 v21, v1

    move-object/from16 v1, v27

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :pswitch_1
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    check-cast v1, Llyiahf/vczjk/zf1;

    const v2, 0x36f2ee3a

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v2, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/content/Context;

    invoke-virtual {v2}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v2

    invoke-static {v2}, Lcom/bumptech/glide/Glide;->with(Landroid/content/Context;)Lcom/bumptech/glide/RequestManager;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ci3;

    invoke-virtual {v2}, Llyiahf/vczjk/ci3;->OooO0O0()Llyiahf/vczjk/ai3;

    move-result-object v2

    invoke-static {}, Lcom/bumptech/glide/load/resource/drawable/DrawableTransitionOptions;->withCrossFade()Lcom/bumptech/glide/load/resource/drawable/DrawableTransitionOptions;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ai3;->OooO(Lcom/bumptech/glide/TransitionOptions;)Llyiahf/vczjk/ai3;

    move-result-object v2

    const-string v3, "transition(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v3, v0, Llyiahf/vczjk/m6;->OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->disabled()Z

    move-result v3

    if-eqz v3, :cond_7

    sget-object v3, Llyiahf/vczjk/ye5;->OooO00o:Llyiahf/vczjk/uj3;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/ai3;->OooO0oo(Llyiahf/vczjk/uj3;)Llyiahf/vczjk/ai3;

    move-result-object v2

    const-string v3, "transform(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_7
    const/4 v3, 0x0

    invoke-virtual {v1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object v2

    :pswitch_2
    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v2, v2, 0x3

    const/4 v3, 0x2

    if-ne v2, v3, :cond_9

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/zf1;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_8

    goto :goto_5

    :cond_8
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_7

    :cond_9
    :goto_5
    sget-object v2, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v5, 0x30

    invoke-static {v4, v2, v1, v5}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/zf1;

    iget v5, v4, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v1, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_a

    invoke-virtual {v4, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_a
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v1, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v6, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v6, v4, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_b

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v6, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_c

    :cond_b
    invoke-static {v5, v4, v5, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x20

    int-to-float v2, v2

    invoke-static {v3, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v3, 0x6

    iget-object v5, v0, Llyiahf/vczjk/m6;->OooOOO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v2, v5, v1, v3}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/4 v2, 0x0

    invoke-static {v2, v1}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v3

    const-string v5, "getAppLabel(...)"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v5, v1

    check-cast v5, Llyiahf/vczjk/zf1;

    const v6, -0x4021aeb5

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v6, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    move-object/from16 v22, v6

    check-cast v22, Llyiahf/vczjk/rn9;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v25, 0x0

    const v26, 0x1fffe

    const/4 v5, 0x0

    const-wide/16 v6, 0x0

    const-wide/16 v8, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v24, 0x0

    move-object/from16 v23, v1

    move-object v1, v4

    move-object v4, v3

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v2, 0x1

    invoke-virtual {v1, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_7
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
