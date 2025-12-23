.class public final Llyiahf/vczjk/su;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $items:Ljava/util/List;

.field final synthetic $viewModel$inlined:Llyiahf/vczjk/dv;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/dv;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/su;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/su;->$viewModel$inlined:Llyiahf/vczjk/dv;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 34

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Landroidx/compose/foundation/lazy/OooO00o;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    move-object/from16 v3, p3

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v4, p4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->intValue()I

    move-result v4

    and-int/lit8 v5, v4, 0x6

    const/4 v6, 0x2

    if-nez v5, :cond_1

    move-object v5, v3

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x4

    goto :goto_0

    :cond_0
    move v1, v6

    :goto_0
    or-int/2addr v1, v4

    goto :goto_1

    :cond_1
    move v1, v4

    :goto_1
    const/16 v5, 0x30

    and-int/2addr v4, v5

    const/16 v7, 0x10

    if-nez v4, :cond_3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    move v4, v7

    :goto_2
    or-int/2addr v1, v4

    :cond_3
    and-int/lit16 v4, v1, 0x93

    const/4 v8, 0x1

    const/16 v9, 0x92

    const/4 v10, 0x0

    if-eq v4, v9, :cond_4

    move v4, v8

    goto :goto_3

    :cond_4
    move v4, v10

    :goto_3
    and-int/2addr v1, v8

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_14

    iget-object v1, v0, Llyiahf/vczjk/su;->$items:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/vt;

    const v2, 0x27b5e621

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v11, v1, Llyiahf/vczjk/vt;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v2, v1, Llyiahf/vczjk/vt;->OooO0O0:Lgithub/tornaco/android/thanos/core/ops/PermInfo;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/ops/PermInfo;->isRuntimePermission()Z

    move-result v12

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/ops/PermInfo;->getHasBackgroundPermission()Z

    move-result v13

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/ops/PermInfo;->isSupportOneTimeGrant()Z

    move-result v14

    const v4, 0x4c5de2

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v4, v0, Llyiahf/vczjk/su;->$viewModel$inlined:Llyiahf/vczjk/dv;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    sget-object v15, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v4, :cond_5

    if-ne v9, v15, :cond_6

    :cond_5
    new-instance v9, Llyiahf/vczjk/f5;

    iget-object v4, v0, Llyiahf/vczjk/su;->$viewModel$inlined:Llyiahf/vczjk/dv;

    const/4 v8, 0x2

    invoke-direct {v9, v4, v8}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v9, Llyiahf/vczjk/ze3;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v16, v3

    move-object v3, v15

    move-object v15, v9

    invoke-static/range {v11 .. v16}, Llyiahf/vczjk/l4a;->Oooo000(Lgithub/tornaco/android/thanos/core/pm/AppInfo;ZZZLlyiahf/vczjk/ze3;Llyiahf/vczjk/zf1;)Llyiahf/vczjk/yg5;

    move-result-object v4

    move-object/from16 v8, v16

    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v11, 0x3f800000    # 1.0f

    invoke-static {v9, v11}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v12

    const/16 v13, 0x44

    int-to-float v13, v13

    const/4 v14, 0x0

    invoke-static {v12, v13, v14, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v12

    const v13, -0x615d173a

    invoke-virtual {v8, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    or-int/2addr v13, v15

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    if-nez v13, :cond_7

    if-ne v15, v3, :cond_8

    :cond_7
    new-instance v15, Llyiahf/vczjk/o0O000;

    const/4 v3, 0x3

    const/4 v13, 0x0

    invoke-direct {v15, v3, v4, v1, v13}, Llyiahf/vczjk/o0O000;-><init>(ILjava/lang/Object;Ljava/lang/Object;Z)V

    invoke-virtual {v8, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v15, Llyiahf/vczjk/le3;

    invoke-virtual {v8, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v12, v15}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    int-to-float v4, v7

    invoke-static {v3, v4, v14, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v6, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    invoke-static {v6, v4, v8, v5}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v7

    iget v12, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v8, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v14, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_9

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_9
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v8, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_a

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v10, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_b

    :cond_a
    invoke-static {v12, v8, v12, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object v10, v2

    float-to-double v2, v11

    const-wide/16 v16, 0x0

    cmpl-double v2, v2, v16

    if-lez v2, :cond_c

    goto :goto_5

    :cond_c
    const-string v2, "invalid weight; must be greater than zero"

    invoke-static {v2}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_5
    new-instance v2, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v3, 0x1

    invoke-direct {v2, v11, v3}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    const/16 v3, 0x30

    invoke-static {v6, v4, v8, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v4, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v8, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_d

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_d
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v3, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v8, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_e

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v3, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_f

    :cond_e
    invoke-static {v4, v8, v4, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_f
    invoke-static {v2, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x2a

    int-to-float v2, v2

    invoke-static {v9, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v1, v1, Llyiahf/vczjk/vt;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v3, 0x6

    invoke-static {v2, v1, v8, v3}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/4 v2, 0x0

    invoke-static {v2, v8}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    sget-object v3, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v4, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v3, v4, v8, v2}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v3

    iget v2, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v8, v9}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_10

    invoke-virtual {v8, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_10
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v3, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v8, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_11

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_12

    :cond_11
    invoke-static {v2, v8, v2, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_12
    invoke-static {v6, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v11

    const-string v1, "getAppLabel(...)"

    invoke-static {v11, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooO:Llyiahf/vczjk/rn9;

    const/16 v32, 0x0

    const v33, 0x1fffe

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v31, 0x0

    move-object/from16 v29, v2

    move-object/from16 v30, v8

    invoke-static/range {v11 .. v33}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const v2, 0x53bfcf76

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/ops/PermInfo;->getOpAccessSummary()Ljava/lang/String;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_13

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/ops/PermInfo;->getOpAccessSummary()Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/n6a;

    iget-object v2, v2, Llyiahf/vczjk/n6a;->OooOO0o:Llyiahf/vczjk/rn9;

    const/16 v32, 0x0

    const v33, 0x1fffe

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v31, 0x0

    move-object/from16 v29, v2

    move-object/from16 v30, v8

    invoke-static/range {v11 .. v33}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :cond_13
    const/4 v2, 0x0

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v3, 0x1

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/ops/PermInfo;->getPermState()Lgithub/tornaco/android/thanos/core/ops/PermState;

    move-result-object v2

    invoke-static {v2, v8}, Llyiahf/vczjk/vr3;->OooO0O0(Lgithub/tornaco/android/thanos/core/ops/PermState;Llyiahf/vczjk/zf1;)Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v1, v1, Llyiahf/vczjk/n6a;->OooO:Llyiahf/vczjk/rn9;

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/ops/PermInfo;->getPermState()Lgithub/tornaco/android/thanos/core/ops/PermState;

    move-result-object v2

    invoke-static {v2, v8}, Llyiahf/vczjk/vr3;->OooO00o(Lgithub/tornaco/android/thanos/core/ops/PermState;Llyiahf/vczjk/zf1;)J

    move-result-wide v13

    const/16 v32, 0x0

    const v33, 0x1fffa

    const/4 v12, 0x0

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const-wide/16 v22, 0x0

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v27, 0x0

    const/16 v28, 0x0

    const/16 v31, 0x0

    move-object/from16 v29, v1

    move-object/from16 v30, v8

    invoke-static/range {v11 .. v33}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    const/4 v3, 0x1

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v2, 0x0

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_8

    :cond_14
    move-object v8, v3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_8
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
