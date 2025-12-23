.class public final Llyiahf/vczjk/xt6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tr3;


# static fields
.field public static OooO00o:Llyiahf/vczjk/qv3;


# direct methods
.method public constructor <init>(Lcom/github/mikephil/charting/charts/PieRadarChartBase;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    return-void
.end method

.method public static final OooO(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move/from16 v2, p3

    const-string v3, "appInfo"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "onItemClick"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v3, p2

    check-cast v3, Llyiahf/vczjk/zf1;

    const v4, 0x69dd3050

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    const/4 v5, 0x2

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    move v4, v5

    :goto_0
    or-int/2addr v4, v2

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    const/16 v7, 0x10

    const/16 v8, 0x20

    if-eqz v6, :cond_1

    move v6, v8

    goto :goto_1

    :cond_1
    move v6, v7

    :goto_1
    or-int/2addr v4, v6

    and-int/lit8 v6, v4, 0x13

    const/16 v9, 0x12

    if-ne v6, v9, :cond_3

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_8

    :cond_3
    :goto_2
    sget-object v6, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v9, -0x615d173a

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v9, v4, 0x70

    const/4 v10, 0x0

    if-ne v9, v8, :cond_4

    const/4 v8, 0x1

    goto :goto_3

    :cond_4
    move v8, v10

    :goto_3
    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v8, :cond_5

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v8, :cond_6

    :cond_5
    new-instance v9, Llyiahf/vczjk/l57;

    const/4 v8, 0x0

    invoke-direct {v9, v1, v0, v8}, Llyiahf/vczjk/l57;-><init>(Llyiahf/vczjk/oe3;Lgithub/tornaco/android/thanos/core/pm/AppInfo;I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v8, 0x7

    const/4 v12, 0x0

    invoke-static {v6, v10, v12, v9, v8}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v9, v10}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v9

    iget v12, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v3, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v14, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_7

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_7
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v11, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v11, :cond_8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v11, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_9

    :cond_8
    invoke-static {v12, v3, v12, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v8, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v8, 0x3f800000    # 1.0f

    invoke-static {v6, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    int-to-float v7, v7

    const/4 v11, 0x0

    invoke-static {v8, v7, v11, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v7

    const/16 v8, 0x40

    int-to-float v8, v8

    invoke-static {v7, v8, v11, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v7, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v8, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v12, 0x36

    invoke-static {v7, v8, v3, v12}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v7

    iget v11, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v3, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v16, v4

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_a

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_a
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    invoke-static {v7, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_b

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_c

    :cond_b
    invoke-static {v11, v3, v11, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    invoke-static {v5, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v5, 0x36

    invoke-static {v4, v8, v3, v5}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    iget v5, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_d

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_d
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v4, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v7, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_e

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_f

    :cond_e
    invoke-static {v5, v3, v5, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_f
    invoke-static {v8, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v4, 0x26

    int-to-float v4, v4

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    shl-int/lit8 v5, v16, 0x3

    and-int/lit8 v5, v5, 0x70

    const/4 v7, 0x6

    or-int/2addr v5, v7

    invoke-static {v4, v0, v3, v5}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/16 v4, 0xc

    int-to-float v4, v4

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v4, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v5, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v4, v5, v3, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v4

    iget v5, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v3, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_10

    invoke-virtual {v3, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_10
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v4, v3, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v8, v3, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_11

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_12

    :cond_11
    invoke-static {v5, v3, v5, v13}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_12
    invoke-static {v11, v3, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v4, 0xdc

    int-to-float v4, v4

    const/16 v5, 0xb

    const/4 v8, 0x0

    invoke-static {v6, v8, v8, v4, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOO(Llyiahf/vczjk/kl5;FFFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v5

    const-string v6, "getAppLabel(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v6, 0x0

    invoke-static {v7, v6, v5, v3, v4}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/4 v4, 0x1

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v3

    if-eqz v3, :cond_13

    new-instance v4, Llyiahf/vczjk/n57;

    const/4 v5, 0x0

    invoke-direct {v4, v0, v1, v2, v5}, Llyiahf/vczjk/n57;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/oe3;II)V

    iput-object v4, v3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_13
    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/td0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 7

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/zf1;

    const p2, -0x49a00548

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    const/4 p2, 0x2

    :goto_0
    or-int/2addr p2, p3

    invoke-virtual {v4, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/16 v0, 0x20

    goto :goto_1

    :cond_1
    const/16 v0, 0x10

    :goto_1
    or-int/2addr p2, v0

    and-int/lit8 v0, p2, 0x13

    const/16 v1, 0x12

    if-ne v0, v1, :cond_3

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v2, p1

    goto :goto_3

    :cond_3
    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/td0;->OooO0o0:Llyiahf/vczjk/nw;

    shl-int/lit8 p2, p2, 0x3

    and-int/lit16 v5, p2, 0x380

    iget-object v1, p0, Llyiahf/vczjk/td0;->OooO0Oo:Ljava/util/List;

    const/4 v3, 0x0

    const/16 v6, 0x8

    move-object v2, p1

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/tg0;->OooOO0O(Llyiahf/vczjk/w03;Ljava/util/List;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_4

    new-instance p2, Llyiahf/vczjk/ai8;

    const/4 v0, 0x6

    invoke-direct {p2, p0, v2, p3, v0}, Llyiahf/vczjk/ai8;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object p2, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 7

    move-object v4, p2

    check-cast v4, Llyiahf/vczjk/zf1;

    const p2, 0x2ab947f8

    invoke-virtual {v4, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    const/4 p2, 0x2

    :goto_0
    or-int/2addr p2, p3

    invoke-virtual {v4, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    const/16 v0, 0x20

    goto :goto_1

    :cond_1
    const/16 v0, 0x10

    :goto_1
    or-int/2addr p2, v0

    and-int/lit8 v0, p2, 0x13

    const/16 v1, 0x12

    if-ne v0, v1, :cond_3

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v2, p1

    goto :goto_3

    :cond_3
    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/t67;->OooO0O0:Llyiahf/vczjk/nw;

    shl-int/lit8 p2, p2, 0x3

    and-int/lit16 v5, p2, 0x380

    iget-object v1, p0, Llyiahf/vczjk/t67;->OooO0o:Ljava/util/List;

    const/4 v3, 0x0

    const/16 v6, 0x8

    move-object v2, p1

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/tg0;->OooOO0O(Llyiahf/vczjk/w03;Ljava/util/List;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;II)V

    :goto_3
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_4

    new-instance p2, Llyiahf/vczjk/e2;

    const/16 v0, 0x19

    invoke-direct {p2, p0, v2, p3, v0}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object p2, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/uh6;ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 28

    move-object/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v11, p3

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, -0x322f4f10

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v4, 0x2

    const/4 v5, 0x4

    if-eqz v0, :cond_0

    move v0, v5

    goto :goto_0

    :cond_0
    move v0, v4

    :goto_0
    or-int v0, p4, v0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v6

    const/16 v7, 0x10

    if-eqz v6, :cond_1

    const/16 v6, 0x20

    goto :goto_1

    :cond_1
    move v6, v7

    :goto_1
    or-int/2addr v0, v6

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    const/16 v6, 0x100

    goto :goto_2

    :cond_2
    const/16 v6, 0x80

    :goto_2
    or-int/2addr v0, v6

    and-int/lit16 v0, v0, 0x93

    const/16 v6, 0x92

    if-ne v0, v6, :cond_4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_d

    :cond_4
    :goto_3
    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v6, 0x3f800000    # 1.0f

    invoke-static {v0, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    int-to-float v9, v7

    int-to-float v5, v5

    invoke-static {v8, v9, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/16 v8, 0x48

    int-to-float v8, v8

    const/4 v9, 0x0

    invoke-static {v5, v8, v9, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v8, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v9, 0x36

    invoke-static {v5, v8, v11, v9}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    iget v10, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v11, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v13, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v13}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_5

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_5
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v11, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v12, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v15, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v15, :cond_6

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    move/from16 p3, v7

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v15, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_7

    goto :goto_5

    :cond_6
    move/from16 p3, v7

    :goto_5
    invoke-static {v10, v11, v10, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    float-to-double v9, v6

    const-wide/16 v15, 0x0

    cmpl-double v9, v9, v15

    if-lez v9, :cond_8

    goto :goto_6

    :cond_8
    const-string v9, "invalid weight; must be greater than zero"

    invoke-static {v9}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_6
    new-instance v15, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v9, 0x0

    invoke-direct {v15, v6, v9}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    const/16 v6, 0xc

    int-to-float v6, v6

    const/16 v17, 0x0

    const/16 v19, 0x0

    const/16 v16, 0x0

    const/16 v20, 0xb

    move/from16 v18, v6

    invoke-static/range {v15 .. v20}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v6

    move/from16 v10, v18

    sget-object v15, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v4, 0x36

    invoke-static {v15, v8, v11, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    iget v8, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v11, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_9

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_9
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v4, v11, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v9, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_a

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_b

    :cond_a
    invoke-static {v8, v11, v8, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    invoke-static {v6, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x26

    int-to-float v2, v2

    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v4, v1, Llyiahf/vczjk/uh6;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v6, 0x6

    invoke-static {v2, v4, v11, v6}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    invoke-static {v0, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v11, v2}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v2, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v4, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v2, v4, v11, v6}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v2

    iget v4, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v11, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_c

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_c
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    invoke-static {v2, v11, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_d

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v2, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_e

    :cond_d
    invoke-static {v4, v11, v4, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v8, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    const/4 v4, 0x0

    invoke-static {v15, v2, v11, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v6, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v11, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_f

    invoke-virtual {v11, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_f
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    invoke-static {v2, v11, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v8, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_10

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v2, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_11

    :cond_10
    invoke-static {v6, v11, v6, v12}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_11
    invoke-static {v0, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/s4;->OooO00o:Llyiahf/vczjk/go3;

    new-instance v5, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    invoke-direct {v5, v0}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Llyiahf/vczjk/go3;)V

    iget-object v2, v1, Llyiahf/vczjk/uh6;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move/from16 v16, v4

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v4

    const-string v6, "getAppLabel(...)"

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static/range {p3 .. p3}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v8

    const/16 v22, 0x0

    const/16 v24, 0x6000

    const-wide/16 v6, 0x0

    const/4 v10, 0x0

    move-object/from16 v23, v11

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    move/from16 v17, v16

    const-wide/16 v15, 0x0

    move/from16 v18, v17

    const/16 v17, 0x0

    move/from16 v19, v18

    const/16 v18, 0x0

    move/from16 v20, v19

    const/16 v19, 0x0

    move/from16 v21, v20

    const/16 v20, 0x0

    move/from16 v25, v21

    const/16 v21, 0x0

    move/from16 v26, v25

    const/16 v25, 0x0

    move/from16 v27, v26

    const v26, 0x3ffec

    move-object/from16 p3, v2

    move/from16 v2, v27

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v23

    const v4, 0x6909128e

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual/range {p3 .. p3}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->isCurrentUser()Z

    move-result v4

    if-nez v4, :cond_12

    invoke-static {v2, v11}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    new-instance v5, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    invoke-direct {v5, v0}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Llyiahf/vczjk/go3;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_common_user:I

    invoke-virtual/range {p3 .. p3}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v0, v4, v11}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v4

    const/16 v0, 0xa

    invoke-static {v0}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v8

    const/16 v22, 0x0

    const/16 v24, 0x6000

    const-wide/16 v6, 0x0

    const/4 v10, 0x0

    move-object/from16 v23, v11

    const/4 v11, 0x0

    const-wide/16 v12, 0x0

    const/4 v14, 0x0

    const-wide/16 v15, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    const/16 v25, 0x0

    const v26, 0x3ffec

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v23

    :cond_12
    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v0, 0x1

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v11}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->wakelock_count:I

    iget-object v5, v1, Llyiahf/vczjk/uh6;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    move-result v6

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    filled-new-array {v6}, [Ljava/lang/Object;

    move-result-object v6

    invoke-static {v4, v6, v11}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v4

    const/16 v6, 0xe

    invoke-static {v6}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v8

    const/16 v22, 0x0

    const/16 v24, 0x6000

    move-object v6, v5

    const/4 v5, 0x0

    move-object v10, v6

    const-wide/16 v6, 0x0

    move-object v12, v10

    const/4 v10, 0x0

    move-object/from16 v23, v11

    const/4 v11, 0x0

    move-object v14, v12

    const-wide/16 v12, 0x0

    move-object v15, v14

    const/4 v14, 0x0

    move-object/from16 v17, v15

    const-wide/16 v15, 0x0

    move-object/from16 v18, v17

    const/16 v17, 0x0

    move-object/from16 v19, v18

    const/16 v18, 0x0

    move-object/from16 v20, v19

    const/16 v19, 0x0

    move-object/from16 v21, v20

    const/16 v20, 0x0

    move-object/from16 v25, v21

    const/16 v21, 0x0

    move-object/from16 v26, v25

    const/16 v25, 0x0

    move-object/from16 v27, v26

    const v26, 0x3ffee

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v23

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    if-eqz p1, :cond_13

    sget-object v4, Llyiahf/vczjk/st;->OooO00o:Llyiahf/vczjk/st;

    goto :goto_c

    :cond_13
    if-nez p1, :cond_19

    invoke-virtual/range {v27 .. v27}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_14

    goto :goto_b

    :cond_14
    invoke-virtual/range {v27 .. v27}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_15
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_19

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/dla;

    iget-boolean v5, v5, Llyiahf/vczjk/dla;->OooO0o:Z

    if-eqz v5, :cond_15

    new-instance v4, Llyiahf/vczjk/tt;

    invoke-virtual/range {v27 .. v27}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_17

    :cond_16
    move v9, v0

    goto :goto_a

    :cond_17
    invoke-virtual/range {v27 .. v27}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_18
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_16

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/dla;

    iget-boolean v6, v6, Llyiahf/vczjk/dla;->OooO0o:Z

    if-nez v6, :cond_18

    move v9, v2

    :goto_a
    invoke-direct {v4, v9}, Llyiahf/vczjk/tt;-><init>(Z)V

    goto :goto_c

    :cond_19
    :goto_b
    sget-object v4, Llyiahf/vczjk/st;->OooO0O0:Llyiahf/vczjk/st;

    :goto_c
    const v5, 0x6e3c21fe

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v6, :cond_1a

    new-instance v5, Llyiahf/vczjk/by9;

    const/16 v6, 0x8

    invoke-direct {v5, v6}, Llyiahf/vczjk/by9;-><init>(I)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1a
    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v2, Llyiahf/vczjk/u71;

    const/4 v5, 0x1

    invoke-direct {v2, v5, v3, v1}, Llyiahf/vczjk/u71;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v5, -0x54896627

    invoke-static {v5, v2, v11}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v10

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v5, 0x0

    const/4 v7, 0x0

    const v12, 0x180180

    const/16 v13, 0x3a

    invoke-static/range {v4 .. v13}, Landroidx/compose/animation/OooO00o;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o4;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_d
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_1b

    new-instance v0, Llyiahf/vczjk/xv6;

    const/4 v5, 0x1

    move/from16 v2, p1

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/xv6;-><init>(Ljava/lang/Object;ZLlyiahf/vczjk/cf3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1b
    return-void
.end method

.method public static final OooO0Oo(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V
    .locals 25

    move-object/from16 v0, p0

    move/from16 v1, p2

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, 0xfb2ce82

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x2

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v3, v1

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_2
    move-object/from16 v21, v2

    goto :goto_2

    :cond_3
    :goto_1
    iget-object v3, v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOo:Ljava/lang/Long;

    if-eqz v3, :cond_2

    invoke-virtual {v3}, Ljava/lang/Long;->longValue()J

    move-result-wide v3

    const-wide/16 v5, 0x3e8

    div-long/2addr v3, v5

    const/4 v5, 0x0

    invoke-static {v5, v3, v4}, Landroid/text/format/DateUtils;->formatElapsedTime(Ljava/lang/StringBuilder;J)Ljava/lang/String;

    move-result-object v3

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->service_running_time:I

    invoke-static {v4, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v4

    const-string v5, " "

    invoke-static {v4, v5, v3}, Llyiahf/vczjk/ix8;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/n6a;

    iget-object v4, v4, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v19, 0x0

    const/16 v22, 0x0

    move-object/from16 v21, v2

    move-object v2, v3

    const/4 v3, 0x0

    move-object/from16 v20, v4

    const-wide/16 v4, 0x0

    const-wide/16 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x0

    const-wide/16 v13, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v23, 0x0

    const v24, 0x1fffe

    invoke-static/range {v2 .. v24}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_2
    invoke-virtual/range {v21 .. v21}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_4

    new-instance v3, Llyiahf/vczjk/o57;

    const/4 v4, 0x3

    invoke-direct {v3, v0, v1, v4}, Llyiahf/vczjk/o57;-><init>(Lnow/fortuitous/thanos/process/v2/RunningAppState;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4
    return-void
.end method

.method public static final OooO0o(ZLlyiahf/vczjk/rf1;I)V
    .locals 8

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zf1;

    const p1, 0x48d9f449

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 p1, p2, 0x6

    const/4 v0, 0x2

    if-nez p1, :cond_1

    invoke-virtual {v5, p0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x4

    goto :goto_0

    :cond_0
    move p1, v0

    :goto_0
    or-int/2addr p1, p2

    goto :goto_1

    :cond_1
    move p1, p2

    :goto_1
    and-int/lit8 p1, p1, 0x3

    if-ne p1, v0, :cond_3

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result p1

    if-nez p1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_4

    :cond_3
    :goto_2
    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v0, 0x20

    int-to-float v0, v0

    invoke-static {p1, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    if-eqz p0, :cond_4

    sget p1, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_arrow_drop_down_fill:I

    goto :goto_3

    :cond_4
    sget p1, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_arrow_drop_up_fill:I

    :goto_3
    invoke-static {p1, v5}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v0

    const-string v1, ""

    const-wide/16 v3, 0x0

    const/16 v6, 0x1b0

    const/16 v7, 0x8

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_4
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_5

    new-instance v0, Llyiahf/vczjk/p57;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/p57;-><init>(ZI)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooO0o0(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 28

    move/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    const-string v0, "setExpand"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v0, p3

    check-cast v0, Llyiahf/vczjk/zf1;

    const v4, -0x214e4f32

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int v4, p4, v4

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    const/16 v6, 0x20

    if-eqz v5, :cond_1

    move v5, v6

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v4, v5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v7, 0x100

    if-eqz v5, :cond_2

    move v5, v7

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v4, v5

    and-int/lit16 v5, v4, 0x93

    const/16 v8, 0x92

    if-ne v5, v8, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v0

    goto/16 :goto_8

    :cond_4
    :goto_3
    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v8, 0x3f800000    # 1.0f

    invoke-static {v5, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/el8;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v9, v10}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/nq9;->OooO0OO:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/ap9;

    iget-wide v10, v10, Llyiahf/vczjk/ap9;->OooO00o:J

    sget-object v12, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v9, v10, v11, v12}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v9

    const v10, -0x615d173a

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v10, v4, 0x380

    const/4 v11, 0x0

    const/4 v12, 0x1

    if-ne v10, v7, :cond_5

    move v7, v12

    goto :goto_4

    :cond_5
    move v7, v11

    :goto_4
    and-int/lit8 v10, v4, 0x70

    if-ne v10, v6, :cond_6

    move v6, v12

    goto :goto_5

    :cond_6
    move v6, v11

    :goto_5
    or-int/2addr v6, v7

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_7

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v6, :cond_8

    :cond_7
    new-instance v7, Llyiahf/vczjk/ev0;

    const/4 v6, 0x3

    invoke-direct {v7, v3, v2, v6}, Llyiahf/vczjk/ev0;-><init>(Llyiahf/vczjk/oe3;ZI)V

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v6, 0x7

    const/4 v10, 0x0

    invoke-static {v9, v11, v10, v7, v6}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v6

    const/16 v7, 0x14

    int-to-float v7, v7

    const/16 v9, 0xc

    int-to-float v9, v9

    invoke-static {v6, v7, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-static {v7, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v9, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v0, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_9

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_9
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v0, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v14, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v14, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-static {v14, v15}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-nez v14, :cond_b

    :cond_a
    invoke-static {v9, v0, v9, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v5, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v8, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v14, 0x36

    invoke-static {v6, v8, v0, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v6

    iget v8, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v0, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_c

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v6, v0, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v6, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_d

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_e

    :cond_d
    invoke-static {v8, v0, v8, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v5, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->running_process_background:I

    invoke-static {v5, v0}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, " - "

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/n6a;

    iget-object v6, v6, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v21, 0x0

    const/16 v24, 0x0

    move v7, v4

    move-object v4, v5

    const/4 v5, 0x0

    move-object/from16 v22, v6

    move v8, v7

    const-wide/16 v6, 0x0

    move v10, v8

    const-wide/16 v8, 0x0

    move v11, v10

    const/4 v10, 0x0

    move v13, v11

    const/4 v11, 0x0

    move v15, v12

    move v14, v13

    const-wide/16 v12, 0x0

    move/from16 v16, v14

    const/4 v14, 0x0

    move/from16 v18, v15

    move/from16 v17, v16

    const-wide/16 v15, 0x0

    move/from16 v19, v17

    const/16 v17, 0x0

    move/from16 v20, v18

    const/16 v18, 0x0

    move/from16 v23, v19

    const/16 v19, 0x0

    move/from16 v25, v20

    const/16 v20, 0x0

    move/from16 v26, v25

    const/16 v25, 0x0

    move/from16 v27, v26

    const v26, 0x1fffe

    move/from16 p3, v23

    move-object/from16 v23, v0

    move/from16 v0, v27

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v4, v23

    shr-int/lit8 v5, p3, 0x3

    and-int/lit8 v5, v5, 0xe

    invoke-static {v2, v4, v5}, Llyiahf/vczjk/xt6;->OooO0o(ZLlyiahf/vczjk/rf1;I)V

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_f

    new-instance v0, Llyiahf/vczjk/j57;

    const/4 v5, 0x1

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/j57;-><init>(IZLlyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooO0oO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V
    .locals 4

    const-string v0, "appState"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, -0x725f61fc

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, p2

    and-int/lit8 v0, v0, 0x3

    if-ne v0, v1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_2
    :goto_1
    const/4 v0, 0x0

    iget-object v2, p0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOo0:Ljava/lang/String;

    const/4 v3, 0x0

    invoke-static {v0, v1, v2, p1, v3}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_3

    new-instance v0, Llyiahf/vczjk/o57;

    const/4 v1, 0x1

    invoke-direct {v0, p0, p2, v1}, Llyiahf/vczjk/o57;-><init>(Lnow/fortuitous/thanos/process/v2/RunningAppState;II)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/rz5;Llyiahf/vczjk/rf1;I)V
    .locals 4

    const-string v0, "netSpeed"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, 0xdb52ac

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, p2

    and-int/lit8 v0, v0, 0x3

    if-ne v0, v1, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_2

    :cond_2
    :goto_1
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "\u2191 "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Llyiahf/vczjk/rz5;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "/s \u2193 "

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v2, p0, Llyiahf/vczjk/rz5;->OooO0O0:Ljava/lang/String;

    const-string v3, "/s"

    invoke-static {v0, v2, v3}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-static {v3, v1, v0, p1, v2}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_3

    new-instance v0, Llyiahf/vczjk/sj5;

    const/16 v1, 0xf

    invoke-direct {v0, p2, v1, p0}, Llyiahf/vczjk/sj5;-><init>(IILjava/lang/Object;)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooOO0(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 28

    move/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    const-string v0, "setExpand"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v0, p3

    check-cast v0, Llyiahf/vczjk/zf1;

    const v4, -0x24c4f5bc

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int v4, p4, v4

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    const/16 v6, 0x20

    if-eqz v5, :cond_1

    move v5, v6

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v4, v5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v7, 0x100

    if-eqz v5, :cond_2

    move v5, v7

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v4, v5

    and-int/lit16 v5, v4, 0x93

    const/16 v8, 0x92

    if-ne v5, v8, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v0

    goto/16 :goto_8

    :cond_4
    :goto_3
    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v8, 0x3f800000    # 1.0f

    invoke-static {v5, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/el8;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v9, v10}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/nq9;->OooO0OO:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/ap9;

    iget-wide v10, v10, Llyiahf/vczjk/ap9;->OooO00o:J

    sget-object v12, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v9, v10, v11, v12}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v9

    const v10, -0x615d173a

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v10, v4, 0x380

    const/4 v11, 0x0

    const/4 v12, 0x1

    if-ne v10, v7, :cond_5

    move v7, v12

    goto :goto_4

    :cond_5
    move v7, v11

    :goto_4
    and-int/lit8 v10, v4, 0x70

    if-ne v10, v6, :cond_6

    move v6, v12

    goto :goto_5

    :cond_6
    move v6, v11

    :goto_5
    or-int/2addr v6, v7

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_7

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v6, :cond_8

    :cond_7
    new-instance v7, Llyiahf/vczjk/ev0;

    const/4 v6, 0x4

    invoke-direct {v7, v3, v2, v6}, Llyiahf/vczjk/ev0;-><init>(Llyiahf/vczjk/oe3;ZI)V

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v6, 0x7

    const/4 v10, 0x0

    invoke-static {v9, v11, v10, v7, v6}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v6

    const/16 v7, 0x14

    int-to-float v7, v7

    const/16 v9, 0xc

    int-to-float v9, v9

    invoke-static {v6, v7, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-static {v7, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v9, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v0, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_9

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_9
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v0, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v14, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v14, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-static {v14, v15}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-nez v14, :cond_b

    :cond_a
    invoke-static {v9, v0, v9, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v5, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v8, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v14, 0x36

    invoke-static {v6, v8, v0, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v6

    iget v8, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v0, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_c

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v6, v0, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v6, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_d

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_e

    :cond_d
    invoke-static {v8, v0, v8, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v5, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->running_process_not_running:I

    invoke-static {v5, v0}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, " - "

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/n6a;

    iget-object v6, v6, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v21, 0x0

    const/16 v24, 0x0

    move v7, v4

    move-object v4, v5

    const/4 v5, 0x0

    move-object/from16 v22, v6

    move v8, v7

    const-wide/16 v6, 0x0

    move v10, v8

    const-wide/16 v8, 0x0

    move v11, v10

    const/4 v10, 0x0

    move v13, v11

    const/4 v11, 0x0

    move v15, v12

    move v14, v13

    const-wide/16 v12, 0x0

    move/from16 v16, v14

    const/4 v14, 0x0

    move/from16 v18, v15

    move/from16 v17, v16

    const-wide/16 v15, 0x0

    move/from16 v19, v17

    const/16 v17, 0x0

    move/from16 v20, v18

    const/16 v18, 0x0

    move/from16 v23, v19

    const/16 v19, 0x0

    move/from16 v25, v20

    const/16 v20, 0x0

    move/from16 v26, v25

    const/16 v25, 0x0

    move/from16 v27, v26

    const v26, 0x1fffe

    move/from16 p3, v23

    move-object/from16 v23, v0

    move/from16 v0, v27

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v4, v23

    shr-int/lit8 v5, p3, 0x3

    and-int/lit8 v5, v5, 0xe

    invoke-static {v2, v4, v5}, Llyiahf/vczjk/xt6;->OooO0o(ZLlyiahf/vczjk/rf1;I)V

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_f

    new-instance v0, Llyiahf/vczjk/j57;

    const/4 v5, 0x4

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/j57;-><init>(IZLlyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooOO0O(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V
    .locals 26

    move-object/from16 v0, p0

    move/from16 v1, p2

    const-string v2, "appState"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, 0x14a76427

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x2

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v3, v1

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v22, v2

    goto :goto_2

    :cond_2
    :goto_1
    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->running_processes_item_description_p_s:I

    iget-object v4, v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO:Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-virtual {v0}, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooO00o()I

    move-result v5

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    filled-new-array {v4, v5}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3, v4, v2}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    const/16 v4, 0xc

    invoke-static {v4}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v7

    const/16 v21, 0x0

    const/16 v23, 0x6000

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v24, 0x0

    const v25, 0x3ffee

    move-object/from16 v22, v2

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_2
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_3

    new-instance v3, Llyiahf/vczjk/o57;

    const/4 v4, 0x0

    invoke-direct {v3, v0, v1, v4}, Llyiahf/vczjk/o57;-><init>(Lnow/fortuitous/thanos/process/v2/RunningAppState;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooOO0o(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V
    .locals 26

    move-object/from16 v0, p0

    move/from16 v1, p2

    const-string v2, "appState"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, 0xed2af58

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v4, 0x2

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v3, v1

    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v22, v2

    goto :goto_2

    :cond_2
    :goto_1
    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->running_processes_item_description_p:I

    iget-object v4, v0, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO:Ljava/util/List;

    invoke-interface {v4}, Ljava/util/List;->size()I

    move-result v4

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3, v4, v2}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    const/16 v4, 0xc

    invoke-static {v4}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v7

    const/16 v21, 0x0

    const/16 v23, 0x6000

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v24, 0x0

    const v25, 0x3ffee

    move-object/from16 v22, v2

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    :goto_2
    invoke-virtual/range {v22 .. v22}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_3

    new-instance v3, Llyiahf/vczjk/o57;

    const/4 v4, 0x2

    invoke-direct {v3, v0, v1, v4}, Llyiahf/vczjk/o57;-><init>(Lnow/fortuitous/thanos/process/v2/RunningAppState;II)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_3
    return-void
.end method

.method public static final OooOOO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Ljava/lang/String;Llyiahf/vczjk/rz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 20

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    const-string v0, "appState"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onItemClick"

    invoke-static {v4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v10, p4

    check-cast v10, Llyiahf/vczjk/zf1;

    const v0, -0x63d90e63

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p5, v0

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    const/16 v7, 0x10

    if-eqz v6, :cond_1

    const/16 v6, 0x20

    goto :goto_1

    :cond_1
    move v6, v7

    :goto_1
    or-int/2addr v0, v6

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    const/16 v6, 0x100

    goto :goto_2

    :cond_2
    const/16 v6, 0x80

    :goto_2
    or-int/2addr v0, v6

    invoke-virtual {v10, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    const/16 v8, 0x800

    if-eqz v6, :cond_3

    move v6, v8

    goto :goto_3

    :cond_3
    const/16 v6, 0x400

    :goto_3
    or-int/2addr v0, v6

    and-int/lit16 v6, v0, 0x493

    const/16 v9, 0x492

    if-ne v6, v9, :cond_5

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v2

    move-object v15, v3

    goto/16 :goto_11

    :cond_5
    :goto_4
    sget-object v14, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const v6, -0x615d173a

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v6, v0, 0x1c00

    const/4 v15, 0x0

    if-ne v6, v8, :cond_6

    const/4 v6, 0x1

    goto :goto_5

    :cond_6
    move v6, v15

    :goto_5
    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v6, v8

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v6, :cond_7

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v8, v6, :cond_8

    :cond_7
    new-instance v8, Llyiahf/vczjk/oo0oO0;

    const/16 v6, 0x1c

    invoke-direct {v8, v6, v4, v1}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v10, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v10, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v6, 0x7

    const/4 v11, 0x0

    invoke-static {v14, v15, v11, v8, v6}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v8, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v8, v15}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v8

    iget v12, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v10, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_9

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_9
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v8, v10, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v10, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_a

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v13, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_b

    :cond_a
    invoke-static {v12, v10, v12, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v10, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/high16 v5, 0x3f800000    # 1.0f

    invoke-static {v14, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    int-to-float v6, v7

    const/4 v7, 0x4

    int-to-float v7, v7

    invoke-static {v5, v6, v7}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/16 v7, 0x48

    int-to-float v7, v7

    const/4 v12, 0x0

    move/from16 v17, v0

    const/4 v0, 0x2

    invoke-static {v5, v7, v12, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v0, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v7, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v12, 0x36

    invoke-static {v0, v7, v10, v12}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v12, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v10, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v3, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v3, :cond_c

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v0, v10, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v10, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_d

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_e

    :cond_d
    invoke-static {v12, v10, v12, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v5, v10, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v0, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v3, 0x36

    invoke-static {v0, v7, v10, v3}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v4

    iget v5, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v12

    invoke-static {v10, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v2, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_f

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_f
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    invoke-static {v4, v10, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12, v10, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_10

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_11

    :cond_10
    invoke-static {v5, v10, v5, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_11
    invoke-static {v3, v10, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x26

    int-to-float v2, v2

    invoke-static {v14, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v1, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v4, 0x6

    invoke-static {v2, v3, v10, v4}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/16 v2, 0xc

    int-to-float v2, v2

    invoke-static {v14, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v10, v2}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v2, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v5, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v2, v5, v10, v4}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v12, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    move-object/from16 v18, v3

    invoke-static {v10, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v19, v2

    iget-boolean v2, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_12

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_12
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    invoke-static {v5, v10, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v10, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_13

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_14

    :cond_13
    invoke-static {v12, v10, v12, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_14
    invoke-static {v3, v10, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x30

    invoke-static {v0, v7, v10, v2}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v0

    iget v2, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v10, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_15

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_a

    :cond_15
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_a
    invoke-static {v0, v10, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v3, v10, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_16

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_17

    :cond_16
    invoke-static {v2, v10, v2, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_17
    invoke-static {v4, v10, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v0, 0xf0

    int-to-float v0, v0

    const/16 v2, 0xb

    const/4 v3, 0x0

    invoke-static {v14, v3, v3, v0, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOOO(Llyiahf/vczjk/kl5;FFFI)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-virtual/range {v18 .. v18}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v2

    const-string v3, "getAppLabel(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v3, 0x0

    const/4 v4, 0x6

    invoke-static {v4, v3, v2, v10, v0}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v0, 0xebd8a6e

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v0, v1, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOoo:Z

    if-eqz v0, :cond_18

    invoke-static {v3, v10}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    invoke-static {v14, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget v0, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_netease_cloud_music_fill:I

    invoke-static {v0, v10}, Llyiahf/vczjk/er8;->OooOOo(ILlyiahf/vczjk/rf1;)Llyiahf/vczjk/un6;

    move-result-object v5

    move-object v0, v8

    move-object v2, v9

    sget-wide v8, Llyiahf/vczjk/n21;->OooO0oO:J

    const/4 v12, 0x0

    const-string v6, "Playing"

    move-object v3, v11

    const/16 v11, 0xdb0

    move-object v4, v0

    const/4 v0, 0x1

    invoke-static/range {v5 .. v12}, Llyiahf/vczjk/yt3;->OooO0O0(Llyiahf/vczjk/un6;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_b
    const/4 v5, 0x0

    goto :goto_c

    :cond_18
    move-object v4, v8

    move-object v2, v9

    move-object v3, v11

    const/4 v0, 0x1

    goto :goto_b

    :goto_c
    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v1}, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooO00o()I

    move-result v5

    if-nez v5, :cond_19

    const v5, 0x10d5a4e2

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v5, v17, 0xe

    invoke-static {v1, v10, v5}, Llyiahf/vczjk/xt6;->OooOO0o(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V

    const/4 v5, 0x0

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_d

    :cond_19
    const/4 v5, 0x0

    const v6, 0x10d6b061

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v6, v17, 0xe

    invoke-static {v1, v10, v6}, Llyiahf/vczjk/xt6;->OooOO0O(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_d
    and-int/lit8 v5, v17, 0xe

    invoke-static {v1, v10, v5}, Llyiahf/vczjk/xt6;->OooO0Oo(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v6, Llyiahf/vczjk/op3;->OooOoo0:Llyiahf/vczjk/sb0;

    move-object/from16 v8, v19

    const/16 v7, 0x36

    invoke-static {v8, v6, v10, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v6

    iget v7, v10, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v10, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_1a

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_e

    :cond_1a
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_e
    invoke-static {v6, v10, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v8, v10, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v10, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_1b

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_1c

    :cond_1b
    invoke-static {v7, v10, v7, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1c
    invoke-static {v9, v10, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    invoke-static {v1, v10, v5}, Llyiahf/vczjk/xt6;->OooO0oO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/rf1;I)V

    const v3, -0x6e815e1

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez p1, :cond_1d

    move-object/from16 v4, p1

    const/4 v5, 0x0

    goto :goto_f

    :cond_1d
    const/4 v5, 0x0

    invoke-static {v5, v10}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "CPU "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    move-object/from16 v4, p1

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v6, "%"

    invoke-virtual {v3, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    const/4 v6, 0x2

    const/4 v7, 0x0

    invoke-static {v5, v6, v3, v10, v7}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    :goto_f
    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v5, v10}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    if-eqz p2, :cond_1e

    move v6, v0

    goto :goto_10

    :cond_1e
    move v6, v5

    :goto_10
    new-instance v3, Llyiahf/vczjk/u20;

    const/16 v5, 0x13

    move-object/from16 v15, p2

    invoke-direct {v3, v15, v5}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v5, 0x5346ff55

    invoke-static {v5, v3, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v11

    const/4 v9, 0x0

    move-object v12, v10

    const/4 v10, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const v13, 0x180006

    const/16 v14, 0x1e

    move-object v5, v2

    invoke-static/range {v5 .. v14}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    move-object v10, v12

    invoke-static {v10, v0, v0, v0}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    :goto_11
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v7

    if-eqz v7, :cond_1f

    new-instance v0, Llyiahf/vczjk/d5;

    const/4 v6, 0x6

    move/from16 v5, p5

    move-object v2, v4

    move-object v3, v15

    move-object/from16 v4, p3

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/d5;-><init>(Landroid/os/Parcelable;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v7, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1f
    return-void
.end method

.method public static final OooOOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 13

    const-string v0, "onBackPressed"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/zf1;

    const p1, 0x2467fa64

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v10, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    const/4 v0, 0x2

    if-eqz p1, :cond_0

    const/4 p1, 0x4

    goto :goto_0

    :cond_0
    move p1, v0

    :goto_0
    or-int/2addr p1, p2

    and-int/lit8 v1, p1, 0x3

    if-ne v1, v0, :cond_2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v5, p0

    goto/16 :goto_2

    :cond_2
    :goto_1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o00ooo(Landroid/content/Context;)Landroidx/appcompat/app/AppCompatActivity;

    move-result-object v0

    const v1, 0x70b323c8

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v0, v10}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v1

    const v2, 0x671a9c9b

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-virtual {v0}, Landroidx/activity/ComponentActivity;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v2

    const-class v3, Llyiahf/vczjk/k77;

    invoke-static {v3, v0, v1, v2, v10}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/k77;

    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Landroidx/compose/runtime/OooO;

    move-result-object v0

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uy4;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/fy4;->OooO0o0(Llyiahf/vczjk/ky4;)V

    iget-object v0, v3, Llyiahf/vczjk/k77;->OooO0oO:Llyiahf/vczjk/gh7;

    invoke-static {v0, v10}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v4

    new-instance v0, Llyiahf/vczjk/n;

    const/4 v2, 0x1

    invoke-direct {v0, v2}, Llyiahf/vczjk/n;-><init>(I)V

    const v2, 0x4c5de2

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v5, :cond_3

    if-ne v6, v7, :cond_4

    :cond_3
    new-instance v6, Llyiahf/vczjk/i57;

    const/4 v5, 0x0

    invoke-direct {v6, v3, v5}, Llyiahf/vczjk/i57;-><init>(Llyiahf/vczjk/k77;I)V

    invoke-virtual {v10, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v6, v10}, Llyiahf/vczjk/zsa;->o00O0O(Llyiahf/vczjk/n;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/wa5;

    move-result-object v6

    invoke-static {v10}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    const/4 v8, 0x0

    if-nez v0, :cond_5

    if-ne v5, v7, :cond_6

    :cond_5
    new-instance v5, Llyiahf/vczjk/v57;

    invoke-direct {v5, v3, v8}, Llyiahf/vczjk/v57;-><init>(Llyiahf/vczjk/k77;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v5, Llyiahf/vczjk/ze3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v10, v5}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v0, 0x3

    invoke-static {v1, v0, v10}, Llyiahf/vczjk/fw4;->OooO00o(IILlyiahf/vczjk/rf1;)Llyiahf/vczjk/dw4;

    move-result-object v5

    invoke-static {v10}, Llyiahf/vczjk/xr6;->OooOOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/hb8;

    move-result-object v0

    const v9, -0x615d173a

    invoke-virtual {v10, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v9, v11

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v11

    if-nez v9, :cond_7

    if-ne v11, v7, :cond_8

    :cond_7
    new-instance v11, Llyiahf/vczjk/x57;

    invoke-direct {v11, v0, v3, v8}, Llyiahf/vczjk/x57;-><init>(Llyiahf/vczjk/hb8;Llyiahf/vczjk/k77;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v10, v11}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v11, Llyiahf/vczjk/ze3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v10, v11}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v0}, Llyiahf/vczjk/hb8;->OooO0OO()Z

    move-result v8

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    if-nez v2, :cond_9

    if-ne v9, v7, :cond_a

    :cond_9
    new-instance v9, Llyiahf/vczjk/n20;

    const/16 v2, 0xb

    invoke-direct {v9, v0, v2}, Llyiahf/vczjk/n20;-><init>(Llyiahf/vczjk/hb8;I)V

    invoke-virtual {v10, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v8, v9, v10, v1, v1}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/pb1;->OooO00o:Llyiahf/vczjk/a91;

    new-instance v2, Llyiahf/vczjk/u20;

    const/16 v7, 0x12

    invoke-direct {v2, v0, v7}, Llyiahf/vczjk/u20;-><init>(Ljava/lang/Object;I)V

    const v7, 0x60e60e22

    invoke-static {v7, v2, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v8

    new-instance v2, Llyiahf/vczjk/f5;

    const/16 v7, 0x19

    invoke-direct {v2, v3, v7}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v7, 0x2764977d

    invoke-static {v7, v2, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v9

    new-instance v2, Llyiahf/vczjk/a6;

    const/16 v7, 0xa

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/a6;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const v3, 0x2c339643

    invoke-static {v3, v2, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v2

    shl-int/lit8 p1, p1, 0xc

    const v3, 0xe000

    and-int/2addr p1, v3

    const v3, 0x60301b0

    or-int v11, p1, v3

    const/4 v4, 0x0

    move-object v3, v8

    const/4 v8, 0x0

    move-object v6, v9

    move-object v9, v2

    move-object v2, v1

    const/4 v1, 0x0

    const/16 v12, 0x89

    move-object v5, p0

    move-object v7, v0

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_2
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p0

    if-eqz p0, :cond_b

    new-instance p1, Llyiahf/vczjk/o20;

    const/16 v0, 0x8

    invoke-direct {p1, p2, v0, v5}, Llyiahf/vczjk/o20;-><init>(IILlyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_b
    return-void
.end method

.method public static final OooOOOO(Llyiahf/vczjk/dw4;Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 19

    move-object/from16 v1, p1

    move-object/from16 v3, p2

    move-object/from16 v7, p3

    move-object/from16 v2, p4

    move-object/from16 v6, p5

    move-object/from16 v5, p6

    move-object/from16 v8, p7

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const-string v4, "state"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "onRunningItemClick"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "onNotRunningItemClick"

    invoke-static {v7, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "onFilterItemSelected"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "setRunningExpand"

    invoke-static {v6, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "setCachedExpand"

    invoke-static {v5, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v4, "setNotRunningExpand"

    invoke-static {v8, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v15, p8

    check-cast v15, Llyiahf/vczjk/zf1;

    const v4, -0x804cbab

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    move-object/from16 v9, p0

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/16 v4, 0x20

    goto :goto_0

    :cond_0
    const/16 v4, 0x10

    :goto_0
    or-int v4, p9, v4

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_1

    const/16 v10, 0x100

    goto :goto_1

    :cond_1
    const/16 v10, 0x80

    :goto_1
    or-int/2addr v4, v10

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_2

    const/16 v10, 0x800

    goto :goto_2

    :cond_2
    const/16 v10, 0x400

    :goto_2
    or-int/2addr v4, v10

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_3

    const/16 v10, 0x4000

    goto :goto_3

    :cond_3
    const/16 v10, 0x2000

    :goto_3
    or-int/2addr v4, v10

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    const/high16 v13, 0x20000

    if-eqz v10, :cond_4

    move v10, v13

    goto :goto_4

    :cond_4
    const/high16 v10, 0x10000

    :goto_4
    or-int/2addr v4, v10

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    const/high16 v14, 0x100000

    if-eqz v10, :cond_5

    move v10, v14

    goto :goto_5

    :cond_5
    const/high16 v10, 0x80000

    :goto_5
    or-int/2addr v4, v10

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_6

    const/high16 v10, 0x800000

    goto :goto_6

    :cond_6
    const/high16 v10, 0x400000

    :goto_6
    or-int/2addr v4, v10

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    if-eqz v10, :cond_7

    const/high16 v10, 0x4000000

    goto :goto_7

    :cond_7
    const/high16 v10, 0x2000000

    :goto_7
    or-int/2addr v10, v4

    const v4, 0x2492493

    and-int/2addr v4, v10

    const v12, 0x2492492

    if-ne v4, v12, :cond_9

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_8

    goto :goto_8

    :cond_8
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_10

    :cond_9
    :goto_8
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v4, p9, 0x1

    if-eqz v4, :cond_b

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v4

    if-eqz v4, :cond_a

    goto :goto_9

    :cond_a
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_b
    :goto_9
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo0()V

    sget-object v4, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/x21;

    iget-wide v11, v4, Llyiahf/vczjk/x21;->OooOOOo:J

    sget-object v4, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v0, v11, v12, v4}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v4, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    invoke-interface {v0, v4}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    const v0, -0x48fade91

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/high16 v4, 0x70000

    and-int/2addr v4, v10

    const/4 v12, 0x0

    if-ne v4, v13, :cond_c

    const/4 v4, 0x1

    goto :goto_a

    :cond_c
    move v4, v12

    :goto_a
    or-int/2addr v0, v4

    const/high16 v4, 0x380000

    and-int/2addr v4, v10

    if-ne v4, v14, :cond_d

    const/4 v4, 0x1

    goto :goto_b

    :cond_d
    move v4, v12

    :goto_b
    or-int/2addr v0, v4

    and-int/lit16 v4, v10, 0x1c00

    const/16 v13, 0x800

    if-ne v4, v13, :cond_e

    const/4 v4, 0x1

    goto :goto_c

    :cond_e
    move v4, v12

    :goto_c
    or-int/2addr v0, v4

    const/high16 v4, 0x1c00000

    and-int/2addr v4, v10

    const/high16 v13, 0x800000

    if-ne v4, v13, :cond_f

    const/4 v4, 0x1

    goto :goto_d

    :cond_f
    move v4, v12

    :goto_d
    or-int/2addr v0, v4

    const/high16 v4, 0xe000000

    and-int/2addr v4, v10

    const/high16 v13, 0x4000000

    if-ne v4, v13, :cond_10

    const/4 v4, 0x1

    goto :goto_e

    :cond_10
    move v4, v12

    :goto_e
    or-int/2addr v0, v4

    const v4, 0xe000

    and-int/2addr v4, v10

    const/16 v13, 0x4000

    if-ne v4, v13, :cond_11

    const/16 v18, 0x1

    goto :goto_f

    :cond_11
    move/from16 v18, v12

    :goto_f
    or-int v0, v0, v18

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v0, :cond_12

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v0, :cond_13

    :cond_12
    new-instance v0, Llyiahf/vczjk/qv5;

    move-object v4, v3

    move-object v3, v6

    move-object v6, v8

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/qv5;-><init>(Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v4, v0

    :cond_13
    move-object v14, v4

    check-cast v14, Llyiahf/vczjk/oe3;

    invoke-virtual {v15, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    and-int/lit8 v16, v10, 0x70

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    move-object v5, v11

    const/4 v11, 0x0

    const/16 v17, 0x1fc

    move-object/from16 v6, p0

    invoke-static/range {v5 .. v17}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_10
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v10

    if-eqz v10, :cond_14

    new-instance v0, Llyiahf/vczjk/r57;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move/from16 v9, p9

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/r57;-><init>(Llyiahf/vczjk/dw4;Llyiahf/vczjk/t67;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;I)V

    iput-object v0, v10, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_14
    return-void
.end method

.method public static final OooOOOo(IZLlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 28

    move/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v3, p2

    const-string v0, "setExpand"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v0, p3

    check-cast v0, Llyiahf/vczjk/zf1;

    const v4, 0x520467ad

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int v4, p4, v4

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v5

    const/16 v6, 0x20

    if-eqz v5, :cond_1

    move v5, v6

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v4, v5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v7, 0x100

    if-eqz v5, :cond_2

    move v5, v7

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v4, v5

    and-int/lit16 v5, v4, 0x93

    const/16 v8, 0x92

    if-ne v5, v8, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v4, v0

    goto/16 :goto_8

    :cond_4
    :goto_3
    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v8, 0x3f800000    # 1.0f

    invoke-static {v5, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/el8;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v9, v10}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/nq9;->OooO0OO:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/ap9;

    iget-wide v10, v10, Llyiahf/vczjk/ap9;->OooO00o:J

    sget-object v12, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v9, v10, v11, v12}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v9

    const v10, -0x615d173a

    invoke-virtual {v0, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v10, v4, 0x380

    const/4 v11, 0x0

    const/4 v12, 0x1

    if-ne v10, v7, :cond_5

    move v7, v12

    goto :goto_4

    :cond_5
    move v7, v11

    :goto_4
    and-int/lit8 v10, v4, 0x70

    if-ne v10, v6, :cond_6

    move v6, v12

    goto :goto_5

    :cond_6
    move v6, v11

    :goto_5
    or-int/2addr v6, v7

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v6, :cond_7

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v6, :cond_8

    :cond_7
    new-instance v7, Llyiahf/vczjk/ev0;

    const/4 v6, 0x2

    invoke-direct {v7, v3, v2, v6}, Llyiahf/vczjk/ev0;-><init>(Llyiahf/vczjk/oe3;ZI)V

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v6, 0x7

    const/4 v10, 0x0

    invoke-static {v9, v11, v10, v7, v6}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v6

    const/16 v7, 0x14

    int-to-float v7, v7

    const/16 v9, 0xc

    int-to-float v9, v9

    invoke-static {v6, v7, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v7, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    invoke-static {v7, v11}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v7

    iget v9, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v0, v6}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v6

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_9

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_9
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v7, v0, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v14, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v14, :cond_a

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-static {v14, v15}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-nez v14, :cond_b

    :cond_a
    invoke-static {v9, v0, v9, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v9, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v6, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v5, v8}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    sget-object v8, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    const/16 v14, 0x36

    invoke-static {v6, v8, v0, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v6

    iget v8, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v0, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_c

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_c
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v6, v0, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v14, v0, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v6, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v6, :cond_d

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_e

    :cond_d
    invoke-static {v8, v0, v8, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v5, v0, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->running_process_running:I

    invoke-static {v5, v0}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, " - "

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v0, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/n6a;

    iget-object v6, v6, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v21, 0x0

    const/16 v24, 0x0

    move v7, v4

    move-object v4, v5

    const/4 v5, 0x0

    move-object/from16 v22, v6

    move v8, v7

    const-wide/16 v6, 0x0

    move v10, v8

    const-wide/16 v8, 0x0

    move v11, v10

    const/4 v10, 0x0

    move v13, v11

    const/4 v11, 0x0

    move v15, v12

    move v14, v13

    const-wide/16 v12, 0x0

    move/from16 v16, v14

    const/4 v14, 0x0

    move/from16 v18, v15

    move/from16 v17, v16

    const-wide/16 v15, 0x0

    move/from16 v19, v17

    const/16 v17, 0x0

    move/from16 v20, v18

    const/16 v18, 0x0

    move/from16 v23, v19

    const/16 v19, 0x0

    move/from16 v25, v20

    const/16 v20, 0x0

    move/from16 v26, v25

    const/16 v25, 0x0

    move/from16 v27, v26

    const v26, 0x1fffe

    move/from16 p3, v23

    move-object/from16 v23, v0

    move/from16 v0, v27

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v4, v23

    shr-int/lit8 v5, p3, 0x3

    and-int/lit8 v5, v5, 0xe

    invoke-static {v2, v4, v5}, Llyiahf/vczjk/xt6;->OooO0o(ZLlyiahf/vczjk/rf1;I)V

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_f

    new-instance v0, Llyiahf/vczjk/j57;

    const/4 v5, 0x0

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/j57;-><init>(IZLlyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_f
    return-void
.end method

.method public static final OooOOo(Llyiahf/vczjk/dla;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 10

    move-object v5, p2

    check-cast v5, Llyiahf/vczjk/zf1;

    const p2, 0x1e895f4

    invoke-virtual {v5, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    const/4 v0, 0x4

    if-eqz p2, :cond_0

    move p2, v0

    goto :goto_0

    :cond_0
    const/4 p2, 0x2

    :goto_0
    or-int/2addr p2, p3

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    const/16 v2, 0x20

    if-eqz v1, :cond_1

    move v1, v2

    goto :goto_1

    :cond_1
    const/16 v1, 0x10

    :goto_1
    or-int/2addr p2, v1

    and-int/lit8 v1, p2, 0x13

    const/16 v3, 0x12

    if-ne v1, v3, :cond_3

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_6

    :cond_3
    :goto_2
    const v1, 0x4c5de2

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v1, p2, 0xe

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-ne v1, v0, :cond_4

    move v6, v3

    goto :goto_3

    :cond_4
    move v6, v4

    :goto_3
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v6, :cond_5

    if-ne v7, v8, :cond_6

    :cond_5
    iget-boolean v6, p0, Llyiahf/vczjk/dla;->OooO0o:Z

    invoke-static {v6}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v6

    invoke-static {v6}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v7

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v7, Llyiahf/vczjk/qs5;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Ljava/lang/Boolean;

    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v6

    const v9, -0x6815fd56

    invoke-virtual {v5, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 p2, p2, 0x70

    if-ne p2, v2, :cond_7

    move p2, v3

    goto :goto_4

    :cond_7
    move p2, v4

    :goto_4
    if-ne v1, v0, :cond_8

    goto :goto_5

    :cond_8
    move v3, v4

    :goto_5
    or-int/2addr p2, v3

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p2, v0

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p2, :cond_9

    if-ne v0, v8, :cond_a

    :cond_9
    new-instance v0, Llyiahf/vczjk/oo0ooO;

    const/16 p2, 0x17

    invoke-direct {v0, p1, p0, p2, v7}, Llyiahf/vczjk/oo0ooO;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v2, 0x0

    move v0, v6

    const/4 v6, 0x0

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/jv0;->OooO00o(ZLlyiahf/vczjk/oe3;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/cv0;Llyiahf/vczjk/rf1;I)V

    :goto_6
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_b

    new-instance v0, Llyiahf/vczjk/ai8;

    const/4 v1, 0x5

    invoke-direct {v0, p0, p1, p3, v1}, Llyiahf/vczjk/ai8;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_b
    return-void
.end method

.method public static final OooOOo0(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 13

    const-string v0, "onBackPressed"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/zf1;

    const p1, -0x61a2ff7f

    invoke-virtual {v10, p1}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v10, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    const/4 v0, 0x2

    if-eqz p1, :cond_0

    const/4 p1, 0x4

    goto :goto_0

    :cond_0
    move p1, v0

    :goto_0
    or-int/2addr p1, p2

    and-int/lit8 v1, p1, 0x3

    if-ne v1, v0, :cond_2

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v5, p0

    goto/16 :goto_2

    :cond_2
    :goto_1
    sget-object v0, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/zsa;->o00ooo(Landroid/content/Context;)Landroidx/appcompat/app/AppCompatActivity;

    move-result-object v0

    const v1, 0x70b323c8

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v0, v10}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v1

    const v2, 0x671a9c9b

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-virtual {v0}, Landroidx/activity/ComponentActivity;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v2

    const-class v3, Llyiahf/vczjk/bla;

    invoke-static {v3, v0, v1, v2, v10}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v0

    const/4 v1, 0x0

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    check-cast v0, Llyiahf/vczjk/bla;

    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Landroidx/compose/runtime/OooO;

    move-result-object v2

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/uy4;

    invoke-interface {v2}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/fy4;->OooO0o0(Llyiahf/vczjk/ky4;)V

    iget-object v2, v0, Llyiahf/vczjk/bla;->OooO0oO:Llyiahf/vczjk/gh7;

    invoke-static {v2, v10}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v2

    const v3, 0x4c5de2

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_3

    sget-object v3, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v3, :cond_4

    :cond_3
    new-instance v4, Llyiahf/vczjk/rka;

    const/4 v3, 0x0

    invoke-direct {v4, v0, v3}, Llyiahf/vczjk/rka;-><init>(Llyiahf/vczjk/bla;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v10, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v4, Llyiahf/vczjk/ze3;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v0, v10, v4}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object v1, v2

    sget-object v2, Llyiahf/vczjk/ld1;->OooO00o:Llyiahf/vczjk/a91;

    sget-object v3, Llyiahf/vczjk/ld1;->OooO0O0:Llyiahf/vczjk/a91;

    new-instance v4, Llyiahf/vczjk/r6;

    const/16 v5, 0x19

    invoke-direct {v4, v5, v0, v1}, Llyiahf/vczjk/r6;-><init>(ILjava/lang/Object;Llyiahf/vczjk/qs5;)V

    const v0, 0x41fa4d60

    invoke-static {v0, v4, v10}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v9

    shl-int/lit8 p1, p1, 0xc

    const v0, 0xe000

    and-int/2addr p1, v0

    const v0, 0x60001b0

    or-int v11, p1, v0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v4, 0x0

    const/4 v6, 0x0

    const/16 v12, 0xe9

    move-object v5, p0

    invoke-static/range {v1 .. v12}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    :goto_2
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p0

    if-eqz p0, :cond_5

    new-instance p1, Llyiahf/vczjk/o20;

    const/16 v0, 0xb

    invoke-direct {p1, p2, v0, v5}, Llyiahf/vczjk/o20;-><init>(IILlyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_5
    return-void
.end method

.method public static final OooOOoo(Llyiahf/vczjk/di6;Llyiahf/vczjk/td0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 16

    move-object/from16 v1, p1

    move-object/from16 v10, p6

    check-cast v10, Llyiahf/vczjk/zf1;

    const v0, 0x50db2159

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/16 v0, 0x20

    goto :goto_0

    :cond_0
    const/16 v0, 0x10

    :goto_0
    or-int v0, p7, v0

    move-object/from16 v2, p2

    invoke-virtual {v10, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/16 v4, 0x100

    if-eqz v3, :cond_1

    move v3, v4

    goto :goto_1

    :cond_1
    const/16 v3, 0x80

    :goto_1
    or-int/2addr v0, v3

    move-object/from16 v5, p3

    invoke-virtual {v10, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/16 v6, 0x800

    if-eqz v3, :cond_2

    move v3, v6

    goto :goto_2

    :cond_2
    const/16 v3, 0x400

    :goto_2
    or-int/2addr v0, v3

    move-object/from16 v3, p4

    invoke-virtual {v10, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    const/16 v8, 0x4000

    if-eqz v7, :cond_3

    move v7, v8

    goto :goto_3

    :cond_3
    const/16 v7, 0x2000

    :goto_3
    or-int/2addr v0, v7

    move-object/from16 v7, p5

    invoke-virtual {v10, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    const/high16 v11, 0x20000

    if-eqz v9, :cond_4

    move v9, v11

    goto :goto_4

    :cond_4
    const/high16 v9, 0x10000

    :goto_4
    or-int/2addr v0, v9

    const v9, 0x12493

    and-int/2addr v9, v0

    const v12, 0x12492

    if-ne v9, v12, :cond_6

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v9

    if-nez v9, :cond_5

    goto :goto_5

    :cond_5
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_a

    :cond_6
    :goto_5
    sget-object v9, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    const v12, -0x48fade91

    invoke-virtual {v10, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v10, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    and-int/lit16 v13, v0, 0x380

    const/4 v14, 0x1

    const/4 v15, 0x0

    if-ne v13, v4, :cond_7

    move v4, v14

    goto :goto_6

    :cond_7
    move v4, v15

    :goto_6
    or-int/2addr v4, v12

    const/high16 v12, 0x70000

    and-int/2addr v12, v0

    if-ne v12, v11, :cond_8

    move v11, v14

    goto :goto_7

    :cond_8
    move v11, v15

    :goto_7
    or-int/2addr v4, v11

    const v11, 0xe000

    and-int/2addr v11, v0

    if-ne v11, v8, :cond_9

    move v8, v14

    goto :goto_8

    :cond_9
    move v8, v15

    :goto_8
    or-int/2addr v4, v8

    and-int/lit16 v0, v0, 0x1c00

    if-ne v0, v6, :cond_a

    goto :goto_9

    :cond_a
    move v14, v15

    :goto_9
    or-int v0, v4, v14

    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v0, :cond_b

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v0, :cond_c

    :cond_b
    new-instance v0, Llyiahf/vczjk/v20;

    const/4 v6, 0x4

    move-object v4, v3

    move-object v3, v7

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/v20;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    invoke-virtual {v10, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v4, v0

    :cond_c
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-virtual {v10, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v1, 0x0

    const/4 v3, 0x0

    move-object v0, v9

    move-object v9, v4

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/16 v11, 0x186

    const/16 v12, 0x1fa

    move-object/from16 v2, p0

    invoke-static/range {v0 .. v12}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_a
    invoke-virtual {v10}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_d

    new-instance v0, Llyiahf/vczjk/f60;

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/f60;-><init>(Llyiahf/vczjk/di6;Llyiahf/vczjk/td0;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_d
    return-void
.end method

.method public static final OooOo(F)I
    .locals 2

    float-to-double v0, p0

    invoke-static {v0, v1}, Ljava/lang/Math;->ceil(D)D

    move-result-wide v0

    double-to-float p0, v0

    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    move-result p0

    return p0
.end method

.method public static final OooOo0(Ljava/lang/reflect/Method;)Ljava/lang/String;
    .locals 8

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    move-result-object v2

    const-string v1, "getParameterTypes(...)"

    invoke-static {v2, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v6, Llyiahf/vczjk/iu6;->OooOoO:Llyiahf/vczjk/iu6;

    const-string v5, ")"

    const/16 v7, 0x18

    const-string v3, ""

    const-string v4, "("

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/sy;->o00000Oo([Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    move-result-object p0

    const-string v1, "getReturnType(...)"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/rl7;->OooO0O0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOo00(Llyiahf/vczjk/uh6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V
    .locals 46

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move/from16 v2, p3

    const-string v5, "packageState"

    invoke-static {v0, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v5, "blockWakeLock"

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v11, p2

    check-cast v11, Llyiahf/vczjk/zf1;

    const v5, -0x153a8c05

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    const/4 v5, 0x4

    goto :goto_0

    :cond_0
    const/4 v5, 0x2

    :goto_0
    or-int/2addr v5, v2

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    const/16 v15, 0x10

    if-eqz v6, :cond_1

    const/16 v6, 0x20

    goto :goto_1

    :cond_1
    move v6, v15

    :goto_1
    or-int/2addr v5, v6

    and-int/lit8 v6, v5, 0x13

    const/16 v7, 0x12

    if-ne v6, v7, :cond_3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_f

    :cond_3
    :goto_2
    sget-object v8, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v6, 0x3f800000    # 1.0f

    invoke-static {v8, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v9, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v10, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v12, 0x0

    invoke-static {v9, v10, v11, v12}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v9

    iget v13, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v11, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v16, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_4

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_4
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v9, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v13}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v4, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_6

    :cond_5
    invoke-static {v13, v11, v13, v3}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_6
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v11, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v3, 0x17329e4f

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v0, Llyiahf/vczjk/uh6;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :goto_4
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_16

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/dla;

    invoke-static {v8, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v7

    const v9, 0x6e3c21fe

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    sget-object v13, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v9, v13, :cond_7

    new-instance v9, Llyiahf/vczjk/oOOO0OO0;

    const/16 v13, 0x16

    invoke-direct {v9, v13}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v7, v9}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v7

    int-to-float v9, v15

    const/4 v13, 0x4

    int-to-float v14, v13

    invoke-static {v7, v9, v14}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v7

    const/16 v9, 0x40

    int-to-float v9, v9

    const/4 v13, 0x0

    const/4 v14, 0x2

    invoke-static {v7, v9, v13, v14}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v9, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v13, Llyiahf/vczjk/tx;->OooO0o:Llyiahf/vczjk/mx;

    const/16 v14, 0x36

    invoke-static {v13, v9, v11, v14}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v13

    iget v14, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v11, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_8

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_8
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v13, v11, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v15, v11, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move-object/from16 v29, v3

    iget-boolean v3, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    move/from16 v30, v5

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_a

    goto :goto_6

    :cond_9
    move/from16 v30, v5

    :goto_6
    invoke-static {v14, v11, v14, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v7, v11, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object v14, v8

    const/high16 v5, 0x3f800000    # 1.0f

    float-to-double v7, v5

    const-wide/16 v18, 0x0

    cmpl-double v7, v7, v18

    const-string v20, "invalid weight; must be greater than zero"

    if-lez v7, :cond_b

    goto :goto_7

    :cond_b
    invoke-static/range {v20 .. v20}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_7
    new-instance v7, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v8, 0x0

    invoke-direct {v7, v5, v8}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    sget-object v5, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v8, 0x30

    invoke-static {v5, v9, v11, v8}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    iget v8, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v11, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v22, v10

    iget-boolean v10, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v10, :cond_c

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_c
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    invoke-static {v5, v11, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v9, v11, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_d

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v5, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_e

    :cond_d
    invoke-static {v8, v11, v8, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_e
    invoke-static {v7, v11, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v4, Llyiahf/vczjk/dla;->OooO0o:Z

    if-eqz v5, :cond_f

    const v5, -0x3f4f8c6e

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object v5, v6

    invoke-static {}, Llyiahf/vczjk/yi4;->OoooO()Llyiahf/vczjk/qv3;

    move-result-object v6

    sget-wide v9, Llyiahf/vczjk/n21;->OooO0oO:J

    move-object v7, v13

    const/4 v13, 0x0

    move-object v8, v7

    const/4 v7, 0x0

    move-object/from16 v23, v12

    const/16 v12, 0xdb0

    move-object/from16 v33, v5

    move-object/from16 v34, v8

    move-object v8, v14

    move-object/from16 v14, v22

    move-object/from16 v32, v23

    const/4 v5, 0x0

    invoke-static/range {v6 .. v13}, Llyiahf/vczjk/zt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v5, v8

    goto/16 :goto_a

    :cond_f
    move-object/from16 v33, v6

    move-object/from16 v32, v12

    move-object/from16 v34, v13

    move-object v8, v14

    move-object/from16 v14, v22

    const/4 v5, 0x0

    const v6, -0x3f4b7b63

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v6, Llyiahf/vczjk/qqa;->OooO0oO:Llyiahf/vczjk/qv3;

    if-eqz v6, :cond_10

    goto/16 :goto_9

    :cond_10
    new-instance v35, Llyiahf/vczjk/pv3;

    const-wide/16 v41, 0x0

    const/16 v45, 0x60

    const-string v36, "Outlined.FileCopy"

    const/high16 v37, 0x41c00000    # 24.0f

    const/high16 v38, 0x41c00000    # 24.0f

    const/high16 v39, 0x41c00000    # 24.0f

    const/high16 v40, 0x41c00000    # 24.0f

    const/16 v43, 0x0

    const/16 v44, 0x0

    invoke-direct/range {v35 .. v45}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    move-object/from16 v6, v35

    sget v7, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v7, Llyiahf/vczjk/gx8;

    sget-wide v9, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v7, v9, v10}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v9, Llyiahf/vczjk/jq;

    const/4 v10, 0x1

    invoke-direct {v9, v10}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v10, 0x41800000    # 16.0f

    const/high16 v12, 0x3f800000    # 1.0f

    invoke-virtual {v9, v10, v12}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v13, 0x40800000    # 4.0f

    invoke-virtual {v9, v13, v12}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v26, -0x40000000    # -2.0f

    const/high16 v27, 0x40000000    # 2.0f

    const v22, -0x40733333    # -1.1f

    const/16 v23, 0x0

    const/high16 v24, -0x40000000    # -2.0f

    const v25, 0x3f666666    # 0.9f

    move-object/from16 v21, v9

    invoke-virtual/range {v21 .. v27}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const/high16 v12, 0x41600000    # 14.0f

    invoke-virtual {v9, v12}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v12, 0x40000000    # 2.0f

    invoke-virtual {v9, v12}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v12, 0x40400000    # 3.0f

    invoke-virtual {v9, v13, v12}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v12, 0x41400000    # 12.0f

    invoke-virtual {v9, v12}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v12, 0x3f800000    # 1.0f

    invoke-virtual {v9, v10, v12}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v9}, Llyiahf/vczjk/jq;->OooO0O0()V

    const/high16 v10, 0x41700000    # 15.0f

    const/high16 v12, 0x40a00000    # 5.0f

    invoke-virtual {v9, v10, v12}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v10, 0x41000000    # 8.0f

    invoke-virtual {v9, v10, v12}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const v26, -0x400147ae    # -1.99f

    const v24, -0x400147ae    # -1.99f

    invoke-virtual/range {v21 .. v27}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const/high16 v13, 0x40c00000    # 6.0f

    const/high16 v5, 0x41a80000    # 21.0f

    invoke-virtual {v9, v13, v5}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const v26, 0x3ffeb852    # 1.99f

    const/16 v22, 0x0

    const v23, 0x3f8ccccd    # 1.1f

    const v24, 0x3f63d70a    # 0.89f

    const/high16 v25, 0x40000000    # 2.0f

    invoke-virtual/range {v21 .. v27}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const/high16 v12, 0x41980000    # 19.0f

    const/high16 v13, 0x41b80000    # 23.0f

    invoke-virtual {v9, v12, v13}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v26, 0x40000000    # 2.0f

    const/high16 v27, -0x40000000    # -2.0f

    const v22, 0x3f8ccccd    # 1.1f

    const/16 v23, 0x0

    const/high16 v24, 0x40000000    # 2.0f

    const v25, -0x4099999a    # -0.9f

    invoke-virtual/range {v21 .. v27}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const/high16 v12, 0x41300000    # 11.0f

    invoke-virtual {v9, v5, v12}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v12, -0x3f400000    # -6.0f

    invoke-virtual {v9, v12, v12}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    invoke-virtual {v9}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v9, v10, v5}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v12, 0x40e00000    # 7.0f

    invoke-virtual {v9, v10, v12}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const/high16 v12, 0x40c00000    # 6.0f

    invoke-virtual {v9, v12}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v12, 0x40a00000    # 5.0f

    invoke-virtual {v9, v12}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v9, v12}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const/high16 v12, 0x41100000    # 9.0f

    invoke-virtual {v9, v12}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    invoke-virtual {v9, v10, v5}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    invoke-virtual {v9}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v5, v9, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v6, v5, v7}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v6}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v6

    sput-object v6, Llyiahf/vczjk/qqa;->OooO0oO:Llyiahf/vczjk/qv3;

    :goto_9
    const/4 v7, 0x0

    const-wide/16 v9, 0x0

    const/16 v12, 0x1b0

    const/16 v13, 0x8

    invoke-static/range {v6 .. v13}, Llyiahf/vczjk/zt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    move-object v5, v8

    const/4 v8, 0x0

    invoke-virtual {v11, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_a
    const/16 v6, 0xc

    int-to-float v6, v6

    invoke-static {v5, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v6

    invoke-static {v11, v6}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/high16 v6, 0x3f800000    # 1.0f

    float-to-double v7, v6

    cmpl-double v7, v7, v18

    if-lez v7, :cond_11

    goto :goto_b

    :cond_11
    invoke-static/range {v20 .. v20}, Llyiahf/vczjk/nz3;->OooO00o(Ljava/lang/String;)V

    :goto_b
    new-instance v7, Landroidx/compose/foundation/layout/LayoutWeightElement;

    const/4 v8, 0x0

    invoke-direct {v7, v6, v8}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    sget-object v8, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const/4 v9, 0x6

    invoke-static {v8, v14, v11, v9}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v8

    iget v9, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v11, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v7

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_12

    move-object/from16 v12, v32

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_c
    move-object/from16 v12, v33

    goto :goto_d

    :cond_12
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_c

    :goto_d
    invoke-static {v8, v11, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v8, v34

    invoke-static {v10, v11, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v8, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_13

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v8, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_14

    :cond_13
    invoke-static {v9, v11, v9, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_14
    invoke-static {v7, v11, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v3, 0xe

    invoke-static {v3}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v7

    move/from16 v31, v6

    iget-object v6, v4, Llyiahf/vczjk/dla;->OooO00o:Ljava/lang/String;

    const/16 v24, 0x0

    const/16 v26, 0x6000

    move-object/from16 v25, v11

    move-wide v10, v7

    const/4 v7, 0x0

    const-wide/16 v8, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    move-object/from16 v22, v14

    const-wide/16 v14, 0x0

    const/16 v3, 0x10

    const/16 v16, 0x0

    const-wide/16 v17, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v21, 0x0

    move-object/from16 v23, v22

    const/16 v22, 0x0

    move-object/from16 v27, v23

    const/16 v23, 0x0

    move-object/from16 v28, v27

    const/16 v27, 0x0

    move-object/from16 v32, v28

    const v28, 0x3ffee

    move-object/from16 v33, v32

    move/from16 v32, v31

    move/from16 v31, v3

    const/4 v3, 0x2

    invoke-static/range {v6 .. v28}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v25

    const/4 v10, 0x1

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v6, -0x2b54ad56

    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v6, v4, Llyiahf/vczjk/dla;->OooO0o0:Z

    if-eqz v6, :cond_15

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->wakelock_state_holding:I

    invoke-static {v6, v11}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    const/4 v7, 0x0

    const/4 v8, 0x0

    invoke-static {v8, v3, v6, v11, v7}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    goto :goto_e

    :cond_15
    const/4 v8, 0x0

    :goto_e
    invoke-virtual {v11, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v10, 0x1

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    and-int/lit8 v6, v30, 0x70

    invoke-static {v4, v1, v11, v6}, Llyiahf/vczjk/xt6;->OooOOo(Llyiahf/vczjk/dla;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move v12, v8

    move-object/from16 v3, v29

    move/from16 v15, v31

    move/from16 v6, v32

    move-object/from16 v10, v33

    move-object v8, v5

    move/from16 v5, v30

    goto/16 :goto_4

    :cond_16
    move v8, v12

    const/4 v10, 0x1

    invoke-virtual {v11, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v11, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_f
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v3

    if-eqz v3, :cond_17

    new-instance v4, Llyiahf/vczjk/ai8;

    const/4 v13, 0x4

    invoke-direct {v4, v0, v1, v2, v13}, Llyiahf/vczjk/ai8;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v4, v3, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_17
    return-void
.end method

.method public static final OooOo0O(ILjava/lang/StringBuilder;)V
    .locals 2

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p0, :cond_1

    const-string v1, "?"

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v1, p0, -0x1

    if-ge v0, v1, :cond_0

    const-string v1, ","

    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public static final OooOo0o(ILjava/lang/StringBuilder;)V
    .locals 6

    if-gtz p0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v1, 0x0

    :goto_0
    if-ge v1, p0, :cond_1

    const-string v2, "?"

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    const/4 v3, 0x0

    const/4 v4, 0x0

    const-string v1, ","

    const/4 v2, 0x0

    const/16 v5, 0x3e

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/d21;->o0ooOoO(Ljava/lang/Iterable;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;I)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    return-void
.end method

.method public static OooOoO(J)Ljava/lang/String;
    .locals 3

    long-to-int v0, p0

    const v1, 0x36ee80

    div-int/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    mul-int/2addr v0, v1

    int-to-long v0, v0

    sub-long v0, p0, v0

    long-to-int v0, v0

    const v1, 0xea60

    div-int/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {p0, p1}, Llyiahf/vczjk/xt6;->Oooo0(J)I

    move-result p0

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p0

    filled-new-array {v2, v0, p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string p1, "%d:%02d:%02d"

    invoke-static {p1, p0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOoO0(Llyiahf/vczjk/cda;)Llyiahf/vczjk/o5a;
    .locals 1

    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    move-result p0

    if-eqz p0, :cond_2

    const/4 v0, 0x1

    if-eq p0, v0, :cond_1

    const/4 v0, 0x2

    if-ne p0, v0, :cond_0

    sget-object p0, Llyiahf/vczjk/o5a;->OooOOO:Llyiahf/vczjk/o5a;

    return-object p0

    :cond_0
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_1
    sget-object p0, Llyiahf/vczjk/o5a;->OooOOO0:Llyiahf/vczjk/o5a;

    return-object p0

    :cond_2
    sget-object p0, Llyiahf/vczjk/o5a;->OooOOOO:Llyiahf/vczjk/o5a;

    return-object p0
.end method

.method public static final OooOoOO()Llyiahf/vczjk/qv3;
    .locals 12

    sget-object v0, Llyiahf/vczjk/xt6;->OooO00o:Llyiahf/vczjk/qv3;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v1, Llyiahf/vczjk/pv3;

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-string v2, "Filled.Search"

    const/high16 v3, 0x41c00000    # 24.0f

    const/high16 v4, 0x41c00000    # 24.0f

    const/high16 v5, 0x41c00000    # 24.0f

    const/high16 v6, 0x41c00000    # 24.0f

    const-wide/16 v7, 0x0

    const/16 v11, 0x60

    invoke-direct/range {v1 .. v11}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/gx8;

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v0, v2, v3}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v4, Llyiahf/vczjk/jq;

    const/4 v2, 0x1

    invoke-direct {v4, v2}, Llyiahf/vczjk/jq;-><init>(I)V

    const/high16 v2, 0x41780000    # 15.5f

    const/high16 v3, 0x41600000    # 14.0f

    invoke-virtual {v4, v2, v3}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const v2, -0x40b5c28f    # -0.79f

    invoke-virtual {v4, v2}, Llyiahf/vczjk/jq;->OooO0o(F)V

    const v2, -0x4170a3d7    # -0.28f

    const v5, -0x4175c28f    # -0.27f

    invoke-virtual {v4, v2, v5}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    const/high16 v7, 0x41800000    # 16.0f

    const v8, 0x4131c28f    # 11.11f

    const v5, 0x41768f5c    # 15.41f

    const v6, 0x414970a4    # 12.59f

    const/high16 v9, 0x41800000    # 16.0f

    const/high16 v10, 0x41180000    # 9.5f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0OO(FFFFFF)V

    const v7, 0x415170a4    # 13.09f

    const/high16 v8, 0x40400000    # 3.0f

    const/high16 v5, 0x41800000    # 16.0f

    const v6, 0x40bd1eb8    # 5.91f

    const/high16 v9, 0x41180000    # 9.5f

    const/high16 v10, 0x40400000    # 3.0f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0OO(FFFFFF)V

    const/high16 v2, 0x40400000    # 3.0f

    const v5, 0x40bd1eb8    # 5.91f

    const/high16 v11, 0x41180000    # 9.5f

    invoke-virtual {v4, v2, v5, v2, v11}, Llyiahf/vczjk/jq;->OooOO0O(FFFF)V

    const/high16 v2, 0x41800000    # 16.0f

    invoke-virtual {v4, v5, v2, v11, v2}, Llyiahf/vczjk/jq;->OooOO0O(FFFF)V

    const v7, 0x4045c28f    # 3.09f

    const v8, -0x40e8f5c3    # -0.59f

    const v5, 0x3fce147b    # 1.61f

    const/4 v6, 0x0

    const v9, 0x40875c29    # 4.23f

    const v10, -0x40370a3d    # -1.57f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0Oo(FFFFFF)V

    const v2, 0x3e8a3d71    # 0.27f

    const v5, 0x3e8f5c29    # 0.28f

    invoke-virtual {v4, v2, v5}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    const v2, 0x3f4a3d71    # 0.79f

    invoke-virtual {v4, v2}, Llyiahf/vczjk/jq;->OooOOOO(F)V

    const/high16 v2, 0x40a00000    # 5.0f

    const v5, 0x409fae14    # 4.99f

    invoke-virtual {v4, v2, v5}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    const v5, 0x41a3eb85    # 20.49f

    const/high16 v6, 0x41980000    # 19.0f

    invoke-virtual {v4, v5, v6}, Llyiahf/vczjk/jq;->OooO0oO(FF)V

    const v5, -0x3f6051ec    # -4.99f

    const/high16 v6, -0x3f600000    # -5.0f

    invoke-virtual {v4, v5, v6}, Llyiahf/vczjk/jq;->OooO0oo(FF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    invoke-virtual {v4, v11, v3}, Llyiahf/vczjk/jq;->OooOO0(FF)V

    const/high16 v7, 0x40a00000    # 5.0f

    const v8, 0x413fd70a    # 11.99f

    const v5, 0x40e051ec    # 7.01f

    const/high16 v6, 0x41600000    # 14.0f

    const/high16 v9, 0x40a00000    # 5.0f

    const/high16 v10, 0x41180000    # 9.5f

    invoke-virtual/range {v4 .. v10}, Llyiahf/vczjk/jq;->OooO0OO(FFFFFF)V

    invoke-virtual {v4, v5, v2, v11, v2}, Llyiahf/vczjk/jq;->OooOO0O(FFFF)V

    invoke-virtual {v4, v3, v5, v3, v11}, Llyiahf/vczjk/jq;->OooOO0O(FFFF)V

    const v2, 0x413fd70a    # 11.99f

    invoke-virtual {v4, v2, v3, v11, v3}, Llyiahf/vczjk/jq;->OooOO0O(FFFF)V

    invoke-virtual {v4}, Llyiahf/vczjk/jq;->OooO0O0()V

    iget-object v2, v4, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v1}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/xt6;->OooO00o:Llyiahf/vczjk/qv3;

    return-object v0
.end method

.method public static final OooOoo(Llyiahf/vczjk/qqa;FF)Z
    .locals 21

    move-object/from16 v0, p0

    instance-of v1, v0, Llyiahf/vczjk/pf6;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/pf6;

    iget-object v0, v0, Llyiahf/vczjk/pf6;->OooO:Llyiahf/vczjk/wj7;

    iget v1, v0, Llyiahf/vczjk/wj7;->OooO00o:F

    cmpg-float v1, v1, p1

    if-gtz v1, :cond_7

    iget v1, v0, Llyiahf/vczjk/wj7;->OooO0OO:F

    cmpg-float v1, p1, v1

    if-gez v1, :cond_7

    iget v1, v0, Llyiahf/vczjk/wj7;->OooO0O0:F

    cmpg-float v1, v1, p2

    if-gtz v1, :cond_7

    iget v0, v0, Llyiahf/vczjk/wj7;->OooO0Oo:F

    cmpg-float v0, p2, v0

    if-gez v0, :cond_7

    goto/16 :goto_0

    :cond_0
    instance-of v1, v0, Llyiahf/vczjk/qf6;

    if-eqz v1, :cond_8

    check-cast v0, Llyiahf/vczjk/qf6;

    iget-object v0, v0, Llyiahf/vczjk/qf6;->OooO:Llyiahf/vczjk/nv7;

    iget v1, v0, Llyiahf/vczjk/nv7;->OooO00o:F

    cmpg-float v2, p1, v1

    if-ltz v2, :cond_7

    iget v2, v0, Llyiahf/vczjk/nv7;->OooO0OO:F

    cmpl-float v3, p1, v2

    if-gez v3, :cond_7

    iget v3, v0, Llyiahf/vczjk/nv7;->OooO0O0:F

    cmpg-float v4, p2, v3

    if-ltz v4, :cond_7

    iget v4, v0, Llyiahf/vczjk/nv7;->OooO0Oo:F

    cmpl-float v5, p2, v4

    if-ltz v5, :cond_1

    goto/16 :goto_1

    :cond_1
    iget-wide v5, v0, Llyiahf/vczjk/nv7;->OooO0o0:J

    const/16 v7, 0x20

    shr-long v8, v5, v7

    long-to-int v8, v8

    invoke-static {v8}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v9

    iget-wide v10, v0, Llyiahf/vczjk/nv7;->OooO0o:J

    shr-long v12, v10, v7

    long-to-int v12, v12

    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v13

    add-float/2addr v13, v9

    invoke-virtual {v0}, Llyiahf/vczjk/nv7;->OooO0O0()F

    move-result v9

    cmpg-float v9, v13, v9

    if-gtz v9, :cond_6

    iget-wide v13, v0, Llyiahf/vczjk/nv7;->OooO0oo:J

    move/from16 p0, v7

    move v9, v8

    shr-long v7, v13, p0

    long-to-int v7, v7

    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v8

    move v15, v1

    move/from16 v16, v2

    iget-wide v1, v0, Llyiahf/vczjk/nv7;->OooO0oO:J

    move-wide/from16 v17, v1

    shr-long v1, v17, p0

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    add-float/2addr v2, v8

    invoke-virtual {v0}, Llyiahf/vczjk/nv7;->OooO0O0()F

    move-result v8

    cmpg-float v2, v2, v8

    if-gtz v2, :cond_6

    const-wide v19, 0xffffffffL

    and-long v5, v5, v19

    long-to-int v2, v5

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v5

    and-long v13, v13, v19

    long-to-int v6, v13

    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v8

    add-float/2addr v8, v5

    invoke-virtual {v0}, Llyiahf/vczjk/nv7;->OooO00o()F

    move-result v5

    cmpg-float v5, v8, v5

    if-gtz v5, :cond_6

    and-long v10, v10, v19

    long-to-int v5, v10

    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v8

    and-long v10, v17, v19

    long-to-int v10, v10

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v11

    add-float/2addr v11, v8

    invoke-virtual {v0}, Llyiahf/vczjk/nv7;->OooO00o()F

    move-result v8

    cmpg-float v8, v11, v8

    if-gtz v8, :cond_6

    invoke-static {v9}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v8

    add-float/2addr v8, v15

    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    add-float/2addr v2, v3

    invoke-static {v12}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v9

    sub-float v9, v16, v9

    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v5

    add-float/2addr v3, v5

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    sub-float v1, v16, v1

    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v5

    sub-float v5, v4, v5

    invoke-static {v6}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v6

    sub-float/2addr v4, v6

    invoke-static {v7}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v6

    add-float/2addr v6, v15

    cmpg-float v7, p1, v8

    if-gez v7, :cond_2

    cmpg-float v7, p2, v2

    if-gez v7, :cond_2

    iget-wide v4, v0, Llyiahf/vczjk/nv7;->OooO0o0:J

    move/from16 v0, p1

    move/from16 v1, p2

    move v3, v2

    move v2, v8

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/xt6;->OooOooo(FFFFJ)Z

    move-result v0

    return v0

    :cond_2
    cmpg-float v2, p1, v6

    if-gez v2, :cond_3

    cmpl-float v2, p2, v4

    if-lez v2, :cond_3

    move v3, v4

    iget-wide v4, v0, Llyiahf/vczjk/nv7;->OooO0oo:J

    move/from16 v0, p1

    move/from16 v1, p2

    move v2, v6

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/xt6;->OooOooo(FFFFJ)Z

    move-result v0

    return v0

    :cond_3
    move v2, v3

    cmpl-float v3, p1, v9

    if-lez v3, :cond_4

    cmpg-float v3, p2, v2

    if-gez v3, :cond_4

    iget-wide v4, v0, Llyiahf/vczjk/nv7;->OooO0o:J

    move/from16 v0, p1

    move/from16 v1, p2

    move v3, v2

    move v2, v9

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/xt6;->OooOooo(FFFFJ)Z

    move-result v0

    return v0

    :cond_4
    cmpl-float v2, p1, v1

    if-lez v2, :cond_5

    cmpl-float v2, p2, v5

    if-lez v2, :cond_5

    move v3, v5

    iget-wide v4, v0, Llyiahf/vczjk/nv7;->OooO0oO:J

    move/from16 v0, p1

    move v2, v1

    move/from16 v1, p2

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/xt6;->OooOooo(FFFFJ)Z

    move-result v0

    return v0

    :cond_5
    :goto_0
    const/4 v0, 0x1

    return v0

    :cond_6
    move/from16 v1, p1

    move/from16 v2, p2

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v3

    invoke-static {v3, v0}, Llyiahf/vczjk/bq6;->OooO0O0(Llyiahf/vczjk/bq6;Llyiahf/vczjk/nv7;)V

    invoke-static {v1, v2, v3}, Llyiahf/vczjk/xt6;->OooOooO(FFLlyiahf/vczjk/bq6;)Z

    move-result v0

    return v0

    :cond_7
    :goto_1
    const/4 v0, 0x0

    return v0

    :cond_8
    move/from16 v1, p1

    move/from16 v2, p2

    instance-of v3, v0, Llyiahf/vczjk/of6;

    if-eqz v3, :cond_9

    check-cast v0, Llyiahf/vczjk/of6;

    iget-object v0, v0, Llyiahf/vczjk/of6;->OooO:Llyiahf/vczjk/qe;

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/xt6;->OooOooO(FFLlyiahf/vczjk/bq6;)Z

    move-result v0

    return v0

    :cond_9
    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0
.end method

.method public static final OooOoo0(Llyiahf/vczjk/zf1;Llyiahf/vczjk/ze3;)V
    .locals 1

    const-string v0, "null cannot be cast to non-null type kotlin.Function2<androidx.compose.runtime.Composer, kotlin.Int, kotlin.Unit>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x2

    invoke-static {v0, p1}, Llyiahf/vczjk/l4a;->OooOO0(ILjava/lang/Object;)Ljava/lang/Object;

    const/4 v0, 0x1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-interface {p1, p0, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public static final OooOooO(FFLlyiahf/vczjk/bq6;)Z
    .locals 4

    const v0, 0x3ba3d70a    # 0.005f

    sub-float v1, p0, v0

    sub-float v2, p1, v0

    add-float/2addr p0, v0

    add-float/2addr p1, v0

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v0

    sget-object v3, Llyiahf/vczjk/yp6;->OooOOO0:[Llyiahf/vczjk/yp6;

    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-static {p0}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-static {p1}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-eqz v3, :cond_1

    :cond_0
    const-string v3, "Invalid rectangle, make sure no value is NaN"

    invoke-static {v3}, Llyiahf/vczjk/se;->OooO0O0(Ljava/lang/String;)V

    :cond_1
    iget-object v3, v0, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    if-nez v3, :cond_2

    new-instance v3, Landroid/graphics/RectF;

    invoke-direct {v3}, Landroid/graphics/RectF;-><init>()V

    iput-object v3, v0, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    :cond_2
    iget-object v3, v0, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v3, v1, v2, p0, p1}, Landroid/graphics/RectF;->set(FFFF)V

    iget-object p0, v0, Llyiahf/vczjk/qe;->OooO0O0:Landroid/graphics/RectF;

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    sget-object p1, Landroid/graphics/Path$Direction;->CCW:Landroid/graphics/Path$Direction;

    iget-object v1, v0, Llyiahf/vczjk/qe;->OooO00o:Landroid/graphics/Path;

    invoke-virtual {v1, p0, p1}, Landroid/graphics/Path;->addRect(Landroid/graphics/RectF;Landroid/graphics/Path$Direction;)V

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object p0

    const/4 p1, 0x1

    invoke-virtual {p0, p2, v0, p1}, Llyiahf/vczjk/qe;->OooO0oO(Llyiahf/vczjk/bq6;Llyiahf/vczjk/bq6;I)Z

    iget-object p2, p0, Llyiahf/vczjk/qe;->OooO00o:Landroid/graphics/Path;

    invoke-virtual {p2}, Landroid/graphics/Path;->isEmpty()Z

    move-result p2

    invoke-virtual {p0}, Llyiahf/vczjk/qe;->OooO0oo()V

    invoke-virtual {v0}, Llyiahf/vczjk/qe;->OooO0oo()V

    xor-int/lit8 p0, p2, 0x1

    return p0
.end method

.method public static final OooOooo(FFFFJ)Z
    .locals 2

    sub-float/2addr p0, p2

    sub-float/2addr p1, p3

    const/16 p2, 0x20

    shr-long p2, p4, p2

    long-to-int p2, p2

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    const-wide v0, 0xffffffffL

    and-long p3, p4, v0

    long-to-int p3, p3

    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p3

    mul-float/2addr p0, p0

    mul-float/2addr p2, p2

    div-float/2addr p0, p2

    mul-float/2addr p1, p1

    mul-float/2addr p3, p3

    div-float/2addr p1, p3

    add-float/2addr p1, p0

    const/high16 p0, 0x3f800000    # 1.0f

    cmpg-float p0, p1, p0

    if-gtz p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static Oooo0(J)I
    .locals 2

    long-to-int v0, p0

    const v1, 0x36ee80

    div-int/2addr v0, v1

    mul-int/2addr v0, v1

    int-to-long v0, v0

    sub-long/2addr p0, v0

    long-to-int v0, p0

    const v1, 0xea60

    div-int/2addr v0, v1

    mul-int/2addr v0, v1

    int-to-long v0, v0

    sub-long/2addr p0, v0

    long-to-int p0, p0

    div-int/lit16 p0, p0, 0x3e8

    return p0
.end method

.method public static final Oooo000(Llyiahf/vczjk/qt5;)Ljava/lang/String;
    .locals 6

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v0

    const-string v1, "asString(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/ck4;->OooO00o:Ljava/util/HashSet;

    invoke-virtual {v2, v0}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_4

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v4

    if-ge v3, v4, :cond_1

    invoke-virtual {v0, v3}, Ljava/lang/String;->charAt(I)C

    move-result v4

    invoke-static {v4}, Ljava/lang/Character;->isLetterOrDigit(C)Z

    move-result v5

    if-nez v5, :cond_0

    const/16 v5, 0x5f

    if-eq v4, v5, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v3

    if-nez v3, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v0, v2}, Ljava/lang/String;->codePointAt(I)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Character;->isJavaIdentifierStart(I)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_1

    :cond_3
    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0

    :cond_4
    :goto_1
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "`"

    invoke-virtual {v1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p0, 0x60

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final Oooo00O(Ljava/util/List;)Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qt5;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    move-result v2

    if-lez v2, :cond_0

    const-string v2, "."

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/xt6;->Oooo000(Llyiahf/vczjk/qt5;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final Oooo00o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    const-string v0, "lowerRendered"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "lowerPrefix"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "upperRendered"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "upperPrefix"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "foldedPrefix"

    invoke-static {p4, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    invoke-static {p0, p1, v0}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-static {p2, p3, v0}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result p1

    invoke-virtual {p0, p1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p0

    const-string p1, "substring(...)"

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p3}, Ljava/lang/String;->length()I

    move-result p3

    invoke-virtual {p2, p3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    move-result-object p2

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p4, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p3

    if-eqz p3, :cond_0

    return-object p1

    :cond_0
    invoke-static {p0, p2}, Llyiahf/vczjk/xt6;->Oooo0OO(Ljava/lang/String;Ljava/lang/String;)Z

    move-result p0

    if-eqz p0, :cond_1

    new-instance p0, Ljava/lang/StringBuilder;

    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p1, 0x21

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_1
    const/4 p0, 0x0

    return-object p0
.end method

.method public static final Oooo0O0(Ljava/util/ArrayList;Ljava/util/List;)Ljava/util/ArrayList;
    .locals 5

    const-string v0, "dataList"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v2, 0x0

    move v3, v2

    :goto_0
    if-ge v3, v0, :cond_0

    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    move-result v0

    :goto_1
    if-ge v2, v0, :cond_1

    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    invoke-interface {p1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {v1, v2, v3}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_1
    return-object v1
.end method

.method public static final Oooo0OO(Ljava/lang/String;Ljava/lang/String;)Z
    .locals 3

    const-string v0, "lower"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "upper"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, ""

    const-string v1, "?"

    invoke-static {p1, v1, v0}, Llyiahf/vczjk/g79;->Oooo000(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p0, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    const/4 v0, 0x0

    invoke-static {p1, v1, v0}, Llyiahf/vczjk/g79;->OooOoOO(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-virtual {p0, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "("

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p0, ")?"

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_1

    goto :goto_0

    :cond_1
    return v0

    :cond_2
    :goto_0
    const/4 p0, 0x1

    return p0
.end method
