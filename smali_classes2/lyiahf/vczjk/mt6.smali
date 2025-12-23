.class public abstract Llyiahf/vczjk/mt6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static OooO00o:Llyiahf/vczjk/qv3;

.field public static final synthetic OooO0O0:I

.field public static OooO0OO:Llyiahf/vczjk/qv3;

.field public static OooO0Oo:Ljava/lang/Thread;

.field public static final synthetic OooO0o0:I


# direct methods
.method public static final OooO(Lnow/fortuitous/thanos/process/v2/RunningAppState;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/oy7;Llyiahf/vczjk/rf1;I)V
    .locals 51

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v7, p3

    check-cast v7, Llyiahf/vczjk/zf1;

    const v0, -0x2ba3dbfe

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p4, v0

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    const/16 v4, 0x20

    goto :goto_1

    :cond_1
    const/16 v4, 0x10

    :goto_1
    or-int/2addr v0, v4

    move-object/from16 v4, p2

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_2

    const/16 v6, 0x100

    goto :goto_2

    :cond_2
    const/16 v6, 0x80

    :goto_2
    or-int/2addr v0, v6

    and-int/lit16 v6, v0, 0x93

    const/16 v8, 0x92

    if-ne v6, v8, :cond_4

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_12

    :cond_4
    :goto_3
    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/content/Context;

    invoke-static {v6}, Llyiahf/vczjk/zsa;->o00ooo(Landroid/content/Context;)Landroidx/appcompat/app/AppCompatActivity;

    move-result-object v6

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v8, v9, :cond_5

    invoke-static {v7}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v8

    invoke-virtual {v7, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v8, Llyiahf/vczjk/xr1;

    const v10, 0x6e3c21fe

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-ne v10, v9, :cond_6

    sget-object v10, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v10}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v10

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v10, Llyiahf/vczjk/qs5;

    const/4 v11, 0x0

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v12, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    sget-object v13, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    sget-object v14, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v15, 0x3f800000    # 1.0f

    invoke-static {v14, v15}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v15

    const v3, 0x4c5de2

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v9, :cond_7

    new-instance v3, Llyiahf/vczjk/a67;

    const/4 v5, 0x4

    invoke-direct {v3, v10, v5}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v15, v3}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v5, 0x10

    int-to-float v5, v5

    const/4 v15, 0x0

    const/4 v11, 0x2

    invoke-static {v3, v5, v15, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v3

    const/16 v5, 0x36

    invoke-static {v13, v12, v7, v5}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v11, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v7, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v17, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v17 .. v17}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 p3, v6

    iget-boolean v6, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_8

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_8
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v7, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v15, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move-object/from16 v17, v8

    iget-boolean v8, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_9

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    move-object/from16 v18, v9

    invoke-static {v11}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_a

    goto :goto_5

    :cond_9
    move-object/from16 v18, v9

    :goto_5
    invoke-static {v11, v7, v11, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v7, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v3, 0xc

    int-to-float v3, v3

    invoke-static {v14, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-static {v7, v9}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v9, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v11, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    move-object/from16 v19, v10

    const/16 v10, 0x30

    move/from16 v20, v3

    invoke-static {v11, v9, v7, v10}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v3

    iget v10, v7, Llyiahf/vczjk/zf1;->Oooo:I

    move-object/from16 v22, v9

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    move-object/from16 v23, v11

    invoke-static {v7, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v26, v0

    iget-boolean v0, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v0, :cond_b

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_b
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v3, v7, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v9, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_c

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_d

    :cond_c
    invoke-static {v10, v7, v10, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_d
    invoke-static {v11, v7, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v0, 0x2a

    int-to-float v0, v0

    invoke-static {v14, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    iget-object v3, v1, Lnow/fortuitous/thanos/process/v2/RunningAppState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const/4 v9, 0x6

    invoke-static {v0, v3, v7, v9}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/16 v0, 0x8

    int-to-float v0, v0

    invoke-static {v14, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v7, v0}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    invoke-static {v13, v12, v7, v9}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v0

    iget v3, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v7, v14}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_e

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_e
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    invoke-static {v0, v7, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v10, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v0, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v0, :cond_f

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_10

    :cond_f
    invoke-static {v3, v7, v3, v15}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_10
    invoke-static {v11, v7, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v0, 0x0

    iget-object v3, v2, Lnow/fortuitous/thanos/process/v2/RunningService;->OooOOO:Ljava/lang/String;

    const/4 v10, 0x1

    const/4 v11, 0x0

    invoke-static {v11, v10, v3, v7, v0}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    shr-int/lit8 v0, v26, 0x3

    and-int/lit8 v0, v0, 0xe

    invoke-static {v2, v7, v0}, Llyiahf/vczjk/mt6;->OooO0oO(Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v11, v7}, Llyiahf/vczjk/ru6;->OooO0oO(ILlyiahf/vczjk/rf1;)V

    iget-object v0, v2, Lnow/fortuitous/thanos/process/v2/RunningService;->OooOOO0:Landroid/app/ActivityManager$RunningServiceInfo;

    iget-object v0, v0, Landroid/app/ActivityManager$RunningServiceInfo;->service:Landroid/content/ComponentName;

    invoke-virtual {v0}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    move-result-object v3

    const-string v0, "flattenToShortString(...)"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n6a;

    iget-object v0, v0, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    move/from16 v12, v20

    const/16 v20, 0x0

    move-object/from16 v13, v23

    const/16 v23, 0x0

    move-object/from16 v16, v4

    const/4 v4, 0x0

    move-object/from16 v25, v5

    move-object/from16 v24, v6

    const-wide/16 v5, 0x0

    move-object/from16 v27, v8

    move-object/from16 v28, v22

    move-object/from16 v22, v7

    const-wide/16 v7, 0x0

    move/from16 v29, v9

    const/4 v9, 0x0

    move/from16 v30, v10

    const/4 v10, 0x0

    move/from16 v31, v11

    move/from16 v32, v12

    const-wide/16 v11, 0x0

    move-object/from16 v33, v13

    const/4 v13, 0x0

    move-object/from16 v34, v14

    move-object/from16 v35, v15

    const-wide/16 v14, 0x0

    move-object/from16 v36, v16

    const/16 v16, 0x0

    move-object/from16 v37, v17

    const/16 v17, 0x0

    move-object/from16 v38, v18

    const/16 v18, 0x0

    move-object/from16 v39, v19

    const/16 v19, 0x0

    move-object/from16 v40, v24

    const/16 v24, 0x0

    move-object/from16 v41, v25

    const v25, 0x1fffe

    move-object/from16 v21, v0

    move-object/from16 v47, v27

    move-object/from16 v49, v28

    move/from16 v0, v31

    move/from16 v48, v32

    move-object/from16 v50, v33

    move-object/from16 v42, v34

    move-object/from16 v46, v35

    move-object/from16 v43, v36

    move-object/from16 v1, v37

    move-object/from16 v44, v40

    move-object/from16 v45, v41

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v7, v22

    const v3, -0x25b5ad04

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v2, Lnow/fortuitous/thanos/process/v2/RunningService;->OooOOo0:Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;

    iget-object v4, v2, Lnow/fortuitous/thanos/process/v2/RunningService;->OooOOOo:Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;

    if-nez v4, :cond_12

    if-eqz v3, :cond_11

    goto :goto_8

    :cond_11
    move-object/from16 v9, v42

    const/4 v10, 0x1

    goto/16 :goto_10

    :cond_12
    :goto_8
    invoke-static {v0, v7}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v5, v49

    move-object/from16 v13, v50

    const/16 v6, 0x30

    invoke-static {v13, v5, v7, v6}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    iget v6, v7, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    move-object/from16 v9, v42

    invoke-static {v7, v9}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v10

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_13

    move-object/from16 v11, v43

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_9
    move-object/from16 v11, v44

    goto :goto_a

    :cond_13
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_9

    :goto_a
    invoke-static {v5, v7, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v5, v45

    invoke-static {v8, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v7, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_14

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_15

    :cond_14
    move-object/from16 v5, v46

    goto :goto_c

    :cond_15
    :goto_b
    move-object/from16 v5, v47

    goto :goto_d

    :goto_c
    invoke-static {v6, v7, v6, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_b

    :goto_d
    invoke-static {v10, v7, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v5, 0x58f8423f

    invoke-virtual {v7, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez v4, :cond_16

    goto :goto_e

    :cond_16
    invoke-static {v4, v7, v0}, Llyiahf/vczjk/zsa;->OooO(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/ComponentRule;Llyiahf/vczjk/rf1;I)V

    :goto_e
    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v4, 0x58f84fe7

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez v3, :cond_17

    goto :goto_f

    :cond_17
    invoke-static {v0, v7}, Llyiahf/vczjk/ru6;->OooO0O0(ILlyiahf/vczjk/rf1;)V

    invoke-static {v3, v7, v0}, Llyiahf/vczjk/zsa;->OooO0O0(Lgithub/tornaco/thanos/module/component/manager/redesign/rule/BlockerRule;Llyiahf/vczjk/rf1;I)V

    :goto_f
    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v10, 0x1

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_10
    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move/from16 v12, v48

    invoke-static {v9, v12}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-static {v7, v3}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v3, -0x6815fd56

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    move-object/from16 v5, p3

    invoke-virtual {v7, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v4, v6

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v4, v6

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_18

    move-object/from16 v4, v38

    if-ne v6, v4, :cond_19

    goto :goto_11

    :cond_18
    move-object/from16 v4, v38

    :goto_11
    new-instance v6, Llyiahf/vczjk/sy7;

    const/4 v8, 0x0

    invoke-direct {v6, v1, v5, v2, v8}, Llyiahf/vczjk/sy7;-><init>(Llyiahf/vczjk/xr1;Landroidx/appcompat/app/AppCompatActivity;Lnow/fortuitous/thanos/process/v2/RunningService;I)V

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_19
    check-cast v6, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    invoke-virtual {v7, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v3, v8

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v3, v8

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v3, :cond_1a

    if-ne v8, v4, :cond_1b

    :cond_1a
    new-instance v8, Llyiahf/vczjk/sy7;

    const/4 v3, 0x1

    invoke-direct {v8, v1, v5, v2, v3}, Llyiahf/vczjk/sy7;-><init>(Llyiahf/vczjk/xr1;Landroidx/appcompat/app/AppCompatActivity;Lnow/fortuitous/thanos/process/v2/RunningService;I)V

    invoke-virtual {v7, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1b
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    and-int/lit8 v0, v26, 0x70

    or-int/lit8 v0, v0, 0x6

    move/from16 v1, v26

    and-int/lit16 v1, v1, 0x380

    or-int/2addr v0, v1

    move-object/from16 v4, p2

    move-object v3, v2

    move-object v5, v6

    move-object v6, v8

    move-object/from16 v2, v39

    move v8, v0

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/mt6;->OooO0o(Llyiahf/vczjk/qs5;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/oy7;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_12
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_1c

    new-instance v0, Llyiahf/vczjk/o0OO00OO;

    const/16 v5, 0xc

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o0OO00OO;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1c
    return-void
.end method

.method public static final OooO00o(FFIJLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V
    .locals 16

    move-wide/from16 v2, p3

    move-object/from16 v6, p6

    check-cast v6, Llyiahf/vczjk/zf1;

    const v0, -0x73cc10a2

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v2, v3}, Llyiahf/vczjk/zf1;->OooO0o(J)Z

    move-result v0

    const/16 v1, 0x20

    if-eqz v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    const/16 v0, 0x10

    :goto_0
    or-int v0, p2, v0

    and-int/lit16 v4, v0, 0x2493

    const/16 v5, 0x2492

    if-ne v4, v5, :cond_2

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_1

    goto :goto_1

    :cond_1
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move/from16 v7, p0

    move-object/from16 v1, p5

    move-object/from16 v10, p7

    goto/16 :goto_4

    :cond_2
    :goto_1
    const v4, 0x49df923b

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v4, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/f62;

    move/from16 v7, p0

    invoke-interface {v4, v7}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v4

    const/4 v8, 0x0

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v5, 0x6e3c21fe

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v9, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v9, :cond_3

    invoke-static {v8}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v5}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v5

    invoke-virtual {v6, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_3
    check-cast v5, Llyiahf/vczjk/qs5;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v10, Llyiahf/vczjk/uv7;->OooO00o:Llyiahf/vczjk/tv7;

    new-instance v10, Llyiahf/vczjk/qf7;

    invoke-direct {v10, v4}, Llyiahf/vczjk/qf7;-><init>(F)V

    new-instance v11, Llyiahf/vczjk/tv7;

    invoke-direct {v11, v10, v10, v10, v10}, Llyiahf/vczjk/ir1;-><init>(Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;)V

    move-object/from16 v10, p7

    invoke-static {v10, v2, v3, v11}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v11

    const v12, 0x4c5de2

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-ne v12, v9, :cond_4

    new-instance v12, Llyiahf/vczjk/w5;

    const/4 v13, 0x4

    invoke-direct {v12, v5, v13}, Llyiahf/vczjk/w5;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v12, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v11, v12}, Landroidx/compose/ui/layout/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v11

    const v12, -0x48fade91

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v12

    and-int/lit8 v0, v0, 0x70

    const/4 v13, 0x1

    if-ne v0, v1, :cond_5

    move v0, v13

    goto :goto_2

    :cond_5
    move v0, v8

    :goto_2
    or-int/2addr v0, v12

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_6

    if-ne v1, v9, :cond_7

    :cond_6
    new-instance v0, Llyiahf/vczjk/lt6;

    move-wide v14, v2

    move v2, v4

    move-wide v3, v14

    move/from16 v1, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/lt6;-><init>(FFJLlyiahf/vczjk/qs5;)V

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v1, v0

    :cond_7
    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-virtual {v6, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v11, v1}, Landroidx/compose/ui/draw/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v1, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v1

    iget v2, v6, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    invoke-static {v6, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v0

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_8

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_8
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v1, v6, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v3, v6, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v3, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_9

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_a

    :cond_9
    invoke-static {v2, v6, v2, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v1, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v0, v6, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v0, 0x6

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    move-object/from16 v1, p5

    invoke-virtual {v1, v6, v0}, Llyiahf/vczjk/a91;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v6, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_b

    new-instance v0, Llyiahf/vczjk/j31;

    move/from16 v5, p1

    move-wide/from16 v2, p3

    move-object v6, v1

    move v4, v7

    move-object v1, v10

    move/from16 v7, p2

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/j31;-><init>(Llyiahf/vczjk/kl5;JFFLlyiahf/vczjk/a91;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_b
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/qs5;Llyiahf/vczjk/oy7;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 9

    check-cast p4, Llyiahf/vczjk/zf1;

    const v0, 0x4ec119be

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p5, 0x6

    if-nez v0, :cond_1

    invoke-virtual {p4, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, p5

    goto :goto_1

    :cond_1
    move v0, p5

    :goto_1
    and-int/lit8 v1, p5, 0x30

    if-nez v1, :cond_3

    invoke-virtual {p4, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/16 v1, 0x20

    goto :goto_2

    :cond_2
    const/16 v1, 0x10

    :goto_2
    or-int/2addr v0, v1

    :cond_3
    and-int/lit16 v1, p5, 0x180

    if-nez v1, :cond_5

    invoke-virtual {p4, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    const/16 v1, 0x100

    goto :goto_3

    :cond_4
    const/16 v1, 0x80

    :goto_3
    or-int/2addr v0, v1

    :cond_5
    and-int/lit16 v1, p5, 0xc00

    const/16 v2, 0x800

    if-nez v1, :cond_7

    invoke-virtual {p4, p3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_6

    move v1, v2

    goto :goto_4

    :cond_6
    const/16 v1, 0x400

    :goto_4
    or-int/2addr v0, v1

    :cond_7
    and-int/lit16 v1, v0, 0x493

    const/16 v3, 0x492

    if-ne v1, v3, :cond_9

    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_8

    goto :goto_5

    :cond_8
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_7

    :cond_9
    :goto_5
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {p4, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/content/Context;

    new-instance v3, Llyiahf/vczjk/ah5;

    sget v4, Lgithub/tornaco/android/thanos/res/R$string;->menu_title_copy:I

    invoke-static {v4, p4}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v4

    sget v5, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_file_copy_fill:I

    const-string v6, "copy"

    invoke-direct {v3, v6, v4, v5}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v4, Llyiahf/vczjk/ah5;

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->service_stop:I

    invoke-static {v5, p4}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    sget v6, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_close_fill:I

    const-string v7, "stop"

    invoke-direct {v4, v7, v5, v6}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v5, Llyiahf/vczjk/ah5;

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_add_to_global_var:I

    invoke-static {v6, p4}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v6

    sget v7, Lgithub/tornaco/android/thanos/R$drawable;->ic_baseline_code_24:I

    const-string v8, "addToGlobalVar"

    invoke-direct {v5, v8, v6, v7}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    filled-new-array {v3, v4, v5}, [Llyiahf/vczjk/ah5;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v3

    const v4, -0x48fade91

    invoke-virtual {p4, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p4, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {p4, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    invoke-virtual {p4, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v4, v5

    and-int/lit16 v5, v0, 0x1c00

    const/4 v6, 0x0

    if-ne v5, v2, :cond_a

    const/4 v2, 0x1

    goto :goto_6

    :cond_a
    move v2, v6

    :goto_6
    or-int/2addr v2, v4

    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_b

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v4, v2, :cond_c

    :cond_b
    new-instance v4, Llyiahf/vczjk/m60;

    invoke-direct {v4, p1, p2, v1, p3}, Llyiahf/vczjk/m60;-><init>(Llyiahf/vczjk/oy7;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Landroid/content/Context;Llyiahf/vczjk/le3;)V

    invoke-virtual {p4, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_c
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-virtual {p4, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    and-int/lit8 v0, v0, 0xe

    invoke-static {p0, v3, v4, p4, v0}, Llyiahf/vczjk/so8;->OooO0o0(Llyiahf/vczjk/qs5;Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_7
    invoke-virtual {p4}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p4

    if-eqz p4, :cond_d

    new-instance v0, Llyiahf/vczjk/wz;

    const/4 v6, 0x3

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move v5, p5

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/wz;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p4, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_d
    return-void
.end method

.method public static final OooO0OO(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/ls1;Llyiahf/vczjk/oy7;Llyiahf/vczjk/rf1;I)V
    .locals 62

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v0, p2

    move-object/from16 v6, p4

    check-cast v6, Llyiahf/vczjk/zf1;

    const v3, -0x2d6fc52f

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v6, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/4 v11, 0x2

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v11

    :goto_0
    or-int v3, p5, v3

    invoke-virtual {v6, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    const/16 v4, 0x20

    goto :goto_1

    :cond_1
    const/16 v4, 0x10

    :goto_1
    or-int/2addr v3, v4

    invoke-virtual {v6, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x100

    goto :goto_2

    :cond_2
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v3, v4

    move-object/from16 v12, p3

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_3

    const/16 v4, 0x800

    goto :goto_3

    :cond_3
    const/16 v4, 0x400

    :goto_3
    or-int v13, v3, v4

    and-int/lit16 v3, v13, 0x493

    const/16 v4, 0x492

    if-ne v3, v4, :cond_5

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v8, v6

    goto/16 :goto_1a

    :cond_5
    :goto_4
    const v3, 0x6e3c21fe

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    sget-object v14, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v3, v14, :cond_6

    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v3

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    move-object v15, v3

    check-cast v15, Llyiahf/vczjk/qs5;

    const/4 v3, 0x0

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v4, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v6, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Landroid/content/Context;

    invoke-static {v4}, Llyiahf/vczjk/zsa;->o00ooo(Landroid/content/Context;)Landroidx/appcompat/app/AppCompatActivity;

    move-result-object v4

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v14, :cond_7

    invoke-static {v6}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v7

    invoke-virtual {v6, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v7, Llyiahf/vczjk/xr1;

    iget-object v8, v2, Lnow/fortuitous/thanos/process/v2/RunningProcessState;->OooOOO:Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;

    iget v9, v8, Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;->importance:I

    const/16 v10, 0x190

    if-ne v9, v10, :cond_8

    const/16 v26, 0x1

    goto :goto_5

    :cond_8
    move/from16 v26, v3

    :goto_5
    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v10, 0x3f800000    # 1.0f

    invoke-static {v9, v10}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v10

    const/16 v12, 0x48

    int-to-float v12, v12

    const/4 v5, 0x0

    invoke-static {v10, v12, v5, v11}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v10

    const v12, 0x4c5de2

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    if-ne v12, v14, :cond_9

    new-instance v12, Llyiahf/vczjk/a67;

    const/4 v5, 0x2

    invoke-direct {v12, v15, v5}, Llyiahf/vczjk/a67;-><init>(Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v6, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v12, Llyiahf/vczjk/le3;

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v10, v12}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v5

    const/16 v10, 0x10

    int-to-float v10, v10

    const/4 v12, 0x0

    invoke-static {v5, v10, v12, v11}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v10, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v12, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    invoke-static {v10, v12, v6, v3}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v11

    iget v3, v6, Llyiahf/vczjk/zf1;->Oooo:I

    move-object/from16 v18, v4

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v6, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v19, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v19 .. v19}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move/from16 v19, v13

    sget-object v13, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v20, v7

    iget-boolean v7, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_a

    invoke-virtual {v6, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_a
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v11, v6, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v6, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move-object/from16 v21, v14

    iget-boolean v14, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v14, :cond_b

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    move-object/from16 v22, v15

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-static {v14, v15}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-nez v14, :cond_c

    goto :goto_7

    :cond_b
    move-object/from16 v22, v15

    :goto_7
    invoke-static {v3, v6, v3, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v6, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v3, 0x0

    invoke-static {v10, v12, v6, v3}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v10, v6, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v6, v9}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v23, v12

    iget-boolean v12, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_d

    invoke-virtual {v6, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_8

    :cond_d
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_8
    invoke-static {v5, v6, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v15, v6, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v5, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v5, :cond_e

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    invoke-static {v10}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v12

    invoke-static {v5, v12}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-nez v5, :cond_f

    :cond_e
    invoke-static {v10, v6, v10, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_f
    invoke-static {v3, v6, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v3, 0xc

    int-to-float v12, v3

    invoke-static {v9, v12}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-static {v6, v3}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v15, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v3, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v5, 0x30

    invoke-static {v3, v15, v6, v5}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v10

    iget v5, v6, Llyiahf/vczjk/zf1;->Oooo:I

    move-object/from16 v25, v3

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v3

    move/from16 v27, v12

    invoke-static {v6, v9}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v12

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v28, v15

    iget-boolean v15, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_10

    invoke-virtual {v6, v13}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_9

    :cond_10
    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_9
    invoke-static {v10, v6, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v3, v6, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v3, v6, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v3, :cond_11

    invoke-virtual {v6}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v3, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_12

    :cond_11
    invoke-static {v5, v6, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_12
    invoke-static {v12, v6, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v3, 0x78bf33c0

    invoke-virtual {v6, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v3, v8, Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;->processName:Ljava/lang/String;

    iget-object v5, v2, Lnow/fortuitous/thanos/process/v2/RunningProcessState;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v5

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_13

    const/16 v3, 0x12

    int-to-float v3, v3

    invoke-static {v9, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {}, Llyiahf/vczjk/qqa;->Oooo000()Llyiahf/vczjk/qv3;

    move-result-object v3

    move-object v10, v4

    const-string v4, "Main process"

    move-object v15, v7

    move-object v12, v8

    move-object v8, v6

    const-wide/16 v6, 0x0

    move-object/from16 v29, v9

    const/16 v9, 0x1b0

    move-object/from16 v30, v10

    const/16 v10, 0x8

    move-object/from16 v32, v15

    move-object/from16 v34, v25

    move-object/from16 v31, v29

    move-object/from16 v33, v30

    move-object v15, v12

    const/4 v12, 0x0

    invoke-static/range {v3 .. v10}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    invoke-static {v12, v8}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    goto :goto_a

    :cond_13
    move-object/from16 v33, v4

    move-object/from16 v32, v7

    move-object v15, v8

    move-object/from16 v31, v9

    move-object/from16 v34, v25

    const/4 v12, 0x0

    move-object v8, v6

    :goto_a
    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v3, Llyiahf/vczjk/s4;->OooO00o:Llyiahf/vczjk/go3;

    new-instance v4, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    invoke-direct {v4, v3}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Llyiahf/vczjk/go3;)V

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->runningservicedetails_processes_title:I

    invoke-static {v5, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v8, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/n6a;

    iget-object v7, v7, Llyiahf/vczjk/n6a;->OooO0oO:Llyiahf/vczjk/rn9;

    move-object/from16 v9, v20

    const/16 v20, 0x0

    move-object/from16 v10, v23

    const/16 v23, 0x0

    move-object/from16 v17, v3

    move-object v3, v5

    move-object/from16 v24, v6

    const-wide/16 v5, 0x0

    move-object/from16 v29, v21

    move-object/from16 v25, v22

    move-object/from16 v21, v7

    move-object/from16 v22, v8

    const-wide/16 v7, 0x0

    move-object/from16 v30, v9

    const/4 v9, 0x0

    move-object/from16 v36, v10

    const/4 v10, 0x0

    move-object/from16 v38, v11

    move/from16 v37, v12

    const-wide/16 v11, 0x0

    move-object/from16 v39, v13

    const/4 v13, 0x0

    move-object/from16 v41, v14

    move-object/from16 v40, v15

    const-wide/16 v14, 0x0

    const/16 v42, 0x2

    const/16 v16, 0x0

    move-object/from16 v43, v17

    const/16 v17, 0x0

    move-object/from16 v44, v18

    const/16 v18, 0x0

    move/from16 v45, v19

    const/16 v19, 0x0

    move-object/from16 v46, v24

    const/16 v24, 0x0

    move-object/from16 v47, v25

    const v25, 0x1fffc

    move/from16 v53, v27

    move-object/from16 v1, v28

    move-object/from16 v48, v29

    move-object/from16 v50, v30

    move-object/from16 v52, v36

    move-object/from16 v0, v39

    move-object/from16 v2, v43

    move-object/from16 v49, v44

    move-object/from16 v54, v46

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v8, v22

    new-instance v3, Landroidx/compose/foundation/layout/WithAlignmentLineElement;

    invoke-direct {v3, v2}, Landroidx/compose/foundation/layout/WithAlignmentLineElement;-><init>(Llyiahf/vczjk/go3;)V

    move-object/from16 v2, v34

    const/16 v4, 0x30

    invoke-static {v2, v1, v8, v4}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v5

    iget v6, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v8, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_14

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_b
    move-object/from16 v9, v32

    goto :goto_c

    :cond_14
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_b

    :goto_c
    invoke-static {v5, v8, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v5, v38

    invoke-static {v7, v8, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v7, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v7, :cond_15

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v7, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_16

    :cond_15
    move-object/from16 v7, v33

    goto :goto_e

    :cond_16
    move-object/from16 v7, v33

    :goto_d
    move-object/from16 v6, v41

    goto :goto_f

    :goto_e
    invoke-static {v6, v8, v6, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_d

    :goto_f
    invoke-static {v3, v8, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v3, v40

    iget v10, v3, Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;->pid:I

    const-string v11, " (id: "

    const-string v12, ")"

    invoke-static {v10, v11, v12}, Llyiahf/vczjk/ii5;->OooO0o(ILjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    move-object/from16 v11, v54

    invoke-virtual {v8, v11}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/n6a;

    iget-object v12, v12, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v20, 0x0

    const/16 v23, 0x0

    move/from16 v35, v4

    const/4 v4, 0x0

    move-object/from16 v38, v5

    move-object/from16 v41, v6

    const-wide/16 v5, 0x0

    move-object/from16 v30, v7

    move-object/from16 v22, v8

    const-wide/16 v7, 0x0

    move-object v15, v9

    const/4 v9, 0x0

    move-object/from16 v40, v3

    move-object v3, v10

    const/4 v10, 0x0

    move-object/from16 v46, v11

    move-object/from16 v21, v12

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    move-object/from16 v32, v15

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v24, 0x0

    const v25, 0x1fffe

    move-object/from16 v39, v0

    move-object/from16 v57, v30

    move-object/from16 v55, v32

    move-object/from16 v56, v38

    move-object/from16 v0, v40

    move-object/from16 v58, v41

    move-object/from16 v59, v46

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v8, v22

    const/4 v12, 0x0

    invoke-static {v12, v8}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v3, p1

    iget-object v4, v3, Lnow/fortuitous/thanos/process/v2/RunningProcessState;->OooOOOo:Ljava/lang/String;

    const/4 v5, 0x0

    const/4 v6, 0x2

    invoke-static {v12, v6, v4, v8, v5}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    iget v4, v0, Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;->pid:I

    int-to-long v6, v4

    invoke-static {v6, v7}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    move-object/from16 v6, p2

    iget-object v7, v6, Llyiahf/vczjk/ls1;->OooO00o:Ljava/lang/Object;

    invoke-interface {v7, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Lgithub/tornaco/android/thanos/core/app/usage/ProcessCpuUsageStats;

    const v7, -0x1958938

    invoke-virtual {v8, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-nez v4, :cond_17

    const/4 v12, 0x0

    :goto_10
    const/4 v4, 0x1

    goto :goto_11

    :cond_17
    const/4 v12, 0x0

    invoke-static {v12, v8}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    iget-object v4, v4, Lgithub/tornaco/android/thanos/core/app/usage/ProcessCpuUsageStats;->cpuRatioString:Ljava/lang/String;

    const-string v7, "CPU "

    const-string v9, "%"

    invoke-static {v7, v4, v9}, Llyiahf/vczjk/u81;->OooOOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    const/4 v7, 0x2

    invoke-static {v12, v7, v4, v8, v5}, Llyiahf/vczjk/nqa;->OooO0o0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    goto :goto_10

    :goto_11
    invoke-static {v8, v12, v4, v4}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    move-object/from16 v7, v31

    move/from16 v9, v53

    invoke-static {v7, v9}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v10

    invoke-static {v8, v10}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const/16 v10, 0x30

    invoke-static {v2, v1, v8, v10}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v1

    iget v2, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v8, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_18

    move-object/from16 v12, v39

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_12
    move-object/from16 v15, v55

    goto :goto_13

    :cond_18
    move-object/from16 v12, v39

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_12

    :goto_13
    invoke-static {v1, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v1, v56

    invoke-static {v10, v8, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v10, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_19

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v10, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_1a

    :cond_19
    move-object/from16 v10, v57

    goto :goto_15

    :cond_1a
    move-object/from16 v10, v57

    :goto_14
    move-object/from16 v2, v58

    goto :goto_16

    :goto_15
    invoke-static {v2, v8, v2, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_14

    :goto_16
    invoke-static {v11, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v11, 0x2a

    int-to-float v11, v11

    invoke-static {v7, v11}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v11

    shl-int/lit8 v13, v45, 0x3

    and-int/lit8 v14, v13, 0x70

    const/4 v6, 0x6

    or-int/2addr v14, v6

    move/from16 v27, v9

    move-object/from16 v9, p0

    invoke-static {v11, v9, v8, v14}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    const/16 v11, 0x8

    int-to-float v11, v11

    invoke-static {v7, v11}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v11

    invoke-static {v8, v11}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    sget-object v11, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    move-object/from16 v14, v52

    invoke-static {v11, v14, v8, v6}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v11

    iget v14, v8, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v8, v7}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_1b

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_17

    :cond_1b
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_17
    invoke-static {v11, v8, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v6, v8, v1}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v1, v8, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_1c

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1d

    :cond_1c
    invoke-static {v14, v8, v14, v10}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1d
    invoke-static {v4, v8, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v0, v0, Lgithub/tornaco/android/thanos/core/app/RunningAppProcessInfoCompat;->processName:Ljava/lang/String;

    const-string v1, "processName"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v1, 0x0

    const/4 v4, 0x1

    const/4 v12, 0x0

    invoke-static {v12, v4, v0, v8, v1}, Llyiahf/vczjk/os9;->OooO0O0(IILjava/lang/String;Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    invoke-static {v12, v8}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    if-eqz v26, :cond_1e

    const v0, -0x1898d4c6

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->cached:I

    invoke-static {v0, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v0

    :goto_18
    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v11, v59

    goto :goto_19

    :cond_1e
    const v0, -0x1898caff

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->running_process_running:I

    invoke-static {v0, v8}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v0

    goto :goto_18

    :goto_19
    invoke-virtual {v8, v11}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v1, v1, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v20, 0x0

    const/16 v23, 0x0

    move/from16 v51, v4

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    move-object/from16 v29, v7

    move-object/from16 v22, v8

    const-wide/16 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const-wide/16 v11, 0x0

    move v2, v13

    const/4 v13, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v24, 0x0

    const v25, 0x1fffe

    move-object/from16 v21, v1

    move/from16 v61, v2

    move-object v2, v3

    move/from16 v60, v27

    move-object/from16 v1, v29

    const/16 v26, 0x6

    move-object v3, v0

    move/from16 v0, v51

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v8, v22

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move/from16 v9, v60

    invoke-static {v1, v9}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-static {v8, v1}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    const v1, -0x6815fd56

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    move-object/from16 v9, v50

    invoke-virtual {v8, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    move-object/from16 v3, v49

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v1, v4

    invoke-virtual {v8, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v1, v4

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_1f

    move-object/from16 v1, v48

    if-ne v4, v1, :cond_20

    :cond_1f
    new-instance v4, Llyiahf/vczjk/x5;

    const/16 v1, 0xd

    invoke-direct {v4, v9, v3, v1, v2}, Llyiahf/vczjk/x5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-virtual {v8, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_20
    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/le3;

    const/4 v12, 0x0

    invoke-virtual {v8, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    shr-int/lit8 v1, v45, 0x6

    and-int/lit8 v1, v1, 0x70

    or-int/lit8 v1, v1, 0x6

    move/from16 v3, v61

    and-int/lit16 v3, v3, 0x380

    or-int v7, v1, v3

    move-object/from16 v3, p3

    move-object v4, v2

    move-object v6, v8

    move-object/from16 v2, v47

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/mt6;->OooO0O0(Llyiahf/vczjk/qs5;Llyiahf/vczjk/oy7;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v8, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1a
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v7

    if-eqz v7, :cond_21

    new-instance v0, Llyiahf/vczjk/d5;

    const/16 v6, 0xa

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move/from16 v5, p5

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/d5;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v7, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_21
    return-void
.end method

.method public static final OooO0Oo(Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 9

    const-string v0, "details"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "closeSetResult"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object v5, p2

    check-cast v5, Llyiahf/vczjk/zf1;

    const p2, 0x62b850f5    # 1.7000172E21f

    invoke-virtual {v5, p2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v5, p0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_0

    const/4 p2, 0x4

    goto :goto_0

    :cond_0
    const/4 p2, 0x2

    :goto_0
    or-int/2addr p2, p3

    invoke-virtual {v5, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/16 v1, 0x20

    if-eqz v0, :cond_1

    move v0, v1

    goto :goto_1

    :cond_1
    const/16 v0, 0x10

    :goto_1
    or-int/2addr p2, v0

    and-int/lit8 v0, p2, 0x13

    const/16 v2, 0x12

    if-ne v0, v2, :cond_3

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_5

    :cond_3
    :goto_2
    const v0, 0x70b323c8

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    invoke-static {v5}, Llyiahf/vczjk/c45;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/lha;

    move-result-object v0

    if-eqz v0, :cond_b

    invoke-static {v0, v5}, Llyiahf/vczjk/mc4;->OooOo0O(Llyiahf/vczjk/lha;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/sn3;

    move-result-object v2

    const v3, 0x671a9c9b

    invoke-virtual {v5, v3}, Llyiahf/vczjk/zf1;->OoooOO0(I)V

    instance-of v3, v0, Llyiahf/vczjk/om3;

    if-eqz v3, :cond_4

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/om3;

    invoke-interface {v3}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object v3

    goto :goto_3

    :cond_4
    sget-object v3, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    :goto_3
    const-class v4, Llyiahf/vczjk/oy7;

    invoke-static {v4, v0, v2, v3, v5}, Llyiahf/vczjk/eo6;->OooOooO(Ljava/lang/Class;Llyiahf/vczjk/lha;Llyiahf/vczjk/sn3;Llyiahf/vczjk/os1;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/dha;

    move-result-object v0

    const/4 v2, 0x0

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/oy7;

    invoke-static {}, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->getLocalLifecycleOwner()Landroidx/compose/runtime/OooO;

    move-result-object v0

    invoke-virtual {v5, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uy4;

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    invoke-virtual {v3, v0}, Llyiahf/vczjk/fy4;->OooO0o0(Llyiahf/vczjk/ky4;)V

    iget-object v0, v3, Llyiahf/vczjk/oy7;->OooO0oO:Llyiahf/vczjk/gh7;

    invoke-static {v0, v5}, Landroidx/compose/runtime/OooO0o;->OooO0O0(Llyiahf/vczjk/q29;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qs5;

    move-result-object v0

    const v4, -0x615d173a

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v5, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    move v6, v1

    iget-object v1, p0, Lnow/fortuitous/thanos/process/v2/RunningAppStateDetails;->OooOOO0:Lnow/fortuitous/thanos/process/v2/RunningAppState;

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    or-int/2addr v4, v7

    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v4, :cond_5

    if-ne v7, v8, :cond_6

    :cond_5
    new-instance v7, Llyiahf/vczjk/xy7;

    const/4 v4, 0x0

    invoke-direct {v7, v3, v1, v4}, Llyiahf/vczjk/xy7;-><init>(Llyiahf/vczjk/oy7;Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v5, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v7, Llyiahf/vczjk/ze3;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v3, v5, v7}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/hy7;

    iget-object v0, v0, Llyiahf/vczjk/hy7;->OooO00o:Llyiahf/vczjk/ls1;

    const v4, 0x4c5de2

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 p2, p2, 0x70

    if-ne p2, v6, :cond_7

    const/4 p2, 0x1

    goto :goto_4

    :cond_7
    move p2, v2

    :goto_4
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez p2, :cond_8

    if-ne v4, v8, :cond_9

    :cond_8
    new-instance v4, Llyiahf/vczjk/fi2;

    const/4 p2, 0x2

    invoke-direct {v4, p1, p2}, Llyiahf/vczjk/fi2;-><init>(Llyiahf/vczjk/oe3;I)V

    invoke-virtual {v5, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_9
    check-cast v4, Llyiahf/vczjk/oe3;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v6, 0x0

    move-object v2, v0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/mt6;->OooO0o0(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/ls1;Llyiahf/vczjk/oy7;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_5
    invoke-virtual {v5}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p2

    if-eqz p2, :cond_a

    new-instance v0, Llyiahf/vczjk/e2;

    const/16 v1, 0x1c

    invoke-direct {v0, p0, p1, p3, v1}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, p2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_a
    return-void

    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "No ViewModelStoreOwner was provided via LocalViewModelStoreOwner"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/qs5;Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/oy7;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 16

    move-object/from16 v2, p1

    move-object/from16 v1, p2

    move-object/from16 v7, p5

    check-cast v7, Llyiahf/vczjk/zf1;

    const v0, 0x78421bfd

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/16 v0, 0x20

    goto :goto_0

    :cond_0
    const/16 v0, 0x10

    :goto_0
    or-int v0, p6, v0

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/16 v3, 0x100

    goto :goto_1

    :cond_1
    const/16 v3, 0x80

    :goto_1
    or-int/2addr v0, v3

    move-object/from16 v4, p3

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    const/16 v5, 0x800

    if-eqz v3, :cond_2

    move v3, v5

    goto :goto_2

    :cond_2
    const/16 v3, 0x400

    :goto_2
    or-int/2addr v0, v3

    move-object/from16 v3, p4

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    const/16 v8, 0x4000

    if-eqz v6, :cond_3

    move v6, v8

    goto :goto_3

    :cond_3
    const/16 v6, 0x2000

    :goto_3
    or-int/2addr v0, v6

    and-int/lit16 v6, v0, 0x2493

    const/16 v9, 0x2492

    if-ne v6, v9, :cond_5

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v6

    if-nez v6, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v1, p0

    goto/16 :goto_7

    :cond_5
    :goto_4
    sget-object v6, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/content/Context;

    new-instance v9, Llyiahf/vczjk/ah5;

    sget v10, Lgithub/tornaco/android/thanos/res/R$string;->menu_title_copy:I

    invoke-static {v10, v7}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v10

    sget v11, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_file_copy_fill:I

    const-string v12, "copy"

    invoke-direct {v9, v12, v10, v11}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v10, Llyiahf/vczjk/ah5;

    sget v11, Lgithub/tornaco/android/thanos/res/R$string;->service_stop:I

    invoke-static {v11, v7}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v11

    sget v12, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_close_fill:I

    const-string v13, "stop"

    invoke-direct {v10, v13, v11, v12}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v11, Llyiahf/vczjk/ah5;

    sget v12, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_add_to_global_var:I

    invoke-static {v12, v7}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v12

    sget v13, Lgithub/tornaco/android/thanos/R$drawable;->ic_baseline_code_24:I

    const-string v14, "addToGlobalVar"

    invoke-direct {v11, v14, v12, v13}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    new-instance v12, Llyiahf/vczjk/ah5;

    sget v13, Lgithub/tornaco/android/thanos/res/R$string;->module_component_manager_keep_service_smart_standby:I

    invoke-static {v13, v7}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v13

    sget v14, Lgithub/tornaco/android/thanos/R$drawable;->ic_mickey_line:I

    const-string v15, "addToSmartStandByKeeps"

    invoke-direct {v12, v15, v13, v14}, Llyiahf/vczjk/ah5;-><init>(Ljava/lang/String;Ljava/lang/String;I)V

    filled-new-array {v9, v10, v11, v12}, [Llyiahf/vczjk/ah5;

    move-result-object v9

    invoke-static {v9}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    const v10, -0x48fade91

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v10, v11

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v11

    or-int/2addr v10, v11

    and-int/lit16 v11, v0, 0x1c00

    const/4 v12, 0x0

    const/4 v13, 0x1

    if-ne v11, v5, :cond_6

    move v5, v13

    goto :goto_5

    :cond_6
    move v5, v12

    :goto_5
    or-int/2addr v5, v10

    const v10, 0xe000

    and-int/2addr v0, v10

    if-ne v0, v8, :cond_7

    goto :goto_6

    :cond_7
    move v13, v12

    :goto_6
    or-int v0, v5, v13

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez v0, :cond_8

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v0, :cond_9

    :cond_8
    new-instance v0, Llyiahf/vczjk/v20;

    move-object v3, v6

    const/4 v6, 0x3

    move-object/from16 v5, p4

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/v20;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v5, v0

    :cond_9
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-virtual {v7, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v0, 0x6

    move-object/from16 v1, p0

    invoke-static {v1, v9, v5, v7, v0}, Llyiahf/vczjk/so8;->OooO0o0(Llyiahf/vczjk/qs5;Ljava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    :goto_7
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_a

    new-instance v0, Llyiahf/vczjk/nu3;

    const/4 v7, 0x4

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move/from16 v6, p6

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/nu3;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_a
    return-void
.end method

.method public static final OooO0o0(Lnow/fortuitous/thanos/process/v2/RunningAppState;Llyiahf/vczjk/ls1;Llyiahf/vczjk/oy7;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 19

    move-object/from16 v1, p0

    move-object/from16 v2, p2

    move-object/from16 v3, p3

    move-object/from16 v9, p4

    check-cast v9, Llyiahf/vczjk/zf1;

    const v0, 0x310a1658

    invoke-virtual {v9, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v9, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int v0, p5, v0

    move-object/from16 v4, p1

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    const/16 v5, 0x20

    goto :goto_1

    :cond_1
    const/16 v5, 0x10

    :goto_1
    or-int/2addr v0, v5

    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x100

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v0, v5

    invoke-virtual {v9, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v12, 0x800

    if-eqz v5, :cond_3

    move v5, v12

    goto :goto_3

    :cond_3
    const/16 v5, 0x400

    :goto_3
    or-int/2addr v0, v5

    and-int/lit16 v5, v0, 0x493

    const/16 v6, 0x492

    if-ne v5, v6, :cond_5

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v15, v2

    goto/16 :goto_9

    :cond_5
    :goto_4
    sget-object v5, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/content/Context;

    new-instance v6, Llyiahf/vczjk/f5;

    const/16 v7, 0x1b

    invoke-direct {v6, v1, v7}, Llyiahf/vczjk/f5;-><init>(Ljava/lang/Object;I)V

    const v7, 0x2f9430a3

    invoke-static {v7, v6, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v6

    new-instance v7, Llyiahf/vczjk/r6;

    const/16 v8, 0x15

    invoke-direct {v7, v8, v5, v1}, Llyiahf/vczjk/r6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const v5, 0x64013eda

    invoke-static {v5, v7, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v7

    const v13, -0x615d173a

    invoke-virtual {v9, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit16 v14, v0, 0x1c00

    const/4 v8, 0x0

    if-ne v14, v12, :cond_6

    const/4 v0, 0x1

    goto :goto_5

    :cond_6
    move v0, v8

    :goto_5
    invoke-virtual {v9, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    or-int/2addr v0, v5

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v0, :cond_7

    if-ne v5, v10, :cond_8

    :cond_7
    new-instance v5, Llyiahf/vczjk/uy7;

    const/4 v0, 0x0

    invoke-direct {v5, v3, v2, v0}, Llyiahf/vczjk/uy7;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oy7;I)V

    invoke-virtual {v9, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    move-object v11, v5

    check-cast v11, Llyiahf/vczjk/le3;

    invoke-virtual {v9, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v0, Llyiahf/vczjk/a6;

    const/16 v5, 0xc

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/a6;-><init>(Landroid/os/Parcelable;Llyiahf/vczjk/fy4;Llyiahf/vczjk/oe3;Ljava/lang/Object;I)V

    const v1, -0x386d2767

    invoke-static {v1, v0, v9}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    move-object v1, v6

    const/4 v6, 0x0

    move-object v2, v7

    const/4 v7, 0x0

    move v3, v8

    move-object v8, v0

    const/4 v0, 0x0

    move v4, v3

    const/4 v3, 0x0

    const/4 v5, 0x0

    move-object/from16 v16, v10

    const v10, 0x60001b0

    move/from16 v17, v4

    move-object v4, v11

    const/16 v11, 0xe9

    move-object/from16 v15, p2

    move-object/from16 v18, v16

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/xr6;->OooO0Oo(Llyiahf/vczjk/hl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/a91;Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/hb8;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    invoke-virtual {v9, v13}, Llyiahf/vczjk/zf1;->OoooO(I)V

    if-ne v14, v12, :cond_9

    const/4 v8, 0x1

    goto :goto_6

    :cond_9
    const/4 v8, 0x0

    :goto_6
    invoke-virtual {v9, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr v0, v8

    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_b

    move-object/from16 v0, v18

    if-ne v1, v0, :cond_a

    goto :goto_7

    :cond_a
    move-object/from16 v3, p3

    goto :goto_8

    :cond_b
    :goto_7
    new-instance v1, Llyiahf/vczjk/uy7;

    const/4 v0, 0x1

    move-object/from16 v3, p3

    invoke-direct {v1, v3, v15, v0}, Llyiahf/vczjk/uy7;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oy7;I)V

    invoke-virtual {v9, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_8
    check-cast v1, Llyiahf/vczjk/le3;

    const/4 v4, 0x0

    invoke-virtual {v9, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v0, 0x1

    invoke-static {v4, v1, v9, v4, v0}, Llyiahf/vczjk/c6a;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V

    :goto_9
    invoke-virtual {v9}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v7

    if-eqz v7, :cond_c

    new-instance v0, Llyiahf/vczjk/d5;

    const/16 v6, 0x8

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v5, p5

    move-object v4, v3

    move-object v3, v15

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/d5;-><init>(Landroid/os/Parcelable;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v7, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_c
    return-void
.end method

.method public static final OooO0oO(Lnow/fortuitous/thanos/process/v2/RunningService;Llyiahf/vczjk/rf1;I)V
    .locals 25

    move-object/from16 v0, p0

    move/from16 v1, p2

    move-object/from16 v2, p1

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0xf574dac

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v3, v1, 0x6

    const/4 v4, 0x2

    if-nez v3, :cond_1

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    or-int/2addr v3, v1

    goto :goto_1

    :cond_1
    move v3, v1

    :goto_1
    and-int/lit8 v3, v3, 0x3

    if-ne v3, v4, :cond_4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_3
    move-object/from16 v21, v2

    goto/16 :goto_4

    :cond_4
    :goto_2
    iget-object v3, v0, Lnow/fortuitous/thanos/process/v2/RunningService;->OooOOO0:Landroid/app/ActivityManager$RunningServiceInfo;

    iget-wide v4, v3, Landroid/app/ActivityManager$RunningServiceInfo;->restarting:J

    const-wide/16 v6, 0x0

    cmp-long v4, v4, v6

    if-nez v4, :cond_5

    iget-wide v3, v3, Landroid/app/ActivityManager$RunningServiceInfo;->activeSince:J

    goto :goto_3

    :cond_5
    const-wide/16 v3, -0x1

    :goto_3
    cmp-long v5, v3, v6

    if-lez v5, :cond_3

    const v5, 0x6e3c21fe

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v5, v6, :cond_6

    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    move-result-wide v7

    sub-long/2addr v7, v3

    const-wide/16 v3, 0x3e8

    div-long/2addr v7, v3

    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v3

    invoke-static {v3}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v5

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v5, Llyiahf/vczjk/qs5;

    const/4 v3, 0x0

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->longValue()J

    move-result-wide v7

    invoke-static {v7, v8}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    const v7, 0x4c5de2

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    const/4 v8, 0x0

    if-ne v7, v6, :cond_7

    new-instance v7, Llyiahf/vczjk/cz7;

    invoke-direct {v7, v5, v8}, Llyiahf/vczjk/cz7;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v7, Llyiahf/vczjk/ze3;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v4, v2, v7}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {v5}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->longValue()J

    move-result-wide v4

    invoke-static {v8, v4, v5}, Landroid/text/format/DateUtils;->formatElapsedTime(Ljava/lang/StringBuilder;J)Ljava/lang/String;

    move-result-object v4

    const v5, 0x6945b421

    invoke-virtual {v2, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Lnow/fortuitous/thanos/process/v2/RunningService;->OooOOOO:Ljava/lang/String;

    if-nez v5, :cond_8

    sget v5, Lgithub/tornaco/android/thanos/res/R$string;->service_started_by_app:I

    invoke-static {v5, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    :cond_8
    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->service_running_time:I

    invoke-static {v3, v2}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v3

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v5, " \u2022 "

    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, " "

    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

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

    :goto_4
    invoke-virtual/range {v21 .. v21}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v2

    if-eqz v2, :cond_9

    new-instance v3, Llyiahf/vczjk/ma2;

    const/4 v4, 0x5

    invoke-direct {v3, v1, v4, v0}, Llyiahf/vczjk/ma2;-><init>(IILjava/lang/Object;)V

    iput-object v3, v2, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_9
    return-void
.end method

.method public static final OooO0oo(Lnow/fortuitous/thanos/process/v2/RunningAppState;Lnow/fortuitous/thanos/process/v2/RunningProcessState;Llyiahf/vczjk/oy7;Llyiahf/vczjk/rf1;I)V
    .locals 32

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v11, p3

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, -0x262afb72

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    const/4 v4, 0x2

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v4

    :goto_0
    or-int v0, p4, v0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    const/16 v6, 0x10

    if-eqz v5, :cond_1

    const/16 v5, 0x20

    goto :goto_1

    :cond_1
    move v5, v6

    :goto_1
    or-int/2addr v0, v5

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x100

    goto :goto_2

    :cond_2
    const/16 v5, 0x80

    :goto_2
    or-int/2addr v0, v5

    and-int/lit16 v0, v0, 0x93

    const/16 v5, 0x92

    if-ne v0, v5, :cond_4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v14, v1

    goto/16 :goto_9

    :cond_4
    :goto_3
    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    sget-object v5, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v7, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v8, 0x0

    invoke-static {v5, v7, v11, v8}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v5

    iget v7, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v9

    invoke-static {v11, v0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v10

    sget-object v12, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v13, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v13, :cond_5

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_5
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v13, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v11, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v9, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v9, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v14, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v14, :cond_6

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v15

    invoke-static {v14, v15}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v14

    if-nez v14, :cond_7

    :cond_6
    invoke-static {v7, v11, v7, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_7
    sget-object v7, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v10, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v27, Llyiahf/vczjk/r31;->OooO00o:Llyiahf/vczjk/r31;

    iget-object v10, v2, Lnow/fortuitous/thanos/process/v2/RunningProcessState;->OooOOOO:Ljava/util/ArrayList;

    invoke-virtual {v10}, Ljava/util/ArrayList;->size()I

    move-result v28

    int-to-float v6, v6

    const/4 v14, 0x0

    invoke-static {v0, v6, v14, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO0(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v14, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    sget-object v15, Llyiahf/vczjk/tx;->OooO00o:Llyiahf/vczjk/ws7;

    const/16 v8, 0x30

    invoke-static {v15, v14, v11, v8}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v8

    iget v14, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v15

    invoke-static {v11, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v2, :cond_8

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_8
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    invoke-static {v8, v11, v13}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v15, v11, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_9

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v2, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_a

    :cond_9
    invoke-static {v14, v11, v14, v9}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    invoke-static {v4, v11, v7}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    if-lez v28, :cond_b

    const v2, -0x1c053f65

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->running_processes_item_description_s:I

    invoke-static/range {v28 .. v28}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v2, v4, v11}, Llyiahf/vczjk/vt6;->Oooo0O0(I[Ljava/lang/Object;Llyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    const/4 v4, 0x0

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_6

    :cond_b
    const/4 v4, 0x0

    const v2, -0x1c052894

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->runningservicedetails_services_title:I

    invoke-static {v2, v11}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_6
    sget-object v5, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/n6a;

    iget-object v12, v7, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v7, 0x12

    invoke-static {v7}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v15

    const/16 v24, 0x0

    const/16 v25, 0x0

    const-wide/16 v13, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const-wide/16 v20, 0x0

    const-wide/16 v22, 0x0

    const v26, 0xfffffd

    invoke-static/range {v12 .. v26}, Llyiahf/vczjk/rn9;->OooO00o(Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/ba3;JJLlyiahf/vczjk/vx6;Llyiahf/vczjk/jz4;I)Llyiahf/vczjk/rn9;

    move-result-object v22

    const/16 v21, 0x0

    const/16 v24, 0x0

    move-object v7, v5

    const/4 v5, 0x0

    move v8, v6

    move-object v9, v7

    const-wide/16 v6, 0x0

    move v12, v8

    move-object v13, v9

    const-wide/16 v8, 0x0

    move-object v14, v10

    const/4 v10, 0x0

    move-object/from16 v23, v11

    const/4 v11, 0x0

    move v15, v12

    move-object/from16 v16, v13

    const-wide/16 v12, 0x0

    move-object/from16 v17, v14

    const/4 v14, 0x0

    move/from16 v18, v15

    move-object/from16 v19, v16

    const-wide/16 v15, 0x0

    move-object/from16 v20, v17

    const/16 v17, 0x0

    move/from16 v25, v18

    const/16 v18, 0x0

    move-object/from16 v26, v19

    const/16 v19, 0x0

    move-object/from16 v29, v20

    const/16 v20, 0x0

    move/from16 v30, v25

    const/16 v25, 0x0

    move-object/from16 v31, v26

    const v26, 0x1fffe

    move-object v4, v2

    move/from16 v2, v30

    move-object/from16 v1, v31

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v23

    const/4 v4, 0x1

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v5, 0x8

    int-to-float v5, v5

    invoke-static {v0, v5}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v11, v5}, Llyiahf/vczjk/qu6;->OooO00o(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)V

    if-nez v28, :cond_c

    const v5, 0x1d3f98d7

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-static {v0, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->no_running_services:I

    invoke-static {v0, v11}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v1, v1, Llyiahf/vczjk/n6a;->OooO:Llyiahf/vczjk/rn9;

    const/16 v21, 0x0

    const/16 v24, 0x30

    const-wide/16 v6, 0x0

    const-wide/16 v8, 0x0

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

    const/16 v25, 0x0

    const v26, 0x1fffc

    move/from16 v22, v4

    move-object v4, v0

    move/from16 v0, v22

    move-object/from16 v22, v1

    invoke-static/range {v4 .. v26}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v23

    const/4 v4, 0x0

    invoke-virtual {v11, v4}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object/from16 v14, p0

    goto :goto_8

    :cond_c
    move v0, v4

    const v1, 0x1d43a966

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual/range {v29 .. v29}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_d

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lnow/fortuitous/thanos/process/v2/RunningService;

    iget-object v4, v2, Lnow/fortuitous/thanos/process/v2/RunningService;->OooOOo:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    xor-int/lit8 v5, v4, 0x1

    new-instance v4, Llyiahf/vczjk/n6;

    const/16 v6, 0x13

    move-object/from16 v14, p0

    invoke-direct {v4, v14, v2, v6, v3}, Llyiahf/vczjk/n6;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    const v2, -0x580ab9fb

    invoke-static {v2, v4, v11}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v10

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const v12, 0x180006

    const/16 v13, 0x1e

    move-object/from16 v4, v27

    invoke-static/range {v4 .. v13}, Landroidx/compose/animation/OooO0O0;->OooO0O0(Llyiahf/vczjk/q31;ZLlyiahf/vczjk/kl5;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;Ljava/lang/String;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    goto :goto_7

    :cond_d
    const/4 v2, 0x0

    move-object/from16 v14, p0

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_8
    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_9
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_e

    new-instance v0, Llyiahf/vczjk/o0OO00OO;

    const/16 v5, 0xf

    move-object/from16 v2, p1

    move/from16 v4, p4

    move-object v1, v14

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/o0OO00OO;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_e
    return-void
.end method

.method public static final OooOO0(Llyiahf/vczjk/nr5;I)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/nr5;->OooO0O0:I

    if-eqz v0, :cond_1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v0

    if-eq v0, p1, :cond_0

    iget v0, p0, Llyiahf/vczjk/nr5;->OooO0O0:I

    add-int/lit8 v0, v0, -0x1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v0

    if-ne v0, p1, :cond_1

    :cond_0
    return-void

    :cond_1
    iget v0, p0, Llyiahf/vczjk/nr5;->OooO0O0:I

    invoke-virtual {p0, p1}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    :goto_0
    if-lez v0, :cond_2

    add-int/lit8 v1, v0, 0x1

    ushr-int/lit8 v1, v1, 0x1

    add-int/lit8 v1, v1, -0x1

    invoke-virtual {p0, v1}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v2

    if-le p1, v2, :cond_2

    invoke-virtual {p0, v0, v2}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    move v0, v1

    goto :goto_0

    :cond_2
    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    return-void
.end method

.method public static final OooOO0O(Ljava/lang/Object;Z)Ljava/lang/Object;
    .locals 1

    const-string v0, "possiblyPrimitiveType"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-eqz p1, :cond_0

    check-cast p0, Llyiahf/vczjk/af4;

    instance-of p1, p0, Llyiahf/vczjk/ze4;

    if-eqz p1, :cond_0

    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/ze4;

    iget-object p1, p1, Llyiahf/vczjk/ze4;->OooO:Llyiahf/vczjk/ee4;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/ee4;->OooO0o()Llyiahf/vczjk/hc3;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/rd4;->OooO0O0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/rd4;

    move-result-object p0

    invoke-virtual {p0}, Llyiahf/vczjk/rd4;->OooO0Oo()Ljava/lang/String;

    move-result-object p0

    const-string p1, "getInternalName(...)"

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/op3;->OooOO0(Ljava/lang/String;)Llyiahf/vczjk/ye4;

    move-result-object p0

    :cond_0
    return-object p0
.end method

.method public static final OooOO0o(Llyiahf/vczjk/n3a;)Ljava/lang/String;
    .locals 4

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "type: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/mt6;->OooOOO0(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "hashCode: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    move-result v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/mt6;->OooOOO0(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "javaClass: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/mt6;->OooOOO0(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object p0

    :goto_0
    if-eqz p0, :cond_0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v3, "fqName: "

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/h72;->OooO0OO:Llyiahf/vczjk/h72;

    invoke-virtual {v3, p0}, Llyiahf/vczjk/h72;->OooOo0o(Llyiahf/vczjk/v02;)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/mt6;->OooOOO0(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Llyiahf/vczjk/mt6;->OooOOO0(Ljava/lang/StringBuilder;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/v02;->OooOO0o()Llyiahf/vczjk/v02;

    move-result-object p0

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOOO(ILjava/lang/String;)I
    .locals 12

    invoke-static {}, Llyiahf/vczjk/rl2;->OooO0Oo()Z

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eqz v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/rl2;->OooO00o()Llyiahf/vczjk/rl2;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/rl2;->OooO0OO()I

    move-result v3

    if-ne v3, v2, :cond_0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_7

    invoke-virtual {v0}, Llyiahf/vczjk/rl2;->OooO0OO()I

    move-result v3

    const/4 v4, 0x0

    if-ne v3, v2, :cond_1

    goto :goto_1

    :cond_1
    move v2, v4

    :goto_1
    if-eqz v2, :cond_6

    const-string v2, "charSequence cannot be null"

    invoke-static {p1, v2}, Llyiahf/vczjk/br6;->OooOOO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/rl2;->OooO0o0:Llyiahf/vczjk/nl2;

    iget-object v5, v0, Llyiahf/vczjk/nl2;->OooO0O0:Llyiahf/vczjk/uqa;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, -0x1

    if-ltz p0, :cond_2

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v2

    if-lt p0, v2, :cond_3

    :cond_2
    move-object v6, p1

    goto :goto_2

    :cond_3
    instance-of v2, p1, Landroid/text/Spanned;

    if-eqz v2, :cond_4

    move-object v2, p1

    check-cast v2, Landroid/text/Spanned;

    add-int/lit8 v3, p0, 0x1

    const-class v6, Llyiahf/vczjk/b6a;

    invoke-interface {v2, p0, v3, v6}, Landroid/text/Spanned;->getSpans(IILjava/lang/Class;)[Ljava/lang/Object;

    move-result-object v3

    check-cast v3, [Llyiahf/vczjk/b6a;

    array-length v6, v3

    if-lez v6, :cond_4

    aget-object v3, v3, v4

    invoke-interface {v2, v3}, Landroid/text/Spanned;->getSpanEnd(Ljava/lang/Object;)I

    move-result v2

    move-object v6, p1

    goto :goto_3

    :cond_4
    add-int/lit8 v2, p0, -0x10

    invoke-static {v4, v2}, Ljava/lang/Math;->max(II)I

    move-result v7

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v2

    add-int/lit8 v3, p0, 0x10

    invoke-static {v2, v3}, Ljava/lang/Math;->min(II)I

    move-result v8

    new-instance v11, Llyiahf/vczjk/dm2;

    invoke-direct {v11, p0}, Llyiahf/vczjk/dm2;-><init>(I)V

    const v9, 0x7fffffff

    const/4 v10, 0x1

    move-object v6, p1

    invoke-virtual/range {v5 .. v11}, Llyiahf/vczjk/uqa;->OooOoOO(Ljava/lang/CharSequence;IIIZLlyiahf/vczjk/cm2;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dm2;

    iget v2, p1, Llyiahf/vczjk/dm2;->OooOOOO:I

    goto :goto_3

    :goto_2
    move v2, v0

    :goto_3
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    if-ne v2, v0, :cond_5

    goto :goto_4

    :cond_5
    move-object v1, p1

    goto :goto_4

    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Not initialized yet"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_7
    move-object v6, p1

    :goto_4
    if-eqz v1, :cond_8

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result p0

    return p0

    :cond_8
    invoke-static {}, Ljava/text/BreakIterator;->getCharacterInstance()Ljava/text/BreakIterator;

    move-result-object p1

    invoke-virtual {p1, v6}, Ljava/text/BreakIterator;->setText(Ljava/lang/String;)V

    invoke-virtual {p1, p0}, Ljava/text/BreakIterator;->following(I)I

    move-result p0

    return p0
.end method

.method public static final OooOOO0(Ljava/lang/StringBuilder;Ljava/lang/String;)V
    .locals 1

    const-string v0, "<this>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 p1, 0xa

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    return-void
.end method

.method public static final OooOOOO(ILjava/lang/String;)I
    .locals 4

    invoke-static {}, Llyiahf/vczjk/rl2;->OooO0Oo()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/rl2;->OooO00o()Llyiahf/vczjk/rl2;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/rl2;->OooO0OO()I

    move-result v2

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    if-eqz v0, :cond_2

    add-int/lit8 v2, p0, -0x1

    const/4 v3, 0x0

    invoke-static {v3, v2}, Ljava/lang/Math;->max(II)I

    move-result v2

    invoke-virtual {v0, v2, p1}, Llyiahf/vczjk/rl2;->OooO0O0(ILjava/lang/CharSequence;)I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    const/4 v3, -0x1

    if-ne v0, v3, :cond_1

    goto :goto_1

    :cond_1
    move-object v1, v2

    :cond_2
    :goto_1
    if-eqz v1, :cond_3

    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    move-result p0

    return p0

    :cond_3
    invoke-static {}, Ljava/text/BreakIterator;->getCharacterInstance()Ljava/text/BreakIterator;

    move-result-object v0

    invoke-virtual {v0, p1}, Ljava/text/BreakIterator;->setText(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/text/BreakIterator;->preceding(I)I

    move-result p0

    return p0
.end method

.method public static final OooOOOo(Llyiahf/vczjk/an;)Z
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    const/4 v1, 0x0

    iget-object p0, p0, Llyiahf/vczjk/an;->OooOOO0:Ljava/util/List;

    if-eqz p0, :cond_1

    invoke-interface {p0}, Ljava/util/Collection;->size()I

    move-result v2

    move v3, v1

    :goto_0
    if-ge v3, v2, :cond_1

    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/zm;

    iget-object v5, v4, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    instance-of v5, v5, Llyiahf/vczjk/e05;

    if-eqz v5, :cond_0

    iget v5, v4, Llyiahf/vczjk/zm;->OooO0O0:I

    iget v4, v4, Llyiahf/vczjk/zm;->OooO0OO:I

    invoke-static {v1, v0, v5, v4}, Llyiahf/vczjk/cn;->OooO0OO(IIII)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    return v1
.end method

.method public static final OooOOo(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/z98;
    .locals 7

    const/4 v0, 0x0

    new-array v1, v0, [Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/z98;->OooO:Llyiahf/vczjk/era;

    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v0

    move-object v4, p0

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p0

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne p0, v0, :cond_1

    :cond_0
    new-instance p0, Llyiahf/vczjk/o98;

    invoke-direct {p0}, Llyiahf/vczjk/o98;-><init>()V

    invoke-virtual {v4, p0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/le3;

    const/4 v5, 0x0

    const/4 v6, 0x4

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/z98;

    return-object p0
.end method

.method public static final OooOOo0(Llyiahf/vczjk/x14;)I
    .locals 3

    sget-object v0, Llyiahf/vczjk/jg7;->OooOOO0:Llyiahf/vczjk/ig7;

    invoke-virtual {p0}, Llyiahf/vczjk/x14;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_2

    const v0, 0x7fffffff

    iget v1, p0, Llyiahf/vczjk/v14;->OooOOO0:I

    iget p0, p0, Llyiahf/vczjk/v14;->OooOOO:I

    if-ge p0, v0, :cond_0

    add-int/lit8 p0, p0, 0x1

    sget-object v0, Llyiahf/vczjk/jg7;->OooOOO:Llyiahf/vczjk/o00OO000;

    invoke-virtual {v0, v1, p0}, Llyiahf/vczjk/jg7;->OooO0OO(II)I

    move-result p0

    return p0

    :cond_0
    const/high16 v0, -0x80000000

    if-le v1, v0, :cond_1

    add-int/lit8 v1, v1, -0x1

    sget-object v0, Llyiahf/vczjk/jg7;->OooOOO:Llyiahf/vczjk/o00OO000;

    invoke-virtual {v0, v1, p0}, Llyiahf/vczjk/jg7;->OooO0OO(II)I

    move-result p0

    add-int/lit8 p0, p0, 0x1

    return p0

    :cond_1
    sget-object p0, Llyiahf/vczjk/jg7;->OooOOO:Llyiahf/vczjk/o00OO000;

    invoke-virtual {p0}, Llyiahf/vczjk/o00OO000;->OooO0O0()I

    move-result p0

    return p0

    :cond_2
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot get random in empty range: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public static OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/z98;Z)Llyiahf/vczjk/kl5;
    .locals 11

    if-eqz p2, :cond_0

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    :goto_0
    move-object v3, v0

    goto :goto_1

    :cond_0
    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    goto :goto_0

    :goto_1
    iget-object v7, p1, Llyiahf/vczjk/z98;->OooO0OO:Llyiahf/vczjk/sr5;

    const/4 v10, 0x0

    const/4 v4, 0x1

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x1

    const/4 v9, 0x0

    move-object v1, p0

    move-object v2, p1

    invoke-static/range {v1 .. v10}, Landroidx/compose/foundation/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;Llyiahf/vczjk/sa8;Llyiahf/vczjk/nf6;ZZLlyiahf/vczjk/o23;Llyiahf/vczjk/sr5;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/rk6;)Llyiahf/vczjk/kl5;

    move-result-object p0

    new-instance p1, Landroidx/compose/foundation/ScrollingLayoutElement;

    invoke-direct {p1, v2, p2}, Landroidx/compose/foundation/ScrollingLayoutElement;-><init>(Llyiahf/vczjk/z98;Z)V

    invoke-interface {p0, p1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOo00(Llyiahf/vczjk/nr5;)I
    .locals 10

    iget v0, p0, Llyiahf/vczjk/nr5;->OooO0O0:I

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v1

    :cond_0
    iget v2, p0, Llyiahf/vczjk/nr5;->OooO0O0:I

    if-eqz v2, :cond_2

    invoke-virtual {p0, v0}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v2

    if-ne v2, v1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/nr5;->OooO0Oo()I

    move-result v2

    invoke-virtual {p0, v0, v2}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    iget v2, p0, Llyiahf/vczjk/nr5;->OooO0O0:I

    add-int/lit8 v2, v2, -0x1

    invoke-virtual {p0, v2}, Llyiahf/vczjk/nr5;->OooO0o(I)I

    iget v2, p0, Llyiahf/vczjk/nr5;->OooO0O0:I

    ushr-int/lit8 v3, v2, 0x1

    move v4, v0

    :goto_0
    if-ge v4, v3, :cond_0

    invoke-virtual {p0, v4}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v5

    add-int/lit8 v6, v4, 0x1

    mul-int/lit8 v6, v6, 0x2

    add-int/lit8 v7, v6, -0x1

    invoke-virtual {p0, v7}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v8

    if-ge v6, v2, :cond_1

    invoke-virtual {p0, v6}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v9

    if-le v9, v8, :cond_1

    if-le v9, v5, :cond_0

    invoke-virtual {p0, v4, v9}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    invoke-virtual {p0, v6, v5}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    move v4, v6

    goto :goto_0

    :cond_1
    if-le v8, v5, :cond_0

    invoke-virtual {p0, v4, v8}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    invoke-virtual {p0, v7, v5}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    move v4, v7

    goto :goto_0

    :cond_2
    return v1
.end method
