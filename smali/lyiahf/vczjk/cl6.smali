.class public abstract Llyiahf/vczjk/cl6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I

.field public static final synthetic OooO0O0:I

.field public static final synthetic OooO0OO:I

.field public static final synthetic OooO0Oo:I


# direct methods
.method public static final OooO(Llyiahf/vczjk/gl9;)Llyiahf/vczjk/an;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-wide v1, p0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p0

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    invoke-virtual {v0, p0, v1}, Llyiahf/vczjk/an;->OooO0OO(II)Llyiahf/vczjk/an;

    move-result-object p0

    return-object p0
.end method

.method public static final OooO00o(Llyiahf/vczjk/rr2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 46

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v11, p2

    check-cast v11, Llyiahf/vczjk/zf1;

    const v3, 0x9005ebc

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int v3, p3, v3

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    const/16 v5, 0x10

    if-eqz v4, :cond_1

    const/16 v4, 0x20

    goto :goto_1

    :cond_1
    move v4, v5

    :goto_1
    or-int v26, v3, v4

    and-int/lit8 v3, v26, 0x13

    const/16 v4, 0x12

    if-ne v3, v4, :cond_3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v14, v1

    goto/16 :goto_d

    :cond_3
    :goto_2
    sget-object v3, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Landroid/content/Context;

    invoke-static {v3}, Llyiahf/vczjk/zsa;->o00ooo(Landroid/content/Context;)Landroidx/appcompat/app/AppCompatActivity;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v7, 0x3f800000    # 1.0f

    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v8

    int-to-float v5, v5

    const/16 v9, 0x8

    int-to-float v9, v9

    invoke-static {v8, v5, v9}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0o(Llyiahf/vczjk/kl5;FF)Llyiahf/vczjk/kl5;

    move-result-object v8

    const/16 v9, 0xc

    int-to-float v9, v9

    invoke-static {v9}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v9

    invoke-static {v8, v9}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v8

    sget-object v9, Llyiahf/vczjk/nq9;->OooO0OO:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ap9;

    iget-wide v9, v9, Llyiahf/vczjk/ap9;->OooO00o:J

    sget-object v12, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v8, v9, v10, v12}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v8

    const v9, -0x615d173a

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v10

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v12

    or-int/2addr v10, v12

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v12

    sget-object v13, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v10, :cond_4

    if-ne v12, v13, :cond_5

    :cond_4
    new-instance v12, Llyiahf/vczjk/w77;

    const/4 v10, 0x0

    invoke-direct {v12, v10, v3, v0}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v12, Llyiahf/vczjk/le3;

    const/4 v3, 0x0

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v8, v12}, Llyiahf/vczjk/yi4;->Oooo0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-static {v8, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v8, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v8, v3}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v10

    iget v12, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v14

    invoke-static {v11, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v15, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v15, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v6, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v6, :cond_6

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_6
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v10, v11, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v14, v11, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v9, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v9, :cond_7

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v9, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_8

    :cond_7
    invoke-static {v12, v11, v12, v14}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_8
    sget-object v3, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v11, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v7}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v9, Llyiahf/vczjk/tx;->OooO0OO:Llyiahf/vczjk/xj0;

    sget-object v12, Llyiahf/vczjk/op3;->OooOoO:Llyiahf/vczjk/sb0;

    const/4 v7, 0x0

    invoke-static {v9, v12, v11, v7}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v9

    iget v12, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v11, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v19, v4

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v4, :cond_9

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_9
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    invoke-static {v9, v11, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v7, v11, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_a

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-static {v4, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_b

    :cond_a
    invoke-static {v12, v11, v12, v14}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    invoke-static {v5, v11, v3}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-object v4, v0, Llyiahf/vczjk/rr2;->OooO00o:Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getName()Ljava/lang/String;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/q6a;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/n6a;

    iget-object v7, v7, Llyiahf/vczjk/n6a;->OooO0oo:Llyiahf/vczjk/rn9;

    const/16 v20, 0x0

    const/16 v23, 0x0

    move-object v9, v3

    move-object v3, v4

    const/4 v4, 0x0

    move-object/from16 v21, v5

    move-object v12, v6

    const-wide/16 v5, 0x0

    move-object/from16 v22, v8

    move-object/from16 v24, v21

    move-object/from16 v21, v7

    const-wide/16 v7, 0x0

    move-object/from16 v25, v9

    const/4 v9, 0x0

    move-object/from16 v27, v10

    const/4 v10, 0x0

    move-object/from16 v29, v12

    move-object/from16 v28, v22

    move-object/from16 v22, v11

    const-wide/16 v11, 0x0

    move-object/from16 v30, v13

    const/4 v13, 0x0

    move-object/from16 v32, v14

    move-object/from16 v31, v15

    const-wide/16 v14, 0x0

    const v33, -0x615d173a

    const/16 v16, 0x0

    const/16 v34, 0x0

    const/16 v17, 0x0

    const/high16 v35, 0x3f800000    # 1.0f

    const/16 v18, 0x0

    move-object/from16 v36, v19

    const/16 v19, 0x0

    move-object/from16 v37, v24

    const/16 v24, 0x0

    move-object/from16 v38, v25

    const v25, 0x1fffe

    move-object/from16 v43, v27

    move-object/from16 v40, v28

    move-object/from16 v42, v29

    move-object/from16 v39, v30

    move-object/from16 v41, v31

    move-object/from16 v44, v32

    move/from16 v2, v34

    move-object/from16 v1, v37

    move-object/from16 v45, v38

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v22

    invoke-static {v2, v11}, Llyiahf/vczjk/ru6;->OooO0o0(ILlyiahf/vczjk/rf1;)V

    iget-object v3, v0, Llyiahf/vczjk/rr2;->OooO00o:Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getDescription()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/n6a;

    iget-object v1, v1, Llyiahf/vczjk/n6a;->OooOOO:Llyiahf/vczjk/rn9;

    const/16 v20, 0x0

    const/16 v23, 0x0

    const/4 v4, 0x0

    const-wide/16 v5, 0x0

    const-wide/16 v7, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    move-object/from16 v22, v11

    const-wide/16 v11, 0x0

    const/4 v13, 0x0

    const-wide/16 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v24, 0x0

    const v25, 0x1fffe

    move-object/from16 v21, v1

    invoke-static/range {v3 .. v25}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v11, v22

    invoke-static {v2, v11}, Llyiahf/vczjk/ru6;->OooO0o(ILlyiahf/vczjk/rf1;)V

    move-object/from16 v1, v36

    const/high16 v3, 0x3f800000    # 1.0f

    invoke-static {v1, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    move-object/from16 v4, v40

    invoke-static {v4, v2}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v4

    iget v5, v11, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v6

    invoke-static {v11, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v7, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v7, :cond_c

    move-object/from16 v7, v41

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    :goto_5
    move-object/from16 v12, v42

    goto :goto_6

    :cond_c
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooooo()V

    goto :goto_5

    :goto_6
    invoke-static {v4, v11, v12}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    move-object/from16 v4, v43

    invoke-static {v6, v11, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v4, v11, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_d

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v6

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_e

    :cond_d
    move-object/from16 v4, v44

    goto :goto_8

    :cond_e
    :goto_7
    move-object/from16 v9, v45

    goto :goto_9

    :goto_8
    invoke-static {v5, v11, v5, v4}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    goto :goto_7

    :goto_9
    invoke-static {v3, v11, v9}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v3, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    sget-object v4, Llyiahf/vczjk/op3;->OooOOoo:Llyiahf/vczjk/ub0;

    invoke-virtual {v3, v1, v4}, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/o4;)Llyiahf/vczjk/kl5;

    move-result-object v4

    const v1, -0x615d173a

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v1, v26, 0x70

    const/4 v13, 0x1

    const/16 v3, 0x20

    if-ne v1, v3, :cond_f

    move v3, v13

    goto :goto_a

    :cond_f
    move v3, v2

    :goto_a
    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v1, v3

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v1, :cond_11

    move-object/from16 v1, v39

    if-ne v3, v1, :cond_10

    goto :goto_b

    :cond_10
    move-object/from16 v14, p1

    goto :goto_c

    :cond_11
    :goto_b
    new-instance v3, Llyiahf/vczjk/w77;

    const/4 v1, 0x1

    move-object/from16 v14, p1

    invoke-direct {v3, v1, v14, v0}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_c
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {v11, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v10, Llyiahf/vczjk/qb1;->OooO0OO:Llyiahf/vczjk/a91;

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/high16 v12, 0x30000000

    invoke-static/range {v3 .. v12}, Llyiahf/vczjk/bua;->OooOO0(Llyiahf/vczjk/le3;Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/qj8;Llyiahf/vczjk/qk0;Llyiahf/vczjk/se0;Llyiahf/vczjk/di6;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    invoke-static {v11, v13, v13, v13}, Llyiahf/vczjk/ii5;->OooOo0O(Llyiahf/vczjk/zf1;ZZZ)V

    :goto_d
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v1

    if-eqz v1, :cond_12

    new-instance v2, Llyiahf/vczjk/e2;

    const/16 v3, 0x1a

    move/from16 v4, p3

    invoke-direct {v2, v0, v14, v4, v3}, Llyiahf/vczjk/e2;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v2, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_12
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/bi6;Llyiahf/vczjk/sr2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 18

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p4

    const-string v0, "contentPadding"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "state"

    invoke-static {v2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "import"

    invoke-static {v3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v15, p3

    check-cast v15, Llyiahf/vczjk/zf1;

    const v0, -0x48021cc1

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, v4, 0x6

    if-nez v0, :cond_1

    invoke-virtual {v15, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v4

    goto :goto_1

    :cond_1
    move v0, v4

    :goto_1
    and-int/lit8 v5, v4, 0x30

    if-nez v5, :cond_3

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_2

    const/16 v5, 0x20

    goto :goto_2

    :cond_2
    const/16 v5, 0x10

    :goto_2
    or-int/2addr v0, v5

    :cond_3
    and-int/lit16 v5, v4, 0x180

    const/16 v6, 0x100

    if-nez v5, :cond_5

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    move v5, v6

    goto :goto_3

    :cond_4
    const/16 v5, 0x80

    :goto_3
    or-int/2addr v0, v5

    :cond_5
    and-int/lit16 v5, v0, 0x93

    const/16 v7, 0x92

    if-ne v5, v7, :cond_7

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v5

    if-nez v5, :cond_6

    goto :goto_4

    :cond_6
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_6

    :cond_7
    :goto_4
    const v5, -0x21dacde9

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v5, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->OooO0O0:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Landroid/content/Context;

    invoke-virtual {v5}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v5

    const-string v7, "getTheme(...)"

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const v7, 0x1010054

    filled-new-array {v7}, [I

    move-result-object v7

    invoke-virtual {v5, v7}, Landroid/content/res/Resources$Theme;->obtainStyledAttributes([I)Landroid/content/res/TypedArray;

    move-result-object v5

    const-string v7, "obtainStyledAttributes(...)"

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v7, 0x0

    invoke-virtual {v5, v7, v7}, Landroid/content/res/TypedArray;->getColor(II)I

    move-result v8

    invoke-virtual {v5}, Landroid/content/res/TypedArray;->recycle()V

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v5, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v9, 0x3f800000    # 1.0f

    invoke-static {v5, v9}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooO0OO(I)J

    move-result-wide v8

    sget-object v10, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v5, v8, v9, v10}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-static {v5, v1}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;)Llyiahf/vczjk/kl5;

    move-result-object v5

    const v8, -0x615d173a

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    and-int/lit16 v0, v0, 0x380

    if-ne v0, v6, :cond_8

    const/4 v0, 0x1

    goto :goto_5

    :cond_8
    move v0, v7

    :goto_5
    or-int/2addr v0, v8

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v0, :cond_9

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v6, v0, :cond_a

    :cond_9
    new-instance v6, Llyiahf/vczjk/gu6;

    const/4 v0, 0x3

    invoke-direct {v6, v0, v2, v3}, Llyiahf/vczjk/gu6;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_a
    move-object v14, v6

    check-cast v14, Llyiahf/vczjk/oe3;

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x1fe

    invoke-static/range {v5 .. v17}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    :goto_6
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v6

    if-eqz v6, :cond_b

    new-instance v0, Llyiahf/vczjk/z4;

    const/4 v5, 0x5

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/z4;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/oe3;II)V

    iput-object v0, v6, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_b
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/lm6;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;Llyiahf/vczjk/uj6;IFLlyiahf/vczjk/n4;Llyiahf/vczjk/hg9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/bz5;Llyiahf/vczjk/dv8;Llyiahf/vczjk/qg6;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;III)V
    .locals 36

    move-object/from16 v1, p0

    move/from16 v0, p16

    move/from16 v2, p17

    move/from16 v3, p18

    const/16 v6, 0x100

    const/16 v11, 0x80

    move-object/from16 v12, p15

    check-cast v12, Llyiahf/vczjk/zf1;

    const v13, -0x51d5e744

    invoke-virtual {v12, v13}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const/4 v13, 0x1

    and-int/lit8 v14, v3, 0x1

    const/4 v15, 0x2

    const/16 v16, 0x10

    const/4 v7, 0x4

    if-eqz v14, :cond_0

    or-int/lit8 v14, v0, 0x6

    goto :goto_1

    :cond_0
    and-int/lit8 v14, v0, 0x6

    if-nez v14, :cond_2

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v14

    if-eqz v14, :cond_1

    move v14, v7

    goto :goto_0

    :cond_1
    move v14, v15

    :goto_0
    or-int/2addr v14, v0

    goto :goto_1

    :cond_2
    move v14, v0

    :goto_1
    and-int/lit8 v17, v3, 0x2

    if-eqz v17, :cond_4

    or-int/lit8 v14, v14, 0x30

    move-object/from16 v8, p1

    :cond_3
    const/16 v18, 0x20

    goto :goto_3

    :cond_4
    and-int/lit8 v18, v0, 0x30

    move-object/from16 v8, p1

    if-nez v18, :cond_3

    const/16 v18, 0x20

    invoke-virtual {v12, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v19

    if-eqz v19, :cond_5

    move/from16 v19, v18

    goto :goto_2

    :cond_5
    move/from16 v19, v16

    :goto_2
    or-int v14, v14, v19

    :goto_3
    and-int/lit8 v19, v3, 0x4

    if-eqz v19, :cond_7

    or-int/lit16 v14, v14, 0x180

    :cond_6
    move-object/from16 v15, p2

    goto :goto_5

    :cond_7
    and-int/lit16 v15, v0, 0x180

    if-nez v15, :cond_6

    move-object/from16 v15, p2

    invoke-virtual {v12, v15}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v20

    if-eqz v20, :cond_8

    move/from16 v20, v6

    goto :goto_4

    :cond_8
    move/from16 v20, v11

    :goto_4
    or-int v14, v14, v20

    :goto_5
    and-int/lit8 v20, v3, 0x8

    if-eqz v20, :cond_a

    or-int/lit16 v14, v14, 0xc00

    :cond_9
    move-object/from16 v7, p3

    goto :goto_7

    :cond_a
    and-int/lit16 v7, v0, 0xc00

    if-nez v7, :cond_9

    move-object/from16 v7, p3

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v22

    if-eqz v22, :cond_b

    const/16 v22, 0x800

    goto :goto_6

    :cond_b
    const/16 v22, 0x400

    :goto_6
    or-int v14, v14, v22

    :goto_7
    and-int/lit8 v22, v3, 0x10

    if-eqz v22, :cond_d

    or-int/lit16 v14, v14, 0x6000

    move/from16 v23, v13

    :cond_c
    move/from16 v13, p4

    goto :goto_9

    :cond_d
    move/from16 v23, v13

    and-int/lit16 v13, v0, 0x6000

    if-nez v13, :cond_c

    move/from16 v13, p4

    invoke-virtual {v12, v13}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v24

    if-eqz v24, :cond_e

    const/16 v24, 0x4000

    goto :goto_8

    :cond_e
    const/16 v24, 0x2000

    :goto_8
    or-int v14, v14, v24

    :goto_9
    and-int/lit8 v24, v3, 0x20

    const/high16 v25, 0x30000

    if-eqz v24, :cond_f

    or-int v14, v14, v25

    move/from16 v4, p5

    goto :goto_b

    :cond_f
    and-int v26, v0, v25

    move/from16 v4, p5

    if-nez v26, :cond_11

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v27

    if-eqz v27, :cond_10

    const/high16 v27, 0x20000

    goto :goto_a

    :cond_10
    const/high16 v27, 0x10000

    :goto_a
    or-int v14, v14, v27

    :cond_11
    :goto_b
    and-int/lit8 v27, v3, 0x40

    const/high16 v28, 0x180000

    if-eqz v27, :cond_12

    or-int v14, v14, v28

    move-object/from16 v9, p6

    goto :goto_d

    :cond_12
    and-int v28, v0, v28

    move-object/from16 v9, p6

    if-nez v28, :cond_14

    invoke-virtual {v12, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v29

    if-eqz v29, :cond_13

    const/high16 v29, 0x100000

    goto :goto_c

    :cond_13
    const/high16 v29, 0x80000

    :goto_c
    or-int v14, v14, v29

    :cond_14
    :goto_d
    const/high16 v29, 0xc00000

    and-int v29, v0, v29

    if-nez v29, :cond_17

    and-int/lit16 v10, v3, 0x80

    if-nez v10, :cond_15

    move-object/from16 v10, p7

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v30

    if-eqz v30, :cond_16

    const/high16 v30, 0x800000

    goto :goto_e

    :cond_15
    move-object/from16 v10, p7

    :cond_16
    const/high16 v30, 0x400000

    :goto_e
    or-int v14, v14, v30

    goto :goto_f

    :cond_17
    move-object/from16 v10, p7

    :goto_f
    and-int/lit16 v11, v3, 0x100

    const/high16 v31, 0x6000000

    if-eqz v11, :cond_18

    or-int v14, v14, v31

    move/from16 v6, p8

    goto :goto_11

    :cond_18
    and-int v31, v0, v31

    move/from16 v6, p8

    if-nez v31, :cond_1a

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v32

    if-eqz v32, :cond_19

    const/high16 v32, 0x4000000

    goto :goto_10

    :cond_19
    const/high16 v32, 0x2000000

    :goto_10
    or-int v14, v14, v32

    :cond_1a
    :goto_11
    and-int/lit16 v5, v3, 0x200

    const/high16 v33, 0x30000000

    if-eqz v5, :cond_1c

    :goto_12
    or-int v14, v14, v33

    :cond_1b
    const/16 v0, 0x400

    goto :goto_13

    :cond_1c
    and-int v33, v0, v33

    move/from16 v0, p9

    if-nez v33, :cond_1b

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v33

    if-eqz v33, :cond_1d

    const/high16 v33, 0x20000000

    goto :goto_12

    :cond_1d
    const/high16 v33, 0x10000000

    goto :goto_12

    :goto_13
    and-int/lit16 v4, v3, 0x400

    if-eqz v4, :cond_1e

    or-int/lit8 v32, v2, 0x6

    move-object/from16 v0, p10

    move/from16 v33, v32

    goto :goto_15

    :cond_1e
    and-int/lit8 v32, v2, 0x6

    move-object/from16 v0, p10

    if-nez v32, :cond_20

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v33

    if-eqz v33, :cond_1f

    const/16 v33, 0x4

    goto :goto_14

    :cond_1f
    const/16 v33, 0x2

    :goto_14
    or-int v33, v2, v33

    goto :goto_15

    :cond_20
    move/from16 v33, v2

    :goto_15
    and-int/lit8 v34, v2, 0x30

    if-nez v34, :cond_22

    move/from16 v34, v4

    const/16 v0, 0x800

    and-int/lit16 v4, v3, 0x800

    move-object/from16 v0, p11

    if-nez v4, :cond_21

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_21

    move/from16 v16, v18

    :cond_21
    or-int v33, v33, v16

    :goto_16
    move/from16 v4, v33

    goto :goto_17

    :cond_22
    move-object/from16 v0, p11

    move/from16 v34, v4

    goto :goto_16

    :goto_17
    and-int/lit16 v0, v3, 0x1000

    if-eqz v0, :cond_23

    or-int/lit16 v4, v4, 0x180

    move/from16 v16, v0

    goto :goto_19

    :cond_23
    move/from16 v16, v0

    and-int/lit16 v0, v2, 0x180

    if-nez v0, :cond_25

    move-object/from16 v0, p12

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v18

    if-eqz v18, :cond_24

    const/16 v31, 0x100

    goto :goto_18

    :cond_24
    const/16 v31, 0x80

    :goto_18
    or-int v4, v4, v31

    goto :goto_19

    :cond_25
    move-object/from16 v0, p12

    :goto_19
    and-int/lit16 v0, v2, 0xc00

    if-nez v0, :cond_27

    move/from16 p15, v4

    const/16 v0, 0x2000

    and-int/lit16 v4, v3, 0x2000

    move-object/from16 v0, p13

    if-nez v4, :cond_26

    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_26

    const/16 v32, 0x800

    goto :goto_1a

    :cond_26
    const/16 v32, 0x400

    :goto_1a
    or-int v4, p15, v32

    :goto_1b
    move/from16 v18, v5

    const/16 v0, 0x4000

    goto :goto_1c

    :cond_27
    move-object/from16 v0, p13

    move/from16 p15, v4

    goto :goto_1b

    :goto_1c
    and-int/lit16 v5, v3, 0x4000

    if-eqz v5, :cond_29

    or-int/lit16 v4, v4, 0x6000

    :cond_28
    move-object/from16 v5, p14

    goto :goto_1e

    :cond_29
    and-int/lit16 v5, v2, 0x6000

    if-nez v5, :cond_28

    move-object/from16 v5, p14

    invoke-virtual {v12, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v26

    if-eqz v26, :cond_2a

    goto :goto_1d

    :cond_2a
    const/16 v0, 0x2000

    :goto_1d
    or-int/2addr v4, v0

    :goto_1e
    const v0, 0x12492493

    and-int/2addr v0, v14

    const v2, 0x12492492

    const/4 v5, 0x0

    if-ne v0, v2, :cond_2c

    and-int/lit16 v0, v4, 0x2493

    const/16 v2, 0x2492

    if-eq v0, v2, :cond_2b

    goto :goto_1f

    :cond_2b
    move v0, v5

    goto :goto_20

    :cond_2c
    :goto_1f
    move/from16 v0, v23

    :goto_20
    and-int/lit8 v2, v14, 0x1

    invoke-virtual {v12, v2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_49

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v0, p16, 0x1

    const v2, -0x1c00001

    if-eqz v0, :cond_31

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_2d

    goto :goto_21

    :cond_2d
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    const/16 v0, 0x80

    and-int/2addr v0, v3

    if-eqz v0, :cond_2e

    and-int/2addr v14, v2

    :cond_2e
    const/16 v0, 0x800

    and-int/2addr v0, v3

    if-eqz v0, :cond_2f

    and-int/lit8 v4, v4, -0x71

    :cond_2f
    const/16 v0, 0x2000

    and-int/2addr v0, v3

    if-eqz v0, :cond_30

    and-int/lit16 v4, v4, -0x1c01

    :cond_30
    move/from16 v3, p9

    move-object/from16 v11, p11

    move-object v0, v8

    move-object v5, v10

    move-object/from16 v17, v12

    move v8, v13

    move v13, v14

    move-object v2, v15

    move-object/from16 v12, p10

    move-object/from16 v15, p12

    move-object v10, v7

    move-object v14, v9

    move/from16 v9, p5

    move-object/from16 v7, p13

    goto/16 :goto_2f

    :cond_31
    :goto_21
    if-eqz v17, :cond_32

    sget-object v0, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    goto :goto_22

    :cond_32
    move-object v0, v8

    :goto_22
    if-eqz v19, :cond_33

    int-to-float v8, v5

    new-instance v15, Llyiahf/vczjk/di6;

    invoke-direct {v15, v8, v8, v8, v8}, Llyiahf/vczjk/di6;-><init>(FFFF)V

    :cond_33
    if-eqz v20, :cond_34

    sget-object v7, Llyiahf/vczjk/qp3;->OooOOoo:Llyiahf/vczjk/qp3;

    :cond_34
    if-eqz v22, :cond_35

    move v13, v5

    :cond_35
    if-eqz v24, :cond_36

    int-to-float v8, v5

    goto :goto_23

    :cond_36
    move/from16 v8, p5

    :goto_23
    if-eqz v27, :cond_37

    sget-object v9, Llyiahf/vczjk/op3;->OooOo:Llyiahf/vczjk/tb0;

    :cond_37
    move/from16 p15, v2

    const/16 v2, 0x80

    and-int/2addr v2, v3

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-eqz v2, :cond_3d

    and-int/lit8 v2, v14, 0xe

    or-int v2, v2, v25

    new-instance v10, Llyiahf/vczjk/tl6;

    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    move-object/from16 p1, v0

    invoke-static {v12}, Llyiahf/vczjk/xy8;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/t02;

    move-result-object v0

    sget-object v19, Llyiahf/vczjk/hka;->OooO00o:Ljava/lang/Object;

    move/from16 p2, v2

    move/from16 v19, v4

    move/from16 v2, v23

    int-to-float v4, v2

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    const/high16 v6, 0x43c80000    # 400.0f

    move-object/from16 p3, v7

    const/4 v7, 0x0

    invoke-static {v7, v6, v4, v2}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/f62;

    sget-object v7, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/yn4;

    and-int/lit8 v20, p2, 0xe

    xor-int/lit8 v2, v20, 0x6

    move/from16 p4, v8

    const/4 v8, 0x4

    if-le v2, v8, :cond_38

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_39

    :cond_38
    and-int/lit8 v2, p2, 0x6

    if-ne v2, v8, :cond_3a

    :cond_39
    const/4 v2, 0x1

    goto :goto_24

    :cond_3a
    const/4 v2, 0x0

    :goto_24
    invoke-virtual {v12, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v2, v8

    invoke-virtual {v12, v4}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v2, v8

    invoke-virtual {v12, v10}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v2, v8

    invoke-virtual {v12, v6}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v2, v6

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v2, v6

    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v2, :cond_3b

    if-ne v6, v5, :cond_3c

    :cond_3b
    new-instance v2, Llyiahf/vczjk/sk6;

    invoke-direct {v2, v1, v7}, Llyiahf/vczjk/sk6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/yn4;)V

    new-instance v6, Llyiahf/vczjk/era;

    invoke-direct {v6, v2, v1, v10}, Llyiahf/vczjk/era;-><init>(Ljava/io/Serializable;Ljava/lang/Object;Ljava/lang/Object;)V

    sget v2, Llyiahf/vczjk/bv8;->OooO00o:F

    new-instance v2, Llyiahf/vczjk/wu8;

    invoke-direct {v2, v6, v0, v4}, Llyiahf/vczjk/wu8;-><init>(Llyiahf/vczjk/era;Llyiahf/vczjk/t02;Llyiahf/vczjk/wz8;)V

    invoke-virtual {v12, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v6, v2

    :cond_3c
    move-object v0, v6

    check-cast v0, Llyiahf/vczjk/hg9;

    and-int v14, v14, p15

    goto :goto_25

    :cond_3d
    move-object/from16 p1, v0

    move/from16 v19, v4

    move-object/from16 p3, v7

    move/from16 p4, v8

    move-object v0, v10

    :goto_25
    if-eqz v11, :cond_3e

    const/4 v2, 0x1

    goto :goto_26

    :cond_3e
    move/from16 v2, p8

    :goto_26
    if-eqz v18, :cond_3f

    const/4 v4, 0x0

    goto :goto_27

    :cond_3f
    move/from16 v4, p9

    :goto_27
    if-eqz v34, :cond_40

    const/4 v6, 0x0

    :goto_28
    const/16 v7, 0x800

    goto :goto_29

    :cond_40
    move-object/from16 v6, p10

    goto :goto_28

    :goto_29
    and-int/2addr v7, v3

    if-eqz v7, :cond_46

    sget-object v7, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    and-int/lit8 v7, v14, 0xe

    or-int/lit16 v7, v7, 0x1b0

    and-int/lit8 v8, v7, 0xe

    xor-int/lit8 v8, v8, 0x6

    const/4 v10, 0x4

    if-le v8, v10, :cond_41

    invoke-virtual {v12, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_42

    :cond_41
    and-int/lit8 v7, v7, 0x6

    if-ne v7, v10, :cond_43

    :cond_42
    const/16 v17, 0x1

    goto :goto_2a

    :cond_43
    const/16 v17, 0x0

    :goto_2a
    invoke-virtual {v12}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v17, :cond_44

    if-ne v7, v5, :cond_45

    :cond_44
    new-instance v7, Llyiahf/vczjk/b32;

    invoke-direct {v7, v1}, Llyiahf/vczjk/b32;-><init>(Llyiahf/vczjk/lm6;)V

    invoke-virtual {v12, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_45
    move-object v5, v7

    check-cast v5, Llyiahf/vczjk/b32;

    and-int/lit8 v7, v19, -0x71

    goto :goto_2b

    :cond_46
    move-object/from16 v5, p11

    move/from16 v7, v19

    :goto_2b
    if-eqz v16, :cond_47

    sget-object v8, Llyiahf/vczjk/pp3;->OooOo0:Llyiahf/vczjk/pp3;

    :goto_2c
    const/16 v10, 0x2000

    goto :goto_2d

    :cond_47
    move-object/from16 v8, p12

    goto :goto_2c

    :goto_2d
    and-int/2addr v10, v3

    if-eqz v10, :cond_48

    invoke-static {v12}, Llyiahf/vczjk/rg6;->OooO00o(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/qg6;

    move-result-object v10

    and-int/lit16 v7, v7, -0x1c01

    move v3, v4

    move-object v11, v5

    move v4, v7

    move-object v7, v10

    move-object/from16 v17, v12

    move-object/from16 v10, p3

    :goto_2e
    move-object v5, v0

    move-object v12, v6

    move-object/from16 v0, p1

    move v6, v2

    move-object v2, v15

    move-object v15, v8

    move v8, v13

    move v13, v14

    move-object v14, v9

    move/from16 v9, p4

    goto :goto_2f

    :cond_48
    move-object/from16 v10, p3

    move v3, v4

    move-object v11, v5

    move v4, v7

    move-object/from16 v17, v12

    move-object/from16 v7, p13

    goto :goto_2e

    :goto_2f
    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/zf1;->OooOOo0()V

    move/from16 v16, v4

    sget-object v4, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    sget-object v18, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    shr-int/lit8 v19, v13, 0x3

    move-object/from16 p1, v0

    and-int/lit8 v0, v19, 0xe

    or-int/lit16 v0, v0, 0x6000

    shl-int/lit8 v19, v13, 0x3

    and-int/lit8 v19, v19, 0x70

    or-int v0, v0, v19

    move/from16 p2, v0

    and-int/lit16 v0, v13, 0x380

    or-int v0, p2, v0

    move/from16 p2, v0

    shr-int/lit8 v0, v13, 0x12

    and-int/lit16 v0, v0, 0x1c00

    or-int v0, p2, v0

    shr-int/lit8 v19, v13, 0x6

    const/high16 v20, 0x70000

    and-int v20, v19, v20

    or-int v0, v0, v20

    const/high16 v20, 0x380000

    and-int v20, v19, v20

    or-int v0, v0, v20

    shl-int/lit8 v20, v16, 0xc

    const/high16 v21, 0x1c00000

    and-int v20, v20, v21

    or-int v0, v0, v20

    shl-int/lit8 v20, v13, 0xc

    const/high16 v21, 0xe000000

    and-int v21, v20, v21

    or-int v0, v0, v21

    const/high16 v21, 0x70000000

    and-int v20, v20, v21

    or-int v0, v0, v20

    shr-int/lit8 v13, v13, 0x9

    and-int/lit8 v13, v13, 0xe

    or-int/lit16 v13, v13, 0xc00

    and-int/lit8 v20, v16, 0x70

    or-int v13, v13, v20

    move/from16 p2, v0

    shl-int/lit8 v0, v16, 0x6

    and-int/lit16 v1, v0, 0x380

    or-int/2addr v1, v13

    const v13, 0xe000

    and-int v13, v19, v13

    or-int/2addr v1, v13

    shl-int/lit8 v13, v16, 0x9

    const/high16 v16, 0x70000

    and-int v13, v13, v16

    or-int/2addr v1, v13

    const/high16 v13, 0x380000

    and-int/2addr v0, v13

    or-int v19, v1, v0

    const/16 v20, 0x0

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    move-object/from16 v16, p14

    move-object/from16 v13, v18

    move/from16 v18, p2

    invoke-static/range {v0 .. v20}, Llyiahf/vczjk/nqa;->OooO0oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/lm6;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/nf6;Llyiahf/vczjk/hg9;ZLlyiahf/vczjk/qg6;IFLlyiahf/vczjk/uj6;Llyiahf/vczjk/bz5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/m4;Llyiahf/vczjk/n4;Llyiahf/vczjk/dv8;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;III)V

    move v4, v8

    move-object v8, v5

    move v5, v4

    move v4, v9

    move v9, v6

    move v6, v4

    move-object v4, v14

    move-object v14, v7

    move-object v7, v4

    move-object v4, v12

    move-object v12, v11

    move-object v11, v4

    move-object v4, v10

    move-object v13, v15

    move v10, v3

    move-object v3, v2

    move-object v2, v0

    goto :goto_30

    :cond_49
    move-object/from16 v17, v12

    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move/from16 v6, p5

    move-object/from16 v11, p10

    move-object/from16 v12, p11

    move-object/from16 v14, p13

    move-object v4, v7

    move-object v2, v8

    move-object v7, v9

    move-object v8, v10

    move v5, v13

    move-object v3, v15

    move/from16 v9, p8

    move/from16 v10, p9

    move-object/from16 v13, p12

    :goto_30
    invoke-virtual/range {v17 .. v17}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v0

    if-eqz v0, :cond_4a

    move-object v1, v0

    new-instance v0, Llyiahf/vczjk/uk6;

    move-object/from16 v15, p14

    move/from16 v16, p16

    move/from16 v17, p17

    move/from16 v18, p18

    move-object/from16 v35, v1

    move-object/from16 v1, p0

    invoke-direct/range {v0 .. v18}, Llyiahf/vczjk/uk6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;Llyiahf/vczjk/uj6;IFLlyiahf/vczjk/n4;Llyiahf/vczjk/hg9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/bz5;Llyiahf/vczjk/dv8;Llyiahf/vczjk/qg6;Llyiahf/vczjk/df3;III)V

    move-object/from16 v1, v35

    iput-object v0, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_4a
    return-void
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/kl5;Ljava/util/List;Ljava/lang/Integer;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 29

    move-object/from16 v1, p0

    move-object/from16 v6, p1

    move-object/from16 v0, p2

    move/from16 v10, p3

    move-object/from16 v11, p4

    move-object/from16 v12, p5

    move/from16 v13, p9

    move-object/from16 v7, p8

    check-cast v7, Llyiahf/vczjk/zf1;

    const v2, 0x153be033

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v2, v13, 0x6

    if-nez v2, :cond_1

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    const/4 v2, 0x4

    goto :goto_0

    :cond_0
    const/4 v2, 0x2

    :goto_0
    or-int/2addr v2, v13

    goto :goto_1

    :cond_1
    move v2, v13

    :goto_1
    and-int/lit8 v4, v13, 0x30

    if-nez v4, :cond_3

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v2, v4

    :cond_3
    and-int/lit16 v4, v13, 0x180

    if-nez v4, :cond_6

    and-int/lit16 v4, v13, 0x200

    if-nez v4, :cond_4

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    goto :goto_3

    :cond_4
    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    :goto_3
    if-eqz v4, :cond_5

    const/16 v4, 0x100

    goto :goto_4

    :cond_5
    const/16 v4, 0x80

    :goto_4
    or-int/2addr v2, v4

    :cond_6
    and-int/lit16 v4, v13, 0xc00

    if-nez v4, :cond_8

    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v4

    if-eqz v4, :cond_7

    const/16 v4, 0x800

    goto :goto_5

    :cond_7
    const/16 v4, 0x400

    :goto_5
    or-int/2addr v2, v4

    :cond_8
    and-int/lit16 v4, v13, 0x6000

    if-nez v4, :cond_a

    invoke-virtual {v7, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_9

    const/16 v4, 0x4000

    goto :goto_6

    :cond_9
    const/16 v4, 0x2000

    :goto_6
    or-int/2addr v2, v4

    :cond_a
    const/high16 v20, 0x30000

    and-int v4, v13, v20

    if-nez v4, :cond_c

    invoke-virtual {v7, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_b

    const/high16 v4, 0x20000

    goto :goto_7

    :cond_b
    const/high16 v4, 0x10000

    :goto_7
    or-int/2addr v2, v4

    :cond_c
    const/high16 v4, 0x180000

    and-int/2addr v4, v13

    if-nez v4, :cond_e

    move-object/from16 v4, p6

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v15

    if-eqz v15, :cond_d

    const/high16 v15, 0x100000

    goto :goto_8

    :cond_d
    const/high16 v15, 0x80000

    :goto_8
    or-int/2addr v2, v15

    goto :goto_9

    :cond_e
    move-object/from16 v4, p6

    :goto_9
    const/high16 v15, 0xc00000

    and-int/2addr v15, v13

    if-nez v15, :cond_10

    move-object/from16 v15, p7

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v16

    if-eqz v16, :cond_f

    const/high16 v16, 0x800000

    goto :goto_a

    :cond_f
    const/high16 v16, 0x400000

    :goto_a
    or-int v2, v2, v16

    goto :goto_b

    :cond_10
    move-object/from16 v15, p7

    :goto_b
    const v16, 0x492493

    const/16 v21, 0x2

    and-int v3, v2, v16

    const v8, 0x492492

    if-ne v3, v8, :cond_12

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_11

    goto :goto_c

    :cond_11
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_1d

    :cond_12
    :goto_c
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v3, v13, 0x1

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-eqz v3, :cond_14

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v3

    if-eqz v3, :cond_13

    goto :goto_d

    :cond_13
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :cond_14
    :goto_d
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v8, :cond_15

    invoke-static {v7}, Llyiahf/vczjk/c6a;->Oooo0(Llyiahf/vczjk/rf1;)Llyiahf/vczjk/xr1;

    move-result-object v3

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    check-cast v3, Llyiahf/vczjk/xr1;

    const v9, 0x6e3c21fe

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-ne v14, v8, :cond_16

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v14

    invoke-virtual {v7, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_16
    move-object/from16 v24, v14

    check-cast v24, Llyiahf/vczjk/qs5;

    const/4 v14, 0x0

    invoke-static {v7, v14, v9}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v8, :cond_17

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    invoke-static {v5}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v5

    invoke-virtual {v7, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_17
    check-cast v5, Llyiahf/vczjk/qs5;

    invoke-static {v7, v14, v9}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v9

    if-ne v9, v8, :cond_18

    invoke-static {v14}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    invoke-static {v9}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v9

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v9, Llyiahf/vczjk/qs5;

    invoke-virtual {v7, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-array v4, v14, [Ljava/lang/Object;

    sget-object v15, Llyiahf/vczjk/dw4;->OooOo0o:Llyiahf/vczjk/era;

    move-object/from16 v25, v9

    const v9, -0x615d173a

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    and-int/lit16 v9, v2, 0x380

    const/16 v14, 0x100

    if-eq v9, v14, :cond_1a

    and-int/lit16 v9, v2, 0x200

    if-eqz v9, :cond_19

    invoke-virtual {v7, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_19

    goto :goto_e

    :cond_19
    const/4 v9, 0x0

    goto :goto_f

    :cond_1a
    :goto_e
    const/4 v9, 0x1

    :goto_f
    or-int v9, v18, v9

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v9, :cond_1b

    if-ne v14, v8, :cond_1c

    :cond_1b
    new-instance v14, Llyiahf/vczjk/w77;

    const/16 v9, 0xe

    invoke-direct {v14, v9, v6, v0}, Llyiahf/vczjk/w77;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v7, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1c
    check-cast v14, Llyiahf/vczjk/le3;

    const/4 v9, 0x0

    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v18, 0x0

    const/16 v19, 0x4

    move-object/from16 v17, v7

    move-object/from16 v16, v14

    const/4 v7, 0x1

    move-object v14, v4

    const/high16 v4, 0x100000

    invoke-static/range {v14 .. v19}, Llyiahf/vczjk/ht6;->OooOo0o([Ljava/lang/Object;Llyiahf/vczjk/era;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)Ljava/lang/Object;

    move-result-object v14

    move-object/from16 v15, v17

    check-cast v14, Llyiahf/vczjk/dw4;

    const v9, -0x4a3adcb4

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v9, v14, Llyiahf/vczjk/dw4;->OooO0oo:Llyiahf/vczjk/u32;

    invoke-virtual {v9}, Llyiahf/vczjk/u32;->OooO00o()Z

    move-result v9

    move/from16 v16, v9

    if-nez v16, :cond_20

    invoke-interface/range {v25 .. v25}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v16

    check-cast v16, Ljava/lang/Number;

    invoke-virtual/range {v16 .. v16}, Ljava/lang/Number;->intValue()I

    move-result v16

    if-lez v16, :cond_20

    iget-object v4, v14, Llyiahf/vczjk/dw4;->OooO0Oo:Llyiahf/vczjk/tq4;

    invoke-virtual {v4}, Llyiahf/vczjk/tq4;->OooO0O0()I

    move-result v9

    neg-int v9, v9

    invoke-interface/range {v25 .. v25}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v18

    check-cast v18, Ljava/lang/Number;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Number;->intValue()I

    move-result v18

    div-int/lit8 v18, v18, 0x2

    add-int v9, v18, v9

    invoke-virtual {v4}, Llyiahf/vczjk/tq4;->OooO0O0()I

    move-result v4

    invoke-interface/range {v25 .. v25}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v18

    check-cast v18, Ljava/lang/Number;

    invoke-virtual/range {v18 .. v18}, Ljava/lang/Number;->intValue()I

    move-result v18

    div-int/lit8 v18, v18, 0x2

    sub-int v4, v4, v18

    invoke-static {v4}, Ljava/lang/Math;->abs(I)I

    move-result v4

    if-le v4, v7, :cond_20

    const v4, -0x48fade91

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v17

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v18

    or-int v17, v17, v18

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v18

    or-int v17, v17, v18

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v18

    or-int v17, v17, v18

    const/high16 v18, 0x380000

    and-int v4, v2, v18

    const/high16 v7, 0x100000

    if-ne v4, v7, :cond_1d

    const/4 v4, 0x1

    goto :goto_10

    :cond_1d
    const/4 v4, 0x0

    :goto_10
    or-int v4, v17, v4

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v4, :cond_1e

    if-ne v7, v8, :cond_1f

    :cond_1e
    move v4, v2

    goto :goto_11

    :cond_1f
    move-object/from16 p8, v14

    move v14, v2

    move-object v2, v7

    move-object/from16 v7, p8

    move-object/from16 p8, v5

    move-object v0, v8

    move-object/from16 v27, v25

    const/4 v10, 0x0

    goto :goto_12

    :goto_11
    new-instance v2, Llyiahf/vczjk/ama;

    move-object v7, v5

    move v5, v9

    const/4 v9, 0x0

    move-object/from16 p8, v14

    move v14, v4

    move-object/from16 v4, p8

    move-object/from16 p8, v7

    move-object v0, v8

    move-object/from16 v8, v24

    move-object/from16 v27, v25

    const/4 v10, 0x0

    move-object/from16 v7, p6

    invoke-direct/range {v2 .. v9}, Llyiahf/vczjk/ama;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/dw4;ILjava/util/List;Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    move-object v7, v4

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_12
    check-cast v2, Llyiahf/vczjk/ze3;

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v7, v15, v2}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    goto :goto_13

    :cond_20
    move-object/from16 p8, v5

    move-object v0, v8

    move-object v7, v14

    move-object/from16 v27, v25

    const/4 v10, 0x0

    move v14, v2

    :goto_13
    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object v2, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v2, v10}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v2

    iget v3, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v15, v1}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v8, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v9, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v9, :cond_21

    invoke-virtual {v15, v8}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_14

    :cond_21
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_14
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v15, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v4, v15, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_22

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v8

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_23

    :cond_22
    invoke-static {v3, v15, v3, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_23
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v15, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const v2, -0x5797e84e

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v3, 0x0

    const/high16 v4, 0x3f800000    # 1.0f

    if-nez v2, :cond_2c

    invoke-interface/range {p8 .. p8}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    div-int/lit8 v2, v2, 0x2

    const v5, 0x2a4a9438

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object v5, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/f62;

    invoke-interface {v5, v2}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result v2

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/16 v5, 0xd

    invoke-static {v3, v2, v3, v3, v5}, Landroidx/compose/foundation/layout/OooO00o;->OooO0OO(FFFFI)Llyiahf/vczjk/di6;

    move-result-object v16

    invoke-static {v9, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    const v5, -0x615d173a

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v0, :cond_24

    new-instance v5, Llyiahf/vczjk/bz0;

    const/4 v8, 0x3

    move-object/from16 v3, p8

    move-object/from16 v4, v27

    invoke-direct {v5, v3, v4, v8}, Llyiahf/vczjk/bz0;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    goto :goto_15

    :cond_24
    move-object/from16 v4, v27

    :goto_15
    check-cast v5, Llyiahf/vczjk/oe3;

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v5}, Landroidx/compose/ui/layout/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v18

    const v2, -0x48fade91

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v2

    and-int/lit16 v3, v14, 0x1c00

    const/16 v5, 0x800

    if-ne v3, v5, :cond_25

    const/4 v3, 0x1

    goto :goto_16

    :cond_25
    move v3, v10

    :goto_16
    or-int/2addr v2, v3

    const/high16 v3, 0x1c00000

    and-int/2addr v3, v14

    const/high16 v5, 0x800000

    if-ne v3, v5, :cond_26

    const/4 v3, 0x1

    goto :goto_17

    :cond_26
    move v3, v10

    :goto_17
    or-int/2addr v2, v3

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    or-int/2addr v2, v3

    const/high16 v3, 0x70000

    and-int/2addr v3, v14

    xor-int v3, v3, v20

    const/high16 v5, 0x20000

    if-le v3, v5, :cond_27

    invoke-virtual {v15, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_28

    :cond_27
    and-int v3, v14, v20

    if-ne v3, v5, :cond_29

    :cond_28
    const/4 v14, 0x1

    goto :goto_18

    :cond_29
    move v14, v10

    :goto_18
    or-int/2addr v2, v14

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-nez v2, :cond_2b

    if-ne v3, v0, :cond_2a

    goto :goto_19

    :cond_2a
    move-object v2, v3

    const/4 v0, 0x0

    const/high16 v12, 0x3f800000    # 1.0f

    move/from16 v3, p3

    goto :goto_1a

    :cond_2b
    :goto_19
    new-instance v2, Llyiahf/vczjk/xla;

    move-object v5, v4

    move-object v3, v6

    move-object v8, v12

    const/4 v0, 0x0

    const/high16 v12, 0x3f800000    # 1.0f

    move/from16 v4, p3

    move-object/from16 v6, p7

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/xla;-><init>(Ljava/util/List;FLlyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dw4;Llyiahf/vczjk/n62;)V

    move v3, v4

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :goto_1a
    move-object/from16 v23, v2

    check-cast v23, Llyiahf/vczjk/oe3;

    invoke-virtual {v15, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move/from16 v2, v21

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v17, 0x0

    move-object/from16 v14, v18

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const/16 v25, 0x6

    const/16 v26, 0x1f8

    move-object/from16 v24, v15

    move-object v15, v7

    invoke-static/range {v14 .. v26}, Llyiahf/vczjk/mc4;->OooO0o0(Llyiahf/vczjk/kl5;Llyiahf/vczjk/dw4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/m4;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v7, v24

    goto :goto_1b

    :cond_2c
    move v0, v3

    move v12, v4

    move-object v7, v15

    move/from16 v2, v21

    move/from16 v3, p3

    :goto_1b
    invoke-virtual {v7, v10}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v4, -0x57973acb

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-boolean v4, v11, Llyiahf/vczjk/w56;->OooO00o:Z

    if-eqz v4, :cond_2d

    invoke-static {v9, v12}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    neg-float v5, v3

    int-to-float v14, v2

    div-float/2addr v5, v14

    const/4 v15, 0x1

    invoke-static {v4, v0, v5, v15}, Landroidx/compose/foundation/layout/OooO00o;->OooO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    iget v5, v11, Llyiahf/vczjk/w56;->OooO0Oo:F

    neg-float v6, v5

    invoke-static {v4, v6, v0, v2}, Landroidx/compose/foundation/layout/OooO00o;->OooO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v4

    mul-float/2addr v5, v14

    move/from16 v21, v2

    move-object v2, v4

    iget-wide v3, v11, Llyiahf/vczjk/w56;->OooO0O0:J

    move v8, v6

    move v6, v5

    iget v5, v11, Llyiahf/vczjk/w56;->OooO0OO:F

    move/from16 v16, v8

    const/4 v8, 0x0

    move-object/from16 v17, v9

    const/4 v9, 0x0

    move/from16 v28, v16

    move-object/from16 v10, v17

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/tg0;->OooO(Llyiahf/vczjk/kl5;JFFLlyiahf/vczjk/rf1;II)V

    invoke-static {v10, v12}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    div-float v3, p3, v14

    invoke-static {v2, v0, v3, v15}, Landroidx/compose/foundation/layout/OooO00o;->OooO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    move/from16 v8, v28

    const/4 v3, 0x2

    invoke-static {v2, v8, v0, v3}, Landroidx/compose/foundation/layout/OooO00o;->OooO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-wide v3, v11, Llyiahf/vczjk/w56;->OooO0O0:J

    iget v5, v11, Llyiahf/vczjk/w56;->OooO0OO:F

    const/4 v8, 0x0

    const/4 v9, 0x0

    invoke-static/range {v2 .. v9}, Llyiahf/vczjk/tg0;->OooO(Llyiahf/vczjk/kl5;JFFLlyiahf/vczjk/rf1;II)V

    const/4 v9, 0x0

    goto :goto_1c

    :cond_2d
    const/4 v15, 0x1

    move v9, v10

    :goto_1c
    invoke-virtual {v7, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v7, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1d
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v10

    if-eqz v10, :cond_2e

    new-instance v0, Llyiahf/vczjk/yla;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move/from16 v4, p3

    move-object/from16 v6, p5

    move-object/from16 v7, p6

    move-object/from16 v8, p7

    move-object v5, v11

    move v9, v13

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/yla;-><init>(Llyiahf/vczjk/kl5;Ljava/util/List;Ljava/lang/Integer;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;I)V

    iput-object v0, v10, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_2e
    return-void
.end method

.method public static OooO0o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 12

    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_5

    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_5

    if-nez p2, :cond_0

    goto/16 :goto_4

    :cond_0
    sget-object v0, Llyiahf/vczjk/qy2;->OooO0oo:Llyiahf/vczjk/qy2;

    const-string v1, "\n\n"

    const-string v2, ":\n"

    invoke-static {v1, p1, v2, p2, v1}, Llyiahf/vczjk/ii5;->OooOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p2, 0x0

    :try_start_0
    new-instance v1, Ljava/io/RandomAccessFile;

    const-string v0, "rws"

    invoke-direct {v1, p0, v0}, Ljava/io/RandomAccessFile;-><init>(Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    :try_start_1
    invoke-virtual {v1}, Ljava/io/RandomAccessFile;->length()J

    move-result-wide v2

    const-wide/16 v4, 0x0

    cmp-long p0, v2, v4

    if-lez p0, :cond_3

    invoke-virtual {v1}, Ljava/io/RandomAccessFile;->getChannel()Ljava/nio/channels/FileChannel;

    move-result-object v6

    sget-object v7, Ljava/nio/channels/FileChannel$MapMode;->READ_ONLY:Ljava/nio/channels/FileChannel$MapMode;

    invoke-virtual {v1}, Ljava/io/RandomAccessFile;->length()J

    move-result-wide v10

    const-wide/16 v8, 0x0

    invoke-virtual/range {v6 .. v11}, Ljava/nio/channels/FileChannel;->map(Ljava/nio/channels/FileChannel$MapMode;JJ)Ljava/nio/MappedByteBuffer;

    move-result-object p0

    invoke-virtual {v1}, Ljava/io/RandomAccessFile;->length()J

    move-result-wide v2

    :goto_0
    cmp-long p2, v2, v4

    if-lez p2, :cond_2

    long-to-int p2, v2

    add-int/lit8 p2, p2, -0x1

    invoke-virtual {p0, p2}, Ljava/nio/ByteBuffer;->get(I)B

    move-result p2

    if-eqz p2, :cond_1

    goto :goto_1

    :cond_1
    const-wide/16 v6, 0x1

    sub-long/2addr v2, v6

    goto :goto_0

    :catchall_0
    move-exception v0

    move-object p0, v0

    move-object p2, v1

    goto :goto_3

    :catch_0
    move-exception v0

    move-object p0, v0

    move-object p2, v1

    goto :goto_2

    :cond_2
    :goto_1
    move-wide v4, v2

    :cond_3
    invoke-virtual {v1, v4, v5}, Ljava/io/RandomAccessFile;->seek(J)V

    const-string p0, "UTF-8"

    invoke-virtual {p1, p0}, Ljava/lang/String;->getBytes(Ljava/lang/String;)[B

    move-result-object p0

    invoke-virtual {v1, p0}, Ljava/io/RandomAccessFile;->write([B)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    invoke-virtual {v1}, Ljava/io/RandomAccessFile;->close()V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_3

    return-void

    :catchall_1
    move-exception v0

    move-object p0, v0

    goto :goto_3

    :catch_1
    move-exception v0

    move-object p0, v0

    :goto_2
    :try_start_3
    const-string p1, "xcrash"

    const-string v0, "FileManager appendText failed"

    invoke-static {p1, v0, p0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    if-eqz p2, :cond_5

    :try_start_4
    invoke-virtual {p2}, Ljava/io/RandomAccessFile;->close()V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_3

    goto :goto_4

    :goto_3
    if-eqz p2, :cond_4

    :try_start_5
    invoke-virtual {p2}, Ljava/io/RandomAccessFile;->close()V
    :try_end_5
    .catch Ljava/lang/Exception; {:try_start_5 .. :try_end_5} :catch_2

    :catch_2
    :cond_4
    throw p0

    :catch_3
    :cond_5
    :goto_4
    return-void
.end method

.method public static final OooO0o0(Llyiahf/vczjk/gl9;)Landroid/view/inputmethod/ExtractedText;
    .locals 4

    new-instance v0, Landroid/view/inputmethod/ExtractedText;

    invoke-direct {v0}, Landroid/view/inputmethod/ExtractedText;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object v1, v1, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    iput-object v1, v0, Landroid/view/inputmethod/ExtractedText;->text:Ljava/lang/CharSequence;

    const/4 v2, 0x0

    iput v2, v0, Landroid/view/inputmethod/ExtractedText;->startOffset:I

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v1

    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->partialEndOffset:I

    const/4 v1, -0x1

    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->partialStartOffset:I

    iget-wide v1, p0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result v3

    iput v3, v0, Landroid/view/inputmethod/ExtractedText;->selectionStart:I

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    iput v1, v0, Landroid/view/inputmethod/ExtractedText;->selectionEnd:I

    iget-object p0, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object p0, p0, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    const/16 v1, 0xa

    invoke-static {p0, v1}, Llyiahf/vczjk/z69;->Oooo0o0(Ljava/lang/CharSequence;C)Z

    move-result p0

    xor-int/lit8 p0, p0, 0x1

    iput p0, v0, Landroid/view/inputmethod/ExtractedText;->flags:I

    return-object v0
.end method

.method public static final OooO0oo(Llyiahf/vczjk/hg2;JJF)V
    .locals 12

    const-string v0, "$this$drawSelectorIndicator"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v9, Llyiahf/vczjk/h79;

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v3, 0x0

    const/16 v6, 0x1e

    move/from16 v2, p5

    move-object v1, v9

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/h79;-><init>(FFIII)V

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0Oo:J

    const/4 v8, 0x0

    const/4 v10, 0x0

    const/16 v11, 0x68

    move-object v1, p0

    move-wide v4, p1

    move-wide v6, p3

    invoke-static/range {v1 .. v11}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    sget-wide v2, Llyiahf/vczjk/n21;->OooO0o:J

    invoke-static/range {p5 .. p5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v0, v0

    invoke-static/range {p5 .. p5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    int-to-long v6, v6

    const/16 v8, 0x20

    shl-long/2addr v0, v8

    const-wide v10, 0xffffffffL

    and-long/2addr v6, v10

    or-long/2addr v0, v6

    invoke-static {p1, p2, v0, v1}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v4

    const/4 p1, 0x2

    int-to-float p1, p1

    mul-float p1, p1, p5

    shr-long v0, p3, v8

    long-to-int p2, v0

    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p2

    sub-float/2addr p2, p1

    and-long v0, p3, v10

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    sub-float/2addr v0, p1

    invoke-static {p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long p1, p1

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v0, v0

    shl-long/2addr p1, v8

    and-long/2addr v0, v10

    or-long v6, p1, v0

    const/4 v8, 0x0

    const/4 v10, 0x0

    const/16 v11, 0x68

    move-object v1, p0

    invoke-static/range {v1 .. v11}, Llyiahf/vczjk/hg2;->Oooooo0(Llyiahf/vczjk/hg2;JJJFLlyiahf/vczjk/h79;Llyiahf/vczjk/p21;I)V

    return-void
.end method

.method public static final OooOO0(Llyiahf/vczjk/gl9;I)Llyiahf/vczjk/an;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-wide v1, p0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v3

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0Oo(J)I

    move-result v1

    add-int/2addr v1, p1

    iget-object p0, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-object p0, p0, Llyiahf/vczjk/an;->OooOOO:Ljava/lang/String;

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result p0

    invoke-static {v1, p0}, Ljava/lang/Math;->min(II)I

    move-result p0

    invoke-virtual {v0, v3, p0}, Llyiahf/vczjk/an;->OooO0OO(II)Llyiahf/vczjk/an;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOO0O(Llyiahf/vczjk/gl9;I)Llyiahf/vczjk/an;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    iget-wide v1, p0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p0

    sub-int/2addr p0, p1

    const/4 p1, 0x0

    invoke-static {p1, p0}, Ljava/lang/Math;->max(II)I

    move-result p0

    invoke-static {v1, v2}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result p1

    invoke-virtual {v0, p0, p1}, Llyiahf/vczjk/an;->OooO0OO(II)Llyiahf/vczjk/an;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOO0o(Landroid/text/Spanned;Ljava/lang/Class;)Z
    .locals 2

    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    move-result v0

    const/4 v1, -0x1

    invoke-interface {p0, v1, v0, p1}, Landroid/text/Spanned;->nextSpanTransition(IILjava/lang/Class;)I

    move-result p1

    invoke-interface {p0}, Ljava/lang/CharSequence;->length()I

    move-result p0

    if-eq p1, p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOOO0(Landroid/content/res/Configuration;Landroid/graphics/Typeface;)Landroid/graphics/Typeface;
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1f

    if-lt v0, v1, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/x9;->OooO00o(Landroid/content/res/Configuration;)I

    move-result v0

    const v1, 0x7fffffff

    if-eq v0, v1, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/x9;->OooO00o(Landroid/content/res/Configuration;)I

    move-result v0

    if-eqz v0, :cond_0

    if-eqz p1, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/md9;->OooO00o(Landroid/graphics/Typeface;)I

    move-result v0

    invoke-static {p0}, Llyiahf/vczjk/x9;->OooO00o(Landroid/content/res/Configuration;)I

    move-result p0

    add-int/2addr p0, v0

    const/4 v0, 0x1

    const/16 v1, 0x3e8

    invoke-static {p0, v0, v1}, Llyiahf/vczjk/l4a;->OooOOOO(III)I

    move-result p0

    invoke-virtual {p1}, Landroid/graphics/Typeface;->isItalic()Z

    move-result v0

    invoke-static {p1, p0, v0}, Llyiahf/vczjk/a32;->OooO0Oo(Landroid/graphics/Typeface;IZ)Landroid/graphics/Typeface;

    move-result-object p0

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public static OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/wea;
    .locals 5

    if-eqz p0, :cond_3

    invoke-static {p0}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_1

    :cond_0
    const-string v0, "(\\d+)(?:\\.(\\d+))(?:\\.(\\d+))(?:-(.+))?"

    invoke-static {v0}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;)Ljava/util/regex/Pattern;

    move-result-object v0

    invoke-virtual {v0, p0}, Ljava/util/regex/Pattern;->matcher(Ljava/lang/CharSequence;)Ljava/util/regex/Matcher;

    move-result-object p0

    invoke-virtual {p0}, Ljava/util/regex/Matcher;->matches()Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    const/4 v0, 0x1

    invoke-virtual {p0, v0}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_3

    invoke-static {v0}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v0

    const/4 v1, 0x2

    invoke-virtual {p0, v1}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_3

    invoke-static {v1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v1

    const/4 v2, 0x3

    invoke-virtual {p0, v2}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_3

    invoke-static {v2}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v2

    const/4 v3, 0x4

    invoke-virtual {p0, v3}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object v4

    if-eqz v4, :cond_2

    invoke-virtual {p0, v3}, Ljava/util/regex/Matcher;->group(I)Ljava/lang/String;

    move-result-object p0

    goto :goto_0

    :cond_2
    const-string p0, ""

    :goto_0
    new-instance v3, Llyiahf/vczjk/wea;

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-direct {v3, v0, v1, v2, p0}, Llyiahf/vczjk/wea;-><init>(IIILjava/lang/String;)V

    return-object v3

    :cond_3
    :goto_1
    const/4 p0, 0x0

    return-object p0
.end method


# virtual methods
.method public OooO0oO(I)V
    .locals 3

    new-instance v0, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    new-instance v1, Llyiahf/vczjk/oOOOOo0O;

    const/4 v2, 0x5

    invoke-direct {v1, p1, v2, p0}, Llyiahf/vczjk/oOOOOo0O;-><init>(IILjava/lang/Object;)V

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    return-void
.end method

.method public abstract OooOOO(I)V
.end method

.method public abstract OooOOOO(Landroid/graphics/Typeface;)V
.end method
