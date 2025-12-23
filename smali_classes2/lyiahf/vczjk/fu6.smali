.class public abstract Llyiahf/vczjk/fu6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final synthetic OooO00o:I

.field public static final synthetic OooO0O0:I

.field public static final synthetic OooO0OO:I


# direct methods
.method public static final OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/n3a;Ljava/util/Set;)Z
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto/16 :goto_5

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/hz0;

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    check-cast v0, Llyiahf/vczjk/hz0;

    goto :goto_0

    :cond_1
    move-object v0, v2

    :goto_0
    if-eqz v0, :cond_2

    invoke-interface {v0}, Llyiahf/vczjk/hz0;->OooOo00()Ljava/util/List;

    move-result-object v0

    goto :goto_1

    :cond_2
    move-object v0, v2

    :goto_1
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/d21;->o0000Oo0(Ljava/util/List;)Llyiahf/vczjk/uy;

    move-result-object p0

    instance-of v1, p0, Ljava/util/Collection;

    const/4 v3, 0x0

    if-eqz v1, :cond_3

    move-object v1, p0

    check-cast v1, Ljava/util/Collection;

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_3

    goto :goto_6

    :cond_3
    invoke-virtual {p0}, Llyiahf/vczjk/uy;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_4
    move-object v1, p0

    check-cast v1, Llyiahf/vczjk/zi2;

    iget-object v4, v1, Llyiahf/vczjk/zi2;->OooOOO:Ljava/util/Iterator;

    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_8

    invoke-virtual {v1}, Llyiahf/vczjk/zi2;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/kx3;

    iget v4, v1, Llyiahf/vczjk/kx3;->OooO00o:I

    iget-object v1, v1, Llyiahf/vczjk/kx3;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/z4a;

    if-eqz v0, :cond_5

    invoke-static {v4, v0}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/t4a;

    goto :goto_2

    :cond_5
    move-object v4, v2

    :goto_2
    if-eqz v4, :cond_6

    if-eqz p2, :cond_6

    invoke-interface {p2, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_6

    goto :goto_3

    :cond_6
    invoke-virtual {v1}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v4

    if-eqz v4, :cond_7

    :goto_3
    move v1, v3

    goto :goto_4

    :cond_7
    invoke-virtual {v1}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v1

    const-string v4, "getType(...)"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1, p1, p2}, Llyiahf/vczjk/fu6;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/n3a;Ljava/util/Set;)Z

    move-result v1

    :goto_4
    if-eqz v1, :cond_4

    :goto_5
    const/4 p0, 0x1

    return p0

    :cond_8
    :goto_6
    return v3
.end method

.method public static final OooO00o(Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;I)V
    .locals 24

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p2

    check-cast v2, Llyiahf/vczjk/zf1;

    const v3, -0x2d01f60d

    invoke-virtual {v2, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v3, p3, 0x6

    if-nez v3, :cond_1

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int v3, p3, v3

    goto :goto_1

    :cond_1
    move/from16 v3, p3

    :goto_1
    invoke-virtual {v2, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    const/16 v5, 0x20

    if-eqz v4, :cond_2

    move v4, v5

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v3, v4

    and-int/lit8 v4, v3, 0x13

    const/16 v6, 0x12

    if-ne v4, v6, :cond_4

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v4

    if-nez v4, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object v1, v2

    goto/16 :goto_6

    :cond_4
    :goto_3
    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v6, 0x48

    int-to-float v6, v6

    invoke-static {v4, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/uv7;->OooO00o:Llyiahf/vczjk/tv7;

    invoke-static {v4, v6}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v6, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/x21;

    iget-wide v7, v7, Llyiahf/vczjk/x21;->OooOOo:J

    sget-object v9, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v4, v7, v8, v9}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v4

    const v7, 0x4c5de2

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v7, v3, 0x70

    const/4 v8, 0x0

    const/4 v9, 0x1

    if-ne v7, v5, :cond_5

    move v5, v9

    goto :goto_4

    :cond_5
    move v5, v8

    :goto_4
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    if-nez v5, :cond_6

    sget-object v5, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v5, :cond_7

    :cond_6
    new-instance v7, Llyiahf/vczjk/ok5;

    const/16 v5, 0x12

    invoke-direct {v7, v5, v1}, Llyiahf/vczjk/ok5;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v2, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_7
    check-cast v7, Llyiahf/vczjk/le3;

    invoke-virtual {v2, v8}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v5, 0x7

    const/4 v10, 0x0

    invoke-static {v4, v8, v10, v7, v5}, Landroidx/compose/foundation/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;ZLjava/lang/String;Llyiahf/vczjk/le3;I)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    invoke-static {v5, v8}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v5

    iget v7, v2, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v8

    invoke-static {v2, v4}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v4

    sget-object v10, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v10, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v11, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v11, :cond_8

    invoke-virtual {v2, v10}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_5

    :cond_8
    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_5
    sget-object v10, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v5, v2, v10}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v8, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v5, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v8, v2, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v8, :cond_9

    invoke-virtual {v2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v10

    invoke-static {v8, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_a

    :cond_9
    invoke-static {v7, v2, v7, v5}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_a
    sget-object v5, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v4, v2, v5}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v4, 0x18

    invoke-static {v4}, Llyiahf/vczjk/eo6;->OooOO0o(I)J

    move-result-wide v4

    sget-object v7, Llyiahf/vczjk/ib3;->OooOo00:Llyiahf/vczjk/ib3;

    invoke-virtual {v2, v6}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/x21;

    iget-wide v10, v6, Llyiahf/vczjk/x21;->OooOOoo:J

    move-object/from16 v19, v2

    move v6, v3

    move-wide v2, v10

    new-instance v10, Llyiahf/vczjk/ch9;

    const/4 v8, 0x3

    invoke-direct {v10, v8}, Llyiahf/vczjk/ch9;-><init>(I)V

    and-int/lit8 v6, v6, 0xe

    const v8, 0x186000

    or-int v20, v6, v8

    const/16 v17, 0x0

    const/16 v18, 0x0

    const/4 v1, 0x0

    move-object v6, v7

    const/4 v7, 0x0

    move v11, v9

    const-wide/16 v8, 0x0

    move v13, v11

    const-wide/16 v11, 0x0

    move v14, v13

    const/4 v13, 0x0

    move v15, v14

    const/4 v14, 0x0

    move/from16 v16, v15

    const/4 v15, 0x0

    move/from16 v21, v16

    const/16 v16, 0x0

    move/from16 v22, v21

    const/16 v21, 0x0

    move/from16 v23, v22

    const v22, 0x3fbaa

    invoke-static/range {v0 .. v22}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    move-object/from16 v1, v19

    const/4 v13, 0x1

    invoke-virtual {v1, v13}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_6
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v1

    if-eqz v1, :cond_b

    new-instance v2, Llyiahf/vczjk/rt;

    const/4 v3, 0x3

    move-object/from16 v4, p1

    move/from16 v5, p3

    invoke-direct {v2, v0, v4, v5, v3}, Llyiahf/vczjk/rt;-><init>(Ljava/lang/Object;Ljava/lang/Object;II)V

    iput-object v2, v1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_b
    return-void
.end method

.method public static final OooO0O0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;II)V
    .locals 23

    move-object/from16 v6, p3

    move-object/from16 v7, p4

    move/from16 v10, p8

    const-string v0, "onVerifyPin"

    invoke-static {v6, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "onSuccess"

    invoke-static {v7, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v11, p7

    check-cast v11, Llyiahf/vczjk/zf1;

    const v0, 0x238ca361

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, v10, 0x6

    move-object/from16 v1, p0

    if-nez v0, :cond_1

    invoke-virtual {v11, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    const/4 v0, 0x2

    :goto_0
    or-int/2addr v0, v10

    goto :goto_1

    :cond_1
    move v0, v10

    :goto_1
    or-int/lit8 v2, v0, 0x10

    and-int/lit8 v3, p9, 0x4

    if-eqz v3, :cond_2

    or-int/lit16 v0, v0, 0x190

    move v2, v0

    move-object/from16 v0, p2

    goto :goto_3

    :cond_2
    move-object/from16 v0, p2

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_3

    const/16 v4, 0x100

    goto :goto_2

    :cond_3
    const/16 v4, 0x80

    :goto_2
    or-int/2addr v2, v4

    :goto_3
    invoke-virtual {v11, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_4

    const/16 v4, 0x800

    goto :goto_4

    :cond_4
    const/16 v4, 0x400

    :goto_4
    or-int/2addr v2, v4

    and-int/lit16 v4, v10, 0x6000

    if-nez v4, :cond_6

    invoke-virtual {v11, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_5

    const/16 v4, 0x4000

    goto :goto_5

    :cond_5
    const/16 v4, 0x2000

    :goto_5
    or-int/2addr v2, v4

    :cond_6
    const/high16 v4, 0x30000

    and-int/2addr v4, v10

    move-object/from16 v8, p5

    if-nez v4, :cond_8

    invoke-virtual {v11, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_7

    const/high16 v4, 0x20000

    goto :goto_6

    :cond_7
    const/high16 v4, 0x10000

    :goto_6
    or-int/2addr v2, v4

    :cond_8
    const/high16 v4, 0xd80000

    or-int/2addr v2, v4

    const v4, 0x492493

    and-int/2addr v2, v4

    const v4, 0x492492

    if-ne v2, v4, :cond_a

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v2

    if-nez v2, :cond_9

    goto :goto_7

    :cond_9
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v2, p1

    move-object/from16 v7, p6

    move-object v3, v0

    move-object/from16 v20, v11

    goto/16 :goto_b

    :cond_a
    :goto_7
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v2, v10, 0x1

    sget-object v4, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const/4 v5, 0x0

    const v9, 0x6e3c21fe

    const/4 v12, 0x0

    if-eqz v2, :cond_c

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v2

    if-eqz v2, :cond_b

    goto :goto_9

    :cond_b
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v2, p1

    move-object/from16 v13, p6

    :goto_8
    move-object v3, v0

    goto :goto_a

    :cond_c
    :goto_9
    sget v2, Lgithub/tornaco/android/thanos/res/R$string;->module_locker_app_name:I

    invoke-static {v2, v11}, Llyiahf/vczjk/vt6;->Oooo0(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v2

    if-eqz v3, :cond_d

    move-object v0, v12

    :cond_d
    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v4, :cond_e

    new-instance v3, Llyiahf/vczjk/oOOO0OO0;

    const/16 v13, 0x16

    invoke-direct {v3, v13}, Llyiahf/vczjk/oOOO0OO0;-><init>(I)V

    invoke-virtual {v11, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    check-cast v3, Llyiahf/vczjk/le3;

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v13, v3

    goto :goto_8

    :goto_a
    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->OooOOo0()V

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v4, :cond_f

    const-string v0, ""

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    invoke-virtual {v11, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    check-cast v0, Llyiahf/vczjk/qs5;

    invoke-static {v11, v5, v9}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v14

    if-ne v14, v4, :cond_10

    sget-object v14, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v14}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v14

    invoke-virtual {v11, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_10
    check-cast v14, Llyiahf/vczjk/qs5;

    invoke-static {v11, v5, v9}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v9

    if-ne v9, v4, :cond_11

    sget-object v9, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v9}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v9

    invoke-virtual {v11, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    check-cast v9, Llyiahf/vczjk/qs5;

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-interface {v9}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v15

    check-cast v15, Ljava/lang/Boolean;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const v5, -0x615d173a

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v4, :cond_12

    new-instance v5, Llyiahf/vczjk/au6;

    invoke-direct {v5, v9, v0, v12}, Llyiahf/vczjk/au6;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v11, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_12
    check-cast v5, Llyiahf/vczjk/ze3;

    const/4 v12, 0x0

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v15, v11, v5}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v12}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v5

    const v15, -0x6815fd56

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v11}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v15

    if-ne v15, v4, :cond_13

    new-instance v15, Llyiahf/vczjk/bu6;

    const/4 v4, 0x0

    invoke-direct {v15, v12, v13, v0, v4}, Llyiahf/vczjk/bu6;-><init>(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v11, v15}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v15, Llyiahf/vczjk/ze3;

    invoke-virtual {v11, v12}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v5, v11, v15}, Llyiahf/vczjk/c6a;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v12, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO:Landroidx/compose/foundation/layout/FillElement;

    move-object v4, v0

    new-instance v0, Llyiahf/vczjk/eu6;

    move-object v5, v14

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/eu6;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;)V

    const v1, 0x3d0d78fc

    invoke-static {v1, v0, v11}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v19

    const/16 v17, 0x0

    const/16 v18, 0x0

    move-object/from16 v20, v11

    move-object v11, v12

    const/4 v12, 0x0

    move-object v0, v13

    const-wide/16 v13, 0x0

    const-wide/16 v15, 0x0

    const v21, 0xc00006

    const/16 v22, 0x7e

    invoke-static/range {v11 .. v22}, Llyiahf/vczjk/ua9;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJFFLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;II)V

    move-object v7, v0

    :goto_b
    invoke-virtual/range {v20 .. v20}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v11

    if-eqz v11, :cond_14

    new-instance v0, Llyiahf/vczjk/oa2;

    move-object/from16 v1, p0

    move-object/from16 v4, p3

    move-object/from16 v5, p4

    move-object/from16 v6, p5

    move/from16 v9, p9

    move v8, v10

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/oa2;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;II)V

    iput-object v0, v11, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_14
    return-void
.end method

.method public static final OooO0OO(Llyiahf/vczjk/qs5;Z)V
    .locals 0

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    invoke-interface {p0, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public static final OooO0Oo(Landroidx/compose/foundation/lazy/OooO00o;Llyiahf/vczjk/fq7;Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 20

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move/from16 v0, p7

    const-string v3, "<this>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v3, "reorderableState"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v7, p6

    check-cast v7, Llyiahf/vczjk/zf1;

    const v3, -0x1a79850d

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v3, v0, 0x6

    if-nez v3, :cond_1

    invoke-virtual {v7, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    const/4 v3, 0x4

    goto :goto_0

    :cond_0
    const/4 v3, 0x2

    :goto_0
    or-int/2addr v3, v0

    goto :goto_1

    :cond_1
    move v3, v0

    :goto_1
    and-int/lit8 v4, v0, 0x30

    const/16 v5, 0x20

    if-nez v4, :cond_3

    invoke-virtual {v7, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_2

    move v4, v5

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v3, v4

    :cond_3
    and-int/lit16 v4, v0, 0x180

    if-nez v4, :cond_5

    move-object/from16 v4, p2

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_4

    const/16 v6, 0x100

    goto :goto_3

    :cond_4
    const/16 v6, 0x80

    :goto_3
    or-int/2addr v3, v6

    goto :goto_4

    :cond_5
    move-object/from16 v4, p2

    :goto_4
    const v6, 0x36c00

    or-int/2addr v3, v6

    const/high16 v6, 0x180000

    and-int/2addr v6, v0

    if-nez v6, :cond_7

    move-object/from16 v6, p5

    invoke-virtual {v7, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_6

    const/high16 v8, 0x100000

    goto :goto_5

    :cond_6
    const/high16 v8, 0x80000

    :goto_5
    or-int/2addr v3, v8

    goto :goto_6

    :cond_7
    move-object/from16 v6, p5

    :goto_6
    const v8, 0x92493

    and-int/2addr v8, v3

    const v9, 0x92492

    if-ne v8, v9, :cond_9

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_8

    goto :goto_7

    :cond_8
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v4, p3

    move/from16 v5, p4

    goto :goto_8

    :cond_9
    :goto_7
    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/4 v8, 0x0

    const/high16 v9, 0x43c80000    # 400.0f

    const/4 v10, 0x0

    const/4 v11, 0x5

    invoke-static {v8, v9, v10, v11}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v12

    const/4 v13, 0x1

    int-to-long v14, v13

    shl-long v16, v14, v5

    const-wide v18, 0xffffffffL

    and-long v14, v14, v18

    or-long v14, v16, v14

    new-instance v5, Llyiahf/vczjk/u14;

    invoke-direct {v5, v14, v15}, Llyiahf/vczjk/u14;-><init>(J)V

    invoke-static {v8, v9, v5, v13}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v5

    invoke-static {v8, v9, v10, v11}, Llyiahf/vczjk/ng0;->OoooOoo(FFLjava/lang/Object;I)Llyiahf/vczjk/wz8;

    move-result-object v8

    new-instance v9, Landroidx/compose/foundation/lazy/layout/LazyLayoutAnimateItemElement;

    invoke-direct {v9, v12, v5, v8}, Landroidx/compose/foundation/lazy/layout/LazyLayoutAnimateItemElement;-><init>(Llyiahf/vczjk/wz8;Llyiahf/vczjk/wz8;Llyiahf/vczjk/wz8;)V

    shr-int/lit8 v5, v3, 0x3

    const v8, 0xe3fe

    and-int/2addr v5, v8

    const/high16 v8, 0x70000

    shl-int/lit8 v10, v3, 0x3

    and-int/2addr v8, v10

    or-int/2addr v5, v8

    const/high16 v8, 0x380000

    and-int/2addr v3, v8

    or-int v8, v5, v3

    move-object/from16 v3, p2

    move-object v5, v9

    invoke-static/range {v2 .. v8}, Llyiahf/vczjk/fu6;->OooO0o0(Llyiahf/vczjk/fq7;Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    move v5, v13

    :goto_8
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_a

    new-instance v0, Llyiahf/vczjk/iv0;

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v6, p5

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/iv0;-><init>(Landroidx/compose/foundation/lazy/OooO00o;Llyiahf/vczjk/fq7;Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;Llyiahf/vczjk/hl5;ZLlyiahf/vczjk/a91;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_a
    return-void
.end method

.method public static final OooO0o(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Ljava/time/LocalTime;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V
    .locals 21

    move-object/from16 v6, p5

    const-string v0, "onTimeChanged"

    invoke-static {v6, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v15, p6

    check-cast v15, Llyiahf/vczjk/zf1;

    const v0, -0x73207c8c

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    const/4 v0, 0x1

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v1

    if-eqz v1, :cond_0

    const/16 v1, 0x20

    goto :goto_0

    :cond_0
    const/16 v1, 0x10

    :goto_0
    or-int v1, p7, v1

    or-int/lit16 v1, v1, 0x400

    move-object/from16 v12, p3

    invoke-virtual {v15, v12}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_1

    const/16 v3, 0x4000

    goto :goto_1

    :cond_1
    const/16 v3, 0x2000

    :goto_1
    or-int/2addr v1, v3

    move-object/from16 v5, p4

    invoke-virtual {v15, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_2

    const/high16 v3, 0x20000

    goto :goto_2

    :cond_2
    const/high16 v3, 0x10000

    :goto_2
    or-int/2addr v1, v3

    invoke-virtual {v15, v6}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_3

    const/high16 v3, 0x100000

    goto :goto_3

    :cond_3
    const/high16 v3, 0x80000

    :goto_3
    or-int/2addr v1, v3

    const v3, 0x92493

    and-int/2addr v3, v1

    const v7, 0x92492

    if-ne v3, v7, :cond_5

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v3

    if-nez v3, :cond_4

    goto :goto_4

    :cond_4
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v3, p2

    goto/16 :goto_b

    :cond_5
    :goto_4
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo()V

    and-int/lit8 v3, p7, 0x1

    if-eqz v3, :cond_7

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOo0o()Z

    move-result v3

    if-eqz v3, :cond_6

    goto :goto_5

    :cond_6
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    and-int/lit16 v1, v1, -0x1c01

    move-object/from16 v11, p2

    goto :goto_6

    :cond_7
    :goto_5
    new-instance v3, Llyiahf/vczjk/w56;

    const/16 v7, 0xf

    const-wide/16 v8, 0x0

    invoke-direct {v3, v7, v8, v9}, Llyiahf/vczjk/w56;-><init>(IJ)V

    and-int/lit16 v1, v1, -0x1c01

    move-object v11, v3

    :goto_6
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo0()V

    const v3, 0x6e3c21fe

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v7, v8, :cond_8

    new-instance v7, Llyiahf/vczjk/pt6;

    invoke-static {v5}, Llyiahf/vczjk/o00O0OO;->OooO0O0(Ljava/time/LocalTime;)I

    move-result v9

    invoke-static {v5}, Llyiahf/vczjk/o00O0OO;->OooOoo0(Ljava/time/LocalTime;)I

    move-result v10

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    iput v9, v7, Llyiahf/vczjk/pt6;->OooO00o:I

    iput v10, v7, Llyiahf/vczjk/pt6;->OooO0O0:I

    const/4 v9, 0x0

    iput-object v9, v7, Llyiahf/vczjk/pt6;->OooO0OO:Llyiahf/vczjk/js9;

    invoke-static {v7}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v7

    invoke-virtual {v15, v7}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v7, Llyiahf/vczjk/qs5;

    const/4 v9, 0x0

    invoke-virtual {v15, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    new-instance v10, Llyiahf/vczjk/x14;

    const/16 v13, 0x17

    invoke-direct {v10, v9, v13, v0}, Llyiahf/vczjk/v14;-><init>(III)V

    invoke-static {v10}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v10

    new-instance v13, Llyiahf/vczjk/x14;

    const/16 v14, 0x3b

    invoke-direct {v13, v9, v14, v0}, Llyiahf/vczjk/v14;-><init>(III)V

    invoke-static {v13}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v17

    sget-object v13, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const/high16 v14, 0x3f800000    # 1.0f

    move-object/from16 v0, p0

    invoke-static {v0, v14}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v2, Llyiahf/vczjk/op3;->OooOo0o:Llyiahf/vczjk/tb0;

    const/4 v9, 0x6

    invoke-static {v13, v2, v15, v9}, Llyiahf/vczjk/fw7;->OooO00o(Llyiahf/vczjk/nx;Llyiahf/vczjk/tb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/hw7;

    move-result-object v2

    iget v9, v15, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v15, v3}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v3

    sget-object v19, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v19 .. v19}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v14, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v14, :cond_9

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_7

    :cond_9
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_7
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v2, v15, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v15, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v4, v15, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v4, :cond_a

    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v13

    invoke-static {v4, v13}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_b

    :cond_a
    invoke-static {v9, v15, v9, v2}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v3, v15, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-interface {v7}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/pt6;

    iget v2, v2, Llyiahf/vczjk/pt6;->OooO00o:I

    sget-object v3, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/high16 v4, 0x3f800000    # 1.0f

    invoke-static {v3, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    const v13, 0x3e99999a    # 0.3f

    invoke-static {v9, v13}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v9

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    const v14, -0x615d173a

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/high16 v20, 0x380000

    and-int v4, v1, v20

    const/high16 v13, 0x100000

    if-ne v4, v13, :cond_c

    const/4 v13, 0x1

    goto :goto_8

    :cond_c
    const/4 v13, 0x0

    :goto_8
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v14

    if-nez v13, :cond_d

    if-ne v14, v8, :cond_e

    :cond_d
    new-instance v14, Llyiahf/vczjk/as9;

    const/4 v13, 0x0

    invoke-direct {v14, v6, v7, v13}, Llyiahf/vczjk/as9;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_e
    move-object v13, v14

    check-cast v13, Llyiahf/vczjk/oe3;

    const/4 v14, 0x0

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v14, 0x4c5de2

    invoke-virtual {v15, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/lit8 v14, v1, 0x70

    const/16 v0, 0x20

    if-ne v14, v0, :cond_f

    const/4 v14, 0x1

    goto :goto_9

    :cond_f
    const/4 v14, 0x0

    :goto_9
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez v14, :cond_10

    if-ne v0, v8, :cond_11

    :cond_10
    new-instance v0, Llyiahf/vczjk/xm8;

    const/16 v14, 0x1a

    invoke-direct {v0, v14}, Llyiahf/vczjk/xm8;-><init>(I)V

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    move-object v14, v0

    check-cast v14, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    shl-int/lit8 v1, v1, 0x3

    const/high16 v16, 0x70000

    and-int v1, v1, v16

    const/16 v16, 0xc06

    or-int v16, v16, v1

    move-object/from16 v18, v7

    move-object v7, v9

    const/high16 v0, 0x3f800000    # 1.0f

    move-object v9, v2

    move-object v2, v8

    move-object v8, v10

    move/from16 v10, p1

    invoke-static/range {v7 .. v16}, Llyiahf/vczjk/cl6;->OooO0Oo(Llyiahf/vczjk/kl5;Ljava/util/List;Ljava/lang/Integer;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    invoke-interface/range {v18 .. v18}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/pt6;

    iget v7, v7, Llyiahf/vczjk/pt6;->OooO0O0:I

    invoke-static {v3, v0}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0OO(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    const v3, 0x3e99999a    # 0.3f

    invoke-static {v0, v3}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0Oo(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v0

    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v9

    const v3, -0x615d173a

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    const/high16 v13, 0x100000

    if-ne v4, v13, :cond_12

    const/4 v3, 0x1

    goto :goto_a

    :cond_12
    const/4 v3, 0x0

    :goto_a
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v3, :cond_13

    if-ne v4, v2, :cond_14

    :cond_13
    new-instance v4, Llyiahf/vczjk/as9;

    const/4 v3, 0x1

    move-object/from16 v7, v18

    invoke-direct {v4, v6, v7, v3}, Llyiahf/vczjk/as9;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/qs5;I)V

    invoke-virtual {v15, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_14
    move-object v13, v4

    check-cast v13, Llyiahf/vczjk/oe3;

    const v3, 0x6e3c21fe

    const/4 v14, 0x0

    invoke-static {v15, v14, v3}, Llyiahf/vczjk/ix8;->OooO0o0(Llyiahf/vczjk/zf1;ZI)Ljava/lang/Object;

    move-result-object v3

    if-ne v3, v2, :cond_15

    new-instance v3, Llyiahf/vczjk/xm8;

    const/16 v2, 0x1b

    invoke-direct {v3, v2}, Llyiahf/vczjk/xm8;-><init>(I)V

    invoke-virtual {v15, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    move-object v14, v3

    check-cast v14, Llyiahf/vczjk/oe3;

    const/4 v2, 0x0

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const v3, 0xc00c06

    or-int v16, v3, v1

    move/from16 v10, p1

    move-object/from16 v12, p3

    move-object v7, v0

    move-object/from16 v8, v17

    invoke-static/range {v7 .. v16}, Llyiahf/vczjk/cl6;->OooO0Oo(Llyiahf/vczjk/kl5;Ljava/util/List;Ljava/lang/Integer;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    const v0, -0x621e71a6

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v15, v2}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    const/4 v0, 0x1

    invoke-virtual {v15, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    move-object v3, v11

    :goto_b
    invoke-virtual {v15}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_16

    new-instance v0, Llyiahf/vczjk/bs9;

    move-object/from16 v1, p0

    move/from16 v2, p1

    move-object/from16 v4, p3

    move/from16 v7, p7

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/bs9;-><init>(Llyiahf/vczjk/kl5;FLlyiahf/vczjk/w56;Llyiahf/vczjk/n62;Ljava/time/LocalTime;Llyiahf/vczjk/oe3;I)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_16
    return-void
.end method

.method public static final OooO0o0(Llyiahf/vczjk/fq7;Lgithub/tornaco/android/thanos/module/compose/common/widget/SortItem;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V
    .locals 16

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v3, p2

    move-object/from16 v5, p4

    move/from16 v6, p6

    const-string v0, "state"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v0, p5

    check-cast v0, Llyiahf/vczjk/zf1;

    const v4, -0x3e34b5bf

    invoke-virtual {v0, v4}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v4, v6, 0x6

    if-nez v4, :cond_1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_0

    const/4 v4, 0x4

    goto :goto_0

    :cond_0
    const/4 v4, 0x2

    :goto_0
    or-int/2addr v4, v6

    goto :goto_1

    :cond_1
    move v4, v6

    :goto_1
    and-int/lit8 v7, v6, 0x30

    if-nez v7, :cond_3

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2

    const/16 v7, 0x20

    goto :goto_2

    :cond_2
    const/16 v7, 0x10

    :goto_2
    or-int/2addr v4, v7

    :cond_3
    and-int/lit16 v7, v6, 0x180

    if-nez v7, :cond_5

    invoke-virtual {v0, v3}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_4

    const/16 v7, 0x100

    goto :goto_3

    :cond_4
    const/16 v7, 0x80

    :goto_3
    or-int/2addr v4, v7

    :cond_5
    and-int/lit16 v7, v6, 0xc00

    if-nez v7, :cond_7

    move-object/from16 v7, p3

    invoke-virtual {v0, v7}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_6

    const/16 v8, 0x800

    goto :goto_4

    :cond_6
    const/16 v8, 0x400

    :goto_4
    or-int/2addr v4, v8

    goto :goto_5

    :cond_7
    move-object/from16 v7, p3

    :goto_5
    and-int/lit16 v8, v6, 0x6000

    const/4 v9, 0x1

    const/16 v10, 0x4000

    if-nez v8, :cond_9

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v8

    if-eqz v8, :cond_8

    move v8, v10

    goto :goto_6

    :cond_8
    const/16 v8, 0x2000

    :goto_6
    or-int/2addr v4, v8

    :cond_9
    const/high16 v8, 0x30000

    and-int/2addr v8, v6

    const/4 v11, 0x0

    if-nez v8, :cond_b

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_a

    const/high16 v8, 0x20000

    goto :goto_7

    :cond_a
    const/high16 v8, 0x10000

    :goto_7
    or-int/2addr v4, v8

    :cond_b
    const/high16 v8, 0x180000

    and-int/2addr v8, v6

    if-nez v8, :cond_d

    invoke-virtual {v0, v5}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_c

    const/high16 v8, 0x100000

    goto :goto_8

    :cond_c
    const/high16 v8, 0x80000

    :goto_8
    or-int/2addr v4, v8

    :cond_d
    const v8, 0x92493

    and-int/2addr v8, v4

    const v12, 0x92492

    if-ne v8, v12, :cond_f

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v8

    if-nez v8, :cond_e

    goto :goto_9

    :cond_e
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto/16 :goto_11

    :cond_f
    :goto_9
    iget-object v8, v1, Llyiahf/vczjk/fq7;->OooO:Llyiahf/vczjk/qs5;

    check-cast v8, Llyiahf/vczjk/fw8;

    invoke-virtual {v8}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v8

    if-eqz v8, :cond_10

    invoke-virtual {v1, v8}, Llyiahf/vczjk/fq7;->OooOO0O(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v8

    goto :goto_a

    :cond_10
    move-object v8, v11

    :goto_a
    invoke-static {v2, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    sget-object v12, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    const v13, 0xe000

    const v14, -0x615d173a

    const/4 v15, 0x0

    if-eqz v8, :cond_14

    const v11, 0x81d86ea

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    new-instance v11, Landroidx/compose/ui/ZIndexElement;

    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/2addr v13, v4

    if-ne v13, v10, :cond_11

    move v10, v9

    goto :goto_b

    :cond_11
    move v10, v15

    :goto_b
    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v10, v13

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v10, :cond_12

    if-ne v13, v12, :cond_13

    :cond_12
    new-instance v13, Llyiahf/vczjk/sp7;

    const/4 v10, 0x0

    invoke-direct {v13, v1, v10}, Llyiahf/vczjk/sp7;-><init>(Llyiahf/vczjk/fq7;I)V

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v13, Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v11, v13}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v10

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_f

    :cond_14
    const v11, 0x822f9ea

    invoke-virtual {v0, v11}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v11, v1, Llyiahf/vczjk/fq7;->OooO0Oo:Llyiahf/vczjk/tz8;

    iget-object v11, v11, Llyiahf/vczjk/tz8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v11, Llyiahf/vczjk/fw8;

    invoke-virtual {v11}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/f54;

    if-eqz v11, :cond_15

    iget-object v11, v11, Llyiahf/vczjk/f54;->OooO0O0:Ljava/lang/Object;

    goto :goto_c

    :cond_15
    const/4 v11, 0x0

    :goto_c
    invoke-static {v2, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v11

    if-eqz v11, :cond_19

    new-instance v11, Landroidx/compose/ui/ZIndexElement;

    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OoooO(I)V

    and-int/2addr v13, v4

    if-ne v13, v10, :cond_16

    move v10, v9

    goto :goto_d

    :cond_16
    move v10, v15

    :goto_d
    invoke-virtual {v0, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v13

    or-int/2addr v10, v13

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    if-nez v10, :cond_17

    if-ne v13, v12, :cond_18

    :cond_17
    new-instance v13, Llyiahf/vczjk/sp7;

    const/4 v10, 0x1

    invoke-direct {v13, v1, v10}, Llyiahf/vczjk/sp7;-><init>(Llyiahf/vczjk/fq7;I)V

    invoke-virtual {v0, v13}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_18
    check-cast v13, Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v11, v13}, Landroidx/compose/ui/graphics/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v10

    goto :goto_e

    :cond_19
    move-object v10, v7

    :goto_e
    invoke-virtual {v0, v15}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_f
    invoke-interface {v3, v10}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v10

    sget-object v11, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-static {v11, v15}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v11

    iget v12, v0, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v13

    invoke-static {v0, v10}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v10

    sget-object v14, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v14, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v15, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_1a

    invoke-virtual {v0, v14}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_10

    :cond_1a
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_10
    sget-object v14, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v11, v0, v14}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v13, v0, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v13, v0, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v13, :cond_1b

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v12}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v14

    invoke-static {v13, v14}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v13

    if-nez v13, :cond_1c

    :cond_1b
    invoke-static {v12, v0, v12, v11}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_1c
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v10, v0, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v10, Landroidx/compose/foundation/layout/OooO0O0;->OooO00o:Landroidx/compose/foundation/layout/OooO0O0;

    invoke-static {v8}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v8

    shr-int/lit8 v4, v4, 0xc

    and-int/lit16 v4, v4, 0x380

    const/4 v11, 0x6

    or-int/2addr v4, v11

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-virtual {v5, v10, v8, v0, v4}, Llyiahf/vczjk/a91;->OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0, v9}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_11
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object v8

    if-eqz v8, :cond_1d

    new-instance v0, Llyiahf/vczjk/ve5;

    const/4 v7, 0x1

    move-object/from16 v4, p3

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/ve5;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/cf3;II)V

    iput-object v0, v8, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_1d
    return-void
.end method

.method public static final OooO0oO(Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Ljava/lang/String;)V
    .locals 0

    invoke-interface {p0, p5}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Boolean;

    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p0

    sget-object p5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-interface {p3, p5}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    if-eqz p0, :cond_0

    const/4 p0, 0x0

    invoke-static {p4, p0}, Llyiahf/vczjk/fu6;->OooO0OO(Llyiahf/vczjk/qs5;Z)V

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void

    :cond_0
    const/4 p0, 0x1

    invoke-static {p4, p0}, Llyiahf/vczjk/fu6;->OooO0OO(Llyiahf/vczjk/qs5;Z)V

    invoke-interface {p2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/f19;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/f19;

    invoke-direct {v0, p0}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;)V

    return-object v0
.end method

.method public static final OooOO0(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;Llyiahf/vczjk/t4a;)Llyiahf/vczjk/f19;
    .locals 1

    const-string v0, "type"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/f19;

    if-eqz p2, :cond_0

    invoke-interface {p2}, Llyiahf/vczjk/t4a;->Oooo0OO()Llyiahf/vczjk/cda;

    move-result-object p2

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-ne p2, p1, :cond_1

    sget-object p1, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    :cond_1
    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)V

    return-object v0
.end method

.method public static final OooOO0O(Llyiahf/vczjk/uk4;Llyiahf/vczjk/dp8;Ljava/util/LinkedHashSet;Ljava/util/Set;)V
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/t4a;

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-nez p0, :cond_0

    invoke-interface {p2, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    return-void

    :cond_0
    check-cast v0, Llyiahf/vczjk/t4a;

    invoke-interface {v0}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object p0

    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_9

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/uk4;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0, p1, p2, p3}, Llyiahf/vczjk/fu6;->OooOO0O(Llyiahf/vczjk/uk4;Llyiahf/vczjk/dp8;Ljava/util/LinkedHashSet;Ljava/util/Set;)V

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/hz0;

    const/4 v2, 0x0

    if-eqz v1, :cond_2

    check-cast v0, Llyiahf/vczjk/hz0;

    goto :goto_1

    :cond_2
    move-object v0, v2

    :goto_1
    if-eqz v0, :cond_3

    invoke-interface {v0}, Llyiahf/vczjk/hz0;->OooOo00()Ljava/util/List;

    move-result-object v0

    goto :goto_2

    :cond_3
    move-object v0, v2

    :goto_2
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00ooo()Ljava/util/List;

    move-result-object p0

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    const/4 v1, 0x0

    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_9

    add-int/lit8 v3, v1, 0x1

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/z4a;

    if-eqz v0, :cond_4

    invoke-static {v1, v0}, Llyiahf/vczjk/d21;->o00oO0o(ILjava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/t4a;

    goto :goto_4

    :cond_4
    move-object v1, v2

    :goto_4
    if-eqz v1, :cond_5

    if-eqz p3, :cond_5

    invoke-interface {p3, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    goto :goto_5

    :cond_5
    invoke-virtual {v4}, Llyiahf/vczjk/z4a;->OooO0OO()Z

    move-result v1

    if-eqz v1, :cond_6

    goto :goto_5

    :cond_6
    invoke-virtual {v4}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v1

    invoke-static {p2, v1}, Llyiahf/vczjk/d21;->OoooooO(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_8

    invoke-virtual {v4}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v5

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    goto :goto_5

    :cond_7
    invoke-virtual {v4}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v1

    const-string v4, "getType(...)"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1, p1, p2, p3}, Llyiahf/vczjk/fu6;->OooOO0O(Llyiahf/vczjk/uk4;Llyiahf/vczjk/dp8;Ljava/util/LinkedHashSet;Ljava/util/Set;)V

    :cond_8
    :goto_5
    move v1, v3

    goto :goto_3

    :cond_9
    return-void
.end method

.method public static final OooOO0o(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/hk4;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/n3a;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object p0

    const-string v0, "getBuiltIns(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static final OooOOO(Llyiahf/vczjk/t4a;)Llyiahf/vczjk/uk4;
    .locals 6

    invoke-interface {p0}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object v0

    const-string v1, "getUpperBounds(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    invoke-interface {p0}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v4, v2

    check-cast v4, Llyiahf/vczjk/uk4;

    invoke-virtual {v4}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v4

    invoke-interface {v4}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v4

    instance-of v5, v4, Llyiahf/vczjk/by0;

    if-eqz v5, :cond_1

    move-object v3, v4

    check-cast v3, Llyiahf/vczjk/by0;

    :cond_1
    if-nez v3, :cond_2

    goto :goto_0

    :cond_2
    invoke-interface {v3}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/ly0;->OooOOO:Llyiahf/vczjk/ly0;

    if-eq v4, v5, :cond_0

    invoke-interface {v3}, Llyiahf/vczjk/by0;->getKind()Llyiahf/vczjk/ly0;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/ly0;->OooOOo0:Llyiahf/vczjk/ly0;

    if-eq v3, v4, :cond_0

    move-object v3, v2

    :cond_3
    check-cast v3, Llyiahf/vczjk/uk4;

    if-nez v3, :cond_4

    invoke-interface {p0}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object p0

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p0

    const-string v0, "first(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Llyiahf/vczjk/uk4;

    return-object p0

    :cond_4
    return-object v3
.end method

.method public static final OooOOOO(Ljava/lang/Object;)Llyiahf/vczjk/zc8;
    .locals 1

    sget-object v0, Llyiahf/vczjk/sb;->OooO0O0:Llyiahf/vczjk/h87;

    if-eq p0, v0, :cond_0

    check-cast p0, Llyiahf/vczjk/zc8;

    return-object p0

    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "Does not contain segment"

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooOOOo(Llyiahf/vczjk/t4a;Llyiahf/vczjk/n3a;Ljava/util/Set;)Z
    .locals 3

    const-string v0, "typeParameter"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Llyiahf/vczjk/t4a;->getUpperBounds()Ljava/util/List;

    move-result-object v0

    const-string v1, "getUpperBounds(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {p0}, Llyiahf/vczjk/gz0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v2

    invoke-static {v1, v2, p2}, Llyiahf/vczjk/fu6;->OooO(Llyiahf/vczjk/uk4;Llyiahf/vczjk/n3a;Ljava/util/Set;)Z

    move-result v2

    if-eqz v2, :cond_1

    if-eqz p1, :cond_2

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    :cond_2
    const/4 p0, 0x1

    return p0

    :cond_3
    :goto_0
    const/4 p0, 0x0

    return p0
.end method

.method public static OooOOo(Ljava/util/concurrent/Callable;)Llyiahf/vczjk/i88;
    .locals 1

    :try_start_0
    invoke-interface {p0}, Ljava/util/concurrent/Callable;->call()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/i88;

    if-eqz p0, :cond_0

    return-object p0

    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    const-string v0, "Scheduler Callable returned null"

    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    move-exception p0

    invoke-static {p0}, Llyiahf/vczjk/ur2;->OooO00o(Ljava/lang/Throwable;)Ljava/lang/RuntimeException;

    move-result-object p0

    throw p0
.end method

.method public static synthetic OooOOo0(Llyiahf/vczjk/t4a;Llyiahf/vczjk/n3a;I)Z
    .locals 1

    and-int/lit8 p2, p2, 0x2

    const/4 v0, 0x0

    if-eqz p2, :cond_0

    move-object p1, v0

    :cond_0
    invoke-static {p0, p1, v0}, Llyiahf/vczjk/fu6;->OooOOOo(Llyiahf/vczjk/t4a;Llyiahf/vczjk/n3a;Ljava/util/Set;)Z

    move-result p0

    return p0
.end method

.method public static final OooOOoo(Ljava/lang/Object;)Z
    .locals 1

    sget-object v0, Llyiahf/vczjk/sb;->OooO0O0:Llyiahf/vczjk/h87;

    if-ne p0, v0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static final OooOo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ko;)Llyiahf/vczjk/uk4;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->OooOOo0()Llyiahf/vczjk/ko;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/ko;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/ko;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o0OOO0o()Llyiahf/vczjk/d3a;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/br6;->Oooo000(Llyiahf/vczjk/d3a;Llyiahf/vczjk/ko;)Llyiahf/vczjk/d3a;

    move-result-object p0

    invoke-virtual {v0, p0}, Llyiahf/vczjk/iaa;->o00000o0(Llyiahf/vczjk/d3a;)Llyiahf/vczjk/iaa;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOo0(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x1

    invoke-static {p0, v0}, Llyiahf/vczjk/l5a;->OooO0oO(Llyiahf/vczjk/uk4;Z)Llyiahf/vczjk/iaa;

    move-result-object p0

    const-string v0, "makeNullable(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static varargs OooOo00(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;
    .locals 9

    const/4 v0, 0x0

    move v1, v0

    :goto_0
    array-length v2, p1

    if-ge v1, v2, :cond_1

    aget-object v2, p1, v1

    if-nez v2, :cond_0

    const-string v2, "null"

    goto :goto_1

    :cond_0
    :try_start_0
    invoke-virtual {v2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v2
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v3

    new-instance v4, Ljava/lang/StringBuilder;

    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v5, 0x40

    invoke-virtual {v4, v5}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-static {v2}, Ljava/lang/System;->identityHashCode(Ljava/lang/Object;)I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->toHexString(I)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v4, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    const-string v4, "com.google.common.base.Strings"

    invoke-static {v4}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    move-result-object v4

    sget-object v5, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    new-instance v6, Ljava/lang/StringBuilder;

    const-string v7, "Exception during lenientFormat for "

    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v6, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v4, v5, v6, v3}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    const-string v4, "<"

    const-string v5, " threw "

    invoke-static {v4, v2, v5}, Llyiahf/vczjk/ix8;->OooOOO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v2

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, ">"

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    :goto_1
    aput-object v2, p1, v1

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_1
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v2

    array-length v3, p1

    mul-int/lit8 v3, v3, 0x10

    add-int/2addr v3, v2

    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    move v2, v0

    :goto_2
    array-length v3, p1

    if-ge v0, v3, :cond_3

    const-string v3, "%s"

    invoke-virtual {p0, v3, v2}, Ljava/lang/String;->indexOf(Ljava/lang/String;I)I

    move-result v3

    const/4 v4, -0x1

    if-ne v3, v4, :cond_2

    goto :goto_3

    :cond_2
    invoke-virtual {v1, p0, v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    add-int/lit8 v2, v0, 0x1

    aget-object v0, p1, v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    add-int/lit8 v0, v3, 0x2

    move v8, v2

    move v2, v0

    move v0, v8

    goto :goto_2

    :cond_3
    :goto_3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    move-result v3

    invoke-virtual {v1, p0, v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;II)Ljava/lang/StringBuilder;

    array-length p0, p1

    if-ge v0, p0, :cond_5

    const-string p0, " ["

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 p0, v0, 0x1

    aget-object v0, p1, v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    :goto_4
    array-length v0, p1

    if-ge p0, v0, :cond_4

    const-string v0, ", "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v0, p0, 0x1

    aget-object p0, p1, p0

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    move p0, v0

    goto :goto_4

    :cond_4
    const/16 p0, 0x5d

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    :cond_5
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOo0O(FJ)J
    .locals 1

    invoke-static {p0}, Ljava/lang/Float;->isNaN(F)Z

    move-result v0

    if-nez v0, :cond_1

    const/high16 v0, 0x3f800000    # 1.0f

    cmpl-float v0, p0, v0

    if-ltz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0Oo(J)F

    move-result v0

    mul-float/2addr v0, p0

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide p0

    return-wide p0

    :cond_1
    :goto_0
    return-wide p1
.end method

.method public static final OooOo0o(Llyiahf/vczjk/bq6;IZLlyiahf/vczjk/y05;FF)V
    .locals 20

    move/from16 v0, p1

    move-object/from16 v1, p3

    move-object/from16 v2, p0

    check-cast v2, Llyiahf/vczjk/qe;

    invoke-virtual {v2}, Llyiahf/vczjk/qe;->OooO()V

    invoke-virtual {v1}, Llyiahf/vczjk/y05;->OooO00o()I

    move-result v3

    const/4 v4, 0x1

    const/4 v5, 0x0

    const/4 v6, 0x0

    move v8, v4

    move v7, v6

    :goto_0
    iget-object v9, v2, Llyiahf/vczjk/qe;->OooO00o:Landroid/graphics/Path;

    const/16 v16, 0x5

    const/16 v17, 0x4

    const/16 v18, 0x3

    const/16 v19, 0x2

    if-ge v7, v3, :cond_2

    invoke-virtual {v1, v7}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/bu1;

    if-eqz v8, :cond_1

    iget-object v8, v10, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v11, v8, v6

    aget v8, v8, v4

    invoke-virtual {v2, v11, v8}, Llyiahf/vczjk/qe;->OooO0o(FF)V

    if-eqz v0, :cond_0

    move-object v5, v10

    :cond_0
    move v8, v6

    :cond_1
    iget-object v11, v10, Llyiahf/vczjk/bu1;->OooO00o:[F

    move-object v12, v10

    aget v10, v11, v19

    move-object v13, v11

    aget v11, v13, v18

    move-object v14, v12

    aget v12, v13, v17

    aget v13, v13, v16

    move-object v15, v14

    invoke-virtual {v15}, Llyiahf/vczjk/bu1;->OooO00o()F

    move-result v14

    invoke-virtual {v15}, Llyiahf/vczjk/bu1;->OooO0O0()F

    move-result v15

    invoke-virtual/range {v9 .. v15}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    add-int/lit8 v7, v7, 0x1

    goto :goto_0

    :cond_2
    if-eqz p2, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/y05;->OooO00o()I

    move-result v3

    move v8, v4

    move v7, v6

    :goto_1
    if-ge v7, v3, :cond_4

    invoke-virtual {v1, v7}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/bu1;

    if-eqz v8, :cond_3

    iget-object v8, v10, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v11, v8, v6

    aget v8, v8, v4

    invoke-virtual {v2, v11, v8}, Llyiahf/vczjk/qe;->OooO0o0(FF)V

    move v8, v6

    :cond_3
    iget-object v11, v10, Llyiahf/vczjk/bu1;->OooO00o:[F

    move-object v12, v10

    aget v10, v11, v19

    move-object v13, v11

    aget v11, v13, v18

    move-object v14, v12

    aget v12, v13, v17

    aget v13, v13, v16

    move-object v15, v14

    invoke-virtual {v15}, Llyiahf/vczjk/bu1;->OooO00o()F

    move-result v14

    invoke-virtual {v15}, Llyiahf/vczjk/bu1;->OooO0O0()F

    move-result v15

    invoke-virtual/range {v9 .. v15}, Landroid/graphics/Path;->cubicTo(FFFFFF)V

    add-int/lit8 v7, v7, 0x1

    goto :goto_1

    :cond_4
    invoke-virtual {v9}, Landroid/graphics/Path;->close()V

    if-eqz v0, :cond_5

    if-eqz v5, :cond_5

    invoke-virtual {v1, v6}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/bu1;

    iget-object v3, v3, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v3, v3, v4

    sub-float v3, v3, p5

    float-to-double v3, v3

    invoke-virtual {v1, v6}, Llyiahf/vczjk/y05;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/bu1;

    iget-object v1, v1, Llyiahf/vczjk/bu1;->OooO00o:[F

    aget v1, v1, v6

    sub-float v1, v1, p4

    float-to-double v5, v1

    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->atan2(DD)D

    move-result-wide v3

    double-to-float v1, v3

    float-to-double v3, v1

    const-wide v5, 0x4066800000000000L    # 180.0

    mul-double/2addr v3, v5

    const-wide v5, 0x400921fb54442d18L    # Math.PI

    div-double/2addr v3, v5

    double-to-float v1, v3

    invoke-static {}, Llyiahf/vczjk/ze5;->OooO00o()[F

    move-result-object v3

    neg-float v1, v1

    int-to-float v0, v0

    add-float/2addr v1, v0

    invoke-static {v1, v3}, Llyiahf/vczjk/ze5;->OooO0o0(F[F)V

    invoke-virtual {v2, v3}, Llyiahf/vczjk/qe;->OooOO0O([F)V

    :cond_5
    return-void
.end method

.method public static final OooOoO(Landroid/content/Context;)[Landroid/content/pm/Signature;
    .locals 2

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/OsUtils;->isPOrAbove()Z

    move-result v0

    const-string v1, "github.tornaco.android.thanos"

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object p0

    const/high16 v0, 0x8000000

    invoke-virtual {p0, v1, v0}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/md9;->OooO0O0(Landroid/content/pm/PackageInfo;)Landroid/content/pm/SigningInfo;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/md9;->OooOO0o(Landroid/content/pm/SigningInfo;)[Landroid/content/pm/Signature;

    move-result-object p0

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object p0

    :cond_0
    invoke-virtual {p0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    move-result-object p0

    const/16 v0, 0x40

    invoke-virtual {p0, v1, v0}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object p0

    iget-object p0, p0, Landroid/content/pm/PackageInfo;->signatures:[Landroid/content/pm/Signature;

    invoke-static {p0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object p0
.end method

.method public static final OooOoO0(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;
    .locals 10

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/uk4;->o00000O()Llyiahf/vczjk/iaa;

    move-result-object p0

    instance-of v0, p0, Llyiahf/vczjk/k23;

    const/4 v1, 0x2

    const/16 v2, 0xa

    const-string v3, "getParameters(...)"

    const/4 v4, 0x0

    if-eqz v0, :cond_6

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/k23;

    iget-object v5, v0, Llyiahf/vczjk/k23;->OooOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->isEmpty()Z

    move-result v6

    if-nez v6, :cond_2

    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v6

    if-nez v6, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {v5}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v6

    invoke-static {v6, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v7, Ljava/util/ArrayList;

    invoke-static {v6, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v8

    invoke-direct {v7, v8}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v6

    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_1

    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/t4a;

    new-instance v9, Llyiahf/vczjk/f19;

    invoke-direct {v9, v8}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/t4a;)V

    invoke-virtual {v7, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    invoke-static {v5, v7, v4, v1}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object v5

    :cond_2
    :goto_1
    iget-object v0, v0, Llyiahf/vczjk/k23;->OooOOOO:Llyiahf/vczjk/dp8;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->isEmpty()Z

    move-result v6

    if-nez v6, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v6

    if-nez v6, :cond_3

    goto :goto_3

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v6

    invoke-static {v6, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v6, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_4

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/t4a;

    new-instance v7, Llyiahf/vczjk/f19;

    invoke-direct {v7, v6}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/t4a;)V

    invoke-virtual {v3, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_4
    invoke-static {v0, v3, v4, v1}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object v0

    :cond_5
    :goto_3
    invoke-static {v5, v0}, Llyiahf/vczjk/so8;->OooOoOO(Llyiahf/vczjk/dp8;Llyiahf/vczjk/dp8;)Llyiahf/vczjk/iaa;

    move-result-object v0

    goto :goto_5

    :cond_6
    instance-of v0, p0, Llyiahf/vczjk/dp8;

    if-eqz v0, :cond_a

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/dp8;

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v5

    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    move-result v5

    if-nez v5, :cond_9

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v5

    if-nez v5, :cond_7

    goto :goto_5

    :cond_7
    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v5

    invoke-interface {v5}, Llyiahf/vczjk/n3a;->OooO0OO()Ljava/util/List;

    move-result-object v5

    invoke-static {v5, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v5, v2}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v2

    invoke-direct {v3, v2}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_4
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/t4a;

    new-instance v6, Llyiahf/vczjk/f19;

    invoke-direct {v6, v5}, Llyiahf/vczjk/f19;-><init>(Llyiahf/vczjk/t4a;)V

    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_8
    invoke-static {v0, v3, v4, v1}, Llyiahf/vczjk/vt6;->OooOooo(Llyiahf/vczjk/dp8;Ljava/util/List;Llyiahf/vczjk/d3a;I)Llyiahf/vczjk/dp8;

    move-result-object v0

    :cond_9
    :goto_5
    invoke-static {v0, p0}, Llyiahf/vczjk/qu6;->OooOOO(Llyiahf/vczjk/iaa;Llyiahf/vczjk/uk4;)Llyiahf/vczjk/iaa;

    move-result-object p0

    return-object p0

    :cond_a
    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0
.end method

.method public static final OooOoOO(Llyiahf/vczjk/pt6;)Ljava/time/LocalTime;
    .locals 2

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/pt6;->OooO0OO:Llyiahf/vczjk/js9;

    if-nez v0, :cond_0

    const/4 v0, -0x1

    goto :goto_0

    :cond_0
    sget-object v1, Llyiahf/vczjk/cs9;->OooO00o:[I

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget v0, v1, v0

    :goto_0
    const/4 v1, 0x1

    if-eq v0, v1, :cond_2

    const/4 v1, 0x2

    if-eq v0, v1, :cond_1

    iget v0, p0, Llyiahf/vczjk/pt6;->OooO00o:I

    goto :goto_1

    :cond_1
    iget v0, p0, Llyiahf/vczjk/pt6;->OooO00o:I

    rem-int/lit8 v0, v0, 0xc

    add-int/lit8 v0, v0, 0xc

    goto :goto_1

    :cond_2
    iget v0, p0, Llyiahf/vczjk/pt6;->OooO00o:I

    rem-int/lit8 v0, v0, 0xc

    :goto_1
    iget p0, p0, Llyiahf/vczjk/pt6;->OooO0O0:I

    invoke-static {v0, p0}, Llyiahf/vczjk/gr9;->OooO0o(II)Ljava/time/LocalTime;

    move-result-object p0

    const-string v0, "of(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method

.method public static OooOoo(Llyiahf/vczjk/aw7;Llyiahf/vczjk/bq6;ZI)V
    .locals 6

    and-int/lit8 p3, p3, 0x4

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    :cond_0
    move v2, p2

    iget-object v3, p0, Llyiahf/vczjk/aw7;->OooO0Oo:Llyiahf/vczjk/y05;

    iget v4, p0, Llyiahf/vczjk/aw7;->OooO0O0:F

    iget v5, p0, Llyiahf/vczjk/aw7;->OooO0OO:F

    const/16 v1, 0x10e

    move-object v0, p1

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/fu6;->OooOo0o(Llyiahf/vczjk/bq6;IZLlyiahf/vczjk/y05;FF)V

    return-void
.end method

.method public static OooOoo0(Llyiahf/vczjk/ao5;FLlyiahf/vczjk/bq6;ZI)Llyiahf/vczjk/bq6;
    .locals 8

    and-int/lit8 v0, p4, 0x4

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    const/16 v0, 0x10e

    move v3, v0

    goto :goto_0

    :cond_0
    move v3, v1

    :goto_0
    and-int/lit8 v0, p4, 0x8

    if-eqz v0, :cond_1

    move v4, v1

    goto :goto_1

    :cond_1
    move v4, p3

    :goto_1
    and-int/lit8 p3, p4, 0x20

    const/high16 v0, 0x3f000000    # 0.5f

    const/4 v1, 0x0

    if-eqz p3, :cond_2

    move v6, v1

    goto :goto_2

    :cond_2
    move v6, v0

    :goto_2
    and-int/lit8 p3, p4, 0x40

    if-eqz p3, :cond_3

    move v7, v1

    goto :goto_3

    :cond_3
    move v7, v0

    :goto_3
    invoke-virtual {p0, p1}, Llyiahf/vczjk/ao5;->OooO00o(F)Llyiahf/vczjk/y05;

    move-result-object v5

    move-object v2, p2

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/fu6;->OooOo0o(Llyiahf/vczjk/bq6;IZLlyiahf/vczjk/y05;FF)V

    return-object v2
.end method


# virtual methods
.method public abstract OooOOO0(Llyiahf/vczjk/js8;)Ljava/lang/Object;
.end method
