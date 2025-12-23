.class public final Llyiahf/vczjk/oh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $drawerBackgroundColor:J

.field final synthetic $drawerContent:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $drawerContentColor:J

.field final synthetic $drawerElevation:F

.field final synthetic $drawerShape:Llyiahf/vczjk/qj8;

.field final synthetic $drawerState:Llyiahf/vczjk/li2;

.field final synthetic $gesturesEnabled:Z

.field final synthetic $scope:Llyiahf/vczjk/xr1;

.field final synthetic $scrimColor:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/li2;ZLlyiahf/vczjk/xr1;JLlyiahf/vczjk/qj8;JJFLlyiahf/vczjk/ze3;Llyiahf/vczjk/bf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oh2;->$drawerState:Llyiahf/vczjk/li2;

    iput-boolean p2, p0, Llyiahf/vczjk/oh2;->$gesturesEnabled:Z

    iput-object p3, p0, Llyiahf/vczjk/oh2;->$scope:Llyiahf/vczjk/xr1;

    iput-wide p4, p0, Llyiahf/vczjk/oh2;->$scrimColor:J

    iput-object p6, p0, Llyiahf/vczjk/oh2;->$drawerShape:Llyiahf/vczjk/qj8;

    iput-wide p7, p0, Llyiahf/vczjk/oh2;->$drawerBackgroundColor:J

    iput-wide p9, p0, Llyiahf/vczjk/oh2;->$drawerContentColor:J

    iput p11, p0, Llyiahf/vczjk/oh2;->$drawerElevation:F

    iput-object p12, p0, Llyiahf/vczjk/oh2;->$content:Llyiahf/vczjk/ze3;

    iput-object p13, p0, Llyiahf/vczjk/oh2;->$drawerContent:Llyiahf/vczjk/bf3;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 29

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/kh0;

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
    and-int/lit8 v4, v3, 0x13

    const/16 v5, 0x12

    const/4 v6, 0x1

    if-eq v4, v5, :cond_2

    move v4, v6

    goto :goto_1

    :cond_2
    const/4 v4, 0x0

    :goto_1
    and-int/2addr v3, v6

    move-object v13, v2

    check-cast v13, Llyiahf/vczjk/zf1;

    invoke-virtual {v13, v3, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_17

    check-cast v1, Llyiahf/vczjk/lh0;

    iget-wide v1, v1, Llyiahf/vczjk/lh0;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/rk1;->OooO0Oo(J)Z

    move-result v3

    if-eqz v3, :cond_16

    invoke-static {v1, v2}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v3

    int-to-float v3, v3

    neg-float v3, v3

    sget-object v4, Llyiahf/vczjk/ch1;->OooO0oo:Llyiahf/vczjk/l39;

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/f62;

    iget-object v8, v0, Llyiahf/vczjk/oh2;->$drawerState:Llyiahf/vczjk/li2;

    invoke-virtual {v13, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v9

    or-int/2addr v8, v9

    iget-object v9, v0, Llyiahf/vczjk/oh2;->$drawerState:Llyiahf/vczjk/li2;

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    sget-object v15, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v8, :cond_3

    if-ne v10, v15, :cond_4

    :cond_3
    new-instance v10, Llyiahf/vczjk/fh2;

    invoke-direct {v10, v9, v5, v3}, Llyiahf/vczjk/fh2;-><init>(Llyiahf/vczjk/li2;Llyiahf/vczjk/f62;F)V

    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v10, Llyiahf/vczjk/le3;

    invoke-static {v10, v13}, Llyiahf/vczjk/c6a;->OooOo00(Llyiahf/vczjk/le3;Llyiahf/vczjk/rf1;)V

    sget-object v5, Llyiahf/vczjk/ch1;->OooOOO:Llyiahf/vczjk/l39;

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v5

    sget-object v8, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    if-ne v5, v8, :cond_5

    move/from16 v23, v6

    goto :goto_2

    :cond_5
    const/16 v23, 0x0

    :goto_2
    sget-object v16, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v5, v0, Llyiahf/vczjk/oh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-object v5, v5, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    sget-object v18, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    iget-boolean v8, v0, Llyiahf/vczjk/oh2;->$gesturesEnabled:Z

    iget-object v9, v5, Llyiahf/vczjk/d9;->OooOO0o:Llyiahf/vczjk/qs5;

    check-cast v9, Llyiahf/vczjk/fw8;

    invoke-virtual {v9}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v9

    if-eqz v9, :cond_6

    move/from16 v21, v6

    goto :goto_3

    :cond_6
    const/16 v21, 0x0

    :goto_3
    new-instance v9, Llyiahf/vczjk/o7;

    const/4 v10, 0x0

    invoke-direct {v9, v5, v10}, Llyiahf/vczjk/o7;-><init>(Llyiahf/vczjk/d9;Llyiahf/vczjk/yo1;)V

    const/16 v20, 0x0

    const/16 v24, 0x20

    iget-object v5, v5, Llyiahf/vczjk/d9;->OooO0o:Llyiahf/vczjk/y8;

    move-object/from16 v17, v5

    move/from16 v19, v8

    move-object/from16 v22, v9

    invoke-static/range {v16 .. v24}, Llyiahf/vczjk/uf2;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ag2;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/rr5;ZLlyiahf/vczjk/bf3;ZI)Llyiahf/vczjk/kl5;

    move-result-object v5

    move-object/from16 v8, v16

    iget-object v9, v0, Llyiahf/vczjk/oh2;->$drawerState:Llyiahf/vczjk/li2;

    iget-boolean v10, v0, Llyiahf/vczjk/oh2;->$gesturesEnabled:Z

    iget-object v11, v0, Llyiahf/vczjk/oh2;->$scope:Llyiahf/vczjk/xr1;

    iget-wide v6, v0, Llyiahf/vczjk/oh2;->$scrimColor:J

    iget-object v12, v0, Llyiahf/vczjk/oh2;->$drawerShape:Llyiahf/vczjk/qj8;

    move-object/from16 p3, v15

    iget-wide v14, v0, Llyiahf/vczjk/oh2;->$drawerBackgroundColor:J

    move-wide/from16 v16, v14

    iget-wide v14, v0, Llyiahf/vczjk/oh2;->$drawerContentColor:J

    move-wide/from16 v18, v14

    iget v15, v0, Llyiahf/vczjk/oh2;->$drawerElevation:F

    iget-object v14, v0, Llyiahf/vczjk/oh2;->$content:Llyiahf/vczjk/ze3;

    move-wide/from16 v20, v1

    iget-object v1, v0, Llyiahf/vczjk/oh2;->$drawerContent:Llyiahf/vczjk/bf3;

    sget-object v2, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    move-wide/from16 v22, v6

    const/4 v0, 0x0

    invoke-static {v2, v0}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v6

    iget v0, v13, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v7

    invoke-static {v13, v5}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v24, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual/range {v24 .. v24}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object/from16 v24, v12

    sget-object v12, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move/from16 v25, v15

    iget-boolean v15, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v15, :cond_7

    invoke-virtual {v13, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_7
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v15, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v6, v13, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v6, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v7, v13, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v7, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    move-object/from16 v26, v1

    iget-boolean v1, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v1, :cond_8

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    move-object/from16 v27, v4

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_9

    goto :goto_5

    :cond_8
    move-object/from16 v27, v4

    :goto_5
    invoke-static {v0, v13, v0, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_9
    sget-object v0, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v5, v13, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v1, 0x0

    invoke-static {v2, v1}, Llyiahf/vczjk/ch0;->OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;

    move-result-object v2

    iget v1, v13, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v4

    invoke-static {v13, v8}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v5

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->OoooOOo()V

    move-object/from16 v28, v8

    iget-boolean v8, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v8, :cond_a

    invoke-virtual {v13, v12}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_6

    :cond_a
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_6
    invoke-static {v2, v13, v15}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    invoke-static {v4, v13, v6}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    iget-boolean v2, v13, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_b

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_c

    :cond_b
    invoke-static {v1, v13, v1, v7}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_c
    invoke-static {v5, v13, v0}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/4 v0, 0x0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {v14, v13, v1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v0, 0x1

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    iget-object v0, v9, Llyiahf/vczjk/li2;->OooO00o:Llyiahf/vczjk/d9;

    iget-object v0, v0, Llyiahf/vczjk/d9;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ni2;

    sget-object v1, Llyiahf/vczjk/ni2;->OooOOO:Llyiahf/vczjk/ni2;

    if-ne v0, v1, :cond_d

    const/4 v8, 0x1

    goto :goto_7

    :cond_d
    const/4 v8, 0x0

    :goto_7
    invoke-virtual {v13, v10}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v13, v11}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    or-int/2addr v0, v1

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez v0, :cond_e

    move-object/from16 v0, p3

    if-ne v1, v0, :cond_f

    goto :goto_8

    :cond_e
    move-object/from16 v0, p3

    :goto_8
    new-instance v1, Llyiahf/vczjk/hh2;

    invoke-direct {v1, v10, v9, v11}, Llyiahf/vczjk/hh2;-><init>(ZLlyiahf/vczjk/li2;Llyiahf/vczjk/xr1;)V

    invoke-virtual {v13, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_f
    check-cast v1, Llyiahf/vczjk/le3;

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO0Oo(F)Z

    move-result v2

    invoke-virtual {v13, v9}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    or-int/2addr v2, v4

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v2, :cond_10

    if-ne v4, v0, :cond_11

    :cond_10
    new-instance v4, Llyiahf/vczjk/ih2;

    invoke-direct {v4, v3, v9}, Llyiahf/vczjk/ih2;-><init>(FLlyiahf/vczjk/li2;)V

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_11
    move-object v10, v4

    check-cast v10, Llyiahf/vczjk/le3;

    const/4 v14, 0x0

    move-object v2, v9

    move-object v3, v11

    move-wide/from16 v11, v22

    move-object v9, v1

    move-object/from16 v1, v28

    invoke-static/range {v8 .. v14}, Llyiahf/vczjk/xh2;->OooO0O0(ZLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;JLlyiahf/vczjk/rf1;I)V

    const/4 v4, 0x0

    invoke-static {v4, v13}, Llyiahf/vczjk/kh6;->OooOooo(ILlyiahf/vczjk/rf1;)Ljava/lang/String;

    move-result-object v5

    move-object/from16 v4, v27

    invoke-virtual {v13, v4}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/f62;

    invoke-static/range {v20 .. v21}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v6

    invoke-interface {v4, v6}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result v6

    invoke-static/range {v20 .. v21}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v7

    invoke-interface {v4, v7}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result v7

    invoke-static/range {v20 .. v21}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v8

    invoke-interface {v4, v8}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result v8

    invoke-static/range {v20 .. v21}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result v9

    invoke-interface {v4, v9}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result v4

    invoke-static {v1, v6, v7, v8, v4}, Landroidx/compose/foundation/layout/OooO0OO;->OooOOO(Llyiahf/vczjk/kl5;FFFF)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_12

    if-ne v6, v0, :cond_13

    :cond_12
    new-instance v6, Llyiahf/vczjk/jh2;

    invoke-direct {v6, v2}, Llyiahf/vczjk/jh2;-><init>(Llyiahf/vczjk/li2;)V

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_13
    check-cast v6, Llyiahf/vczjk/oe3;

    invoke-static {v1, v6}, Landroidx/compose/foundation/layout/OooO00o;->OooO0oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v7

    sget v10, Llyiahf/vczjk/xh2;->OooO00o:F

    const/4 v8, 0x0

    const/16 v12, 0xb

    const/4 v9, 0x0

    const/4 v11, 0x0

    invoke-static/range {v7 .. v12}, Landroidx/compose/foundation/layout/OooO00o;->OooOOO(Llyiahf/vczjk/kl5;FFFFI)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {v13, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v4

    invoke-virtual {v13, v2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v4, v6

    invoke-virtual {v13, v3}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v6

    or-int/2addr v4, v6

    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v6

    if-nez v4, :cond_14

    if-ne v6, v0, :cond_15

    :cond_14
    new-instance v6, Llyiahf/vczjk/mh2;

    invoke-direct {v6, v5, v2, v3}, Llyiahf/vczjk/mh2;-><init>(Ljava/lang/String;Llyiahf/vczjk/li2;Llyiahf/vczjk/xr1;)V

    invoke-virtual {v13, v6}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_15
    check-cast v6, Llyiahf/vczjk/oe3;

    const/4 v0, 0x0

    invoke-static {v1, v0, v6}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v8

    new-instance v0, Llyiahf/vczjk/nh2;

    move-object/from16 v1, v26

    invoke-direct {v0, v1}, Llyiahf/vczjk/nh2;-><init>(Llyiahf/vczjk/bf3;)V

    const v1, -0x73b4e307

    invoke-static {v1, v0, v13}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/4 v14, 0x0

    move-object v2, v13

    move-wide/from16 v12, v18

    const/high16 v18, 0x180000

    const/16 v19, 0x10

    move-wide/from16 v10, v16

    move-object/from16 v9, v24

    move/from16 v15, v25

    move-object/from16 v16, v0

    move-object/from16 v17, v2

    invoke-static/range {v8 .. v19}, Llyiahf/vczjk/rd3;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;JJLlyiahf/vczjk/se0;FLlyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    move-object/from16 v13, v17

    const/4 v0, 0x1

    invoke-virtual {v13, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_9

    :cond_16
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Drawer shouldn\'t have infinite width"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_17
    invoke-virtual {v13}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_9
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
