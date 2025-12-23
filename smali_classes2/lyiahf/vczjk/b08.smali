.class public final Llyiahf/vczjk/b08;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $items:Ljava/util/List;

.field final synthetic $sfVM$inlined:Llyiahf/vczjk/i48;

.field final synthetic $state$delegate$inlined:Llyiahf/vczjk/p29;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/qs5;Llyiahf/vczjk/i48;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b08;->$items:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/b08;->$state$delegate$inlined:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/b08;->$sfVM$inlined:Llyiahf/vczjk/i48;

    const/4 p1, 0x4

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 31

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/eq4;

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

    if-nez v5, :cond_1

    move-object v5, v3

    check-cast v5, Llyiahf/vczjk/zf1;

    invoke-virtual {v5, v1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x4

    goto :goto_0

    :cond_0
    const/4 v1, 0x2

    :goto_0
    or-int/2addr v1, v4

    goto :goto_1

    :cond_1
    move v1, v4

    :goto_1
    and-int/lit8 v4, v4, 0x30

    if-nez v4, :cond_3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/zf1;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result v4

    if-eqz v4, :cond_2

    const/16 v4, 0x20

    goto :goto_2

    :cond_2
    const/16 v4, 0x10

    :goto_2
    or-int/2addr v1, v4

    :cond_3
    and-int/lit16 v4, v1, 0x93

    const/16 v5, 0x92

    const/4 v6, 0x1

    const/4 v7, 0x0

    if-eq v4, v5, :cond_4

    move v4, v6

    goto :goto_3

    :cond_4
    move v4, v7

    :goto_3
    and-int/2addr v1, v6

    check-cast v3, Llyiahf/vczjk/zf1;

    invoke-virtual {v3, v1, v4}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v1

    if-eqz v1, :cond_c

    iget-object v1, v0, Llyiahf/vczjk/b08;->$items:Ljava/util/List;

    invoke-interface {v1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const v2, 0x5c6ac174

    invoke-virtual {v3, v2}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v2, v0, Llyiahf/vczjk/b08;->$state$delegate$inlined:Llyiahf/vczjk/p29;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/j28;

    iget-object v2, v2, Llyiahf/vczjk/j28;->OooO0Oo:Ljava/util/Set;

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v4

    invoke-interface {v2, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v2

    sget-object v4, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    const/16 v5, 0x14

    int-to-float v5, v5

    invoke-static {v5}, Llyiahf/vczjk/uv7;->OooO00o(F)Llyiahf/vczjk/tv7;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/zsa;->OooOooo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v5

    sget-object v8, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/x21;

    iget-wide v8, v8, Llyiahf/vczjk/x21;->OooO0oo:J

    sget-object v10, Llyiahf/vczjk/e16;->OooO0o:Llyiahf/vczjk/pp3;

    invoke-static {v4, v8, v9, v10}, Landroidx/compose/foundation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;JLlyiahf/vczjk/qj8;)Llyiahf/vczjk/kl5;

    move-result-object v8

    invoke-static {v5, v8, v2}, Llyiahf/vczjk/ye5;->Oooo0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Z)Llyiahf/vczjk/kl5;

    move-result-object v2

    const v5, -0x6815fd56

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v8, v0, Llyiahf/vczjk/b08;->$state$delegate$inlined:Llyiahf/vczjk/p29;

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v8

    iget-object v9, v0, Llyiahf/vczjk/b08;->$sfVM$inlined:Llyiahf/vczjk/i48;

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v9

    or-int/2addr v8, v9

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v9

    sget-object v10, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v8, :cond_5

    if-ne v9, v10, :cond_6

    :cond_5
    new-instance v9, Llyiahf/vczjk/yz7;

    iget-object v8, v0, Llyiahf/vczjk/b08;->$sfVM$inlined:Llyiahf/vczjk/i48;

    iget-object v11, v0, Llyiahf/vczjk/b08;->$state$delegate$inlined:Llyiahf/vczjk/p29;

    const/4 v12, 0x0

    invoke-direct {v9, v8, v1, v11, v12}, Llyiahf/vczjk/yz7;-><init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/p29;I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_6
    check-cast v9, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object v5, v0, Llyiahf/vczjk/b08;->$state$delegate$inlined:Llyiahf/vczjk/p29;

    invoke-virtual {v3, v5}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v5

    iget-object v8, v0, Llyiahf/vczjk/b08;->$sfVM$inlined:Llyiahf/vczjk/i48;

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v5, v8

    invoke-virtual {v3, v1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    or-int/2addr v5, v8

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v8

    if-nez v5, :cond_7

    if-ne v8, v10, :cond_8

    :cond_7
    new-instance v8, Llyiahf/vczjk/yz7;

    iget-object v5, v0, Llyiahf/vczjk/b08;->$sfVM$inlined:Llyiahf/vczjk/i48;

    iget-object v10, v0, Llyiahf/vczjk/b08;->$state$delegate$inlined:Llyiahf/vczjk/p29;

    const/4 v11, 0x1

    invoke-direct {v8, v5, v1, v10, v11}, Llyiahf/vczjk/yz7;-><init>(Llyiahf/vczjk/i48;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/p29;I)V

    invoke-virtual {v3, v8}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_8
    check-cast v8, Llyiahf/vczjk/le3;

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-static {v2, v9, v8}, Landroidx/compose/foundation/OooO00o;->OooO0oO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    const/4 v5, 0x6

    int-to-float v8, v5

    invoke-static {v2, v8}, Landroidx/compose/foundation/layout/OooO00o;->OooOO0O(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v8, Llyiahf/vczjk/op3;->OooOoOO:Llyiahf/vczjk/sb0;

    sget-object v9, Llyiahf/vczjk/tx;->OooO0o0:Llyiahf/vczjk/mx;

    const/16 v10, 0x36

    invoke-static {v9, v8, v3, v10}, Llyiahf/vczjk/n31;->OooO00o(Llyiahf/vczjk/px;Llyiahf/vczjk/sb0;Llyiahf/vczjk/rf1;I)Llyiahf/vczjk/p31;

    move-result-object v8

    iget v9, v3, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v10

    invoke-static {v3, v2}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    sget-object v11, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v11, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v12, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v12, :cond_9

    invoke-virtual {v3, v11}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_4

    :cond_9
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_4
    sget-object v11, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    invoke-static {v8, v3, v11}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v10, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v8, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v10, v3, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v10, :cond_a

    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    invoke-static {v9}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v11

    invoke-static {v10, v11}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_b

    :cond_a
    invoke-static {v9, v3, v9, v8}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_b
    sget-object v8, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v2, v3, v8}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    const/16 v2, 0x32

    int-to-float v2, v2

    invoke-static {v4, v2}, Landroidx/compose/foundation/layout/OooO0OO;->OooOO0o(Llyiahf/vczjk/kl5;F)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-static {v2, v1, v3, v5}, Llyiahf/vczjk/ye5;->OooO0O0(Llyiahf/vczjk/kl5;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v8

    const-string v1, "getAppLabel(...)"

    invoke-static {v8, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const-wide/high16 v1, 0x4029000000000000L    # 12.5

    invoke-static {v1, v2}, Llyiahf/vczjk/eo6;->OooOO0O(D)J

    move-result-wide v12

    new-instance v1, Llyiahf/vczjk/ch9;

    const/4 v2, 0x3

    invoke-direct {v1, v2}, Llyiahf/vczjk/ch9;-><init>(I)V

    const/16 v29, 0x6000

    const v30, 0x3bbee

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const-wide/16 v16, 0x0

    const-wide/16 v19, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    const/16 v23, 0x2

    const/16 v24, 0x0

    const/16 v25, 0x0

    const/16 v26, 0x0

    const/16 v28, 0x6000

    move-object/from16 v18, v1

    move-object/from16 v27, v3

    invoke-static/range {v8 .. v30}, Llyiahf/vczjk/gm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/ga3;JLlyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    invoke-virtual {v3, v6}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    invoke-virtual {v3, v7}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_5

    :cond_c
    invoke-virtual {v3}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
