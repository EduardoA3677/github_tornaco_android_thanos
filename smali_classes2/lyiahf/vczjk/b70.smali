.class public final Llyiahf/vczjk/b70;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/g70;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g70;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b70;->this$0:Llyiahf/vczjk/g70;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/b70;

    iget-object v0, p0, Llyiahf/vczjk/b70;->this$0:Llyiahf/vczjk/g70;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/b70;-><init>(Llyiahf/vczjk/g70;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/b70;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/b70;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/b70;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 24

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/b70;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_2

    if-eq v2, v4, :cond_1

    if-ne v2, v3, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_a

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/b70;->this$0:Llyiahf/vczjk/g70;

    iput v4, v0, Llyiahf/vczjk/b70;->label:I

    invoke-static {v2, v0}, Llyiahf/vczjk/g70;->OooO(Llyiahf/vczjk/g70;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_3

    goto/16 :goto_9

    :cond_3
    :goto_0
    iget-object v2, v0, Llyiahf/vczjk/b70;->this$0:Llyiahf/vczjk/g70;

    iget-object v4, v2, Llyiahf/vczjk/g70;->OooO0oO:Llyiahf/vczjk/e60;

    iget-object v4, v4, Llyiahf/vczjk/e60;->OooO0OO:Llyiahf/vczjk/du;

    iget-object v4, v4, Llyiahf/vczjk/du;->OooO00o:Llyiahf/vczjk/cu;

    instance-of v5, v4, Llyiahf/vczjk/au;

    if-eqz v5, :cond_5

    check-cast v4, Llyiahf/vczjk/au;

    iget-object v4, v4, Llyiahf/vczjk/au;->OooO00o:Ljava/util/List;

    new-instance v5, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v4, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/zt;

    new-instance v7, Llyiahf/vczjk/nw;

    iget-object v8, v6, Llyiahf/vczjk/zt;->OooO0Oo:Ljava/lang/String;

    new-instance v9, Llyiahf/vczjk/o000OO;

    const/16 v10, 0xb

    invoke-direct {v9, v6, v10}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v7, v8, v9}, Llyiahf/vczjk/nw;-><init>(Ljava/lang/String;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    invoke-static {v5}, Llyiahf/vczjk/d21;->o0000OO0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/yu;->OooOOO0:Llyiahf/vczjk/nw;

    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_2
    move-object v10, v4

    goto :goto_3

    :cond_5
    sget-object v4, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    goto :goto_2

    :goto_3
    iget-object v2, v2, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v2, v2, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/rs5;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rs5;

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v5, v2

    check-cast v5, Llyiahf/vczjk/yu;

    const-string v2, "$this$updateState"

    invoke-static {v5, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v15, 0x0

    const/16 v18, 0xfcf

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    sget-object v11, Llyiahf/vczjk/yu;->OooOOO0:Llyiahf/vczjk/nw;

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/16 v16, 0x0

    const/16 v17, 0x0

    invoke-static/range {v5 .. v18}, Llyiahf/vczjk/yu;->OooO00o(Llyiahf/vczjk/yu;Ljava/util/ArrayList;ZLjava/util/List;Llyiahf/vczjk/nw;Ljava/util/List;Llyiahf/vczjk/nw;Llyiahf/vczjk/vw;ZLjava/util/ArrayList;Ljava/lang/String;ZLjava/util/List;I)Llyiahf/vczjk/yu;

    move-result-object v5

    check-cast v4, Llyiahf/vczjk/s29;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    iget-object v4, v0, Llyiahf/vczjk/b70;->this$0:Llyiahf/vczjk/g70;

    iget-object v5, v4, Llyiahf/vczjk/g70;->OooO0oO:Llyiahf/vczjk/e60;

    iget-object v5, v5, Llyiahf/vczjk/e60;->OooO0OO:Llyiahf/vczjk/du;

    iget-object v5, v5, Llyiahf/vczjk/du;->OooO00o:Llyiahf/vczjk/cu;

    instance-of v6, v5, Llyiahf/vczjk/bu;

    if-eqz v6, :cond_8

    sget-object v5, Llyiahf/vczjk/vw;->OooOOoo:Llyiahf/vczjk/np2;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v5}, Llyiahf/vczjk/o00O00O;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_6
    :goto_4
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/vw;

    sget-object v9, Llyiahf/vczjk/vw;->OooOOO:Llyiahf/vczjk/vw;

    if-eq v8, v9, :cond_6

    sget-object v9, Llyiahf/vczjk/vw;->OooOOOO:Llyiahf/vczjk/vw;

    if-eq v8, v9, :cond_6

    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_4

    :cond_7
    move-object/from16 v19, v6

    goto :goto_7

    :cond_8
    instance-of v6, v5, Llyiahf/vczjk/yt;

    if-eqz v6, :cond_a

    sget-object v5, Llyiahf/vczjk/vw;->OooOOoo:Llyiahf/vczjk/np2;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v5}, Llyiahf/vczjk/o00O00O;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_9
    :goto_5
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/vw;

    sget-object v9, Llyiahf/vczjk/vw;->OooOOOO:Llyiahf/vczjk/vw;

    if-eq v8, v9, :cond_9

    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_5

    :cond_a
    instance-of v5, v5, Llyiahf/vczjk/au;

    if-eqz v5, :cond_e

    sget-object v5, Llyiahf/vczjk/vw;->OooOOoo:Llyiahf/vczjk/np2;

    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v5}, Llyiahf/vczjk/o00O00O;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_b
    :goto_6
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_7

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/vw;

    sget-object v9, Llyiahf/vczjk/vw;->OooOOO:Llyiahf/vczjk/vw;

    if-eq v8, v9, :cond_b

    invoke-virtual {v6, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :goto_7
    invoke-static {}, Llyiahf/vczjk/v41;->OooO00o()Llyiahf/vczjk/v41;

    move-result-object v5

    iget-object v6, v4, Llyiahf/vczjk/g70;->OooO0oO:Llyiahf/vczjk/e60;

    iget-object v6, v6, Llyiahf/vczjk/e60;->OooO00o:Ljava/lang/String;

    sget-object v7, Llyiahf/vczjk/vw;->OooOOO0:Llyiahf/vczjk/vw;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v5, "PREF_KEY_FEATURE_SORT_SELECTION_"

    iget-object v8, v4, Llyiahf/vczjk/g70;->OooO0o:Landroid/content/Context;

    invoke-static {v8}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v8

    invoke-virtual {v8}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v9

    if-nez v9, :cond_c

    goto :goto_8

    :cond_c
    :try_start_0
    invoke-virtual {v8}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPrefManager()Lgithub/tornaco/android/thanos/core/pref/PrefManager;

    move-result-object v8

    new-instance v9, Ljava/lang/StringBuilder;

    invoke-direct {v9, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v9, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    move-result v6

    invoke-virtual {v8, v5, v6}, Lgithub/tornaco/android/thanos/core/pref/PrefManager;->getInt(Ljava/lang/String;I)I

    move-result v5

    invoke-static {}, Llyiahf/vczjk/vw;->values()[Llyiahf/vczjk/vw;

    move-result-object v6

    aget-object v7, v6, v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :catchall_0
    :goto_8
    move-object/from16 v17, v7

    iget-object v4, v4, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v4, v4, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/sc9;

    invoke-virtual {v4}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/rs5;

    invoke-virtual {v4}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/rs5;

    check-cast v4, Llyiahf/vczjk/s29;

    invoke-virtual {v4}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v4

    move-object v10, v4

    check-cast v10, Llyiahf/vczjk/yu;

    invoke-static {v10, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static/range {v17 .. v17}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/16 v20, 0x0

    const/16 v23, 0xebf

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v18, 0x0

    const/16 v21, 0x0

    const/16 v22, 0x0

    invoke-static/range {v10 .. v23}, Llyiahf/vczjk/yu;->OooO00o(Llyiahf/vczjk/yu;Ljava/util/ArrayList;ZLjava/util/List;Llyiahf/vczjk/nw;Ljava/util/List;Llyiahf/vczjk/nw;Llyiahf/vczjk/vw;ZLjava/util/ArrayList;Ljava/lang/String;ZLjava/util/List;I)Llyiahf/vczjk/yu;

    move-result-object v2

    check-cast v5, Llyiahf/vczjk/s29;

    invoke-virtual {v5, v2}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/b70;->this$0:Llyiahf/vczjk/g70;

    iput v3, v0, Llyiahf/vczjk/b70;->label:I

    invoke-static {v2, v0}, Llyiahf/vczjk/g70;->OooO0oo(Llyiahf/vczjk/g70;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_d

    :goto_9
    return-object v1

    :cond_d
    :goto_a
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :cond_e
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1
.end method
