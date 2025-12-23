.class public final Llyiahf/vczjk/d70;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field Z$0:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/g70;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g70;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d70;->this$0:Llyiahf/vczjk/g70;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/d70;

    iget-object v0, p0, Llyiahf/vczjk/d70;->this$0:Llyiahf/vczjk/g70;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/d70;-><init>(Llyiahf/vczjk/g70;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/d70;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/d70;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/d70;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/d70;->label:I

    sget-object v3, Llyiahf/vczjk/yu;->OooOOO0:Llyiahf/vczjk/nw;

    const/4 v4, 0x1

    if-eqz v2, :cond_1

    if-ne v2, v4, :cond_0

    iget-boolean v1, v0, Llyiahf/vczjk/d70;->Z$0:Z

    iget-object v2, v0, Llyiahf/vczjk/d70;->L$3:Ljava/lang/Object;

    check-cast v2, Ljava/lang/String;

    iget-object v4, v0, Llyiahf/vczjk/d70;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/nw;

    iget-object v5, v0, Llyiahf/vczjk/d70;->L$1:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/vw;

    iget-object v6, v0, Llyiahf/vczjk/d70;->L$0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/g70;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v7, v2

    move-object/from16 v2, p1

    goto/16 :goto_2

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v6, v0, Llyiahf/vczjk/d70;->this$0:Llyiahf/vczjk/g70;

    iget-object v2, v6, Llyiahf/vczjk/g70;->OooO0oO:Llyiahf/vczjk/e60;

    iget-object v5, v6, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    invoke-virtual {v5}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v7

    iget-object v7, v7, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v7, Llyiahf/vczjk/s29;

    invoke-virtual {v7}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Llyiahf/vczjk/yu;

    iget-object v7, v7, Llyiahf/vczjk/yu;->OooOO0:Ljava/lang/String;

    invoke-static {v7}, Llyiahf/vczjk/z69;->OoooOO0(Ljava/lang/CharSequence;)Z

    move-result v8

    if-nez v8, :cond_2

    goto :goto_0

    :cond_2
    const/4 v7, 0x0

    :goto_0
    if-nez v7, :cond_3

    const-string v7, ""

    :cond_3
    invoke-virtual {v5}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v8

    iget-object v8, v8, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v8, Llyiahf/vczjk/s29;

    invoke-virtual {v8}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/yu;

    iget-object v8, v8, Llyiahf/vczjk/yu;->OooO0oO:Llyiahf/vczjk/vw;

    invoke-virtual {v5}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v9

    iget-object v9, v9, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v9, Llyiahf/vczjk/s29;

    invoke-virtual {v9}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/yu;

    iget-boolean v9, v9, Llyiahf/vczjk/yu;->OooO0oo:Z

    invoke-virtual {v5}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v10

    iget-object v10, v10, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v10, Llyiahf/vczjk/s29;

    invoke-virtual {v10}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/yu;

    iget-object v10, v10, Llyiahf/vczjk/yu;->OooO0o:Llyiahf/vczjk/nw;

    if-nez v10, :cond_4

    move-object v10, v3

    :cond_4
    iget-object v2, v2, Llyiahf/vczjk/e60;->OooO0OO:Llyiahf/vczjk/du;

    iget-object v2, v2, Llyiahf/vczjk/du;->OooO0O0:Llyiahf/vczjk/eb9;

    invoke-virtual {v5}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v5

    iget-object v5, v5, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v5, Llyiahf/vczjk/s29;

    invoke-virtual {v5}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/yu;

    iget-object v5, v5, Llyiahf/vczjk/yu;->OooO0Oo:Llyiahf/vczjk/nw;

    if-eqz v5, :cond_5

    iget-object v5, v5, Llyiahf/vczjk/nw;->OooO00o:Ljava/lang/String;

    goto :goto_1

    :cond_5
    const-string v5, "D878029F-1D75-42EF-9DEA-48B552172C3D"

    :goto_1
    iput-object v6, v0, Llyiahf/vczjk/d70;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/d70;->L$1:Ljava/lang/Object;

    iput-object v10, v0, Llyiahf/vczjk/d70;->L$2:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/d70;->L$3:Ljava/lang/Object;

    iput-boolean v9, v0, Llyiahf/vczjk/d70;->Z$0:Z

    iput v4, v0, Llyiahf/vczjk/d70;->label:I

    iget-object v4, v6, Llyiahf/vczjk/g70;->OooO0o:Landroid/content/Context;

    invoke-interface {v2, v4, v5, v0}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_6

    return-object v1

    :cond_6
    move-object v5, v8

    move v1, v9

    move-object v4, v10

    :goto_2
    check-cast v2, Ljava/lang/Iterable;

    new-instance v8, Ljava/util/ArrayList;

    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_7
    :goto_3
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v9

    if-eqz v9, :cond_b

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v9

    move-object v10, v9

    check-cast v10, Llyiahf/vczjk/xw;

    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v11

    if-nez v11, :cond_8

    goto :goto_4

    :cond_8
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    move-result v11

    const/4 v12, 0x2

    if-le v11, v12, :cond_9

    iget-object v11, v10, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v11}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v11

    const-string v12, "getPkgName(...)"

    invoke-static {v11, v12}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v12, 0x0

    invoke-static {v11, v7, v12}, Llyiahf/vczjk/z69;->Oooo0OO(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Z)Z

    move-result v11

    if-nez v11, :cond_a

    :cond_9
    iget-object v11, v6, Llyiahf/vczjk/g70;->OooO:Llyiahf/vczjk/sc9;

    invoke-virtual {v11}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v11

    check-cast v11, Llyiahf/vczjk/hu;

    iget-object v10, v10, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v10

    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v7, v10}, Llyiahf/vczjk/hu;->OooO00o(Ljava/lang/String;Ljava/lang/String;)Z

    move-result v10

    if-eqz v10, :cond_7

    :cond_a
    :goto_4
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_b
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v7

    :cond_c
    :goto_5
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_e

    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/xw;

    invoke-static {v4, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_d

    iget-object v9, v9, Llyiahf/vczjk/xw;->OooOO0:Ljava/lang/String;

    iget-object v10, v4, Llyiahf/vczjk/nw;->OooO00o:Ljava/lang/String;

    invoke-static {v9, v10}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_c

    :cond_d
    invoke-virtual {v2, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_5

    :cond_e
    invoke-virtual {v5}, Llyiahf/vczjk/vw;->OooO0O0()Llyiahf/vczjk/uw;

    move-result-object v3

    iget-object v4, v6, Llyiahf/vczjk/g70;->OooO0o:Landroid/content/Context;

    invoke-interface {v3, v4}, Llyiahf/vczjk/uw;->Oooooo0(Landroid/content/Context;)Ljava/util/Comparator;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v2

    if-eqz v1, :cond_f

    invoke-static {v2}, Llyiahf/vczjk/d21;->o00000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v2

    :cond_f
    sget-object v1, Llyiahf/vczjk/vw;->OooOOo0:Llyiahf/vczjk/vw;

    const/16 v3, 0xa

    if-eq v5, v1, :cond_10

    sget-object v1, Llyiahf/vczjk/vw;->OooOOOo:Llyiahf/vczjk/vw;

    if-ne v5, v1, :cond_13

    :cond_10
    iget-object v1, v6, Llyiahf/vczjk/g70;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getUsageStatsManager()Lgithub/tornaco/android/thanos/core/app/usage/UsageStatsManager;

    move-result-object v1

    const-wide/16 v7, 0x0

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v9

    invoke-virtual {v1, v7, v8, v9, v10}, Lgithub/tornaco/android/thanos/core/app/usage/UsageStatsManager;->queryAndAggregateUsageStats(JJ)Ljava/util/Map;

    move-result-object v1

    new-instance v4, Ljava/util/ArrayList;

    invoke-static {v2, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v7

    invoke-direct {v4, v7}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_6
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_12

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    move-object v8, v7

    check-cast v8, Llyiahf/vczjk/xw;

    iget-object v7, v8, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v7}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v7

    invoke-interface {v1, v7}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_11

    iget-object v7, v8, Llyiahf/vczjk/xw;->OooO00o:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v7}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v7

    invoke-interface {v1, v7}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Landroid/app/usage/UsageStats;

    if-eqz v7, :cond_11

    invoke-virtual {v7}, Landroid/app/usage/UsageStats;->getLastTimeUsed()J

    move-result-wide v10

    invoke-virtual {v7}, Landroid/app/usage/UsageStats;->getTotalTimeInForeground()J

    move-result-wide v12

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/4 v9, 0x0

    const/16 v16, 0x3e7

    invoke-static/range {v8 .. v16}, Llyiahf/vczjk/xw;->OooO00o(Llyiahf/vczjk/xw;Ljava/lang/String;JJZLjava/lang/String;I)Llyiahf/vczjk/xw;

    move-result-object v8

    :cond_11
    invoke-virtual {v4, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_12
    move-object v2, v4

    :cond_13
    new-instance v8, Ljava/util/ArrayList;

    invoke-static {v2, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v1

    invoke-direct {v8, v1}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_18

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v9, v2

    check-cast v9, Llyiahf/vczjk/xw;

    invoke-virtual {v5}, Llyiahf/vczjk/vw;->OooO0O0()Llyiahf/vczjk/uw;

    move-result-object v2

    iget-object v3, v6, Llyiahf/vczjk/g70;->OooO0o:Landroid/content/Context;

    invoke-interface {v2, v3, v9}, Llyiahf/vczjk/uw;->o00Oo0(Landroid/content/Context;Llyiahf/vczjk/xw;)Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_17

    invoke-virtual {v2}, Ljava/lang/String;->length()I

    move-result v3

    if-nez v3, :cond_14

    goto :goto_a

    :cond_14
    iget-object v3, v9, Llyiahf/vczjk/xw;->OooO0O0:Ljava/lang/String;

    if-eqz v3, :cond_16

    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    move-result-object v4

    invoke-static {v3, v4, v2}, Llyiahf/vczjk/ix8;->OooO0oO(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    if-nez v3, :cond_15

    goto :goto_8

    :cond_15
    move-object v10, v3

    goto :goto_9

    :cond_16
    :goto_8
    move-object v10, v2

    :goto_9
    const/4 v15, 0x0

    const/16 v16, 0x0

    const-wide/16 v11, 0x0

    const-wide/16 v13, 0x0

    const/16 v17, 0x3fd

    invoke-static/range {v9 .. v17}, Llyiahf/vczjk/xw;->OooO00o(Llyiahf/vczjk/xw;Ljava/lang/String;JJZLjava/lang/String;I)Llyiahf/vczjk/xw;

    move-result-object v9

    :cond_17
    :goto_a
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_7

    :cond_18
    iget-object v1, v6, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v1, v1, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/rs5;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v7, v1

    check-cast v7, Llyiahf/vczjk/yu;

    const/16 v17, 0x0

    const/16 v20, 0xffc

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/16 v16, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    invoke-static/range {v7 .. v20}, Llyiahf/vczjk/yu;->OooO00o(Llyiahf/vczjk/yu;Ljava/util/ArrayList;ZLjava/util/List;Llyiahf/vczjk/nw;Ljava/util/List;Llyiahf/vczjk/nw;Llyiahf/vczjk/vw;ZLjava/util/ArrayList;Ljava/lang/String;ZLjava/util/List;I)Llyiahf/vczjk/yu;

    move-result-object v1

    check-cast v2, Llyiahf/vczjk/s29;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
