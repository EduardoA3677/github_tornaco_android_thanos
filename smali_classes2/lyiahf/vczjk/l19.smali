.class public final Llyiahf/vczjk/l19;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/n19;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/n19;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/l19;->this$0:Llyiahf/vczjk/n19;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/l19;

    iget-object v0, p0, Llyiahf/vczjk/l19;->this$0:Llyiahf/vczjk/n19;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/l19;-><init>(Llyiahf/vczjk/n19;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/l19;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/l19;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/l19;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v0, p0

    const/4 v1, 0x1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/l19;->label:I

    if-nez v2, :cond_b

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance v2, Ljava/util/LinkedHashSet;

    invoke-direct {v2}, Ljava/util/LinkedHashSet;-><init>()V

    iget-object v3, v0, Llyiahf/vczjk/l19;->this$0:Llyiahf/vczjk/n19;

    iget-object v3, v3, Llyiahf/vczjk/n19;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v3}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/j19;

    iget-object v3, v3, Llyiahf/vczjk/j19;->OooO0OO:Llyiahf/vczjk/ur0;

    iget-object v4, v0, Llyiahf/vczjk/l19;->this$0:Llyiahf/vczjk/n19;

    iget-object v4, v4, Llyiahf/vczjk/n19;->OooO0O0:Landroid/content/Context;

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v4

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v4

    invoke-virtual {v3}, Llyiahf/vczjk/ur0;->OooO0O0()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getStartRecordAllowedPackages()Ljava/util/List;

    move-result-object v5

    const-string v6, "getStartRecordAllowedPackages(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2, v5}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/ur0;->OooO0OO()Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getStartRecordBlockedPackages()Ljava/util/List;

    move-result-object v5

    const-string v6, "getStartRecordBlockedPackages(...)"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2, v5}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    :cond_1
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_2
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    move-object v7, v6

    check-cast v7, Ljava/lang/String;

    const-string v8, "android"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-nez v8, :cond_2

    const-string v8, "com.android.systemui"

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_2

    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    iget-object v2, v0, Llyiahf/vczjk/l19;->this$0:Llyiahf/vczjk/n19;

    new-instance v6, Ljava/util/ArrayList;

    const/16 v7, 0xa

    invoke-static {v5, v7}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v8

    invoke-direct {v6, v8}, Ljava/util/ArrayList;-><init>(I)V

    invoke-virtual {v5}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v5

    const-wide/16 v12, 0x0

    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v10

    if-eqz v10, :cond_8

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/lang/String;

    invoke-virtual {v3}, Llyiahf/vczjk/ur0;->OooO0O0()Z

    move-result v11

    if-eqz v11, :cond_4

    invoke-virtual {v4, v10}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getStartRecordAllowedCountByPackageName(Ljava/lang/String;)J

    move-result-wide v14

    goto :goto_2

    :cond_4
    const-wide/16 v14, 0x0

    :goto_2
    invoke-virtual {v3}, Llyiahf/vczjk/ur0;->OooO0OO()Z

    move-result v11

    if-eqz v11, :cond_5

    invoke-virtual {v4, v10}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getStartRecordBlockedCountByPackageName(Ljava/lang/String;)J

    move-result-wide v16

    add-long v14, v16, v14

    :cond_5
    add-long/2addr v12, v14

    new-instance v11, Llyiahf/vczjk/s19;

    iget-object v8, v2, Llyiahf/vczjk/n19;->OooO0O0:Landroid/content/Context;

    invoke-static {v8}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v8

    invoke-virtual {v8}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v8

    invoke-virtual {v8, v10}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v8

    if-eqz v8, :cond_6

    invoke-virtual {v8}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v8

    if-nez v8, :cond_7

    :cond_6
    move-object v8, v10

    :cond_7
    invoke-direct {v11, v10, v8, v14, v15}, Llyiahf/vczjk/s19;-><init>(Ljava/lang/String;Ljava/lang/String;J)V

    invoke-virtual {v6, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_8
    new-instance v2, Llyiahf/vczjk/ms8;

    invoke-direct {v2, v1}, Llyiahf/vczjk/ms8;-><init>(I)V

    invoke-static {v6, v2}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v2

    new-instance v3, Ljava/util/ArrayList;

    invoke-static {v2, v7}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v4

    invoke-direct {v3, v4}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    const/4 v5, 0x0

    move v6, v5

    :goto_3
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    const/4 v8, 0x0

    if-eqz v7, :cond_a

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v7

    add-int/lit8 v9, v6, 0x1

    if-ltz v6, :cond_9

    check-cast v7, Llyiahf/vczjk/s19;

    new-instance v14, Llyiahf/vczjk/iu0;

    iget-object v15, v7, Llyiahf/vczjk/s19;->OooO00o:Ljava/lang/String;

    sget-object v8, Llyiahf/vczjk/u21;->OooO00o:[Llyiahf/vczjk/n21;

    array-length v10, v8

    rem-int/2addr v6, v10

    aget-object v6, v8, v6

    iget-wide v10, v6, Llyiahf/vczjk/n21;->OooO00o:J

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v8, v7, Llyiahf/vczjk/s19;->OooO0O0:Ljava/lang/String;

    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v8, " - "

    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-wide v7, v7, Llyiahf/vczjk/s19;->OooO0OO:J

    invoke-virtual {v6, v7, v8}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v20

    move-wide/from16 v18, v7

    move-wide/from16 v16, v10

    invoke-direct/range {v14 .. v20}, Llyiahf/vczjk/iu0;-><init>(Ljava/lang/Object;JJLjava/lang/String;)V

    invoke-virtual {v3, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    move v6, v9

    goto :goto_3

    :cond_9
    invoke-static {}, Llyiahf/vczjk/e21;->OoooOO0()V

    throw v8

    :cond_a
    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v1

    const/16 v2, 0x18

    invoke-static {v1, v2}, Ljava/lang/Math;->min(II)I

    move-result v1

    invoke-virtual {v3, v5, v1}, Ljava/util/ArrayList;->subList(II)Ljava/util/List;

    move-result-object v15

    iget-object v1, v0, Llyiahf/vczjk/l19;->this$0:Llyiahf/vczjk/n19;

    iget-object v1, v1, Llyiahf/vczjk/n19;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    move-object v10, v2

    check-cast v10, Llyiahf/vczjk/j19;

    const/4 v11, 0x0

    const/4 v14, 0x0

    const/16 v16, 0x4

    invoke-static/range {v10 .. v16}, Llyiahf/vczjk/j19;->OooO00o(Llyiahf/vczjk/j19;ZJLlyiahf/vczjk/ur0;Ljava/util/List;I)Llyiahf/vczjk/j19;

    move-result-object v2

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v8, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1

    :cond_b
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1
.end method
