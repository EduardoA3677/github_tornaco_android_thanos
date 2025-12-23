.class public final Llyiahf/vczjk/gt;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $listener:Llyiahf/vczjk/ws;

.field final synthetic $pickedFileIS:Ljava/io/InputStream;

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Ljava/io/InputStream;Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/ws;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gt;->$pickedFileIS:Ljava/io/InputStream;

    iput-object p2, p0, Llyiahf/vczjk/gt;->$context:Landroid/content/Context;

    iput-object p3, p0, Llyiahf/vczjk/gt;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iput-object p4, p0, Llyiahf/vczjk/gt;->$listener:Llyiahf/vczjk/ws;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method

.method public static final OooOOO(Lnow/fortuitous/thanos/apps/AppComponentBackup;Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;)Z
    .locals 3

    iget-object p0, p0, Lnow/fortuitous/thanos/apps/AppComponentBackup;->disabledComponents:Ljava/util/List;

    const-string v0, "disabledComponents"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    return v1

    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v2

    invoke-virtual {v2}, Landroid/content/ComponentName;->flattenToString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_2

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v2

    invoke-virtual {v2}, Landroid/content/ComponentName;->flattenToShortString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    :cond_2
    const/4 p0, 0x1

    return p0

    :cond_3
    return v1
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/gt;

    iget-object v1, p0, Llyiahf/vczjk/gt;->$pickedFileIS:Ljava/io/InputStream;

    iget-object v2, p0, Llyiahf/vczjk/gt;->$context:Landroid/content/Context;

    iget-object v3, p0, Llyiahf/vczjk/gt;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v4, p0, Llyiahf/vczjk/gt;->$listener:Llyiahf/vczjk/ws;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/gt;-><init>(Ljava/io/InputStream;Landroid/content/Context;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/ws;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/gt;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gt;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gt;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gt;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    move-object/from16 v1, p0

    const/4 v0, 0x1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v3, v1, Llyiahf/vczjk/gt;->label:I

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v5, 0x3

    const/4 v6, 0x2

    const/4 v7, 0x0

    if-eqz v3, :cond_3

    if-eq v3, v0, :cond_2

    if-eq v3, v6, :cond_1

    if-ne v3, v5, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_17

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-object v0, v1, Llyiahf/vczjk/gt;->L$1:Ljava/lang/Object;

    iget-object v3, v1, Llyiahf/vczjk/gt;->L$0:Ljava/lang/Object;

    check-cast v3, Ljava/io/Closeable;

    :try_start_0
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_12

    :catchall_0
    move-exception v0

    move-object v5, v3

    move-object v3, v0

    goto/16 :goto_13

    :cond_2
    iget-object v0, v1, Llyiahf/vczjk/gt;->L$1:Ljava/lang/Object;

    move-object v3, v0

    check-cast v3, Ljava/io/Closeable;

    iget-object v0, v1, Llyiahf/vczjk/gt;->L$0:Ljava/lang/Object;

    move-object v9, v0

    check-cast v9, Llyiahf/vczjk/ws;

    :try_start_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto/16 :goto_f

    :catchall_1
    move-exception v0

    goto/16 :goto_10

    :cond_3
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v3, v1, Llyiahf/vczjk/gt;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xr1;

    iget-object v3, v1, Llyiahf/vczjk/gt;->$pickedFileIS:Ljava/io/InputStream;

    iget-object v9, v1, Llyiahf/vczjk/gt;->$context:Landroid/content/Context;

    iget-object v10, v1, Llyiahf/vczjk/gt;->$app:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v11, v1, Llyiahf/vczjk/gt;->$listener:Llyiahf/vczjk/ws;

    :try_start_2
    sget-object v12, Llyiahf/vczjk/eu0;->OooO00o:Ljava/nio/charset/Charset;

    new-instance v13, Ljava/io/InputStreamReader;

    invoke-direct {v13, v3, v12}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;Ljava/nio/charset/Charset;)V

    new-instance v12, Ljava/io/BufferedReader;

    const/16 v14, 0x2000

    invoke-direct {v12, v13, v14}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;I)V

    invoke-static {v12}, Llyiahf/vczjk/tn6;->OooOOOo(Ljava/io/Reader;)Ljava/lang/String;

    move-result-object v12

    sget-object v13, Lgithub/tornaco/android/thanos/core/util/GsonUtils;->GSON:Llyiahf/vczjk/nk3;

    const-class v14, Lnow/fortuitous/thanos/apps/AppComponentBackup;

    invoke-virtual {v13, v14, v12}, Llyiahf/vczjk/nk3;->OooO0O0(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Lnow/fortuitous/thanos/apps/AppComponentBackup;

    invoke-static {v12}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    invoke-static {v9}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v9

    invoke-virtual {v9}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v9

    move v13, v7

    :goto_0
    const/16 v14, 0x14

    const v15, 0x7fffffff

    if-ge v13, v15, :cond_4

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v5

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v9, v5, v6, v14, v13}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getActivitiesInBatch(ILjava/lang/String;II)Ljava/util/List;

    move-result-object v5

    if-nez v5, :cond_5

    :cond_4
    move/from16 v16, v0

    goto :goto_4

    :cond_5
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_8

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;

    invoke-static {v12, v6}, Llyiahf/vczjk/gt;->OooOOO(Lnow/fortuitous/thanos/apps/AppComponentBackup;Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;)Z

    move-result v14

    if-eqz v14, :cond_6

    const/4 v14, 0x2

    goto :goto_2

    :cond_6
    move v14, v0

    :goto_2
    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v15

    move/from16 v16, v0

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v0

    invoke-virtual {v9, v15, v0}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getComponentEnabledSetting(ILandroid/content/ComponentName;)I

    move-result v0

    if-eq v0, v14, :cond_7

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v0

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v6

    invoke-virtual {v9, v0, v6, v14, v7}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->setComponentEnabledSetting(ILandroid/content/ComponentName;II)V

    goto :goto_3

    :catchall_2
    move-exception v0

    move-object v9, v11

    goto/16 :goto_10

    :cond_7
    :goto_3
    move/from16 v0, v16

    goto :goto_1

    :cond_8
    move/from16 v16, v0

    add-int/lit8 v13, v13, 0x1

    const/4 v5, 0x3

    const/4 v6, 0x2

    goto :goto_0

    :goto_4
    move v0, v7

    :goto_5
    if-ge v0, v15, :cond_d

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v5

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v9, v5, v6, v14, v0}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getServicesInBatch(ILjava/lang/String;II)Ljava/util/List;

    move-result-object v5

    if-nez v5, :cond_9

    goto :goto_8

    :cond_9
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_6
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_c

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;

    invoke-static {v12, v6}, Llyiahf/vczjk/gt;->OooOOO(Lnow/fortuitous/thanos/apps/AppComponentBackup;Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;)Z

    move-result v13

    if-eqz v13, :cond_a

    const/4 v13, 0x2

    goto :goto_7

    :cond_a
    move/from16 v13, v16

    :goto_7
    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v8

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v14

    invoke-virtual {v9, v8, v14}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getComponentEnabledSetting(ILandroid/content/ComponentName;)I

    move-result v8

    if-eq v8, v13, :cond_b

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v8

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v6

    invoke-virtual {v9, v8, v6, v13, v7}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->setComponentEnabledSetting(ILandroid/content/ComponentName;II)V

    :cond_b
    const/16 v14, 0x14

    goto :goto_6

    :cond_c
    add-int/lit8 v0, v0, 0x1

    const/16 v14, 0x14

    goto :goto_5

    :cond_d
    :goto_8
    move v0, v7

    :goto_9
    if-ge v0, v15, :cond_12

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v5

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v6

    const/16 v8, 0x14

    invoke-virtual {v9, v5, v6, v8, v0}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getReceiversInBatch(ILjava/lang/String;II)Ljava/util/List;

    move-result-object v5

    if-nez v5, :cond_e

    goto :goto_c

    :cond_e
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_a
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_11

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;

    invoke-static {v12, v6}, Llyiahf/vczjk/gt;->OooOOO(Lnow/fortuitous/thanos/apps/AppComponentBackup;Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;)Z

    move-result v13

    if-eqz v13, :cond_f

    const/4 v13, 0x2

    goto :goto_b

    :cond_f
    move/from16 v13, v16

    :goto_b
    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v14

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v8

    invoke-virtual {v9, v14, v8}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getComponentEnabledSetting(ILandroid/content/ComponentName;)I

    move-result v8

    if-eq v8, v13, :cond_10

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v8

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v6

    invoke-virtual {v9, v8, v6, v13, v7}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->setComponentEnabledSetting(ILandroid/content/ComponentName;II)V

    :cond_10
    const/16 v8, 0x14

    goto :goto_a

    :cond_11
    add-int/lit8 v0, v0, 0x1

    goto :goto_9

    :cond_12
    :goto_c
    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v0

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v9, v0, v5}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getProviders(ILjava/lang/String;)Ljava/util/List;

    move-result-object v0

    const-string v5, "getProviders(...)"

    invoke-static {v0, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_13
    :goto_d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_15

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;

    invoke-static {v12, v5}, Llyiahf/vczjk/gt;->OooOOO(Lnow/fortuitous/thanos/apps/AppComponentBackup;Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;)Z

    move-result v6

    if-eqz v6, :cond_14

    const/4 v6, 0x2

    goto :goto_e

    :cond_14
    move/from16 v6, v16

    :goto_e
    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v8

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v13

    invoke-virtual {v9, v8, v13}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getComponentEnabledSetting(ILandroid/content/ComponentName;)I

    move-result v8

    if-eq v8, v6, :cond_13

    invoke-virtual {v10}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getUserId()I

    move-result v8

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/pm/ComponentInfo;->getComponentName()Landroid/content/ComponentName;

    move-result-object v5

    invoke-virtual {v9, v8, v5, v6, v7}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->setComponentEnabledSetting(ILandroid/content/ComponentName;II)V

    goto :goto_d

    :cond_15
    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    new-instance v5, Llyiahf/vczjk/dt;

    const/4 v6, 0x0

    invoke-direct {v5, v11, v6}, Llyiahf/vczjk/dt;-><init>(Llyiahf/vczjk/ws;Llyiahf/vczjk/yo1;)V

    iput-object v11, v1, Llyiahf/vczjk/gt;->L$0:Ljava/lang/Object;

    iput-object v3, v1, Llyiahf/vczjk/gt;->L$1:Ljava/lang/Object;

    move/from16 v6, v16

    iput v6, v1, Llyiahf/vczjk/gt;->label:I

    invoke-static {v0, v5, v1}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    if-ne v0, v2, :cond_16

    goto :goto_16

    :cond_16
    move-object v9, v11

    :goto_f
    move-object v0, v4

    goto :goto_11

    :goto_10
    :try_start_3
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_11
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v5

    if-eqz v5, :cond_17

    sget-object v6, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v6, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    new-instance v8, Llyiahf/vczjk/et;

    const/4 v10, 0x0

    invoke-direct {v8, v9, v5, v10}, Llyiahf/vczjk/et;-><init>(Llyiahf/vczjk/ws;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    iput-object v3, v1, Llyiahf/vczjk/gt;->L$0:Ljava/lang/Object;

    iput-object v0, v1, Llyiahf/vczjk/gt;->L$1:Ljava/lang/Object;

    const/4 v5, 0x2

    iput v5, v1, Llyiahf/vczjk/gt;->label:I

    invoke-static {v6, v8, v1}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v5
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    if-ne v5, v2, :cond_17

    goto :goto_16

    :cond_17
    :goto_12
    const/4 v6, 0x0

    :try_start_4
    invoke-static {v3, v6}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    new-instance v3, Llyiahf/vczjk/vs7;

    invoke-direct {v3, v0}, Llyiahf/vczjk/vs7;-><init>(Ljava/lang/Object;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    goto :goto_15

    :catchall_3
    move-exception v0

    goto :goto_14

    :goto_13
    :try_start_5
    throw v3
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    :catchall_4
    move-exception v0

    :try_start_6
    invoke-static {v5, v3}, Llyiahf/vczjk/rs;->OooOOO(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    :goto_14
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v3

    :goto_15
    iget-object v0, v1, Llyiahf/vczjk/gt;->$listener:Llyiahf/vczjk/ws;

    invoke-static {v3}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v5

    if-eqz v5, :cond_18

    const-string v6, "performComponentsRestore error"

    new-array v7, v7, [Ljava/lang/Object;

    invoke-static {v6, v7, v5}, Llyiahf/vczjk/zsa;->Oooo0o(Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/Throwable;)V

    sget-object v6, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v6, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    new-instance v7, Llyiahf/vczjk/ft;

    const/4 v10, 0x0

    invoke-direct {v7, v0, v5, v10}, Llyiahf/vczjk/ft;-><init>(Llyiahf/vczjk/ws;Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    iput-object v3, v1, Llyiahf/vczjk/gt;->L$0:Ljava/lang/Object;

    iput-object v10, v1, Llyiahf/vczjk/gt;->L$1:Ljava/lang/Object;

    const/4 v3, 0x3

    iput v3, v1, Llyiahf/vczjk/gt;->label:I

    invoke-static {v6, v7, v1}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v2, :cond_18

    :goto_16
    return-object v2

    :cond_18
    :goto_17
    return-object v4
.end method
