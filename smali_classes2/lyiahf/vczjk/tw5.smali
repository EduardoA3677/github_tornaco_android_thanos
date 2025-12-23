.class public final Llyiahf/vczjk/tw5;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field Z$0:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/vw5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vw5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tw5;->this$0:Llyiahf/vczjk/vw5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/tw5;

    iget-object v0, p0, Llyiahf/vczjk/tw5;->this$0:Llyiahf/vczjk/vw5;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/tw5;-><init>(Llyiahf/vczjk/vw5;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tw5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tw5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/tw5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v1, p0

    const/4 v2, 0x1

    sget-object v3, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, v1, Llyiahf/vczjk/tw5;->label:I

    const/4 v4, 0x2

    const/4 v5, 0x0

    const/4 v6, 0x0

    if-eqz v0, :cond_2

    if-eq v0, v2, :cond_1

    if-ne v0, v4, :cond_0

    iget-boolean v0, v1, Llyiahf/vczjk/tw5;->Z$0:Z

    iget-object v3, v1, Llyiahf/vczjk/tw5;->L$1:Ljava/lang/Object;

    check-cast v3, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    iget-object v4, v1, Llyiahf/vczjk/tw5;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/vw5;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v7, v4

    move-object/from16 v4, p1

    goto/16 :goto_8

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-object v0, v1, Llyiahf/vczjk/tw5;->L$1:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    iget-object v7, v1, Llyiahf/vczjk/tw5;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/vw5;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v8, p1

    goto/16 :goto_6

    :cond_2
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v7, v1, Llyiahf/vczjk/tw5;->this$0:Llyiahf/vczjk/vw5;

    iget-object v8, v7, Llyiahf/vczjk/vw5;->OooO0o0:Landroid/content/Context;

    sget-object v0, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v0, Ljava/lang/Iterable;

    instance-of v9, v0, Ljava/util/Collection;

    if-eqz v9, :cond_3

    move-object v9, v0

    check-cast v9, Ljava/util/Collection;

    invoke-interface {v9}, Ljava/util/Collection;->isEmpty()Z

    move-result v9

    if-eqz v9, :cond_3

    goto :goto_2

    :cond_3
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v9

    :cond_4
    invoke-interface {v9}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-interface {v9}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    :try_start_0
    new-instance v10, Ljava/io/File;

    invoke-virtual {v8}, Landroid/content/Context;->getDataDir()Ljava/io/File;

    move-result-object v11

    invoke-static {v0}, Lutil/EncryptUtils;->decrypt(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v10, v11, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v10}, Ljava/io/File;->exists()Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v10

    if-nez v10, :cond_5

    goto :goto_1

    :cond_5
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_1
    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_4

    goto :goto_3

    :cond_6
    :goto_2
    const-string v0, "getDataDir(...)"

    invoke-static {v8, v0}, Llyiahf/vczjk/u81;->OooOo0o(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_7

    :goto_3
    move v0, v2

    goto :goto_4

    :cond_7
    move v0, v6

    :goto_4
    const-string v9, "Required value was null."

    const-string v10, "39M5DC32-B17D-4370-AB98-A9L809256685"

    if-eqz v0, :cond_9

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-virtual {v0, v10}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_8

    invoke-static {v0}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-static {v8}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v11

    invoke-virtual {v0, v11}, Lcom/tencent/mmkv/MMKV;->OooO0o0(Ljava/lang/String;)V

    goto :goto_5

    :cond_8
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v9}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_9
    :goto_5
    sget-object v0, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_f

    invoke-static {v8}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v11

    if-eqz v11, :cond_f

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v11

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v12

    invoke-virtual {v12, v10}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    if-eqz v10, :cond_e

    invoke-static {v10}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v9

    invoke-static {v8}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v9, v8}, Lcom/tencent/mmkv/MMKV;->OooO0O0(Ljava/lang/String;)I

    move-result v8

    const-string v9, "github.tornaco.android.thanos"

    invoke-static {v9, v8}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->newPkg(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v8

    invoke-virtual {v11, v8}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v8

    if-eqz v8, :cond_f

    iput-object v7, v1, Llyiahf/vczjk/tw5;->L$0:Ljava/lang/Object;

    iput-object v0, v1, Llyiahf/vczjk/tw5;->L$1:Ljava/lang/Object;

    iput v2, v1, Llyiahf/vczjk/tw5;->label:I

    sget-object v8, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v8, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v9, Llyiahf/vczjk/sw5;

    invoke-direct {v9, v7, v5}, Llyiahf/vczjk/sw5;-><init>(Llyiahf/vczjk/vw5;Llyiahf/vczjk/yo1;)V

    invoke-static {v8, v9, v1}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v3, :cond_a

    goto :goto_7

    :cond_a
    :goto_6
    check-cast v8, Ljava/lang/Boolean;

    invoke-virtual {v8}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v8

    iput-object v7, v1, Llyiahf/vczjk/tw5;->L$0:Ljava/lang/Object;

    iput-object v0, v1, Llyiahf/vczjk/tw5;->L$1:Ljava/lang/Object;

    iput-boolean v8, v1, Llyiahf/vczjk/tw5;->Z$0:Z

    iput v4, v1, Llyiahf/vczjk/tw5;->label:I

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v4, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v9, Llyiahf/vczjk/rw5;

    invoke-direct {v9, v7, v5}, Llyiahf/vczjk/rw5;-><init>(Llyiahf/vczjk/vw5;Llyiahf/vczjk/yo1;)V

    invoke-static {v4, v9, v1}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v3, :cond_b

    :goto_7
    return-object v3

    :cond_b
    move-object v3, v0

    move v0, v8

    :goto_8
    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    iget-object v7, v7, Llyiahf/vczjk/vw5;->OooO0o:Llyiahf/vczjk/s29;

    invoke-virtual {v7}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v8

    move-object v9, v8

    check-cast v9, Llyiahf/vczjk/ow5;

    xor-int/lit8 v15, v0, 0x1

    if-eqz v0, :cond_c

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v0

    const-string v8, "PREF_KEY_FIRST_RUN"

    invoke-interface {v0, v8, v2}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v0

    if-eqz v0, :cond_c

    move/from16 v16, v2

    goto :goto_9

    :cond_c
    move/from16 v16, v6

    :goto_9
    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPatchingSource()Ljava/util/List;

    move-result-object v0

    const-string v3, "getPatchingSource(...)"

    invoke-static {v0, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez v4, :cond_d

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/OsUtils;->isOOrAbove()Z

    move-result v3

    if-nez v3, :cond_d

    move/from16 v18, v2

    goto :goto_a

    :cond_d
    move/from16 v18, v6

    :goto_a
    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/16 v19, 0x1f

    move-object/from16 v17, v0

    invoke-static/range {v9 .. v19}, Llyiahf/vczjk/ow5;->OooO00o(Llyiahf/vczjk/ow5;ZLjava/util/ArrayList;Llyiahf/vczjk/x39;Llyiahf/vczjk/oO00o0;ZZZLjava/util/List;ZI)Llyiahf/vczjk/ow5;

    move-result-object v0

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v7, v5, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    goto :goto_b

    :cond_e
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v9}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_f
    :goto_b
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
