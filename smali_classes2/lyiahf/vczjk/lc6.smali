.class public final Llyiahf/vczjk/lc6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/nc6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nc6;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lc6;->this$0:Llyiahf/vczjk/nc6;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/lc6;

    iget-object v0, p0, Llyiahf/vczjk/lc6;->this$0:Llyiahf/vczjk/nc6;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/lc6;-><init>(Llyiahf/vczjk/nc6;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/lc6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lc6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/lc6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v1, p0

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v1, Llyiahf/vczjk/lc6;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x0

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eqz v2, :cond_1

    if-ne v2, v5, :cond_0

    iget-object v0, v1, Llyiahf/vczjk/lc6;->L$1:Ljava/lang/Object;

    check-cast v0, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    iget-object v2, v1, Llyiahf/vczjk/lc6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/nc6;

    :try_start_0
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object/from16 v8, p1

    move-object v7, v0

    goto :goto_0

    :catchall_0
    move-exception v0

    goto/16 :goto_8

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v1, Llyiahf/vczjk/lc6;->this$0:Llyiahf/vczjk/nc6;

    :try_start_1
    iget-object v7, v2, Llyiahf/vczjk/nc6;->OooO0oO:Llyiahf/vczjk/sc9;

    invoke-virtual {v7}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v7

    check-cast v7, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v7}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v7

    iget-object v8, v2, Llyiahf/vczjk/nc6;->OooO0OO:Llyiahf/vczjk/ec6;

    iput-object v2, v1, Llyiahf/vczjk/lc6;->L$0:Ljava/lang/Object;

    iput-object v7, v1, Llyiahf/vczjk/lc6;->L$1:Ljava/lang/Object;

    iput v5, v1, Llyiahf/vczjk/lc6;->label:I

    invoke-virtual {v8, v1}, Llyiahf/vczjk/ec6;->OooO00o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    check-cast v8, Ljava/util/List;

    new-instance v9, Ljava/util/ArrayList;

    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v8}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v8

    :cond_3
    :goto_1
    invoke-interface {v8}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_9

    invoke-interface {v8}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v11, v0

    check-cast v11, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    iget-object v0, v2, Llyiahf/vczjk/nc6;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/nk3;

    invoke-virtual {v11}, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;->getProfile()Lgithub/tornaco/thanos/android/module/profile/repo/Profile;

    move-result-object v10

    invoke-static {v10}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v10

    invoke-virtual {v0, v10}, Llyiahf/vczjk/nk3;->OooO0oo(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lutil/JsonFormatter;->format(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v13

    invoke-virtual {v7, v13, v6}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->parseRuleOrNull(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v12

    if-eqz v12, :cond_7

    invoke-virtual {v12}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v7, v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getRuleByName(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v0

    if-eqz v0, :cond_4

    move v14, v5

    goto :goto_2

    :cond_4
    move v14, v6

    :goto_2
    if-eqz v0, :cond_6

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getVersionCode()I

    move-result v0

    invoke-virtual {v11}, Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;->getVersion()I

    move-result v10

    if-ge v0, v10, :cond_5

    move v0, v5

    goto :goto_3

    :cond_5
    move v0, v6

    :goto_3
    move v15, v0

    goto :goto_4

    :catchall_1
    move-exception v0

    goto :goto_5

    :cond_6
    move v15, v6

    :goto_4
    new-instance v10, Llyiahf/vczjk/cc6;

    invoke-static {v13}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-direct/range {v10 .. v15}, Llyiahf/vczjk/cc6;-><init>(Lgithub/tornaco/thanos/android/module/profile/repo/OnlineProfile;Lgithub/tornaco/android/thanos/core/profile/RuleInfo;Ljava/lang/String;ZZ)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    goto :goto_6

    :cond_7
    move-object v10, v4

    goto :goto_6

    :goto_5
    :try_start_3
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v10

    :goto_6
    invoke-static {v10}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-nez v0, :cond_8

    goto :goto_7

    :cond_8
    invoke-static {v0}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    new-instance v10, Ljava/lang/StringBuilder;

    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    const-string v11, "Parse one profile error: "

    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    move-object v10, v4

    :goto_7
    check-cast v10, Llyiahf/vczjk/cc6;

    if-eqz v10, :cond_3

    invoke-virtual {v9, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto/16 :goto_1

    :cond_9
    iget-object v0, v2, Llyiahf/vczjk/nc6;->OooO0Oo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gc6;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/gc6;

    invoke-direct {v2, v9, v6}, Llyiahf/vczjk/gc6;-><init>(Ljava/util/List;Z)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    move-object v0, v3

    goto :goto_9

    :goto_8
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_9
    iget-object v2, v1, Llyiahf/vczjk/lc6;->this$0:Llyiahf/vczjk/nc6;

    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-eqz v0, :cond_a

    invoke-static {v0}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object v0

    const-string v5, "loadOnlineProfiles error: "

    invoke-static {v5, v0}, Llyiahf/vczjk/ix8;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, v2, Llyiahf/vczjk/nc6;->OooO0Oo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/gc6;

    sget-object v5, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/gc6;

    invoke-direct {v2, v5, v6}, Llyiahf/vczjk/gc6;-><init>(Ljava/util/List;Z)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v4, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    :cond_a
    return-object v3
.end method
