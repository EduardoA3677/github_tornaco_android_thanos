.class public final synthetic Llyiahf/vczjk/di8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/dj8;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/dj8;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/di8;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/di8;->OooOOO:Llyiahf/vczjk/dj8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v1, p0

    iget v0, v1, Llyiahf/vczjk/di8;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    move-object/from16 v0, p1

    check-cast v0, Landroid/os/ParcelFileDescriptor;

    const-string v2, "it"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v1, Llyiahf/vczjk/di8;->OooOOO:Llyiahf/vczjk/dj8;

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2, v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->writeLogsTo(Landroid/os/ParcelFileDescriptor;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    move-object/from16 v0, p1

    check-cast v0, Llyiahf/vczjk/mi8;

    const-string v2, "$this$updateState"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v1, Llyiahf/vczjk/di8;->OooOOO:Llyiahf/vczjk/dj8;

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isAppStabilityUpKeepEnabled()Z

    move-result v9

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPowerManager()Lgithub/tornaco/android/thanos/core/power/PowerManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/power/PowerManager;->isPowerSaveModeEnabled()Z

    move-result v10

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->isProtectedWhitelistEnabled()Z

    move-result v11

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->isAutoApplyForNewInstalledAppsEnabled()Z

    move-result v14

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->isAutoConfigTemplateNotificationEnabled()Z

    move-result v15

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getAutoConfigTemplateSelectionId()Ljava/lang/String;

    move-result-object v3

    if-eqz v3, :cond_0

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v4

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v4

    invoke-virtual {v4, v3}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getConfigTemplateById(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/profile/ConfigTemplate;

    move-result-object v3

    :goto_0
    move-object/from16 v16, v3

    goto :goto_1

    :cond_0
    const/4 v3, 0x0

    goto :goto_0

    :goto_1
    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getAllConfigTemplates()Ljava/util/List;

    move-result-object v3

    if-nez v3, :cond_1

    sget-object v3, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_1
    move-object/from16 v17, v3

    invoke-static {}, Llyiahf/vczjk/i51;->OooO00o()Llyiahf/vczjk/i51;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v3, v2, Llyiahf/vczjk/vo1;->OooO0o:Landroid/content/Context;

    invoke-static {v3}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v4

    const-string v5, "PREF_KEY_APP_LIST_SHOW_VERSION"

    const/4 v6, 0x0

    invoke-interface {v4, v5, v6}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v12

    invoke-static {}, Llyiahf/vczjk/i51;->OooO00o()Llyiahf/vczjk/i51;

    move-result-object v4

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v3}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v4

    const-string v5, "PREF_KEY_APP_LIST_SHOW_PKG_NAME"

    invoke-interface {v4, v5, v6}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v13

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v4

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v4

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->isShowCurrentComponentViewEnabled()Z

    move-result v18

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO0oo()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isNetStatTrackerEnabled()Z

    move-result v19

    invoke-static {v3}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v2

    const-string v4, "NEW_OPS"

    invoke-interface {v2, v4, v6}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v20

    invoke-static {v3}, Llyiahf/vczjk/n27;->OooO00o(Landroid/content/Context;)Landroid/content/SharedPreferences;

    move-result-object v2

    const-string v3, "NEW_HOME"

    invoke-interface {v2, v3, v6}, Landroid/content/SharedPreferences;->getBoolean(Ljava/lang/String;Z)Z

    move-result v21

    iget-object v6, v0, Llyiahf/vczjk/mi8;->OooO0O0:Ljava/lang/String;

    iget-object v7, v0, Llyiahf/vczjk/mi8;->OooO0OO:Ljava/lang/String;

    new-instance v4, Llyiahf/vczjk/mi8;

    iget-boolean v5, v0, Llyiahf/vczjk/mi8;->OooO00o:Z

    iget-boolean v8, v0, Llyiahf/vczjk/mi8;->OooO0Oo:Z

    invoke-direct/range {v4 .. v21}, Llyiahf/vczjk/mi8;-><init>(ZLjava/lang/String;Ljava/lang/String;ZZZZZZZZLgithub/tornaco/android/thanos/core/profile/ConfigTemplate;Ljava/util/List;ZZZZ)V

    return-object v4

    :pswitch_1
    move-object/from16 v0, p1

    check-cast v0, Ljava/lang/String;

    const-string v2, "it"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v1, Llyiahf/vczjk/di8;->OooOOO:Llyiahf/vczjk/dj8;

    sget-object v0, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v0, Ljava/lang/Iterable;

    instance-of v3, v0, Ljava/util/Collection;

    iget-object v4, v2, Llyiahf/vczjk/vo1;->OooO0o:Landroid/content/Context;

    if-eqz v3, :cond_2

    move-object v3, v0

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_2

    goto :goto_4

    :cond_2
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v3

    :cond_3
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    :try_start_0
    new-instance v5, Ljava/io/File;

    invoke-virtual {v4}, Landroid/content/Context;->getDataDir()Ljava/io/File;

    move-result-object v6

    invoke-static {v0}, Lutil/EncryptUtils;->decrypt(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v5, v6, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v5}, Ljava/io/File;->exists()Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_2
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v5

    if-nez v5, :cond_4

    goto :goto_3

    :cond_4
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_3
    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_3

    goto :goto_5

    :cond_5
    :goto_4
    const-string v0, "getDataDir(...)"

    invoke-static {v4, v0}, Llyiahf/vczjk/u81;->OooOo0o(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_6

    :goto_5
    const/4 v0, 0x1

    goto :goto_6

    :cond_6
    const/4 v0, 0x0

    :goto_6
    const-string v3, "Required value was null."

    const-string v5, "39M5DC32-B17D-4370-AB98-A9L809256685"

    if-eqz v0, :cond_8

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-virtual {v0, v5}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_7

    invoke-static {v0}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-static {v4}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v6

    invoke-virtual {v0, v6}, Lcom/tencent/mmkv/MMKV;->OooO0o0(Ljava/lang/String;)V

    goto :goto_7

    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_8
    :goto_7
    sget-object v0, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_a

    invoke-static {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v6

    if-eqz v6, :cond_a

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v6

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v7

    invoke-virtual {v7, v5}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    if-eqz v5, :cond_9

    invoke-static {v5}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v3

    invoke-static {v4}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Lcom/tencent/mmkv/MMKV;->OooO0O0(Ljava/lang/String;)I

    move-result v3

    const-string v4, "github.tornaco.android.thanos"

    invoke-static {v4, v3}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->newPkg(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v3

    invoke-virtual {v6, v3}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v3

    if-eqz v3, :cond_a

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getBackupAgent()Lgithub/tornaco/android/thanos/core/backup/BackupAgent;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/backup/BackupAgent;->restoreDefault()Z

    invoke-static {v2}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v3, Llyiahf/vczjk/bj8;

    const/4 v4, 0x0

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/bj8;-><init>(Llyiahf/vczjk/dj8;Llyiahf/vczjk/yo1;)V

    const/4 v5, 0x3

    invoke-static {v0, v4, v4, v3, v5}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    invoke-virtual {v2}, Llyiahf/vczjk/dj8;->OooO()V

    goto :goto_8

    :cond_9
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_a
    :goto_8
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
