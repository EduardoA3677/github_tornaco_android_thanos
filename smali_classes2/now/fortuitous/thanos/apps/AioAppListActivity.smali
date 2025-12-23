.class public final Lnow/fortuitous/thanos/apps/AioAppListActivity;
.super Lgithub/tornaco/android/thanos/module/compose/common/infra/BaseAppListFilterActivity;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0007\u0018\u00002\u00020\u0001:\u0001\u0004B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0005"
    }
    d2 = {
        "Lnow/fortuitous/thanos/apps/AioAppListActivity;",
        "Lgithub/tornaco/android/thanos/module/compose/common/infra/BaseAppListFilterActivity;",
        "<init>",
        "()V",
        "lyiahf/vczjk/rs",
        "app_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final synthetic OoooO:I


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/module/compose/common/infra/BaseAppListFilterActivity;-><init>()V

    return-void
.end method

.method public static final OooOooO(Lnow/fortuitous/thanos/apps/AioAppListActivity;Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/ze3;)Ljava/util/List;
    .locals 16

    invoke-virtual/range {p0 .. p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/hd;

    const/4 v0, 0x1

    move-object/from16 v2, p0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/hd;-><init>(Landroid/content/Context;I)V

    sget-object v0, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v0, Ljava/lang/Iterable;

    instance-of v2, v0, Ljava/util/Collection;

    if-eqz v2, :cond_0

    move-object v2, v0

    check-cast v2, Ljava/util/Collection;

    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_0

    goto :goto_2

    :cond_0
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :cond_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    :try_start_0
    new-instance v3, Ljava/io/File;

    invoke-virtual/range {p1 .. p1}, Landroid/content/Context;->getDataDir()Ljava/io/File;

    move-result-object v4

    invoke-static {v0}, Lutil/EncryptUtils;->decrypt(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {v3, v4, v0}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v3}, Ljava/io/File;->exists()Z

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

    move-result-object v3

    if-nez v3, :cond_2

    goto :goto_1

    :cond_2
    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    :goto_1
    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_1

    move-object/from16 v2, p1

    goto :goto_3

    :cond_3
    :goto_2
    const-string v0, "getDataDir(...)"

    move-object/from16 v2, p1

    invoke-static {v2, v0}, Llyiahf/vczjk/u81;->OooOo0o(Landroid/content/Context;Ljava/lang/String;)Z

    move-result v0

    if-eqz v0, :cond_4

    :goto_3
    const/4 v0, 0x1

    goto :goto_4

    :cond_4
    const/4 v0, 0x0

    :goto_4
    const-string v3, "Required value was null."

    const-string v4, "39M5DC32-B17D-4370-AB98-A9L809256685"

    if-eqz v0, :cond_6

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-virtual {v0, v4}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_5

    invoke-static {v0}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-static {v2}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v0, v5}, Lcom/tencent/mmkv/MMKV;->OooO0o0(Ljava/lang/String;)V

    goto :goto_5

    :cond_5
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_6
    :goto_5
    sget-object v0, Llyiahf/vczjk/on1;->OooO00o:Ljava/util/Set;

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_8

    invoke-static {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v5

    if-eqz v5, :cond_8

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v5

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v6

    invoke-virtual {v6, v4}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    if-eqz v4, :cond_7

    invoke-static {v4}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v3

    invoke-static {v2}, Llyiahf/vczjk/on1;->OooO0O0(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Lcom/tencent/mmkv/MMKV;->OooO0O0(Ljava/lang/String;)I

    move-result v2

    const-string v3, "github.tornaco.android.thanos"

    invoke-static {v3, v2}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->newPkg(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v2

    invoke-virtual {v5, v2}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v2

    if-eqz v2, :cond_8

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v2

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getAudioManager()Lgithub/tornaco/android/thanos/core/audio/AudioManager;

    move-result-object v3

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v4

    move-object/from16 v5, p2

    invoke-virtual {v4, v5}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getInstalledPkgsByPackageSetId(Ljava/lang/String;)Ljava/util/List;

    move-result-object v4

    const-string v5, "getInstalledPkgsByPackageSetId(...)"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4}, Llyiahf/vczjk/d21;->Ooooooo(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v4

    new-instance v5, Ljava/util/ArrayList;

    const/16 v6, 0xa

    invoke-static {v4, v6}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v6

    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :goto_6
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_9

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    move-object v8, v6

    check-cast v8, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-static {v8}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v6

    new-instance v7, Llyiahf/vczjk/xw;

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, v8}, Llyiahf/vczjk/hd;->OooO00o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Ljava/lang/String;

    move-result-object v9

    invoke-virtual {v2, v6}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isPackageRunning(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v10

    invoke-virtual {v2, v6}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isPackageIdle(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v11

    invoke-virtual {v3, v6}, Lgithub/tornaco/android/thanos/core/audio/AudioManager;->hasAudioFocus(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result v12

    invoke-static {v8}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->fromAppInfo(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v6

    const-string v13, "fromAppInfo(...)"

    invoke-static {v6, v13}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v13, p3

    invoke-interface {v13, v0, v6}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    move-object v14, v6

    check-cast v14, Ljava/lang/String;

    const/4 v13, 0x0

    const/16 v15, 0x11c

    invoke-direct/range {v7 .. v15}, Llyiahf/vczjk/xw;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;ZZZZLjava/lang/String;I)V

    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_8
    const/4 v5, 0x0

    :cond_9
    if-nez v5, :cond_a

    new-instance v6, Llyiahf/vczjk/xw;

    invoke-static {}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->dummy()Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v7

    const-string v0, "dummy(...)"

    invoke-static {v7, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v11, 0x0

    const/16 v14, 0x3fe

    const/4 v8, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    invoke-direct/range {v6 .. v14}, Llyiahf/vczjk/xw;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;ZZZZLjava/lang/String;I)V

    invoke-static {v6}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v5

    :cond_a
    new-instance v0, Llyiahf/vczjk/h93;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/h93;-><init>(I)V

    invoke-static {v5, v0}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method


# virtual methods
.method public final OooOoo(I)Llyiahf/vczjk/e60;
    .locals 23

    move-object/from16 v0, p0

    move/from16 v1, p1

    const/4 v2, 0x2

    const/4 v3, 0x0

    if-eq v1, v2, :cond_7

    const/4 v2, 0x3

    if-eq v1, v2, :cond_6

    const/4 v4, 0x4

    if-eq v1, v4, :cond_5

    const/4 v4, 0x5

    if-eq v1, v4, :cond_4

    const/4 v2, 0x6

    if-eq v1, v2, :cond_1

    const/16 v2, 0x10

    if-eq v1, v2, :cond_0

    packed-switch v1, :pswitch_data_0

    packed-switch v1, :pswitch_data_1

    packed-switch v1, :pswitch_data_2

    new-instance v2, Ljava/lang/IllegalStateException;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Unknown feature id: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v2, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v2

    :pswitch_0
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/b2;

    const/16 v4, 0xc

    invoke-direct {v2, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/w1;

    const/4 v5, 0x6

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/d3;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/d3;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/w1;

    const/4 v3, 0x7

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/b2;

    const/16 v1, 0xd

    invoke-direct {v8, v1}, Llyiahf/vczjk/b2;-><init>(I)V

    const/4 v9, 0x0

    const/16 v12, 0xb0

    const-string v5, "updateBlocker"

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_1
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0x1c

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/w1;

    const/4 v5, 0x4

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/z2;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/z2;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/w1;

    const/4 v3, 0x5

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/b2;

    const/16 v1, 0xf

    invoke-direct {v8, v1}, Llyiahf/vczjk/b2;-><init>(I)V

    const/4 v9, 0x0

    const/16 v12, 0xb0

    const-string v5, "shortcutCleaner"

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_2
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0xb

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/w1;

    const/4 v5, 0x0

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/k2;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/k2;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/w1;

    const/4 v3, 0x1

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/o0OOooO0;

    const/16 v1, 0xc

    invoke-direct {v8, v1}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    const/4 v9, 0x0

    const/16 v12, 0xb0

    const-string v5, "clearDataBlocker"

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_3
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/b2;

    const/4 v4, 0x4

    invoke-direct {v2, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/w1;

    const/4 v5, 0x2

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/c3;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/c3;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/w1;

    const/4 v3, 0x3

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/w1;-><init>(Lgithub/tornaco/android/thanos/core/pm/PackageManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/b2;

    const/4 v1, 0x5

    invoke-direct {v8, v1}, Llyiahf/vczjk/b2;-><init>(I)V

    const/4 v9, 0x0

    const/16 v12, 0xb0

    const-string v5, "uninstallBlocker"

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_4
    new-instance v5, Llyiahf/vczjk/e60;

    new-instance v7, Llyiahf/vczjk/fp;

    new-instance v1, Llyiahf/vczjk/b2;

    const/16 v2, 0xe

    invoke-direct {v1, v2}, Llyiahf/vczjk/b2;-><init>(I)V

    invoke-direct {v7, v1}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v8, Llyiahf/vczjk/du;

    new-instance v1, Llyiahf/vczjk/bu;

    new-instance v2, Llyiahf/vczjk/u1;

    const/4 v4, 0x7

    invoke-direct {v2, v0, v4}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v1, v2}, Llyiahf/vczjk/bu;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v2, Llyiahf/vczjk/g2;

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/g2;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;Llyiahf/vczjk/yo1;)V

    invoke-direct {v8, v1, v2}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v1, Llyiahf/vczjk/xu2;

    new-instance v2, Llyiahf/vczjk/b2;

    const/16 v3, 0x10

    invoke-direct {v2, v3}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v3, Llyiahf/vczjk/t1;

    const/16 v4, 0xa

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/t1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v1, v3, v2}, Llyiahf/vczjk/xu2;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V

    new-instance v2, Llyiahf/vczjk/xu2;

    new-instance v3, Llyiahf/vczjk/b2;

    const/16 v4, 0x11

    invoke-direct {v3, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/t1;

    const/16 v6, 0xb

    invoke-direct {v4, v0, v6}, Llyiahf/vczjk/t1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v2, v4, v3}, Llyiahf/vczjk/xu2;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V

    filled-new-array {v1, v2}, [Llyiahf/vczjk/xu2;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v10

    const/4 v11, 0x0

    const/16 v13, 0xe8

    const-string v6, "appsManagerRecentUsedConfig"

    const/4 v9, 0x0

    const/4 v12, 0x0

    invoke-direct/range {v5 .. v13}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    :goto_0
    move-object v4, v5

    goto/16 :goto_3

    :pswitch_5
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPrivacyManager()Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0x19

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x6

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;->isSensorOffEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/a2;

    const/4 v7, 0x0

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/a2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v11, Llyiahf/vczjk/ma0;

    new-instance v2, Llyiahf/vczjk/la0;

    new-instance v4, Llyiahf/vczjk/o0OOooO0;

    const/16 v5, 0x1b

    invoke-direct {v4, v5}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v5, Llyiahf/vczjk/w2;

    invoke-direct {v5, v1, v3}, Llyiahf/vczjk/w2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/la0;

    new-instance v5, Llyiahf/vczjk/o0OOooO0;

    const/16 v7, 0x1d

    invoke-direct {v5, v7}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v7, Llyiahf/vczjk/x2;

    invoke-direct {v7, v1, v3}, Llyiahf/vczjk/x2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v4, v5, v7}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    new-instance v5, Llyiahf/vczjk/la0;

    new-instance v7, Llyiahf/vczjk/b2;

    const/4 v8, 0x0

    invoke-direct {v7, v8}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v8, Llyiahf/vczjk/y2;

    invoke-direct {v8, v1, v3}, Llyiahf/vczjk/y2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v5, v7, v8}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    filled-new-array {v2, v4, v5}, [Llyiahf/vczjk/la0;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    invoke-direct {v11, v2}, Llyiahf/vczjk/ma0;-><init>(Ljava/util/List;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/au;

    new-instance v12, Llyiahf/vczjk/zt;

    new-instance v13, Llyiahf/vczjk/b2;

    const/4 v4, 0x1

    invoke-direct {v13, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    sget v14, Lgithub/tornaco/android/thanos/R$drawable;->module_ops_ic_checkbox_circle_fill_green:I

    sget-wide v18, Llyiahf/vczjk/n21;->OooOO0:J

    const-string v17, "0"

    move-wide/from16 v15, v18

    const/16 v19, 0x70

    const/16 v18, 0x0

    invoke-direct/range {v12 .. v19}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    new-instance v4, Llyiahf/vczjk/zt;

    new-instance v5, Llyiahf/vczjk/b2;

    const/4 v8, 0x2

    invoke-direct {v5, v8}, Llyiahf/vczjk/b2;-><init>(I)V

    sget v17, Lgithub/tornaco/android/thanos/R$drawable;->module_ops_ic_checkbox_circle_fill_grey:I

    const-string v20, "1"

    const/16 v22, 0x70

    const/16 v21, 0x0

    move-wide/from16 v18, v15

    move-object v15, v4

    move-object/from16 v16, v5

    invoke-direct/range {v15 .. v22}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    move-wide/from16 v15, v18

    new-instance v5, Llyiahf/vczjk/zt;

    new-instance v8, Llyiahf/vczjk/b2;

    const/4 v9, 0x3

    invoke-direct {v8, v9}, Llyiahf/vczjk/b2;-><init>(I)V

    sget v17, Lgithub/tornaco/android/thanos/R$drawable;->module_ops_ic_forbid_2_fill_red:I

    const-string v20, "2"

    const/16 v22, 0x70

    const/16 v21, 0x0

    move-wide/from16 v18, v15

    move-object v15, v5

    move-object/from16 v16, v8

    invoke-direct/range {v15 .. v22}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    filled-new-array {v12, v4, v15}, [Llyiahf/vczjk/zt;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/c2;

    const/4 v8, 0x0

    invoke-direct {v5, v1, v8}, Llyiahf/vczjk/c2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;I)V

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/au;-><init>(Ljava/util/List;Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/v2;

    invoke-direct {v4, v0, v1, v3}, Llyiahf/vczjk/v2;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/o0OOooO0;

    const/16 v1, 0x1a

    invoke-direct {v8, v1}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    const-string v5, "sensorOff"

    const/16 v12, 0x90

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_6
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/b2;

    const/16 v5, 0x12

    invoke-direct {v2, v5}, Llyiahf/vczjk/b2;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v5, Llyiahf/vczjk/s1;

    const/16 v8, 0xa

    invoke-direct {v5, v1, v8}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v2, v5}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v5, Llyiahf/vczjk/t2;

    invoke-direct {v5, v1, v3}, Llyiahf/vczjk/t2;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v5}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/s1;

    const/16 v3, 0xb

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    const/4 v9, 0x0

    const/16 v12, 0xb8

    const-string v5, "resident"

    const/4 v8, 0x0

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_7
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0xe

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/u1;

    const/4 v5, 0x3

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x4

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->isLaunchOtherAppBlockerEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/o000OO;

    const/4 v7, 0x4

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v11, Llyiahf/vczjk/ma0;

    new-instance v2, Llyiahf/vczjk/la0;

    new-instance v4, Llyiahf/vczjk/o0OOooO0;

    const/16 v5, 0x10

    invoke-direct {v4, v5}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v5, Llyiahf/vczjk/q2;

    invoke-direct {v5, v1, v3}, Llyiahf/vczjk/q2;-><init>(Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;Llyiahf/vczjk/yo1;)V

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/la0;

    new-instance v5, Llyiahf/vczjk/o0OOooO0;

    const/16 v7, 0x11

    invoke-direct {v5, v7}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v7, Llyiahf/vczjk/r2;

    invoke-direct {v7, v1, v3}, Llyiahf/vczjk/r2;-><init>(Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;Llyiahf/vczjk/yo1;)V

    invoke-direct {v4, v5, v7}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    new-instance v5, Llyiahf/vczjk/la0;

    new-instance v7, Llyiahf/vczjk/o0OOooO0;

    const/16 v8, 0x12

    invoke-direct {v7, v8}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v8, Llyiahf/vczjk/o2;

    invoke-direct {v8, v1, v3}, Llyiahf/vczjk/o2;-><init>(Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;Llyiahf/vczjk/yo1;)V

    invoke-direct {v5, v7, v8}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    filled-new-array {v2, v4, v5}, [Llyiahf/vczjk/la0;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    invoke-direct {v11, v2}, Llyiahf/vczjk/ma0;-><init>(Ljava/util/List;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/au;

    new-instance v12, Llyiahf/vczjk/zt;

    new-instance v13, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0x13

    invoke-direct {v13, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    sget v14, Lgithub/tornaco/android/thanos/R$drawable;->module_ops_ic_checkbox_circle_fill_green:I

    sget-wide v18, Llyiahf/vczjk/n21;->OooOO0:J

    const-string v17, "0"

    move-wide/from16 v15, v18

    const/16 v19, 0x70

    const/16 v18, 0x0

    invoke-direct/range {v12 .. v19}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    move-wide/from16 v18, v15

    new-instance v15, Llyiahf/vczjk/zt;

    new-instance v4, Llyiahf/vczjk/o0OOooO0;

    const/16 v5, 0x14

    invoke-direct {v4, v5}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    sget v17, Lgithub/tornaco/android/thanos/R$drawable;->module_ops_ic_remix_question_fill_amber:I

    const-string v20, "1"

    const/16 v22, 0x70

    const/16 v21, 0x0

    move-object/from16 v16, v4

    invoke-direct/range {v15 .. v22}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    move-object v4, v15

    new-instance v15, Llyiahf/vczjk/zt;

    new-instance v5, Llyiahf/vczjk/o0OOooO0;

    const/16 v8, 0x15

    invoke-direct {v5, v8}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    sget v17, Lgithub/tornaco/android/thanos/R$drawable;->module_ops_ic_forbid_2_fill_red:I

    const-string v20, "-1"

    const/16 v22, 0x70

    const/16 v21, 0x0

    move-object/from16 v16, v5

    invoke-direct/range {v15 .. v22}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    move-object v5, v15

    new-instance v15, Llyiahf/vczjk/zt;

    new-instance v8, Llyiahf/vczjk/o0OOooO0;

    const/16 v9, 0xf

    invoke-direct {v8, v9}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    sget v17, Lgithub/tornaco/android/thanos/R$drawable;->module_ops_ic_checkbox_circle_fill_light_green:I

    sget v9, Lgithub/tornaco/android/thanos/res/R$string;->nav_title_settings:I

    invoke-virtual {v0, v9}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v9

    const-string v13, "getString(...)"

    invoke-static {v9, v13}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v13, Llyiahf/vczjk/u1;

    const/4 v14, 0x2

    invoke-direct {v13, v0, v14}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    new-instance v14, Llyiahf/vczjk/xn6;

    invoke-direct {v14, v9, v13}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    const-string v20, "2"

    const/16 v22, 0x30

    move-object/from16 v16, v8

    move-object/from16 v21, v14

    invoke-direct/range {v15 .. v22}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    filled-new-array {v12, v4, v5, v15}, [Llyiahf/vczjk/zt;

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/x1;

    const/4 v8, 0x0

    invoke-direct {v5, v1, v8}, Llyiahf/vczjk/x1;-><init>(Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;I)V

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/au;-><init>(Ljava/util/List;Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/p2;

    invoke-direct {v4, v0, v1, v3}, Llyiahf/vczjk/p2;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v4, Llyiahf/vczjk/e60;

    const/4 v8, 0x0

    const/16 v12, 0x98

    const-string v5, "launchOther"

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_8
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getNotificationManager()Lgithub/tornaco/android/thanos/core/n/NotificationManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/4 v4, 0x6

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x2

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/n/NotificationManager;->isScreenOnNotificationEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/o000OO;

    const/4 v7, 0x3

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/y1;

    const/4 v5, 0x0

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/y1;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/u2;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/u2;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/y1;

    const/4 v3, 0x1

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/y1;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    const/4 v8, 0x0

    const/16 v12, 0x98

    const-string v5, "screenOnNoti"

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_9
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getAppOpsManager()Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;

    move-result-object v1

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v5, 0x16

    invoke-direct {v2, v5}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v5, Llyiahf/vczjk/z1;

    const/4 v8, 0x0

    invoke-direct {v5, v1, v8}, Llyiahf/vczjk/z1;-><init>(Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;I)V

    invoke-direct {v2, v5}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v5, Llyiahf/vczjk/s2;

    invoke-direct {v5, v1, v3}, Llyiahf/vczjk/s2;-><init>(Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v5}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/z1;

    const/4 v3, 0x1

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/z1;-><init>(Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    const/4 v9, 0x0

    const/16 v12, 0xb8

    const-string v5, "opRemind"

    const/4 v8, 0x0

    const/4 v10, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :pswitch_a
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0xd

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/u1;

    const/4 v5, 0x1

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x3

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isRecentTaskBlurEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/r1;

    const/4 v7, 0x3

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/r1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/s1;

    const/4 v5, 0x6

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/b3;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/b3;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/s1;

    const/4 v3, 0x7

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    const/4 v8, 0x0

    const/16 v12, 0x98

    const-string v5, "appLock"

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :cond_0
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/b2;

    const/16 v4, 0x13

    invoke-direct {v2, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/u1;

    const/16 v5, 0x8

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/16 v4, 0x8

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isSmartStandByEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/r1;

    const/4 v7, 0x0

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/r1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/s1;

    const/4 v5, 0x0

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/a3;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/a3;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/s1;

    const/4 v3, 0x1

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/o0OOooO0;

    const/4 v1, 0x7

    invoke-direct {v8, v1}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    const-string v5, "smartStandby"

    const/16 v12, 0x90

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :cond_1
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPrivacyManager()Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/b2;

    const/4 v4, 0x6

    invoke-direct {v2, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/u1;

    const/4 v5, 0x5

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x7

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;->isPrivacyEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/a2;

    const/4 v7, 0x1

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/a2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;->getAllFieldsProfiles()Ljava/util/List;

    move-result-object v2

    const-string v4, "getAllFieldsProfiles(...)"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v5, Ljava/util/ArrayList;

    const/16 v7, 0xa

    invoke-static {v2, v7}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v8

    invoke-direct {v5, v8}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_2

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    new-instance v9, Llyiahf/vczjk/la0;

    new-instance v11, Llyiahf/vczjk/d2;

    const/4 v12, 0x0

    invoke-direct {v11, v8, v12}, Llyiahf/vczjk/d2;-><init>(Lgithub/tornaco/android/thanos/core/secure/field/Fields;I)V

    new-instance v12, Llyiahf/vczjk/m2;

    invoke-direct {v12, v1, v8, v3}, Llyiahf/vczjk/m2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Lgithub/tornaco/android/thanos/core/secure/field/Fields;Llyiahf/vczjk/yo1;)V

    invoke-direct {v9, v11, v12}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    invoke-virtual {v5, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_2
    new-instance v2, Llyiahf/vczjk/la0;

    new-instance v8, Llyiahf/vczjk/b2;

    const/4 v9, 0x7

    invoke-direct {v8, v9}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v9, Llyiahf/vczjk/n2;

    invoke-direct {v9, v1, v3}, Llyiahf/vczjk/n2;-><init>(Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v2, v8, v9}, Llyiahf/vczjk/la0;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;)V

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    invoke-static {v2, v5}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v2

    new-instance v11, Llyiahf/vczjk/ma0;

    invoke-direct {v11, v2}, Llyiahf/vczjk/ma0;-><init>(Ljava/util/List;)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;->getAllFieldsProfiles()Ljava/util/List;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v4, Ljava/util/ArrayList;

    invoke-static {v2, v7}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v5

    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v2

    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_3

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Lgithub/tornaco/android/thanos/core/secure/field/Fields;

    new-instance v12, Llyiahf/vczjk/zt;

    new-instance v13, Llyiahf/vczjk/d2;

    const/4 v7, 0x1

    invoke-direct {v13, v5, v7}, Llyiahf/vczjk/d2;-><init>(Lgithub/tornaco/android/thanos/core/secure/field/Fields;I)V

    sget v14, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_file_list_2_line:I

    sget-wide v15, Llyiahf/vczjk/n21;->OooOO0:J

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/secure/field/Fields;->getId()Ljava/lang/String;

    move-result-object v5

    const-string v7, "getId(...)"

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    const/16 v18, 0x0

    const/16 v19, 0x70

    move-object/from16 v17, v5

    invoke-direct/range {v12 .. v19}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    invoke-virtual {v4, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_2

    :cond_3
    new-instance v13, Llyiahf/vczjk/zt;

    new-instance v14, Llyiahf/vczjk/b2;

    const/16 v2, 0x8

    invoke-direct {v14, v2}, Llyiahf/vczjk/b2;-><init>(I)V

    sget v15, Lgithub/tornaco/android/thanos/icon/remix/R$drawable;->ic_remix_file_list_2_line:I

    sget-wide v16, Llyiahf/vczjk/n21;->OooOO0:J

    const-string v18, ""

    const/16 v20, 0x50

    const/16 v19, 0x0

    invoke-direct/range {v13 .. v20}, Llyiahf/vczjk/zt;-><init>(Llyiahf/vczjk/oe3;IJLjava/lang/String;Llyiahf/vczjk/xn6;I)V

    invoke-static {v13}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v2

    invoke-static {v2, v4}, Llyiahf/vczjk/d21;->o00000O0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object v2

    new-instance v4, Llyiahf/vczjk/e2;

    const/4 v5, 0x0

    invoke-direct {v4, v5, v1, v0}, Llyiahf/vczjk/e2;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance v5, Llyiahf/vczjk/au;

    invoke-direct {v5, v2, v4}, Llyiahf/vczjk/au;-><init>(Ljava/util/List;Llyiahf/vczjk/ze3;)V

    new-instance v2, Llyiahf/vczjk/l2;

    invoke-direct {v2, v0, v1, v3}, Llyiahf/vczjk/l2;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;Lgithub/tornaco/android/thanos/core/secure/PrivacyManager;Llyiahf/vczjk/yo1;)V

    new-instance v7, Llyiahf/vczjk/du;

    invoke-direct {v7, v5, v2}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/b2;

    const/16 v1, 0x9

    invoke-direct {v8, v1}, Llyiahf/vczjk/b2;-><init>(I)V

    const-string v5, "dataCheat"

    const/16 v12, 0x90

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :cond_4
    new-instance v5, Llyiahf/vczjk/e60;

    new-instance v7, Llyiahf/vczjk/fp;

    new-instance v1, Llyiahf/vczjk/b2;

    const/16 v4, 0xa

    invoke-direct {v1, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    invoke-direct {v7, v1}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v8, Llyiahf/vczjk/du;

    new-instance v1, Llyiahf/vczjk/bu;

    new-instance v4, Llyiahf/vczjk/u1;

    const/4 v6, 0x6

    invoke-direct {v4, v0, v6}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v1, v4}, Llyiahf/vczjk/bu;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v4, Llyiahf/vczjk/f2;

    invoke-direct {v4, v2, v3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-direct {v8, v1, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v1, Llyiahf/vczjk/xu2;

    new-instance v2, Llyiahf/vczjk/b2;

    const/16 v3, 0xb

    invoke-direct {v2, v3}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v3, Llyiahf/vczjk/t1;

    const/16 v4, 0x9

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/t1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v1, v3, v2}, Llyiahf/vczjk/xu2;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v10

    const/4 v11, 0x0

    const/16 v13, 0xe8

    const-string v6, "AppsManageActivity2"

    const/4 v9, 0x0

    const/4 v12, 0x0

    invoke-direct/range {v5 .. v13}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_0

    :cond_5
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0x9

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    invoke-direct {v6, v2}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x1

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isCleanUpOnTaskRemovalEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/r1;

    const/4 v7, 0x2

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/r1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/s1;

    const/4 v5, 0x4

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/j2;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/j2;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/s1;

    const/4 v3, 0x5

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/o0OOooO0;

    const/16 v1, 0xa

    invoke-direct {v8, v1}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    const-string v5, "cleanTask"

    const/16 v12, 0x90

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto/16 :goto_3

    :cond_6
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/o0OOooO0;

    const/16 v4, 0x17

    invoke-direct {v2, v4}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/u1;

    const/4 v5, 0x4

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x5

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isBgRestrictEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/r1;

    const/4 v7, 0x4

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/r1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/s1;

    const/16 v5, 0x8

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/h2;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/h2;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/s1;

    const/16 v3, 0x9

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/o0OOooO0;

    const/16 v1, 0x18

    invoke-direct {v8, v1}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    const-string v5, "bgRestrict"

    const/16 v12, 0x90

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    goto :goto_3

    :cond_7
    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v1

    new-instance v6, Llyiahf/vczjk/fp;

    new-instance v2, Llyiahf/vczjk/b2;

    const/16 v4, 0x14

    invoke-direct {v2, v4}, Llyiahf/vczjk/b2;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/u1;

    const/4 v5, 0x0

    invoke-direct {v4, v0, v5}, Llyiahf/vczjk/u1;-><init>(Lnow/fortuitous/thanos/apps/AioAppListActivity;I)V

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/fp;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    new-instance v10, Llyiahf/vczjk/lc9;

    new-instance v2, Llyiahf/vczjk/v1;

    const/4 v4, 0x0

    invoke-direct {v2, v4}, Llyiahf/vczjk/v1;-><init>(I)V

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isStartBlockEnabled()Z

    move-result v4

    new-instance v5, Llyiahf/vczjk/r1;

    const/4 v7, 0x1

    invoke-direct {v5, v1, v7}, Llyiahf/vczjk/r1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v10, v2, v4, v5}, Llyiahf/vczjk/lc9;-><init>(Llyiahf/vczjk/ze3;ZLlyiahf/vczjk/oe3;)V

    new-instance v7, Llyiahf/vczjk/du;

    new-instance v2, Llyiahf/vczjk/yt;

    new-instance v4, Llyiahf/vczjk/s1;

    const/4 v5, 0x2

    invoke-direct {v4, v1, v5}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-direct {v2, v4}, Llyiahf/vczjk/yt;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v4, Llyiahf/vczjk/i2;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/i2;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;Llyiahf/vczjk/yo1;)V

    invoke-direct {v7, v2, v4}, Llyiahf/vczjk/du;-><init>(Llyiahf/vczjk/cu;Llyiahf/vczjk/bf3;)V

    new-instance v2, Llyiahf/vczjk/s1;

    const/4 v3, 0x3

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/s1;-><init>(Lgithub/tornaco/android/thanos/core/app/ActivityManager;I)V

    invoke-static {v2}, Llyiahf/vczjk/ng0;->OooOOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/ma0;

    move-result-object v11

    new-instance v4, Llyiahf/vczjk/e60;

    new-instance v8, Llyiahf/vczjk/o0OOooO0;

    const/16 v1, 0x8

    invoke-direct {v8, v1}, Llyiahf/vczjk/o0OOooO0;-><init>(I)V

    const-string v5, "bgStart"

    const/16 v12, 0x90

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v12}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;I)V

    :goto_3
    sget-object v13, Llyiahf/vczjk/b91;->OooO00o:Llyiahf/vczjk/a91;

    const-string v1, "featureId"

    iget-object v6, v4, Llyiahf/vczjk/e60;->OooO00o:Ljava/lang/String;

    invoke-static {v6, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "appBarConfig"

    iget-object v7, v4, Llyiahf/vczjk/e60;->OooO0O0:Llyiahf/vczjk/fp;

    invoke-static {v7, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "appItemConfig"

    iget-object v8, v4, Llyiahf/vczjk/e60;->OooO0OO:Llyiahf/vczjk/du;

    invoke-static {v8, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "featureDescription"

    iget-object v9, v4, Llyiahf/vczjk/e60;->OooO0Oo:Llyiahf/vczjk/oe3;

    invoke-static {v9, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "fabs"

    iget-object v10, v4, Llyiahf/vczjk/e60;->OooO0o0:Ljava/util/List;

    invoke-static {v10, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v5, Llyiahf/vczjk/e60;

    iget-object v11, v4, Llyiahf/vczjk/e60;->OooO0o:Llyiahf/vczjk/lc9;

    iget-object v12, v4, Llyiahf/vczjk/e60;->OooO0oO:Llyiahf/vczjk/ma0;

    invoke-direct/range {v5 .. v13}, Llyiahf/vczjk/e60;-><init>(Ljava/lang/String;Llyiahf/vczjk/fp;Llyiahf/vczjk/du;Llyiahf/vczjk/oe3;Ljava/util/List;Llyiahf/vczjk/lc9;Llyiahf/vczjk/ma0;Llyiahf/vczjk/ze3;)V

    return-object v5

    :pswitch_data_0
    .packed-switch 0xa
        :pswitch_a
        :pswitch_9
        :pswitch_8
    .end packed-switch

    :pswitch_data_1
    .packed-switch 0x19
        :pswitch_7
        :pswitch_6
        :pswitch_5
    .end packed-switch

    :pswitch_data_2
    .packed-switch 0x1f
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
