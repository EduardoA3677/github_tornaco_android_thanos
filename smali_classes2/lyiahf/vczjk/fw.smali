.class public final Llyiahf/vczjk/fw;
.super Llyiahf/vczjk/aq9;
.source "SourceFile"

# interfaces
.implements Lgithub/tornaco/android/thanos/core/secure/ops/IAppOpsService;


# instance fields
.field public final OooOO0:Z

.field public OooOO0O:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

.field public OooOO0o:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

.field public OooOOO:Z

.field public OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

.field public OooOOOO:Z

.field public OooOOOo:Llyiahf/vczjk/rc6;

.field public OooOOo:Z

.field public final OooOOo0:Ljava/util/HashSet;

.field public final OooOOoo:Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fo9;)V
    .locals 1

    const-string v0, "s"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1}, Llyiahf/vczjk/aq9;-><init>(Llyiahf/vczjk/fo9;)V

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/OsUtils;->isQOrAbove()Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/fw;->OooOO0:Z

    new-instance p1, Ljava/util/HashSet;

    invoke-direct {p1}, Ljava/util/HashSet;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fw;->OooOOo0:Ljava/util/HashSet;

    new-instance p1, Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;

    invoke-direct {p1, p0}, Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;-><init>(Llyiahf/vczjk/fw;)V

    iput-object p1, p0, Llyiahf/vczjk/fw;->OooOOoo:Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;

    return-void
.end method


# virtual methods
.method public final OooOO0o(Landroid/content/Context;)V
    .locals 5

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-super {p0, p1}, Llyiahf/vczjk/td9;->OooOO0o(Landroid/content/Context;)V

    invoke-static {}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->get()Lgithub/tornaco/android/thanos/core/persist/RepoFactory;

    move-result-object v0

    new-instance v1, Ljava/io/File;

    const/4 v2, 0x0

    invoke-static {v2}, Llyiahf/vczjk/rd3;->OooO(I)Ljava/io/File;

    move-result-object v3

    const-string v4, "reminding_ops.xml"

    invoke-direct {v1, v3, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->getOrCreateStringSetRepo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fw;->OooOO0O:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    invoke-static {}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->get()Lgithub/tornaco/android/thanos/core/persist/RepoFactory;

    move-result-object v0

    new-instance v1, Ljava/io/File;

    invoke-static {v2}, Llyiahf/vczjk/rd3;->OooO(I)Ljava/io/File;

    move-result-object v3

    const-string v4, "op_reminding_pkgs.xml"

    invoke-direct {v1, v3, v4}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->getOrCreateStringSetRepo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fw;->OooOO0o:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    invoke-static {}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->get()Lgithub/tornaco/android/thanos/core/persist/RepoFactory;

    move-result-object v0

    new-instance v1, Ljava/io/File;

    invoke-static {v2}, Llyiahf/vczjk/rd3;->OooO(I)Ljava/io/File;

    move-result-object v2

    const-string v3, "op_settings.xml"

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-virtual {v1}, Ljava/io/File;->getPath()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/persist/RepoFactory;->getOrCreateStringMapRepo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    new-instance v0, Llyiahf/vczjk/rc6;

    iget-object v1, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/rc6;-><init>(Landroid/content/Context;Llyiahf/vczjk/fo9;)V

    iput-object v0, p0, Llyiahf/vczjk/fw;->OooOOOo:Llyiahf/vczjk/rc6;

    return-void
.end method

.method public final OooOOOo()V
    .locals 17

    move-object/from16 v0, p0

    invoke-super {v0}, Llyiahf/vczjk/td9;->OooOOOo()V

    new-instance v1, Lgithub/tornaco/android/thanos/core/app/AppResources;

    iget-object v2, v0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    const-string v3, "github.tornaco.android.thanos"

    invoke-direct {v1, v2, v3}, Lgithub/tornaco/android/thanos/core/app/AppResources;-><init>(Landroid/content/Context;Ljava/lang/String;)V

    const-string v2, "op_remind_whitelist"

    invoke-virtual {v1, v2}, Lgithub/tornaco/android/thanos/core/app/AppResources;->getStringArray(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v1

    const-string v2, "getStringArray(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v2, v0, Llyiahf/vczjk/fw;->OooOOo0:Ljava/util/HashSet;

    invoke-static {v2, v1}, Llyiahf/vczjk/j21;->OoooOoo(Ljava/util/Collection;[Ljava/lang/Object;)V

    const/4 v1, 0x0

    new-array v3, v1, [Ljava/lang/String;

    invoke-virtual {v2, v3}, Ljava/util/HashSet;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v2

    invoke-static {v2}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    const-string v3, "toString(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0}, Llyiahf/vczjk/fw;->OooOo0()V

    iget-object v2, v0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v3, v2, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v4, Llyiahf/vczjk/wg8;->o0OoOo0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    iget-object v6, v3, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v6, v5, v4}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v4

    if-eqz v4, :cond_0

    const-string v1, "AppOpsService Already migrated to S."

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    goto/16 :goto_2

    :cond_0
    const-string v4, "AppOpsService Start migrate"

    invoke-static {v4}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    const/4 v4, 0x1

    iput-boolean v4, v0, Llyiahf/vczjk/fw;->OooOOOO:Z

    iget-object v5, v0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    const-string v7, "opSettingsRepo"

    if-eqz v5, :cond_8

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->keySet()Ljava/util/Set;

    move-result-object v5

    const-string v8, "<get-keys>(...)"

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v5, Ljava/lang/Iterable;

    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :goto_0
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v8

    if-eqz v8, :cond_6

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/lang/String;

    invoke-static {v8}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const-string v9, "-"

    invoke-static {v8, v9, v8}, Llyiahf/vczjk/z69;->Ooooooo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v10

    invoke-static {v10}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v10

    invoke-static {v8, v9, v8}, Llyiahf/vczjk/z69;->o00O0O(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    const/16 v12, 0x63

    if-gt v12, v10, :cond_5

    const/16 v12, 0x68

    if-ge v10, v12, :cond_5

    const v12, 0xf4240

    add-int/2addr v12, v10

    iget-object v13, v0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v13, :cond_4

    invoke-virtual {v13, v8}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Ljava/lang/String;

    if-eqz v13, :cond_1

    invoke-static {v13}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v13

    goto :goto_1

    :cond_1
    move v13, v1

    :goto_1
    const-string v14, "AppOpsService Will migrate opSettingsRepo code for pkg "

    const-string v15, " "

    invoke-static {v14, v11, v15, v8, v15}, Llyiahf/vczjk/q99;->OooO0oo(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v14

    const-string v15, " -> "

    const/16 v16, 0x0

    const-string v6, ", mode: "

    invoke-static {v14, v10, v15, v12, v6}, Llyiahf/vczjk/ii5;->OooOo00(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    invoke-virtual {v14, v13}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v14}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-static {v6}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    iget-object v6, v0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v6, :cond_3

    new-instance v10, Ljava/lang/StringBuilder;

    invoke-direct {v10}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v10, v11}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v9}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v12}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v9

    invoke-static {v13}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object v10

    invoke-interface {v6, v9, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v6, v0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v6, :cond_2

    const-string v9, "0"

    invoke-interface {v6, v8, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_2
    invoke-static {v7}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v16

    :cond_3
    invoke-static {v7}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v16

    :cond_4
    const/16 v16, 0x0

    invoke-static {v7}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v16

    :cond_5
    const/16 v16, 0x0

    goto/16 :goto_0

    :cond_6
    iput-boolean v1, v0, Llyiahf/vczjk/fw;->OooOOOO:Z

    sget-object v1, Llyiahf/vczjk/wg8;->o0OoOo0:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, v1, v4}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    const-string v1, "AppOpsService Finish migrate"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    :goto_2
    new-instance v1, Llyiahf/vczjk/ew;

    invoke-direct {v1, v0}, Llyiahf/vczjk/ew;-><init>(Llyiahf/vczjk/fw;)V

    iget-object v2, v2, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/o27;->registerSettingsChangeListener(Lgithub/tornaco/android/thanos/core/pref/IPrefChangeListener;)Z

    invoke-virtual {v0}, Llyiahf/vczjk/fw;->OooOo0O()V

    iget-boolean v1, v0, Llyiahf/vczjk/fw;->OooOO0:Z

    if-eqz v1, :cond_7

    const-string v1, "installAppOpsActiveWatcher"

    invoke-static {v1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/oO0O00o0;

    const/16 v2, 0xd

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    :cond_7
    return-void

    :cond_8
    const/16 v16, 0x0

    invoke-static {v7}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v16
.end method

.method public final OooOo0()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OoooooO:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v3, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v3, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v1

    iput-boolean v1, p0, Llyiahf/vczjk/fw;->OooOOO:Z

    sget-object v1, Llyiahf/vczjk/wg8;->Ooooooo:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getDefaultValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    iget-object v0, v0, Llyiahf/vczjk/o27;->OooOO0:Llyiahf/vczjk/mi;

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/mi;->OooOO0(Ljava/lang/String;Z)Z

    move-result v0

    iput-boolean v0, p0, Llyiahf/vczjk/fw;->OooOOo:Z

    return-void
.end method

.method public final OooOo0O()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/fw;->OooOOoo:Lnow/fortuitous/secure/ops/AppOpsService$monitor$1;

    iget-object v1, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    sget-object v2, Landroid/os/UserHandle;->CURRENT:Landroid/os/UserHandle;

    invoke-static {}, Llyiahf/vczjk/w40;->OooO00o()Llyiahf/vczjk/nq2;

    move-result-object v3

    iget-object v4, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v4, v4, Llyiahf/vczjk/fo9;->OooOO0O:Llyiahf/vczjk/uv6;

    invoke-virtual {v0, v1, v2, v3, v4}, Lnow/fortuitous/pm/PackageMonitor;->OooO0o0(Landroid/content/Context;Landroid/os/UserHandle;Llyiahf/vczjk/nq2;Llyiahf/vczjk/uv6;)V

    return-void
.end method

.method public final asBinder()Landroid/os/IBinder;
    .locals 1

    invoke-static {}, Lgithub/tornaco/android/thanos/core/util/Noop;->notSupported()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/os/IBinder;

    return-object v0
.end method

.method public final checkOperation(IILjava/lang/String;)I
    .locals 2

    const-string v0, "packageName"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p3}, Lgithub/tornaco/android/thanos/core/util/PkgUtils;->isAndroid(Ljava/lang/String;)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/td9;->OooO0o0:Z

    if-nez v0, :cond_1

    :goto_0
    return v1

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/fw;->OooOOOO:Z

    if-eqz v0, :cond_2

    const-string p1, "checkOperation MODE_ALLOWED when isMigrating"

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Ooooo0o(Ljava/lang/String;)V

    return v1

    :cond_2
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/fw;->checkOperationNonCheck(IILjava/lang/String;)I

    move-result v0

    const/4 v1, 0x4

    if-ne v0, v1, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOo0:Lnow/fortuitous/app/OooO00o;

    invoke-virtual {v0}, Lnow/fortuitous/app/OooO00o;->getCurrentFrontApp()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, p3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    xor-int/lit8 v0, v0, 0x1

    :cond_3
    if-nez v0, :cond_4

    const/4 v1, 0x0

    invoke-virtual {p0, v1, p1, p2, p3}, Llyiahf/vczjk/fw;->onStartOp(Landroid/os/IBinder;IILjava/lang/String;)V

    :cond_4
    return v0
.end method

.method public final checkOperationNonCheck(IILjava/lang/String;)I
    .locals 2

    const-string p2, "packageName"

    invoke-static {p3, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p2, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->MERGED_LOCATION_OPS:[I

    const-string v0, "MERGED_LOCATION_OPS"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2, p1}, Llyiahf/vczjk/sy;->OoooooO([II)Z

    move-result p2

    if-eqz p2, :cond_0

    const p1, 0xf42a7

    :cond_0
    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->isControllableOp(I)Z

    move-result p2

    const/4 v0, 0x0

    if-nez p2, :cond_1

    return v0

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz p2, :cond_3

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p3, "-"

    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    if-eqz p1, :cond_2

    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    move-result v0

    :cond_2
    return v0

    :cond_3
    const-string p1, "opSettingsRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final clearSettingsReadRecords()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/sh8;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    return-void
.end method

.method public final clearSettingsWriteRecords()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/sh8;->OooO0O0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    return-void
.end method

.method public final dump(Lgithub/tornaco/android/thanos/core/IPrinter;)V
    .locals 5

    const-string v0, "p"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "===== AppOps dump start ====="

    invoke-interface {p1, v0}, Lgithub/tornaco/android/thanos/core/IPrinter;->println(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/td9;->OooO0o:Landroid/content/Context;

    new-instance v1, Ljava/io/File;

    const/4 v2, 0x0

    invoke-static {v2}, Llyiahf/vczjk/rd3;->OooOO0o(I)Ljava/io/File;

    move-result-object v2

    const-string v3, "db"

    invoke-direct {v1, v2, v3}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    invoke-static {v0, v1}, Lgithub/tornaco/android/thanos/db/ops/OpsDb;->getInstance(Landroid/content/Context;Ljava/io/File;)Lgithub/tornaco/android/thanos/db/ops/OpsDb;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/db/ops/OpsDb;->opsDao()Lgithub/tornaco/android/thanos/db/ops/OpsDao;

    move-result-object v0

    invoke-interface {v0}, Lgithub/tornaco/android/thanos/db/ops/OpsDao;->loadAll()Ljava/util/List;

    move-result-object v0

    const-string v1, "loadAll(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/db/ops/OpRecord;

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "OpRecord: "

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-interface {p1, v2}, Lgithub/tornaco/android/thanos/core/IPrinter;->println(Ljava/lang/String;)V

    goto :goto_0

    :cond_0
    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Total "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v0, " entries"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Lgithub/tornaco/android/thanos/core/IPrinter;->println(Ljava/lang/String;)V

    const-string v0, "===== AppOps dump end ====="

    invoke-interface {p1, v0}, Lgithub/tornaco/android/thanos/core/IPrinter;->println(Ljava/lang/String;)V

    return-void
.end method

.method public final getSettingsReadRecords(Ljava/lang/String;)Ljava/util/List;
    .locals 5

    sget-object v0, Llyiahf/vczjk/sh8;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lgithub/tornaco/android/thanos/core/secure/ops/SettingsAccessRecord;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v4

    if-nez v4, :cond_1

    goto :goto_1

    :cond_1
    iget-object v3, v3, Lgithub/tornaco/android/thanos/core/secure/ops/SettingsAccessRecord;->callerPackageName:Ljava/lang/String;

    invoke-static {v3, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    :cond_2
    :goto_1
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0x12

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    invoke-static {v1, p1}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getSettingsWriteRecords(Ljava/lang/String;)Ljava/util/List;
    .locals 5

    sget-object v0, Llyiahf/vczjk/sh8;->OooO0O0:Ljava/util/ArrayList;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o000OO(Ljava/lang/Iterable;)Ljava/util/List;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    move-object v3, v2

    check-cast v3, Lgithub/tornaco/android/thanos/core/secure/ops/SettingsAccessRecord;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Ljava/lang/String;->length()I

    move-result v4

    if-nez v4, :cond_1

    goto :goto_1

    :cond_1
    iget-object v3, v3, Lgithub/tornaco/android/thanos/core/secure/ops/SettingsAccessRecord;->callerPackageName:Ljava/lang/String;

    invoke-static {v3, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    :cond_2
    :goto_1
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    new-instance p1, Llyiahf/vczjk/h93;

    const/16 v0, 0x13

    invoke-direct {p1, v0}, Llyiahf/vczjk/h93;-><init>(I)V

    invoke-static {v1, p1}, Llyiahf/vczjk/d21;->o0000O00(Ljava/lang/Iterable;Ljava/util/Comparator;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final isOpRemindEnabled(I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fw;->OooOO0O:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-eqz v0, :cond_0

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->has(Ljava/lang/String;)Z

    move-result p1

    return p1

    :cond_0
    const-string p1, "opRemindOpRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final isOpsEnabled()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/fw;->OooOOO:Z

    return v0
.end method

.method public final isPkgOpRemindEnable(Ljava/lang/String;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fw;->OooOO0o:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->has(Ljava/lang/String;)Z

    move-result p1

    return p1

    :cond_0
    const-string p1, "opRemindPkgRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final isSettingsRecordEnabled()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/fw;->OooOOo:Z

    return v0
.end method

.method public final onFinishOp(Landroid/os/IBinder;IILjava/lang/String;)V
    .locals 6

    new-instance v3, Llyiahf/vczjk/fl7;

    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    iput p2, v3, Llyiahf/vczjk/fl7;->element:I

    sget-object v0, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->MERGED_LOCATION_OPS:[I

    const-string v1, "MERGED_LOCATION_OPS"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/sy;->OoooooO([II)Z

    move-result p2

    if-eqz p2, :cond_0

    const p2, 0xf42a7

    iput p2, v3, Llyiahf/vczjk/fl7;->element:I

    :cond_0
    iget-boolean p2, p0, Llyiahf/vczjk/td9;->OooO0o0:Z

    if-eqz p2, :cond_1

    iget-boolean p2, p0, Llyiahf/vczjk/td9;->OooO0oO:Z

    if-eqz p2, :cond_1

    iget p2, v3, Llyiahf/vczjk/fl7;->element:I

    invoke-virtual {p0, p2}, Llyiahf/vczjk/fw;->isOpRemindEnabled(I)Z

    move-result p2

    if-eqz p2, :cond_1

    new-instance v0, Llyiahf/vczjk/dw;

    move-object v1, p0

    move-object v2, p1

    move v4, p3

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/dw;-><init>(Llyiahf/vczjk/fw;Landroid/os/IBinder;Llyiahf/vczjk/fl7;ILjava/lang/String;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void

    :cond_1
    move-object v1, p0

    return-void
.end method

.method public final onSettingsGetString(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "value"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "callerPackageName"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/oOO0OO;

    const/4 v1, 0x1

    invoke-direct {v0, p1, p2, p3, v1}, Llyiahf/vczjk/oOO0OO;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    new-instance p1, Llyiahf/vczjk/y51;

    const/4 p2, 0x1

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object p2, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    return-void
.end method

.method public final onSettingsPutString(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "value"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "callerPackageName"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/oOO0OO;

    const/4 v1, 0x2

    invoke-direct {v0, p1, p2, p3, v1}, Llyiahf/vczjk/oOO0OO;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)V

    new-instance p1, Llyiahf/vczjk/y51;

    const/4 p2, 0x1

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/y51;-><init>(Ljava/lang/Object;I)V

    sget-object p2, Llyiahf/vczjk/s88;->OooO00o:Llyiahf/vczjk/i88;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/t51;->OooooO0(Llyiahf/vczjk/i88;)Llyiahf/vczjk/g61;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/t51;->OoooOoo()Llyiahf/vczjk/um2;

    return-void
.end method

.method public final onStartOp(Landroid/os/IBinder;IILjava/lang/String;)V
    .locals 2

    new-instance p1, Llyiahf/vczjk/fl7;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput p2, p1, Llyiahf/vczjk/fl7;->element:I

    sget-object v0, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->MERGED_LOCATION_OPS:[I

    const-string v1, "MERGED_LOCATION_OPS"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/sy;->OoooooO([II)Z

    move-result p2

    if-eqz p2, :cond_0

    const p2, 0xf42a7

    iput p2, p1, Llyiahf/vczjk/fl7;->element:I

    :cond_0
    iget-boolean p2, p0, Llyiahf/vczjk/td9;->OooO0o0:Z

    if-eqz p2, :cond_2

    iget-boolean p2, p0, Llyiahf/vczjk/td9;->OooO0oO:Z

    if-eqz p2, :cond_2

    iget p2, p1, Llyiahf/vczjk/fl7;->element:I

    invoke-virtual {p0, p2}, Llyiahf/vczjk/fw;->isOpRemindEnabled(I)Z

    move-result p2

    if-eqz p2, :cond_2

    if-eqz p4, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOOo0:Ljava/util/HashSet;

    invoke-virtual {p2, p4}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_2

    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOO0o:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-eqz p2, :cond_1

    invoke-virtual {p2, p4}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->has(Ljava/lang/String;)Z

    move-result p2

    if-eqz p2, :cond_2

    new-instance p2, Llyiahf/vczjk/dw;

    invoke-direct {p2, p0, p1, p3, p4}, Llyiahf/vczjk/dw;-><init>(Llyiahf/vczjk/fw;Llyiahf/vczjk/fl7;ILjava/lang/String;)V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/td9;->OooO0o(Ljava/lang/Runnable;)V

    return-void

    :cond_1
    const-string p1, "opRemindPkgRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1

    :cond_2
    return-void
.end method

.method public final resetAllModes(Ljava/lang/String;)V
    .locals 8

    const-string v0, "resetAllModes: "

    invoke-static {v0, p1}, Llyiahf/vczjk/u81;->OooOo0(Ljava/lang/String;Ljava/lang/String;)V

    if-nez p1, :cond_0

    goto/16 :goto_3

    :cond_0
    const-string v0, "*"

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    const-string v2, "0"

    const-string v3, "opSettingsRepo"

    if-eqz v0, :cond_4

    const-string p1, "resetModeForAllPkgs"

    invoke-static {p1}, Llyiahf/vczjk/zsa;->o0ooOOo(Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz p1, :cond_3

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;->keySet()Ljava/util/Set;

    move-result-object p1

    const-string v0, "<get-keys>(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/util/Collection;

    const/4 v0, 0x0

    new-array v4, v0, [Ljava/lang/String;

    invoke-interface {p1, v4}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    array-length v4, p1

    move v5, v0

    :goto_0
    if-ge v5, v4, :cond_6

    aget-object v6, p1, v5

    check-cast v6, Ljava/lang/String;

    invoke-static {v6}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const-string v7, "thanox.config.template."

    invoke-static {v6, v7, v0}, Llyiahf/vczjk/g79;->Oooo00o(Ljava/lang/String;Ljava/lang/String;Z)Z

    move-result v7

    if-nez v7, :cond_2

    iget-object v7, p0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v7, :cond_1

    invoke-interface {v7, v6, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :cond_1
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_2
    :goto_1
    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_3
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_4
    invoke-static {}, Lgithub/tornaco/android/thanos/core/secure/ops/AppOpsManager;->getAllOp()Ljava/util/List;

    move-result-object v0

    const-string v4, "getAllOp(...)"

    invoke-static {v0, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_6

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Integer;

    iget-object v5, p0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz v5, :cond_5

    new-instance v6, Ljava/lang/StringBuilder;

    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v6, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v7, "-"

    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-interface {v5, v4, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_2

    :cond_5
    invoke-static {v3}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v1

    :cond_6
    :goto_3
    return-void
.end method

.method public final setMode(IILjava/lang/String;I)V
    .locals 1

    const-string p2, "packageName"

    invoke-static {p3, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOOO0:Lgithub/tornaco/android/thanos/core/persist/StringMapRepo;

    if-eqz p2, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p3, "-"

    invoke-virtual {v0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p4}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p3

    invoke-interface {p2, p1, p3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :cond_0
    const-string p1, "opSettingsRepo"

    invoke-static {p1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final setOpRemindEnable(IZ)V
    .locals 2

    const/4 v0, 0x0

    const-string v1, "opRemindOpRepo"

    if-eqz p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOO0O:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-eqz p2, :cond_0

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->add(Ljava/lang/String;)Z

    return-void

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOO0O:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-eqz p2, :cond_2

    invoke-static {p1}, Ljava/lang/String;->valueOf(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->remove(Ljava/lang/String;)Z

    return-void

    :cond_2
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v0
.end method

.method public final setOpsEnabled(Z)V
    .locals 2

    iput-boolean p1, p0, Llyiahf/vczjk/fw;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->OoooooO:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method

.method public final setPkgOpRemindEnable(Ljava/lang/String;Z)V
    .locals 2

    const/4 v0, 0x0

    const-string v1, "opRemindPkgRepo"

    if-eqz p2, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOO0o:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-eqz p2, :cond_0

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->add(Ljava/lang/String;)Z

    return-void

    :cond_0
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/fw;->OooOO0o:Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;

    if-eqz p2, :cond_2

    invoke-virtual {p2, p1}, Lgithub/tornaco/android/thanos/core/persist/StringSetRepo;->remove(Ljava/lang/String;)Z

    return-void

    :cond_2
    invoke-static {v1}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v0
.end method

.method public final setSettingsRecordEnabled(Z)V
    .locals 2

    iput-boolean p1, p0, Llyiahf/vczjk/fw;->OooOOo:Z

    iget-object v0, p0, Llyiahf/vczjk/aq9;->OooO:Llyiahf/vczjk/fo9;

    iget-object v0, v0, Llyiahf/vczjk/fo9;->OooOOOO:Llyiahf/vczjk/o27;

    sget-object v1, Llyiahf/vczjk/wg8;->Ooooooo:Lgithub/tornaco/android/thanos/core/ThanosFeature;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/ThanosFeature;->getKey()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/o27;->putBoolean(Ljava/lang/String;Z)Z

    return-void
.end method
