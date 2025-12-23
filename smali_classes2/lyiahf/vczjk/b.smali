.class public final Llyiahf/vczjk/b;
.super Lgithub/tornaco/android/thanos/core/app/IActivityManager$Stub;
.source "SourceFile"


# instance fields
.field public final OooO0o0:Llyiahf/vczjk/a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a;)V
    .locals 1

    const-string v0, "ams"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/app/IActivityManager$Stub;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    return-void
.end method


# virtual methods
.method public final addApp(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->addApp(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-void
.end method

.method public final addAppStabilityUpKeepExceptions(Ljava/util/List;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->addAppStabilityUpKeepExceptions(Ljava/util/List;)V

    return-void
.end method

.method public final addStandbyRule(Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->addStandbyRule(Ljava/lang/String;)V

    return-void
.end method

.method public final addStartRule(Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->addStartRule(Ljava/lang/String;)V

    return-void
.end method

.method public final asBinder()Landroid/os/IBinder;
    .locals 2

    invoke-super {p0}, Lgithub/tornaco/android/thanos/core/app/IActivityManager$Stub;->asBinder()Landroid/os/IBinder;

    move-result-object v0

    const-string v1, "asBinder(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final checkBroadcast(Landroid/content/Intent;II)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/a;->checkBroadcast(Landroid/content/Intent;II)Z

    move-result p1

    return p1
.end method

.method public final checkBroadcastingIntent(Landroid/content/Intent;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->checkBroadcastingIntent(Landroid/content/Intent;)Z

    move-result p1

    return p1
.end method

.method public final checkGetContentProvider(Ljava/lang/String;Ljava/lang/String;I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/a;->checkGetContentProvider(Ljava/lang/String;Ljava/lang/String;I)Z

    move-result p1

    return p1
.end method

.method public final checkRestartService(Ljava/lang/String;Landroid/content/ComponentName;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->checkRestartService(Ljava/lang/String;Landroid/content/ComponentName;)Z

    const/4 p1, 0x0

    throw p1
.end method

.method public final checkService(Landroid/content/Intent;Landroid/content/ComponentName;II)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/a;->checkService(Landroid/content/Intent;Landroid/content/ComponentName;II)Z

    move-result p1

    return p1
.end method

.method public final checkStartActivity(Landroid/content/Intent;I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->checkStartActivity(Landroid/content/Intent;I)Z

    move-result p1

    return p1
.end method

.method public final checkStartProcess(Ljava/lang/String;Landroid/content/pm/ApplicationInfo;Ljava/lang/String;Ljava/lang/String;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/a;->checkStartProcess(Ljava/lang/String;Landroid/content/pm/ApplicationInfo;Ljava/lang/String;Ljava/lang/String;)Z

    move-result p1

    return p1
.end method

.method public final deleteStandbyRule(Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->deleteStandbyRule(Ljava/lang/String;)V

    return-void
.end method

.method public final deleteStartRule(Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->deleteStartRule(Ljava/lang/String;)V

    return-void
.end method

.method public final dump(Lgithub/tornaco/android/thanos/core/IPrinter;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->dump(Lgithub/tornaco/android/thanos/core/IPrinter;)V

    return-void
.end method

.method public final dumpCpu(Lgithub/tornaco/android/thanos/core/IPrinter;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->dumpCpu(Lgithub/tornaco/android/thanos/core/IPrinter;)V

    return-void
.end method

.method public final dumpHeap(Ljava/lang/String;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->dumpHeap(Ljava/lang/String;)Z

    move-result p1

    return p1
.end method

.method public final fastGetProcessPss(I)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->fastGetProcessPss(I)J

    move-result-wide v0

    return-wide v0
.end method

.method public final forceStopPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->forceStopPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;Ljava/lang/String;)V

    return-void
.end method

.method public final freezeApp(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->freezeApp(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-void
.end method

.method public final freezeAppProcess(J)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->freezeAppProcess(J)V

    return-void
.end method

.method public final getAllStandbyRules()[Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getAllStandbyRules()[Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getAllStartRecords(I)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getAllStartRecords(I)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getAllStartRecordsForPackageSetWithRes(Ljava/lang/String;ZZ)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/a;->getAllStartRecordsForPackageSetWithRes(Ljava/lang/String;ZZ)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getAllStartRecordsWithRes(IZZ)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/a;->getAllStartRecordsWithRes(IZZ)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getAllStartRules()[Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getAllStartRules()[Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getAppStabilityUpKeepExceptions()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getAppStabilityUpKeepExceptions()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final getBgTaskCleanUpDelayTimeMills()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-wide v0, v0, Llyiahf/vczjk/a;->Oooo0O0:J

    return-wide v0
.end method

.method public final getCurrentFrontApp()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getCurrentFrontApp()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getCurrentFrontPkg()Lgithub/tornaco/android/thanos/core/pm/Pkg;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getCurrentFrontPkg()Lgithub/tornaco/android/thanos/core/pm/Pkg;

    move-result-object v0

    return-object v0
.end method

.method public final getLastRecentUsedPackages(I)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getLastRecentUsedPackages(I)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getMemoryInfo()Landroid/app/ActivityManager$MemoryInfo;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getMemoryInfo()Landroid/app/ActivityManager$MemoryInfo;

    move-result-object v0

    return-object v0
.end method

.method public final getPackageNameForTaskId(I)Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getPackageNameForTaskId(I)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final getPid(Lgithub/tornaco/android/thanos/core/os/ProcessName;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getPid(Lgithub/tornaco/android/thanos/core/os/ProcessName;)I

    move-result p1

    return p1
.end method

.method public final getPkgRecentTaskBlurMode(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getPkgRecentTaskBlurMode(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I

    move-result p1

    return p1
.end method

.method public final getProcessPss([I)[J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getProcessPss([I)[J

    move-result-object p1

    return-object p1
.end method

.method public final getProcessStartTime(I)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getProcessStartTime(I)J

    move-result-wide v0

    return-wide v0
.end method

.method public final getRecentTaskExcludeSettingForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getRecentTaskExcludeSettingForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)I

    move-result p1

    return p1
.end method

.method public final getRunningAppPackages()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getRunningAppPackages()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final getRunningAppProcess()[Lgithub/tornaco/android/thanos/core/process/ProcessRecord;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getRunningAppProcess()[Lgithub/tornaco/android/thanos/core/process/ProcessRecord;

    move-result-object v0

    return-object v0
.end method

.method public final getRunningAppProcessForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getRunningAppProcessForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getRunningAppProcessLegacy()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getRunningAppProcessLegacy()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final getRunningAppServiceForPackage(Ljava/lang/String;I)[Lgithub/tornaco/android/thanos/core/app/RunningServiceInfoCompat;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->getRunningAppServiceForPackage(Ljava/lang/String;I)[Lgithub/tornaco/android/thanos/core/app/RunningServiceInfoCompat;

    move-result-object p1

    return-object p1
.end method

.method public final getRunningAppsCount()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getRunningAppsCount()I

    move-result v0

    return v0
.end method

.method public final getRunningServiceLegacy(I)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getRunningServiceLegacy(I)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getStartRecordAllowedCountByPackageName(Ljava/lang/String;)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getStartRecordAllowedCountByPackageName(Ljava/lang/String;)J

    move-result-wide v0

    return-wide v0
.end method

.method public final getStartRecordAllowedPackages()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getStartRecordAllowedPackages()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final getStartRecordBlockedCountByPackageName(Ljava/lang/String;)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getStartRecordBlockedCountByPackageName(Ljava/lang/String;)J

    move-result-wide v0

    return-wide v0
.end method

.method public final getStartRecordBlockedPackages()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getStartRecordBlockedPackages()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final getStartRecordsAllowedByPackageName(Ljava/lang/String;)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getStartRecordsAllowedByPackageName(Ljava/lang/String;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getStartRecordsAllowedCount()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getStartRecordsAllowedCount()J

    move-result-wide v0

    return-wide v0
.end method

.method public final getStartRecordsBlockedByPackageName(Ljava/lang/String;)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getStartRecordsBlockedByPackageName(Ljava/lang/String;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getStartRecordsBlockedCount()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getStartRecordsBlockedCount()J

    move-result-wide v0

    return-wide v0
.end method

.method public final getStartRecordsByPackageName(Ljava/lang/String;)Ljava/util/List;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    return-object p1
.end method

.method public final getSwapInfo()Lgithub/tornaco/android/thanos/core/os/SwapInfo;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getSwapInfo()Lgithub/tornaco/android/thanos/core/os/SwapInfo;

    move-result-object v0

    return-object v0
.end method

.method public final getTopNCpuUsagePackages(IZ)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->getTopNCpuUsagePackages(IZ)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getTopVisibleActivities()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->getTopVisibleActivities()Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final getTotalCpuPercent(Z)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getTotalCpuPercent(Z)F

    move-result p1

    return p1
.end method

.method public final getUserInfo(I)Landroid/content/pm/UserInfo;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->getUserInfo(I)Landroid/content/pm/UserInfo;

    move-result-object p1

    return-object p1
.end method

.method public final hasRunningForegroundService(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->hasRunningForegroundService(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)Z

    move-result p1

    return p1
.end method

.method public final hasRunningServiceForPackage(Ljava/lang/String;I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->hasRunningServiceForPackage(Ljava/lang/String;I)Z

    move-result p1

    return p1
.end method

.method public final idlePackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->idlePackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-void
.end method

.method public final isAppForeground(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isAppForeground(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isAppStabilityUpKeepEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOOOo:Z

    return v0
.end method

.method public final isBgRestrictEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOo0:Z

    return v0
.end method

.method public final isBgRestrictNotificationEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOo0O:Z

    return v0
.end method

.method public final isBgTaskCleanUpSkipAudioFocusedAppEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->Oooo000:Z

    return v0
.end method

.method public final isBgTaskCleanUpSkipForegroundEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->Oooo0:Z

    return v0
.end method

.method public final isBgTaskCleanUpSkipWhenHasRecentTaskEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->Oooo00o:Z

    return v0
.end method

.method public final isBgTaskCleanUpSkipWhichHasNotificationEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->Oooo00O:Z

    return v0
.end method

.method public final isBlockAllProvider(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-object v0, v0, Llyiahf/vczjk/a;->OoooOOO:Ljava/util/HashSet;

    invoke-virtual {v0, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final isBlockAllReceiver(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-object v0, v0, Llyiahf/vczjk/a;->OoooOO0:Ljava/util/HashSet;

    invoke-virtual {v0, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final isBlockAllService(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-object v0, v0, Llyiahf/vczjk/a;->o000oOoO:Ljava/util/HashSet;

    invoke-virtual {v0, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final isCachedAppsFreezerSupported()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v0, 0x0

    return v0
.end method

.method public final isCleanUpOnTaskRemovalEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOo00:Z

    return v0
.end method

.method public final isNetStatTrackerEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOOO0:Z

    return v0
.end method

.method public final isPackageIdle(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isPackageIdle(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPackageRunning(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->Oooo0o0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPkgBgRestricted(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isPkgBgRestricted(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPkgCleanUpOnTaskRemovalEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isPkgCleanUpOnTaskRemovalEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPkgRecentTaskBlurEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isPkgRecentTaskBlurEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPkgResident(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isPkgResident(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPkgSmartStandByEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isPkgSmartStandByEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPkgStartBlocking(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->isPkgStartBlocking(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    move-result p1

    return p1
.end method

.method public final isPlatformAppIdleEnabled()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->isPlatformAppIdleEnabled()I

    move-result v0

    return v0
.end method

.method public final isRecentTaskBlurEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOo0o:Z

    return v0
.end method

.method public final isSmartStandByBlockBgServiceStartEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOooO:Z

    return v0
.end method

.method public final isSmartStandByByPassIfHasNotificationEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOoo0:Z

    return v0
.end method

.method public final isSmartStandByByPassIfHasVisibleWindows()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOoo:Z

    return v0
.end method

.method public final isSmartStandByEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOo:Z

    return v0
.end method

.method public final isSmartStandByInactiveEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOoOO:Z

    return v0
.end method

.method public final isSmartStandByStopServiceEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOoO0:Z

    return v0
.end method

.method public final isSmartStandByUnbindServiceEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOoO:Z

    return v0
.end method

.method public final isStandbyRuleEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOooo:Z

    return v0
.end method

.method public final isStartBlockEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOOo:Z

    return v0
.end method

.method public final isStartRuleEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    iget-boolean v0, v0, Llyiahf/vczjk/a;->OooOOoo:Z

    return v0
.end method

.method public final killBackgroundProcesses(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->killBackgroundProcesses(Lgithub/tornaco/android/thanos/core/pm/Pkg;)Z

    const/4 p1, 0x1

    return p1
.end method

.method public final killProcess(J)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->killProcess(J)Z

    const/4 p1, 0x1

    return p1
.end method

.method public final killProcessByName(Lgithub/tornaco/android/thanos/core/os/ProcessName;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->killProcessByName(Lgithub/tornaco/android/thanos/core/os/ProcessName;)I

    move-result p1

    return p1
.end method

.method public final killProcessByNames(Ljava/util/List;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->killProcessByNames(Ljava/util/List;)V

    return-void
.end method

.method public final launchAppDetailsActivity(Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->launchAppDetailsActivity(Ljava/lang/String;)V

    return-void
.end method

.method public final notifyTaskCreated(ILandroid/content/ComponentName;)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method

.method public final onApplicationCrashing(Ljava/lang/String;Ljava/lang/String;Lgithub/tornaco/android/thanos/core/process/ProcessRecord;Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/a;->onApplicationCrashing(Ljava/lang/String;Ljava/lang/String;Lgithub/tornaco/android/thanos/core/process/ProcessRecord;Ljava/lang/String;)V

    return-void
.end method

.method public final onStartProcessLocked(Landroid/content/pm/ApplicationInfo;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->onStartProcessLocked(Landroid/content/pm/ApplicationInfo;)V

    return-void
.end method

.method public final queryCpuUsageRatio([JZ)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->queryCpuUsageRatio([JZ)F

    move-result p1

    return p1
.end method

.method public final queryProcessCpuUsageStats([JZ)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->queryProcessCpuUsageStats([JZ)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final removeAppStabilityUpKeepExceptions(Ljava/util/List;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->removeAppStabilityUpKeepExceptions(Ljava/util/List;)V

    return-void
.end method

.method public final resetStartRecordsAllowed()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->resetStartRecordsAllowed()V

    return-void
.end method

.method public final resetStartRecordsBlocked()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->resetStartRecordsBlocked()V

    return-void
.end method

.method public final setAppStabilityUpKeepEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setAppStabilityUpKeepEnabled(Z)V

    return-void
.end method

.method public final setBgRestrictEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setBgRestrictEnabled(Z)V

    return-void
.end method

.method public final setBgRestrictNotificationEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setBgRestrictNotificationEnabled(Z)V

    return-void
.end method

.method public final setBgTaskCleanUpDelayTimeMills(J)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setBgTaskCleanUpDelayTimeMills(J)V

    return-void
.end method

.method public final setBgTaskCleanUpSkipAudioFocusedAppEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setBgTaskCleanUpSkipAudioFocusedAppEnabled(Z)V

    return-void
.end method

.method public final setBgTaskCleanUpSkipForegroundEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setBgTaskCleanUpSkipForegroundEnabled(Z)V

    return-void
.end method

.method public final setBgTaskCleanUpSkipWhenHasRecentTaskEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setBgTaskCleanUpSkipWhenHasRecentTaskEnabled(Z)V

    return-void
.end method

.method public final setBgTaskCleanUpSkipWhichHasNotificationEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setBgTaskCleanUpSkipWhichHasNotificationEnabled(Z)V

    return-void
.end method

.method public final setBlockAllProvider(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setBlockAllProvider(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setBlockAllReceiver(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setBlockAllReceiver(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setBlockAllService(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setBlockAllService(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setCleanUpOnTaskRemovalEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setCleanUpOnTaskRemovalEnabled(Z)V

    return-void
.end method

.method public final setNetStatTrackerEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setNetStatTrackerEnabled(Z)V

    return-void
.end method

.method public final setPkgBgRestrictEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setPkgBgRestrictEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setPkgCleanUpOnTaskRemovalEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setPkgCleanUpOnTaskRemovalEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setPkgRecentTaskBlurEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setPkgRecentTaskBlurEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setPkgRecentTaskBlurMode(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setPkgRecentTaskBlurMode(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V

    return-void
.end method

.method public final setPkgResident(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setPkgResident(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setPkgSmartStandByEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->Oooooo(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setPkgStartBlockEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setPkgStartBlockEnabled(Lgithub/tornaco/android/thanos/core/pm/Pkg;Z)V

    return-void
.end method

.method public final setRecentTaskBlurEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setRecentTaskBlurEnabled(Z)V

    return-void
.end method

.method public final setRecentTaskExcludeSettingForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->setRecentTaskExcludeSettingForPackage(Lgithub/tornaco/android/thanos/core/pm/Pkg;I)V

    return-void
.end method

.method public final setSmartStandByBlockBgServiceStartEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setSmartStandByBlockBgServiceStartEnabled(Z)V

    return-void
.end method

.method public final setSmartStandByByPassIfHasNotificationEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setSmartStandByByPassIfHasNotificationEnabled(Z)V

    return-void
.end method

.method public final setSmartStandByByPassIfHasVisibleWindowsEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setSmartStandByByPassIfHasVisibleWindowsEnabled(Z)V

    return-void
.end method

.method public final setSmartStandByEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setSmartStandByEnabled(Z)V

    return-void
.end method

.method public final setSmartStandByInactiveEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setSmartStandByInactiveEnabled(Z)V

    return-void
.end method

.method public final setSmartStandByStopServiceEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setSmartStandByStopServiceEnabled(Z)V

    return-void
.end method

.method public final setSmartStandByUnbindServiceEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setSmartStandByUnbindServiceEnabled(Z)V

    return-void
.end method

.method public final setStandbyRuleEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setStandbyRuleEnabled(Z)V

    return-void
.end method

.method public final setStartBlockEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setStartBlockEnabled(Z)V

    return-void
.end method

.method public final setStartRuleEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->setStartRuleEnabled(Z)V

    return-void
.end method

.method public final setupService(ILandroid/content/Intent;Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/a;->setupService(ILandroid/content/Intent;Lgithub/tornaco/android/thanos/core/os/SynchronousResultReceiver;)J

    move-result-wide p1

    return-wide p1
.end method

.method public final stopService(Landroid/content/Intent;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->stopService(Landroid/content/Intent;)Z

    move-result p1

    return p1
.end method

.method public final unfreezeApp(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/a;->unfreezeApp(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V

    return-void
.end method

.method public final unfreezeAppProcess(J)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/a;->unfreezeAppProcess(J)V

    return-void
.end method

.method public final updateProcessCpuUsageStats()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b;->OooO0o0:Llyiahf/vczjk/a;

    invoke-virtual {v0}, Llyiahf/vczjk/a;->updateProcessCpuUsageStats()V

    return-void
.end method
