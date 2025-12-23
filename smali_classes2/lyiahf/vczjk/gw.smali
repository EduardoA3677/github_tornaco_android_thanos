.class public final Llyiahf/vczjk/gw;
.super Lgithub/tornaco/android/thanos/core/secure/ops/IAppOpsService$Stub;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o0:Llyiahf/vczjk/fw;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fw;)V
    .locals 1

    const-string v0, "service"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/secure/ops/IAppOpsService$Stub;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    return-void
.end method


# virtual methods
.method public final asBinder()Landroid/os/IBinder;
    .locals 2

    invoke-super {p0}, Lgithub/tornaco/android/thanos/core/secure/ops/IAppOpsService$Stub;->asBinder()Landroid/os/IBinder;

    move-result-object v0

    const-string v1, "asBinder(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final checkOperation(IILjava/lang/String;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/fw;->checkOperation(IILjava/lang/String;)I

    move-result p1

    return p1
.end method

.method public final checkOperationNonCheck(IILjava/lang/String;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/fw;->checkOperationNonCheck(IILjava/lang/String;)I

    move-result p1

    return p1
.end method

.method public final clearSettingsReadRecords()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0}, Llyiahf/vczjk/fw;->clearSettingsReadRecords()V

    return-void
.end method

.method public final clearSettingsWriteRecords()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0}, Llyiahf/vczjk/fw;->clearSettingsWriteRecords()V

    return-void
.end method

.method public final dump(Lgithub/tornaco/android/thanos/core/IPrinter;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->dump(Lgithub/tornaco/android/thanos/core/IPrinter;)V

    return-void
.end method

.method public final getSettingsReadRecords(Ljava/lang/String;)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->getSettingsReadRecords(Ljava/lang/String;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final getSettingsWriteRecords(Ljava/lang/String;)Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->getSettingsWriteRecords(Ljava/lang/String;)Ljava/util/List;

    move-result-object p1

    return-object p1
.end method

.method public final isOpRemindEnabled(I)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->isOpRemindEnabled(I)Z

    move-result p1

    return p1
.end method

.method public final isOpsEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    iget-boolean v0, v0, Llyiahf/vczjk/fw;->OooOOO:Z

    return v0
.end method

.method public final isPkgOpRemindEnable(Ljava/lang/String;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->isPkgOpRemindEnable(Ljava/lang/String;)Z

    move-result p1

    return p1
.end method

.method public final isSettingsRecordEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    iget-boolean v0, v0, Llyiahf/vczjk/fw;->OooOOo:Z

    return v0
.end method

.method public final onFinishOp(Landroid/os/IBinder;IILjava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/fw;->onFinishOp(Landroid/os/IBinder;IILjava/lang/String;)V

    return-void
.end method

.method public final onSettingsGetString(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/fw;->onSettingsGetString(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public final onSettingsPutString(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/fw;->onSettingsPutString(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public final onStartOp(Landroid/os/IBinder;IILjava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/fw;->onStartOp(Landroid/os/IBinder;IILjava/lang/String;)V

    return-void
.end method

.method public final resetAllModes(Ljava/lang/String;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->resetAllModes(Ljava/lang/String;)V

    return-void
.end method

.method public final setMode(IILjava/lang/String;I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/fw;->setMode(IILjava/lang/String;I)V

    return-void
.end method

.method public final setOpRemindEnable(IZ)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/fw;->setOpRemindEnable(IZ)V

    return-void
.end method

.method public final setOpsEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->setOpsEnabled(Z)V

    return-void
.end method

.method public final setPkgOpRemindEnable(Ljava/lang/String;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/fw;->setPkgOpRemindEnable(Ljava/lang/String;Z)V

    return-void
.end method

.method public final setSettingsRecordEnabled(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/gw;->OooO0o0:Llyiahf/vczjk/fw;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw;->setSettingsRecordEnabled(Z)V

    return-void
.end method
