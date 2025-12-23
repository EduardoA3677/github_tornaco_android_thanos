.class public final Llyiahf/vczjk/y40;
.super Lgithub/tornaco/android/thanos/core/backup/IBackupAgent$Stub;
.source "SourceFile"


# instance fields
.field public final OooO0o0:Llyiahf/vczjk/x40;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x40;)V
    .locals 1

    const-string v0, "service"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/backup/IBackupAgent$Stub;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y40;->OooO0o0:Llyiahf/vczjk/x40;

    return-void
.end method


# virtual methods
.method public final asBinder()Landroid/os/IBinder;
    .locals 2

    invoke-super {p0}, Lgithub/tornaco/android/thanos/core/backup/IBackupAgent$Stub;->asBinder()Landroid/os/IBinder;

    move-result-object v0

    const-string v1, "asBinder(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final performBackup(Landroid/os/ParcelFileDescriptor;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/y40;->OooO0o0:Llyiahf/vczjk/x40;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x40;->performBackup(Landroid/os/ParcelFileDescriptor;)V

    return-void
.end method

.method public final performRestore(Landroid/os/ParcelFileDescriptor;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/y40;->OooO0o0:Llyiahf/vczjk/x40;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/x40;->performRestore(Landroid/os/ParcelFileDescriptor;)V

    return-void
.end method

.method public final restoreDefault()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/y40;->OooO0o0:Llyiahf/vczjk/x40;

    invoke-virtual {v0}, Llyiahf/vczjk/x40;->restoreDefault()Z

    move-result v0

    return v0
.end method
