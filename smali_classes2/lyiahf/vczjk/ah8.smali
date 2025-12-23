.class public final Llyiahf/vczjk/ah8;
.super Lgithub/tornaco/android/thanos/core/os/IServiceManager$Stub;
.source "SourceFile"


# instance fields
.field public final OooO0o0:Llyiahf/vczjk/zg8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zg8;)V
    .locals 1

    const-string v0, "serviceManagerService"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/os/IServiceManager$Stub;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ah8;->OooO0o0:Llyiahf/vczjk/zg8;

    return-void
.end method


# virtual methods
.method public final addService(Ljava/lang/String;Landroid/os/IBinder;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ah8;->OooO0o0:Llyiahf/vczjk/zg8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/zg8;->addService(Ljava/lang/String;Landroid/os/IBinder;)V

    return-void
.end method

.method public final asBinder()Landroid/os/IBinder;
    .locals 2

    invoke-super {p0}, Lgithub/tornaco/android/thanos/core/os/IServiceManager$Stub;->asBinder()Landroid/os/IBinder;

    move-result-object v0

    const-string v1, "asBinder(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final getService(Ljava/lang/String;)Landroid/os/IBinder;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ah8;->OooO0o0:Llyiahf/vczjk/zg8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zg8;->getService(Ljava/lang/String;)Landroid/os/IBinder;

    move-result-object p1

    return-object p1
.end method

.method public final hasService(Ljava/lang/String;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ah8;->OooO0o0:Llyiahf/vczjk/zg8;

    iget-object v0, v0, Llyiahf/vczjk/zg8;->OooO:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->containsKey(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method
