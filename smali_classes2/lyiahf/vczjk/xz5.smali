.class public final Llyiahf/vczjk/xz5;
.super Lgithub/tornaco/android/thanos/core/net/INetworkManager$Stub;
.source "SourceFile"


# instance fields
.field public final OooO0o0:Llyiahf/vczjk/wz5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wz5;)V
    .locals 1

    const-string v0, "service"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/core/net/INetworkManager$Stub;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xz5;->OooO0o0:Llyiahf/vczjk/wz5;

    return-void
.end method


# virtual methods
.method public final asBinder()Landroid/os/IBinder;
    .locals 2

    invoke-super {p0}, Lgithub/tornaco/android/thanos/core/net/INetworkManager$Stub;->asBinder()Landroid/os/IBinder;

    move-result-object v0

    const-string v1, "asBinder(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final getUidTrafficStats(I)Lgithub/tornaco/android/thanos/core/net/TrafficStats;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xz5;->OooO0o0:Llyiahf/vczjk/wz5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wz5;->getUidTrafficStats(I)Lgithub/tornaco/android/thanos/core/net/TrafficStats;

    move-result-object p1

    return-object p1
.end method
