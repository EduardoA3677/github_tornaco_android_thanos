.class public final Llyiahf/vczjk/vm8;
.super Llyiahf/vczjk/fy4;
.source "SourceFile"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "StaticFieldLeak"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0007\u0018\u00002\u00020\u0001\u00a8\u0006\u0002"
    }
    d2 = {
        "Llyiahf/vczjk/vm8;",
        "Llyiahf/vczjk/fy4;",
        "ui_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooO0o:Llyiahf/vczjk/s29;

.field public final OooO0o0:Lgithub/tornaco/android/thanos/core/Logger;

.field public final OooO0oO:Llyiahf/vczjk/gh7;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    invoke-direct {p0}, Llyiahf/vczjk/fy4;-><init>()V

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "ShizukuVM"

    invoke-direct {p1, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/vm8;->OooO0o0:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance p1, Llyiahf/vczjk/rm8;

    const/4 v0, 0x1

    const/4 v1, 0x0

    invoke-direct {p1, v1, v0}, Llyiahf/vczjk/rm8;-><init>(ZZ)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/vm8;->OooO0o:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/vm8;->OooO0oO:Llyiahf/vczjk/gh7;

    new-instance p1, Llyiahf/vczjk/sm8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/sm8;-><init>(Llyiahf/vczjk/vm8;)V

    sget-object v0, Llyiahf/vczjk/gm8;->OooO0oo:Ljava/util/ArrayList;

    monitor-enter v0

    :try_start_0
    new-instance v1, Llyiahf/vczjk/fm8;

    invoke-direct {v1, p1}, Llyiahf/vczjk/fm8;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    new-instance p1, Llyiahf/vczjk/tm8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/tm8;-><init>(Llyiahf/vczjk/vm8;)V

    monitor-enter v0

    :try_start_1
    sget-object v1, Llyiahf/vczjk/gm8;->OooO:Ljava/util/ArrayList;

    new-instance v2, Llyiahf/vczjk/fm8;

    invoke-direct {v2, p1}, Llyiahf/vczjk/fm8;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    monitor-exit v0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1

    :catchall_1
    move-exception p1

    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p1
.end method

.method public static OooO0oo()Z
    .locals 3

    sget-boolean v0, Llyiahf/vczjk/gm8;->OooO0o0:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0OO()I

    move-result v0

    const/4 v2, 0x1

    if-nez v0, :cond_1

    return v2

    :cond_1
    sget-boolean v0, Llyiahf/vczjk/gm8;->OooO0OO:Z

    if-eqz v0, :cond_2

    move v2, v1

    goto :goto_0

    :cond_2
    sget-boolean v0, Llyiahf/vczjk/gm8;->OooO0Oo:Z

    if-eqz v0, :cond_3

    goto :goto_0

    :cond_3
    :try_start_0
    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0o0()Llyiahf/vczjk/jt3;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ht3;

    invoke-virtual {v0}, Llyiahf/vczjk/ht3;->OooOO0()Z

    move-result v2

    sput-boolean v2, Llyiahf/vczjk/gm8;->OooO0Oo:Z
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_1

    :goto_0
    if-eqz v2, :cond_4

    :goto_1
    return v1

    :cond_4
    :try_start_1
    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0o0()Llyiahf/vczjk/jt3;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ht3;

    invoke-virtual {v0}, Llyiahf/vczjk/ht3;->OooO()V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_0

    return v1

    :catch_0
    move-exception v0

    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1

    :catch_1
    move-exception v0

    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1
.end method


# virtual methods
.method public final OooO()V
    .locals 4

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/um8;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/um8;-><init>(Llyiahf/vczjk/vm8;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final OooO0o()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/fy4;->OooO0OO:Z

    invoke-virtual {p0}, Llyiahf/vczjk/vm8;->OooO()V

    return-void
.end method
