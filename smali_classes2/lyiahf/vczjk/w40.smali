.class public final Llyiahf/vczjk/w40;
.super Landroid/os/HandlerThread;
.source "SourceFile"


# static fields
.field public static OooOOO:Llyiahf/vczjk/nq2;

.field public static OooOOO0:Llyiahf/vczjk/w40;


# direct methods
.method public static OooO00o()Llyiahf/vczjk/nq2;
    .locals 4

    sget v0, Llyiahf/vczjk/he0;->OooO0O0:I

    if-eqz v0, :cond_1

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    const/4 v1, 0x1

    if-lt v0, v1, :cond_1

    const-class v0, Llyiahf/vczjk/w40;

    monitor-enter v0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/w40;->OooOOO0:Llyiahf/vczjk/w40;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/w40;

    const-string v2, "thanos.bg"

    const/16 v3, 0xa

    invoke-direct {v1, v2, v3}, Landroid/os/HandlerThread;-><init>(Ljava/lang/String;I)V

    sput-object v1, Llyiahf/vczjk/w40;->OooOOO0:Llyiahf/vczjk/w40;

    invoke-virtual {v1}, Ljava/lang/Thread;->start()V

    new-instance v1, Llyiahf/vczjk/nq2;

    sget-object v2, Llyiahf/vczjk/w40;->OooOOO0:Llyiahf/vczjk/w40;

    invoke-virtual {v2}, Landroid/os/HandlerThread;->getLooper()Landroid/os/Looper;

    move-result-object v2

    const/4 v3, 0x0

    invoke-direct {v1, v2, v3}, Llyiahf/vczjk/nq2;-><init>(Landroid/os/Looper;I)V

    sput-object v1, Llyiahf/vczjk/w40;->OooOOO:Llyiahf/vczjk/nq2;

    :cond_0
    sget-object v1, Llyiahf/vczjk/w40;->OooOOO:Llyiahf/vczjk/nq2;

    monitor-exit v0

    return-object v1

    :catchall_0
    move-exception v1

    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "System is not ready!!!"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
