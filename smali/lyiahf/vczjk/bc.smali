.class public final Llyiahf/vczjk/bc;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/ComponentCallbacks2;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/wr7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wr7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bc;->OooOOO0:Llyiahf/vczjk/wr7;

    return-void
.end method


# virtual methods
.method public final onConfigurationChanged(Landroid/content/res/Configuration;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/bc;->OooOOO0:Llyiahf/vczjk/wr7;

    monitor-enter p1

    :try_start_0
    iget-object v0, p1, Llyiahf/vczjk/wr7;->OooO00o:Llyiahf/vczjk/or5;

    invoke-virtual {v0}, Llyiahf/vczjk/or5;->OooO0OO()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p1

    return-void

    :catchall_0
    move-exception v0

    monitor-exit p1

    throw v0
.end method

.method public final onLowMemory()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bc;->OooOOO0:Llyiahf/vczjk/wr7;

    monitor-enter v0

    :try_start_0
    iget-object v1, v0, Llyiahf/vczjk/wr7;->OooO00o:Llyiahf/vczjk/or5;

    invoke-virtual {v1}, Llyiahf/vczjk/or5;->OooO0OO()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-void

    :catchall_0
    move-exception v1

    monitor-exit v0

    throw v1
.end method

.method public final onTrimMemory(I)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/bc;->OooOOO0:Llyiahf/vczjk/wr7;

    monitor-enter p1

    :try_start_0
    iget-object v0, p1, Llyiahf/vczjk/wr7;->OooO00o:Llyiahf/vczjk/or5;

    invoke-virtual {v0}, Llyiahf/vczjk/or5;->OooO0OO()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p1

    return-void

    :catchall_0
    move-exception v0

    monitor-exit p1

    throw v0
.end method
