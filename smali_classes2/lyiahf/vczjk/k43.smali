.class public final Llyiahf/vczjk/k43;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lcom/bumptech/glide/request/target/Target;
.implements Llyiahf/vczjk/lj1;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final OooOOO0:Llyiahf/vczjk/hv3;

.field public OooOOOO:Llyiahf/vczjk/s77;

.field public OooOOOo:Llyiahf/vczjk/b24;

.field public final OooOOo:Ljava/util/ArrayList;

.field public OooOOo0:Lcom/bumptech/glide/request/Request;

.field public OooOOoo:Ljava/lang/Throwable;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hv3;)V
    .locals 1

    const-string v0, "imageOptions"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k43;->OooOOO0:Llyiahf/vczjk/hv3;

    new-instance p1, Ljava/lang/Object;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k43;->OooOOO:Ljava/lang/Object;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k43;->OooOOo:Ljava/util/ArrayList;

    return-void
.end method


# virtual methods
.method public final getRequest()Lcom/bumptech/glide/request/Request;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/k43;->OooOOo0:Lcom/bumptech/glide/request/Request;

    return-object v0
.end method

.method public final getSize(Lcom/bumptech/glide/request/target/SizeReadyCallback;)V
    .locals 8

    const-string v0, "cb"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/k43;->OooOOOo:Llyiahf/vczjk/b24;

    const-wide v1, 0xffffffffL

    const/16 v3, 0x20

    if-eqz v0, :cond_0

    iget-wide v4, v0, Llyiahf/vczjk/b24;->OooO00o:J

    shr-long v6, v4, v3

    long-to-int v0, v6

    and-long/2addr v1, v4

    long-to-int v1, v1

    invoke-interface {p1, v0, v1}, Lcom/bumptech/glide/request/target/SizeReadyCallback;->onSizeReady(II)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/k43;->OooOOO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v4, p0, Llyiahf/vczjk/k43;->OooOOOo:Llyiahf/vczjk/b24;

    if-eqz v4, :cond_1

    iget-wide v4, v4, Llyiahf/vczjk/b24;->OooO00o:J

    shr-long v6, v4, v3

    long-to-int v3, v6

    and-long/2addr v1, v4

    long-to-int v1, v1

    invoke-interface {p1, v3, v1}, Lcom/bumptech/glide/request/target/SizeReadyCallback;->onSizeReady(II)V

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/k43;->OooOOo:Ljava/util/ArrayList;

    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_0
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0

    throw p1
.end method

.method public final onDestroy()V
    .locals 0

    return-void
.end method

.method public final onLoadCleared(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/k43;->OooOOOO:Llyiahf/vczjk/s77;

    if-eqz p1, :cond_0

    sget-object v0, Llyiahf/vczjk/bv3;->OooO00o:Llyiahf/vczjk/bv3;

    invoke-static {p1, v0}, Llyiahf/vczjk/t51;->OooooOO(Llyiahf/vczjk/if8;Llyiahf/vczjk/dv3;)V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/k43;->OooOOOO:Llyiahf/vczjk/s77;

    if-eqz p1, :cond_1

    check-cast p1, Llyiahf/vczjk/r77;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/r77;->OooO0o(Ljava/lang/Throwable;)Z

    :cond_1
    return-void
.end method

.method public final onLoadFailed(Landroid/graphics/drawable/Drawable;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/k43;->OooOOOO:Llyiahf/vczjk/s77;

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/zu3;

    iget-object v2, p0, Llyiahf/vczjk/k43;->OooOOoo:Ljava/lang/Throwable;

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/zu3;-><init>(Landroid/graphics/drawable/Drawable;Ljava/lang/Throwable;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooooOO(Llyiahf/vczjk/if8;Llyiahf/vczjk/dv3;)V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/k43;->OooOOOO:Llyiahf/vczjk/s77;

    if-eqz p1, :cond_1

    check-cast p1, Llyiahf/vczjk/r77;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/r77;->OooO0o(Ljava/lang/Throwable;)Z

    :cond_1
    return-void
.end method

.method public final onLoadStarted(Landroid/graphics/drawable/Drawable;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/k43;->OooOOOO:Llyiahf/vczjk/s77;

    if-eqz p1, :cond_0

    sget-object v0, Llyiahf/vczjk/av3;->OooO00o:Llyiahf/vczjk/av3;

    invoke-static {p1, v0}, Llyiahf/vczjk/t51;->OooooOO(Llyiahf/vczjk/if8;Llyiahf/vczjk/dv3;)V

    :cond_0
    return-void
.end method

.method public final onResourceReady(Ljava/lang/Object;Lcom/bumptech/glide/request/transition/Transition;)V
    .locals 0

    const-string p2, "resource"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method

.method public final onStart()V
    .locals 0

    return-void
.end method

.method public final onStop()V
    .locals 0

    return-void
.end method

.method public final removeCallback(Lcom/bumptech/glide/request/target/SizeReadyCallback;)V
    .locals 2

    const-string v0, "cb"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/k43;->OooOOO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/k43;->OooOOo:Ljava/util/ArrayList;

    invoke-virtual {v1, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final setRequest(Lcom/bumptech/glide/request/Request;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/k43;->OooOOo0:Lcom/bumptech/glide/request/Request;

    return-void
.end method
