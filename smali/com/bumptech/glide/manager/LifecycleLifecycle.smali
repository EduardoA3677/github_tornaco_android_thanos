.class final Lcom/bumptech/glide/manager/LifecycleLifecycle;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Lcom/bumptech/glide/manager/Lifecycle;
.implements Llyiahf/vczjk/ty4;


# instance fields
.field private final lifecycle:Llyiahf/vczjk/ky4;

.field private final lifecycleListeners:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/bumptech/glide/manager/LifecycleListener;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    iput-object v0, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycleListeners:Ljava/util/Set;

    iput-object p1, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    return-void
.end method


# virtual methods
.method public addListener(Lcom/bumptech/glide/manager/LifecycleListener;)V
    .locals 2

    iget-object v0, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycleListeners:Ljava/util/Set;

    invoke-interface {v0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {v0}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/jy4;->OooOOO0:Llyiahf/vczjk/jy4;

    if-ne v0, v1, :cond_0

    invoke-interface {p1}, Lcom/bumptech/glide/manager/LifecycleListener;->onDestroy()V

    return-void

    :cond_0
    iget-object v0, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycle:Llyiahf/vczjk/ky4;

    invoke-virtual {v0}, Llyiahf/vczjk/ky4;->OooO0O0()Llyiahf/vczjk/jy4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/jy4;->OooOOOo:Llyiahf/vczjk/jy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jy4;->OooO00o(Llyiahf/vczjk/jy4;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Lcom/bumptech/glide/manager/LifecycleListener;->onStart()V

    return-void

    :cond_1
    invoke-interface {p1}, Lcom/bumptech/glide/manager/LifecycleListener;->onStop()V

    return-void
.end method

.method public onDestroy(Llyiahf/vczjk/uy4;)V
    .locals 2
    .annotation runtime Llyiahf/vczjk/wa6;
        value = .enum Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;
    .end annotation

    iget-object v0, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycleListeners:Ljava/util/Set;

    invoke-static {v0}, Lcom/bumptech/glide/util/Util;->getSnapshot(Ljava/util/Collection;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/bumptech/glide/manager/LifecycleListener;

    invoke-interface {v1}, Lcom/bumptech/glide/manager/LifecycleListener;->onDestroy()V

    goto :goto_0

    :cond_0
    invoke-interface {p1}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object p1

    invoke-virtual {p1, p0}, Llyiahf/vczjk/ky4;->OooO0OO(Llyiahf/vczjk/ty4;)V

    return-void
.end method

.method public onStart(Llyiahf/vczjk/uy4;)V
    .locals 1
    .annotation runtime Llyiahf/vczjk/wa6;
        value = .enum Llyiahf/vczjk/iy4;->ON_START:Llyiahf/vczjk/iy4;
    .end annotation

    iget-object p1, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycleListeners:Ljava/util/Set;

    invoke-static {p1}, Lcom/bumptech/glide/util/Util;->getSnapshot(Ljava/util/Collection;)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/bumptech/glide/manager/LifecycleListener;

    invoke-interface {v0}, Lcom/bumptech/glide/manager/LifecycleListener;->onStart()V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public onStop(Llyiahf/vczjk/uy4;)V
    .locals 1
    .annotation runtime Llyiahf/vczjk/wa6;
        value = .enum Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;
    .end annotation

    iget-object p1, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycleListeners:Ljava/util/Set;

    invoke-static {p1}, Lcom/bumptech/glide/util/Util;->getSnapshot(Ljava/util/Collection;)Ljava/util/List;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/bumptech/glide/manager/LifecycleListener;

    invoke-interface {v0}, Lcom/bumptech/glide/manager/LifecycleListener;->onStop()V

    goto :goto_0

    :cond_0
    return-void
.end method

.method public removeListener(Lcom/bumptech/glide/manager/LifecycleListener;)V
    .locals 1

    iget-object v0, p0, Lcom/bumptech/glide/manager/LifecycleLifecycle;->lifecycleListeners:Ljava/util/Set;

    invoke-interface {v0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    return-void
.end method
