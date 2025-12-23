.class public final Llyiahf/vczjk/k8a;
.super Llyiahf/vczjk/x88;
.source "SourceFile"


# instance fields
.field public final OooOOo0:Ljava/lang/ThreadLocal;

.field private volatile threadLocalIsSet:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/bq0;->OooOOOO:Llyiahf/vczjk/bq0;

    invoke-interface {p2, v0}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-interface {p2, v0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    goto :goto_0

    :cond_0
    move-object v0, p2

    :goto_0
    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/x88;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V

    new-instance v0, Ljava/lang/ThreadLocal;

    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/k8a;->OooOOo0:Ljava/lang/ThreadLocal;

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    invoke-interface {p1, v0}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    instance-of p1, p1, Llyiahf/vczjk/qr1;

    if-nez p1, :cond_1

    const/4 p1, 0x0

    invoke-static {p2, p1}, Llyiahf/vczjk/jp8;->OooooO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-static {p2, p1}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/k8a;->o00O0O(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    :cond_1
    return-void
.end method


# virtual methods
.method public final OooOOO(Ljava/lang/Object;)V
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/k8a;->ooOO()V

    invoke-static {p1}, Llyiahf/vczjk/c6a;->o00o0O(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/x88;->OooOOOo:Llyiahf/vczjk/yo1;

    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    const/4 v2, 0x0

    invoke-static {v1, v2}, Llyiahf/vczjk/jp8;->OooooO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/jp8;->OooOOo:Llyiahf/vczjk/h87;

    if-eq v3, v4, :cond_0

    invoke-static {v0, v1, v3}, Llyiahf/vczjk/t51;->Oooooo0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;Ljava/lang/Object;)Llyiahf/vczjk/k8a;

    move-result-object v2

    :cond_0
    :try_start_0
    invoke-interface {v0, p1}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v2, :cond_2

    invoke-virtual {v2}, Llyiahf/vczjk/k8a;->Ooooooo()Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    return-void

    :cond_2
    :goto_0
    invoke-static {v1, v3}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    return-void

    :catchall_0
    move-exception p1

    if-eqz v2, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/k8a;->Ooooooo()Z

    move-result v0

    if-eqz v0, :cond_4

    :cond_3
    invoke-static {v1, v3}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    :cond_4
    throw p1
.end method

.method public final OoooooO()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/k8a;->ooOO()V

    return-void
.end method

.method public final Ooooooo()Z
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/k8a;->threadLocalIsSet:Z

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/k8a;->OooOOo0:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/k8a;->OooOOo0:Ljava/lang/ThreadLocal;

    invoke-virtual {v2}, Ljava/lang/ThreadLocal;->remove()V

    xor-int/2addr v0, v1

    return v0
.end method

.method public final o00O0O(Llyiahf/vczjk/or1;Ljava/lang/Object;)V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/k8a;->threadLocalIsSet:Z

    iget-object v0, p0, Llyiahf/vczjk/k8a;->OooOOo0:Ljava/lang/ThreadLocal;

    new-instance v1, Llyiahf/vczjk/xn6;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    return-void
.end method

.method public final ooOO()V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/k8a;->threadLocalIsSet:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/k8a;->OooOOo0:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xn6;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/or1;

    invoke-virtual {v0}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v0

    invoke-static {v1, v0}, Llyiahf/vczjk/jp8;->OoooOO0(Llyiahf/vczjk/or1;Ljava/lang/Object;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/k8a;->OooOOo0:Ljava/lang/ThreadLocal;

    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->remove()V

    :cond_1
    return-void
.end method
