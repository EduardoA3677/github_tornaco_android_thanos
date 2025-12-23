.class public final Llyiahf/vczjk/wg;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xn5;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/sg;

.field public final OooOOO0:Landroid/view/Choreographer;


# direct methods
.method public constructor <init>(Landroid/view/Choreographer;Llyiahf/vczjk/sg;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wg;->OooOOO0:Landroid/view/Choreographer;

    iput-object p2, p0, Llyiahf/vczjk/wg;->OooOOO:Llyiahf/vczjk/sg;

    return-void
.end method


# virtual methods
.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOoOO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOooO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p2, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/wg;->OooOOO:Llyiahf/vczjk/sg;

    if-nez v0, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/vp3;->OooOOOO:Llyiahf/vczjk/vp3;

    invoke-interface {v0, v1}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/sg;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/sg;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :cond_1
    :goto_0
    new-instance v1, Llyiahf/vczjk/yp0;

    invoke-static {p1}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    const/4 v2, 0x1

    invoke-direct {v1, v2, p1}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v1}, Llyiahf/vczjk/yp0;->OooOOoo()V

    new-instance p1, Llyiahf/vczjk/vg;

    invoke-direct {p1, v1, p0, p2}, Llyiahf/vczjk/vg;-><init>(Llyiahf/vczjk/yp0;Llyiahf/vczjk/wg;Llyiahf/vczjk/oe3;)V

    if-eqz v0, :cond_3

    iget-object p2, v0, Llyiahf/vczjk/sg;->OooOOOO:Landroid/view/Choreographer;

    iget-object v3, p0, Llyiahf/vczjk/wg;->OooOOO0:Landroid/view/Choreographer;

    invoke-static {p2, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-eqz p2, :cond_3

    iget-object p2, v0, Llyiahf/vczjk/sg;->OooOOo0:Ljava/lang/Object;

    monitor-enter p2

    :try_start_0
    iget-object v3, v0, Llyiahf/vczjk/sg;->OooOOoo:Ljava/util/ArrayList;

    invoke-virtual {v3, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-boolean v3, v0, Llyiahf/vczjk/sg;->OooOo0O:Z

    if-nez v3, :cond_2

    iput-boolean v2, v0, Llyiahf/vczjk/sg;->OooOo0O:Z

    iget-object v2, v0, Llyiahf/vczjk/sg;->OooOOOO:Landroid/view/Choreographer;

    iget-object v3, v0, Llyiahf/vczjk/sg;->OooOo0o:Llyiahf/vczjk/rg;

    invoke-virtual {v2, v3}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_2
    :goto_1
    monitor-exit p2

    new-instance p2, Llyiahf/vczjk/tg;

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/tg;-><init>(Llyiahf/vczjk/sg;Llyiahf/vczjk/vg;)V

    invoke-virtual {v1, p2}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    goto :goto_3

    :goto_2
    monitor-exit p2

    throw p1

    :cond_3
    iget-object p2, p0, Llyiahf/vczjk/wg;->OooOOO0:Landroid/view/Choreographer;

    invoke-virtual {p2, p1}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V

    new-instance p2, Llyiahf/vczjk/ug;

    invoke-direct {p2, p0, p1}, Llyiahf/vczjk/ug;-><init>(Llyiahf/vczjk/wg;Llyiahf/vczjk/vg;)V

    invoke-virtual {v1, p2}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    :goto_3
    invoke-virtual {v1}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method
