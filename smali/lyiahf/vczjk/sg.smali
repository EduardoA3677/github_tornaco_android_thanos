.class public final Llyiahf/vczjk/sg;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"


# static fields
.field public static final OooOoO:Llyiahf/vczjk/qg;

.field public static final OooOoO0:Llyiahf/vczjk/sc9;


# instance fields
.field public final OooOOOO:Landroid/view/Choreographer;

.field public final OooOOOo:Landroid/os/Handler;

.field public final OooOOo:Llyiahf/vczjk/xx;

.field public final OooOOo0:Ljava/lang/Object;

.field public OooOOoo:Ljava/util/ArrayList;

.field public final OooOo:Llyiahf/vczjk/wg;

.field public OooOo0:Z

.field public OooOo00:Ljava/util/ArrayList;

.field public OooOo0O:Z

.field public final OooOo0o:Llyiahf/vczjk/rg;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/u;->OooOoO0:Llyiahf/vczjk/u;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/sg;->OooOoO0:Llyiahf/vczjk/sc9;

    new-instance v0, Llyiahf/vczjk/qg;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/qg;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/sg;->OooOoO:Llyiahf/vczjk/qg;

    return-void
.end method

.method public constructor <init>(Landroid/view/Choreographer;Landroid/os/Handler;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/qr1;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sg;->OooOOOO:Landroid/view/Choreographer;

    iput-object p2, p0, Llyiahf/vczjk/sg;->OooOOOo:Landroid/os/Handler;

    new-instance p2, Ljava/lang/Object;

    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/sg;->OooOOo0:Ljava/lang/Object;

    new-instance p2, Llyiahf/vczjk/xx;

    invoke-direct {p2}, Llyiahf/vczjk/xx;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/sg;->OooOOo:Llyiahf/vczjk/xx;

    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/sg;->OooOOoo:Ljava/util/ArrayList;

    new-instance p2, Ljava/util/ArrayList;

    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/sg;->OooOo00:Ljava/util/ArrayList;

    new-instance p2, Llyiahf/vczjk/rg;

    invoke-direct {p2, p0}, Llyiahf/vczjk/rg;-><init>(Llyiahf/vczjk/sg;)V

    iput-object p2, p0, Llyiahf/vczjk/sg;->OooOo0o:Llyiahf/vczjk/rg;

    new-instance p2, Llyiahf/vczjk/wg;

    invoke-direct {p2, p1, p0}, Llyiahf/vczjk/wg;-><init>(Landroid/view/Choreographer;Llyiahf/vczjk/sg;)V

    iput-object p2, p0, Llyiahf/vczjk/sg;->OooOo:Llyiahf/vczjk/wg;

    return-void
.end method

.method public static final o0000(Llyiahf/vczjk/sg;)V
    .locals 4

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/sg;->OooOOo0:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/sg;->OooOOo:Llyiahf/vczjk/xx;

    invoke-virtual {v1}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_1

    move-object v1, v3

    goto :goto_0

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/xx;->removeFirst()Ljava/lang/Object;

    move-result-object v1

    :goto_0
    check-cast v1, Ljava/lang/Runnable;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    monitor-exit v0

    :goto_1
    if-eqz v1, :cond_3

    invoke-interface {v1}, Ljava/lang/Runnable;->run()V

    iget-object v0, p0, Llyiahf/vczjk/sg;->OooOOo0:Ljava/lang/Object;

    monitor-enter v0

    :try_start_1
    iget-object v1, p0, Llyiahf/vczjk/sg;->OooOOo:Llyiahf/vczjk/xx;

    invoke-virtual {v1}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v2

    if-eqz v2, :cond_2

    move-object v1, v3

    goto :goto_2

    :cond_2
    invoke-virtual {v1}, Llyiahf/vczjk/xx;->removeFirst()Ljava/lang/Object;

    move-result-object v1

    :goto_2
    check-cast v1, Ljava/lang/Runnable;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v0

    goto :goto_1

    :catchall_0
    move-exception p0

    monitor-exit v0

    throw p0

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/sg;->OooOOo0:Ljava/lang/Object;

    monitor-enter v0

    :try_start_2
    iget-object v1, p0, Llyiahf/vczjk/sg;->OooOOo:Llyiahf/vczjk/xx;

    invoke-virtual {v1}, Llyiahf/vczjk/xx;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_4

    const/4 v1, 0x0

    iput-boolean v1, p0, Llyiahf/vczjk/sg;->OooOo0:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    goto :goto_3

    :catchall_1
    move-exception p0

    goto :goto_4

    :cond_4
    const/4 v1, 0x1

    :goto_3
    monitor-exit v0

    if-nez v1, :cond_0

    return-void

    :goto_4
    monitor-exit v0

    throw p0

    :catchall_2
    move-exception p0

    monitor-exit v0

    throw p0
.end method


# virtual methods
.method public final o00000o0(Llyiahf/vczjk/or1;Ljava/lang/Runnable;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/sg;->OooOOo0:Ljava/lang/Object;

    monitor-enter p1

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/sg;->OooOOo:Llyiahf/vczjk/xx;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/xx;->addLast(Ljava/lang/Object;)V

    iget-boolean p2, p0, Llyiahf/vczjk/sg;->OooOo0:Z

    if-nez p2, :cond_0

    const/4 p2, 0x1

    iput-boolean p2, p0, Llyiahf/vczjk/sg;->OooOo0:Z

    iget-object v0, p0, Llyiahf/vczjk/sg;->OooOOOo:Landroid/os/Handler;

    iget-object v1, p0, Llyiahf/vczjk/sg;->OooOo0o:Llyiahf/vczjk/rg;

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    iget-boolean v0, p0, Llyiahf/vczjk/sg;->OooOo0O:Z

    if-nez v0, :cond_0

    iput-boolean p2, p0, Llyiahf/vczjk/sg;->OooOo0O:Z

    iget-object p2, p0, Llyiahf/vczjk/sg;->OooOOOO:Landroid/view/Choreographer;

    iget-object v0, p0, Llyiahf/vczjk/sg;->OooOo0o:Llyiahf/vczjk/rg;

    invoke-virtual {p2, v0}, Landroid/view/Choreographer;->postFrameCallback(Landroid/view/Choreographer$FrameCallback;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p2

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit p1

    return-void

    :goto_1
    monitor-exit p1

    throw p2
.end method
