.class public final Llyiahf/vczjk/tg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $callback:Landroid/view/Choreographer$FrameCallback;

.field final synthetic $uiDispatcher:Llyiahf/vczjk/sg;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sg;Llyiahf/vczjk/vg;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tg;->$uiDispatcher:Llyiahf/vczjk/sg;

    iput-object p2, p0, Llyiahf/vczjk/tg;->$callback:Landroid/view/Choreographer$FrameCallback;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/tg;->$uiDispatcher:Llyiahf/vczjk/sg;

    iget-object v0, p0, Llyiahf/vczjk/tg;->$callback:Landroid/view/Choreographer$FrameCallback;

    iget-object v1, p1, Llyiahf/vczjk/sg;->OooOOo0:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    iget-object p1, p1, Llyiahf/vczjk/sg;->OooOOoo:Ljava/util/ArrayList;

    invoke-virtual {p1, v0}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_0
    move-exception p1

    monitor-exit v1

    throw p1
.end method
