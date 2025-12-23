.class public final Llyiahf/vczjk/ye;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $methodSession:Llyiahf/vczjk/r04;

.field final synthetic this$0:Llyiahf/vczjk/af;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/r04;Llyiahf/vczjk/af;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ye;->$methodSession:Llyiahf/vczjk/r04;

    iput-object p2, p0, Llyiahf/vczjk/ye;->this$0:Llyiahf/vczjk/af;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Ljava/lang/Throwable;

    iget-object p1, p0, Llyiahf/vczjk/ye;->$methodSession:Llyiahf/vczjk/r04;

    iget-object v0, p1, Llyiahf/vczjk/r04;->OooO0OO:Ljava/lang/Object;

    monitor-enter v0

    const/4 v1, 0x1

    :try_start_0
    iput-boolean v1, p1, Llyiahf/vczjk/r04;->OooO0o0:Z

    iget-object v1, p1, Llyiahf/vczjk/r04;->OooO0Oo:Llyiahf/vczjk/ws5;

    iget-object v2, v1, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v1, v1, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x0

    :goto_0
    const/4 v4, 0x0

    if-ge v3, v1, :cond_1

    aget-object v5, v2, v3

    check-cast v5, Llyiahf/vczjk/ola;

    invoke-virtual {v5}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/z46;

    if-eqz v5, :cond_0

    iget-object v6, v5, Llyiahf/vczjk/z46;->OooO0O0:Llyiahf/vczjk/rj7;

    if-eqz v6, :cond_0

    invoke-virtual {v5, v6}, Llyiahf/vczjk/z46;->OooO00o(Llyiahf/vczjk/rj7;)V

    iput-object v4, v5, Llyiahf/vczjk/z46;->OooO0O0:Llyiahf/vczjk/rj7;

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_1
    iget-object p1, p1, Llyiahf/vczjk/r04;->OooO0Oo:Llyiahf/vczjk/ws5;

    invoke-virtual {p1}, Llyiahf/vczjk/ws5;->OooO0oO()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v0

    iget-object p1, p0, Llyiahf/vczjk/ye;->this$0:Llyiahf/vczjk/af;

    iget-object p1, p1, Llyiahf/vczjk/af;->OooOOO:Llyiahf/vczjk/tl9;

    iget-object v0, p1, Llyiahf/vczjk/tl9;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0, v4}, Ljava/util/concurrent/atomic/AtomicReference;->set(Ljava/lang/Object;)V

    iget-object p1, p1, Llyiahf/vczjk/tl9;->OooO00o:Llyiahf/vczjk/tx6;

    invoke-interface {p1}, Llyiahf/vczjk/tx6;->OooO0o()V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_1
    monitor-exit v0

    throw p1
.end method
