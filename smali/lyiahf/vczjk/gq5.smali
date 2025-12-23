.class public final Llyiahf/vczjk/gq5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/n62;

.field public final OooO00o:Ljava/lang/String;

.field public final OooO0O0:Llyiahf/vczjk/q44;

.field public final OooO0OO:Landroid/content/Context;

.field public final OooO0Oo:Llyiahf/vczjk/xr1;

.field public OooO0o:I

.field public final OooO0o0:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public OooO0oO:Llyiahf/vczjk/cs3;

.field public final OooO0oo:Llyiahf/vczjk/jl8;

.field public final OooOO0:Llyiahf/vczjk/fq5;

.field public final OooOO0O:Llyiahf/vczjk/kw;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Llyiahf/vczjk/q44;)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/gq5;->OooO00o:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/gq5;->OooO0O0:Llyiahf/vczjk/q44;

    invoke-virtual {p1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/gq5;->OooO0OO:Landroid/content/Context;

    iget-object p1, p3, Llyiahf/vczjk/q44;->OooO00o:Llyiahf/vczjk/ru7;

    invoke-virtual {p1}, Llyiahf/vczjk/ru7;->getCoroutineScope()Llyiahf/vczjk/xr1;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/gq5;->OooO0Oo:Llyiahf/vczjk/xr1;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 p2, 0x1

    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object p1, p0, Llyiahf/vczjk/gq5;->OooO0o0:Ljava/util/concurrent/atomic/AtomicBoolean;

    sget-object p1, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    const/4 p2, 0x0

    invoke-static {p2, p2, p1}, Llyiahf/vczjk/zsa;->OooOO0O(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/gq5;->OooO0oo:Llyiahf/vczjk/jl8;

    new-instance p1, Llyiahf/vczjk/n62;

    iget-object p2, p3, Llyiahf/vczjk/q44;->OooO0O0:[Ljava/lang/String;

    const/16 p3, 0x17

    invoke-direct {p1, p3, p0, p2}, Llyiahf/vczjk/n62;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/gq5;->OooO:Llyiahf/vczjk/n62;

    new-instance p1, Llyiahf/vczjk/fq5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/fq5;-><init>(Llyiahf/vczjk/gq5;)V

    iput-object p1, p0, Llyiahf/vczjk/gq5;->OooOO0:Llyiahf/vczjk/fq5;

    new-instance p1, Llyiahf/vczjk/kw;

    const/4 p2, 0x1

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/kw;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/gq5;->OooOO0O:Llyiahf/vczjk/kw;

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/content/Intent;)V
    .locals 6

    const-string v0, "serviceIntent"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/gq5;->OooO0o0:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x1

    const/4 v2, 0x0

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/atomic/AtomicBoolean;->compareAndSet(ZZ)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/gq5;->OooOO0O:Llyiahf/vczjk/kw;

    iget-object v2, p0, Llyiahf/vczjk/gq5;->OooO0OO:Landroid/content/Context;

    invoke-virtual {v2, p1, v0, v1}, Landroid/content/Context;->bindService(Landroid/content/Intent;Landroid/content/ServiceConnection;I)Z

    iget-object p1, p0, Llyiahf/vczjk/gq5;->OooO0O0:Llyiahf/vczjk/q44;

    iget-object v0, p0, Llyiahf/vczjk/gq5;->OooO:Llyiahf/vczjk/n62;

    const-string v1, "observer"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v0, Llyiahf/vczjk/n62;->OooOOO:Ljava/lang/Object;

    check-cast v1, [Ljava/lang/String;

    iget-object v2, p1, Llyiahf/vczjk/q44;->OooO0OO:Llyiahf/vczjk/b1a;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/b1a;->OooO0oO([Ljava/lang/String;)Llyiahf/vczjk/xn6;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, [Ljava/lang/String;

    invoke-virtual {v1}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [I

    new-instance v4, Llyiahf/vczjk/n86;

    invoke-direct {v4, v0, v1, v3}, Llyiahf/vczjk/n86;-><init>(Llyiahf/vczjk/n62;[I[Ljava/lang/String;)V

    iget-object v3, p1, Llyiahf/vczjk/q44;->OooO0o0:Ljava/util/concurrent/locks/ReentrantLock;

    invoke-virtual {v3}, Ljava/util/concurrent/locks/ReentrantLock;->lock()V

    iget-object p1, p1, Llyiahf/vczjk/q44;->OooO0Oo:Ljava/util/LinkedHashMap;

    :try_start_0
    invoke-interface {p1, v0}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-static {v0, p1}, Llyiahf/vczjk/lc5;->oo000o(Ljava/lang/Object;Ljava/util/Map;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n86;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    invoke-interface {p1, v0, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n86;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_0
    invoke-virtual {v3}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    if-nez p1, :cond_1

    iget-object p1, v2, Llyiahf/vczjk/b1a;->OooO0oo:Llyiahf/vczjk/zu1;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/zu1;->OooO([I)Z

    return-void

    :goto_1
    invoke-virtual {v3}, Ljava/util/concurrent/locks/ReentrantLock;->unlock()V

    throw p1

    :cond_1
    return-void
.end method
