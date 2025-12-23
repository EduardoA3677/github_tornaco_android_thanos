.class public final Llyiahf/vczjk/rh7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:J

.field public final OooO0O0:Llyiahf/vczjk/tg9;

.field public final OooO0OO:Llyiahf/vczjk/oq3;

.field public final OooO0Oo:Ljava/util/concurrent/ConcurrentLinkedQueue;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vg9;)V
    .locals 3

    sget-object v0, Ljava/util/concurrent/TimeUnit;->MINUTES:Ljava/util/concurrent/TimeUnit;

    const-string v1, "taskRunner"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "timeUnit"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide/16 v1, 0x5

    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toNanos(J)J

    move-result-wide v0

    iput-wide v0, p0, Llyiahf/vczjk/rh7;->OooO00o:J

    invoke-virtual {p1}, Llyiahf/vczjk/vg9;->OooO0o0()Llyiahf/vczjk/tg9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/rh7;->OooO0O0:Llyiahf/vczjk/tg9;

    new-instance p1, Ljava/lang/StringBuilder;

    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v0, Llyiahf/vczjk/kba;->OooO0oO:Ljava/lang/String;

    const-string v1, " ConnectionPool"

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/oq3;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/oq3;-><init>(Llyiahf/vczjk/rh7;Ljava/lang/String;)V

    iput-object v0, p0, Llyiahf/vczjk/rh7;->OooO0OO:Llyiahf/vczjk/oq3;

    new-instance p1, Ljava/util/concurrent/ConcurrentLinkedQueue;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentLinkedQueue;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rh7;->OooO0Oo:Ljava/util/concurrent/ConcurrentLinkedQueue;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/o1;Llyiahf/vczjk/mh7;Ljava/util/ArrayList;Z)Z
    .locals 5

    const-string v0, "call"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/rh7;->OooO0Oo:Ljava/util/concurrent/ConcurrentLinkedQueue;

    invoke-virtual {v0}, Ljava/util/concurrent/ConcurrentLinkedQueue;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qh7;

    const-string v3, "connection"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    monitor-enter v1

    const/4 v3, 0x1

    if-eqz p4, :cond_1

    :try_start_0
    iget-object v4, v1, Llyiahf/vczjk/qh7;->OooO0oO:Llyiahf/vczjk/qq3;

    if-eqz v4, :cond_0

    move v2, v3

    :cond_0
    if-eqz v2, :cond_2

    :cond_1
    invoke-virtual {v1, p1, p3}, Llyiahf/vczjk/qh7;->OooO0oo(Llyiahf/vczjk/o1;Ljava/util/ArrayList;)Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-virtual {p2, v1}, Llyiahf/vczjk/mh7;->OooO0O0(Llyiahf/vczjk/qh7;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    return v3

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    monitor-exit v1

    goto :goto_0

    :goto_1
    monitor-exit v1

    throw p1

    :cond_3
    return v2
.end method

.method public final OooO0O0(Llyiahf/vczjk/qh7;J)I
    .locals 7

    const/4 v0, 0x1

    sget-object v1, Llyiahf/vczjk/kba;->OooO00o:[B

    iget-object v1, p1, Llyiahf/vczjk/qh7;->OooOOOo:Ljava/util/ArrayList;

    const/4 v2, 0x0

    move v3, v2

    :cond_0
    :goto_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v4

    if-ge v3, v4, :cond_2

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/ref/Reference;

    invoke-virtual {v4}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v5

    if-eqz v5, :cond_1

    add-int/2addr v3, v0

    goto :goto_0

    :cond_1
    check-cast v4, Llyiahf/vczjk/kh7;

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "A connection to "

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v6, p1, Llyiahf/vczjk/qh7;->OooO0O0:Llyiahf/vczjk/bw7;

    iget-object v6, v6, Llyiahf/vczjk/bw7;->OooO00o:Llyiahf/vczjk/o1;

    iget-object v6, v6, Llyiahf/vczjk/o1;->OooO0oo:Llyiahf/vczjk/lr3;

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v6, " was leaked. Did you forget to close a response body?"

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/yw6;->OooO00o:Llyiahf/vczjk/yw6;

    sget-object v6, Llyiahf/vczjk/yw6;->OooO00o:Llyiahf/vczjk/yw6;

    iget-object v4, v4, Llyiahf/vczjk/kh7;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v6, v4, v5}, Llyiahf/vczjk/yw6;->OooOO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    iput-boolean v0, p1, Llyiahf/vczjk/qh7;->OooOO0:Z

    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v4

    if-eqz v4, :cond_0

    iget-wide v0, p0, Llyiahf/vczjk/rh7;->OooO00o:J

    sub-long/2addr p2, v0

    iput-wide p2, p1, Llyiahf/vczjk/qh7;->OooOOo0:J

    return v2

    :cond_2
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result p1

    return p1
.end method
