.class public final Llyiahf/vczjk/mg8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j86;
.implements Llyiahf/vczjk/nc2;


# instance fields
.field public OooOOO:Llyiahf/vczjk/nc2;

.field public final OooOOO0:Llyiahf/vczjk/j86;

.field public OooOOOO:Z

.field public OooOOOo:Llyiahf/vczjk/yw;

.field public volatile OooOOo0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j86;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/mg8;->OooOOO0:Llyiahf/vczjk/j86;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-interface {v0}, Llyiahf/vczjk/nc2;->OooO00o()V

    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-static {v0, p1}, Llyiahf/vczjk/tc2;->OooO0o0(Llyiahf/vczjk/nc2;Llyiahf/vczjk/nc2;)Z

    move-result v0

    if-eqz v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/mg8;->OooOOO:Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/mg8;->OooOOO0:Llyiahf/vczjk/j86;

    invoke-interface {p1, p0}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    :cond_0
    return-void
.end method

.method public final OooO0OO(Ljava/lang/Throwable;)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    if-eqz v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    goto :goto_1

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOOO:Z

    const/4 v2, 0x0

    if-eqz v0, :cond_3

    iput-boolean v1, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    if-nez v0, :cond_2

    new-instance v0, Llyiahf/vczjk/yw;

    const/4 v1, 0x0

    const/4 v3, 0x0

    invoke-direct {v0, v1, v3}, Llyiahf/vczjk/yw;-><init>(IB)V

    iput-object v0, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_2
    :goto_0
    new-instance v1, Llyiahf/vczjk/y26;

    invoke-direct {v1, p1}, Llyiahf/vczjk/y26;-><init>(Ljava/lang/Throwable;)V

    iget-object p1, v0, Llyiahf/vczjk/yw;->OooO0OO:Ljava/lang/Object;

    check-cast p1, [Ljava/lang/Object;

    aput-object v1, p1, v2

    monitor-exit p0

    return-void

    :cond_3
    iput-boolean v1, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    iput-boolean v1, p0, Llyiahf/vczjk/mg8;->OooOOOO:Z

    move v1, v2

    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOO0:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public final OooO0Oo()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    monitor-enter p0

    :try_start_0
    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    if-eqz v0, :cond_1

    monitor-exit p0

    return-void

    :catchall_0
    move-exception v0

    goto :goto_0

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOOO:Z

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    if-nez v0, :cond_2

    new-instance v0, Llyiahf/vczjk/yw;

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/yw;-><init>(IB)V

    iput-object v0, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    :cond_2
    sget-object v1, Llyiahf/vczjk/z26;->OooOOO0:Llyiahf/vczjk/z26;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yw;->OooO0O0(Ljava/lang/Object;)V

    monitor-exit p0

    return-void

    :cond_3
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    iput-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOOO:Z

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOO0:Llyiahf/vczjk/j86;

    invoke-interface {v0}, Llyiahf/vczjk/j86;->OooO0Oo()V

    return-void

    :goto_0
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public final OooOO0O(Ljava/lang/Object;)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    if-eqz v0, :cond_0

    goto/16 :goto_5

    :cond_0
    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/mg8;->OooOOO:Llyiahf/vczjk/nc2;

    invoke-interface {p1}, Llyiahf/vczjk/nc2;->OooO00o()V

    new-instance p1, Ljava/lang/NullPointerException;

    const-string v0, "onNext called with null. Null values are generally not allowed in 2.x operators and sources."

    invoke-direct {p1, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Llyiahf/vczjk/mg8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_1
    monitor-enter p0

    :try_start_0
    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOo0:Z

    if-eqz v0, :cond_2

    monitor-exit p0

    return-void

    :catchall_0
    move-exception p1

    goto :goto_7

    :cond_2
    iget-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOOO:Z

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    if-nez v0, :cond_3

    new-instance v0, Llyiahf/vczjk/yw;

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/yw;-><init>(IB)V

    iput-object v0, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    :cond_3
    invoke-virtual {v0, p1}, Llyiahf/vczjk/yw;->OooO0O0(Ljava/lang/Object;)V

    monitor-exit p0

    return-void

    :cond_4
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/mg8;->OooOOOO:Z

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOO0:Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    :cond_5
    monitor-enter p0

    :try_start_1
    iget-object p1, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    if-nez p1, :cond_6

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/mg8;->OooOOOO:Z

    monitor-exit p0

    return-void

    :catchall_1
    move-exception p1

    goto :goto_6

    :cond_6
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/mg8;->OooOOOo:Llyiahf/vczjk/yw;

    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    iget-object v0, p0, Llyiahf/vczjk/mg8;->OooOOO0:Llyiahf/vczjk/j86;

    iget-object p1, p1, Llyiahf/vczjk/yw;->OooO0OO:Ljava/lang/Object;

    check-cast p1, [Ljava/lang/Object;

    :goto_0
    const/4 v1, 0x0

    if-eqz p1, :cond_b

    :goto_1
    const/4 v2, 0x4

    if-ge v1, v2, :cond_a

    aget-object v3, p1, v1

    if-nez v3, :cond_7

    goto :goto_3

    :cond_7
    sget-object v2, Llyiahf/vczjk/z26;->OooOOO0:Llyiahf/vczjk/z26;

    if-ne v3, v2, :cond_8

    invoke-interface {v0}, Llyiahf/vczjk/j86;->OooO0Oo()V

    goto :goto_2

    :cond_8
    instance-of v2, v3, Llyiahf/vczjk/y26;

    if-eqz v2, :cond_9

    check-cast v3, Llyiahf/vczjk/y26;

    iget-object p1, v3, Llyiahf/vczjk/y26;->e:Ljava/lang/Throwable;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    :goto_2
    const/4 v1, 0x1

    goto :goto_4

    :cond_9
    invoke-interface {v0, v3}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_a
    :goto_3
    aget-object p1, p1, v2

    check-cast p1, [Ljava/lang/Object;

    goto :goto_0

    :cond_b
    :goto_4
    if-eqz v1, :cond_5

    :goto_5
    return-void

    :goto_6
    :try_start_2
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    throw p1

    :goto_7
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p1
.end method
