.class public final Llyiahf/vczjk/tw8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/b39;
.implements Ljava/util/List;
.implements Ljava/util/RandomAccess;
.implements Llyiahf/vczjk/eg4;


# instance fields
.field public OooOOO0:Llyiahf/vczjk/qw8;


# direct methods
.method public constructor <init>()V
    .locals 5

    sget-object v0, Llyiahf/vczjk/qs8;->OooOOO:Llyiahf/vczjk/qs8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/qw8;

    invoke-virtual {v1}, Llyiahf/vczjk/nv8;->OooO0oO()J

    move-result-wide v3

    invoke-direct {v2, v3, v4, v0}, Llyiahf/vczjk/qw8;-><init>(JLlyiahf/vczjk/o00O;)V

    instance-of v1, v1, Llyiahf/vczjk/li3;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/qw8;

    const/4 v3, 0x1

    int-to-long v3, v3

    invoke-direct {v1, v3, v4, v0}, Llyiahf/vczjk/qw8;-><init>(JLlyiahf/vczjk/o00O;)V

    iput-object v1, v2, Llyiahf/vczjk/d39;->OooO0O0:Llyiahf/vczjk/d39;

    :cond_0
    iput-object v2, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    return-void
.end method

.method public static OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z
    .locals 2

    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget v1, p0, Llyiahf/vczjk/qw8;->OooO0Oo:I

    if-ne v1, p1, :cond_1

    iput-object p2, p0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    const/4 p1, 0x1

    if-eqz p3, :cond_0

    iget p2, p0, Llyiahf/vczjk/qw8;->OooO0o0:I

    add-int/2addr p2, p1

    iput p2, p0, Llyiahf/vczjk/qw8;->OooO0o0:I

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_2

    :cond_0
    :goto_0
    add-int/2addr v1, p1

    iput v1, p0, Llyiahf/vczjk/qw8;->OooO0Oo:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :cond_1
    const/4 p1, 0x0

    :goto_1
    monitor-exit v0

    return p1

    :goto_2
    monitor-exit v0

    throw p0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/d39;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    iput-object v0, p1, Llyiahf/vczjk/d39;->OooO0O0:Llyiahf/vczjk/d39;

    check-cast p1, Llyiahf/vczjk/qw8;

    iput-object p1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/d39;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    return-object v0
.end method

.method public final OooO0oo()Llyiahf/vczjk/qw8;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p0}, Llyiahf/vczjk/vv8;->OooOo00(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qw8;

    return-object v0
.end method

.method public final OooOO0()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qw8;

    iget v0, v0, Llyiahf/vczjk/qw8;->OooO0o0:I

    return v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/oe3;)Z
    .locals 7

    :cond_0
    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget v2, v1, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v1, v1, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1}, Llyiahf/vczjk/o00O;->OooO()Llyiahf/vczjk/dt6;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {v0}, Llyiahf/vczjk/dt6;->OooO0o()Llyiahf/vczjk/o00O;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v4, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v4

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v5

    invoke-static {v1, p0, v5}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    const/4 v6, 0x1

    invoke-static {v1, v2, v0, v6}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v4

    invoke-static {v5, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v0, :cond_0

    goto :goto_0

    :catchall_0
    move-exception p1

    monitor-exit v4

    throw p1

    :cond_1
    :goto_0
    check-cast v3, Ljava/lang/Boolean;

    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1

    :catchall_1
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final add(ILjava/lang/Object;)V
    .locals 6

    :cond_0
    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget v2, v1, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v1, v1, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/o00O;->OooO0O0(ILjava/lang/Object;)Llyiahf/vczjk/o00O;

    move-result-object v0

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v3

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v4

    invoke-static {v1, p0, v4}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    const/4 v5, 0x1

    invoke-static {v1, v2, v0, v5}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v3

    invoke-static {v4, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v0, :cond_0

    :goto_0
    return-void

    :catchall_0
    move-exception p1

    monitor-exit v3

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 6

    :cond_0
    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget v2, v1, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v1, v1, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o00O;->OooO0o(Ljava/lang/Object;)Llyiahf/vczjk/o00O;

    move-result-object v0

    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v3

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v4

    invoke-static {v1, p0, v4}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    const/4 v5, 0x1

    invoke-static {v1, v2, v0, v5}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v3

    invoke-static {v4, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v0, :cond_0

    return v5

    :catchall_0
    move-exception p1

    monitor-exit v3

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 1

    new-instance v0, Llyiahf/vczjk/rw8;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/rw8;-><init>(ILjava/util/Collection;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/tw8;->OooOO0O(Llyiahf/vczjk/oe3;)Z

    move-result p1

    return p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 6

    :cond_0
    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget v2, v1, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v1, v1, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o00O;->OooO0oo(Ljava/util/Collection;)Llyiahf/vczjk/o00O;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v3

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v4

    invoke-static {v1, p0, v4}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    const/4 v5, 0x1

    invoke-static {v1, v2, v0, v5}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v3

    invoke-static {v4, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v0, :cond_0

    return v5

    :catchall_0
    move-exception p1

    monitor-exit v3

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final clear()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v2

    invoke-static {v0, p0, v2}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qw8;

    sget-object v3, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :try_start_1
    sget-object v4, Llyiahf/vczjk/qs8;->OooOOO:Llyiahf/vczjk/qs8;

    iput-object v4, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    iget v4, v0, Llyiahf/vczjk/qw8;->OooO0Oo:I

    add-int/lit8 v4, v4, 0x1

    iput v4, v0, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget v4, v0, Llyiahf/vczjk/qw8;->OooO0o0:I

    add-int/lit8 v4, v4, 0x1

    iput v4, v0, Llyiahf/vczjk/qw8;->OooO0o0:I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    monitor-exit v3
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    monitor-exit v1

    invoke-static {v2, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    return-void

    :catchall_0
    move-exception v0

    goto :goto_0

    :catchall_1
    move-exception v0

    :try_start_3
    monitor-exit v3

    throw v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    :goto_0
    monitor-exit v1

    throw v0
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->OooO0oo()Llyiahf/vczjk/qw8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/o00O;->contains(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->OooO0oo()Llyiahf/vczjk/qw8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/o00O;->containsAll(Ljava/util/Collection;)Z

    move-result p1

    return p1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->OooO0oo()Llyiahf/vczjk/qw8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    invoke-interface {v0, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->OooO0oo()Llyiahf/vczjk/qw8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    invoke-interface {v0, p1}, Ljava/util/List;->indexOf(Ljava/lang/Object;)I

    move-result p1

    return p1
.end method

.method public final isEmpty()Z
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->OooO0oo()Llyiahf/vczjk/qw8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    check-cast v0, Llyiahf/vczjk/o0000O;

    invoke-virtual {v0}, Llyiahf/vczjk/o0000O;->isEmpty()Z

    move-result v0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->listIterator()Ljava/util/ListIterator;

    move-result-object v0

    return-object v0
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->OooO0oo()Llyiahf/vczjk/qw8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    invoke-interface {v0, p1}, Ljava/util/List;->lastIndexOf(Ljava/lang/Object;)I

    move-result p1

    return p1
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 2

    new-instance v0, Llyiahf/vczjk/co3;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/co3;-><init>(Llyiahf/vczjk/tw8;I)V

    return-object v0
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 1

    new-instance v0, Llyiahf/vczjk/co3;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/co3;-><init>(Llyiahf/vczjk/tw8;I)V

    return-object v0
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 7

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tw8;->get(I)Ljava/lang/Object;

    move-result-object v0

    :cond_0
    sget-object v1, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qw8;

    iget v3, v2, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v2, v2, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v1

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v2, p1}, Llyiahf/vczjk/o00O;->OooOO0O(I)Llyiahf/vczjk/o00O;

    move-result-object v1

    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_0

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v4, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v4

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v5

    invoke-static {v2, p0, v5}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qw8;

    const/4 v6, 0x1

    invoke-static {v2, v3, v1, v6}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v4

    invoke-static {v5, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v1, :cond_0

    :goto_0
    return-object v0

    :catchall_0
    move-exception p1

    monitor-exit v4

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v1

    throw p1
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 6

    :cond_0
    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget v2, v1, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v1, v1, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/o00O00O;->indexOf(Ljava/lang/Object;)I

    move-result v0

    const/4 v3, -0x1

    if-eq v0, v3, :cond_1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/o00O;->OooOO0O(I)Llyiahf/vczjk/o00O;

    move-result-object v0

    goto :goto_0

    :cond_1
    move-object v0, v1

    :goto_0
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    const/4 p1, 0x0

    return p1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v3

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v4

    invoke-static {v1, p0, v4}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    const/4 v5, 0x1

    invoke-static {v1, v2, v0, v5}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v3

    invoke-static {v4, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v0, :cond_0

    return v5

    :catchall_0
    move-exception p1

    monitor-exit v3

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 6

    :cond_0
    sget-object v0, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v0

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v2, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v1}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    iget v2, v1, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v1, v1, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v0

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    new-instance v0, Llyiahf/vczjk/oo0oOO0;

    invoke-direct {v0, p1}, Llyiahf/vczjk/oo0oOO0;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v1, v0}, Llyiahf/vczjk/o00O;->OooOO0(Llyiahf/vczjk/oo0oOO0;)Llyiahf/vczjk/o00O;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v3, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v3

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v4

    invoke-static {v1, p0, v4}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/qw8;

    const/4 v5, 0x1

    invoke-static {v1, v2, v0, v5}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v3

    invoke-static {v4, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v0, :cond_0

    return v5

    :catchall_0
    move-exception p1

    monitor-exit v3

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v0

    throw p1
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 1

    new-instance v0, Llyiahf/vczjk/sw8;

    invoke-direct {v0, p1}, Llyiahf/vczjk/sw8;-><init>(Ljava/util/Collection;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/tw8;->OooOO0O(Llyiahf/vczjk/oe3;)Z

    move-result p1

    return p1
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 7

    invoke-virtual {p0, p1}, Llyiahf/vczjk/tw8;->get(I)Ljava/lang/Object;

    move-result-object v0

    :cond_0
    sget-object v1, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v1

    :try_start_0
    iget-object v2, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v3, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v2}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qw8;

    iget v3, v2, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v2, v2, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v1

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v2, p1, p2}, Llyiahf/vczjk/o00O;->OooOO0o(ILjava/lang/Object;)Llyiahf/vczjk/o00O;

    move-result-object v1

    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_1

    goto :goto_0

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v4, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v4, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v4

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v5

    invoke-static {v2, p0, v5}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qw8;

    const/4 v6, 0x0

    invoke-static {v2, v3, v1, v6}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v4

    invoke-static {v5, p0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v1, :cond_0

    :goto_0
    return-object v0

    :catchall_0
    move-exception p1

    monitor-exit v4

    throw p1

    :catchall_1
    move-exception p1

    monitor-exit v1

    throw p1
.end method

.method public final size()I
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->OooO0oo()Llyiahf/vczjk/qw8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    check-cast v0, Llyiahf/vczjk/o0000O;

    invoke-virtual {v0}, Llyiahf/vczjk/o0000O;->OooO00o()I

    move-result v0

    return v0
.end method

.method public final subList(II)Ljava/util/List;
    .locals 1

    if-ltz p1, :cond_0

    if-gt p1, p2, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/tw8;->size()I

    move-result v0

    if-gt p2, v0, :cond_0

    const/4 v0, 0x1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    const-string v0, "fromIndex or toIndex are out of bounds"

    invoke-static {v0}, Llyiahf/vczjk/v07;->OooO00o(Ljava/lang/String;)V

    :cond_1
    new-instance v0, Llyiahf/vczjk/t79;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/t79;-><init>(Llyiahf/vczjk/tw8;II)V

    return-object v0
.end method

.method public final toArray()[Ljava/lang/Object;
    .locals 1

    invoke-static {p0}, Llyiahf/vczjk/nqa;->Oooo0oo(Ljava/util/Collection;)[Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final toArray([Ljava/lang/Object;)[Ljava/lang/Object;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/nqa;->Oooo(Ljava/util/Collection;[Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v1, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/qw8;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "SnapshotStateList(value="

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, v0, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, ")@"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
