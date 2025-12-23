.class public final Llyiahf/vczjk/t79;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/List;
.implements Llyiahf/vczjk/eg4;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:Llyiahf/vczjk/tw8;

.field public OooOOOO:I

.field public OooOOOo:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tw8;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    iput p2, p0, Llyiahf/vczjk/t79;->OooOOO:I

    invoke-virtual {p1}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    sub-int/2addr p3, p2

    iput p3, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {v0}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    if-ne v0, v1, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/util/ConcurrentModificationException;

    invoke-direct {v0}, Ljava/util/ConcurrentModificationException;-><init>()V

    throw v0
.end method

.method public final add(ILjava/lang/Object;)V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr v0, p1

    iget-object p1, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/tw8;->add(ILjava/lang/Object;)V

    iget p2, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    add-int/lit8 p2, p2, 0x1

    iput p2, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-virtual {p1}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    return-void
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr v1, v0

    iget-object v0, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/tw8;->add(ILjava/lang/Object;)V

    iget p1, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    const/4 v1, 0x1

    add-int/2addr p1, v1

    iput p1, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-virtual {v0}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    return v1
.end method

.method public final addAll(ILjava/util/Collection;)Z
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr p1, v0

    iget-object v0, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/tw8;->addAll(ILjava/util/Collection;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p2

    add-int/2addr p2, v1

    iput p2, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-virtual {v0}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result p2

    iput p2, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    :cond_0
    return p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-virtual {p0, v0, p1}, Llyiahf/vczjk/t79;->addAll(ILjava/util/Collection;)Z

    move-result p1

    return p1
.end method

.method public final clear()V
    .locals 9

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    if-lez v0, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget-object v0, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOO:I

    iget v2, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    add-int/2addr v2, v1

    :cond_0
    sget-object v3, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v3

    :try_start_0
    iget-object v4, v0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v5, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/qw8;

    iget v5, v4, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v4, v4, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v3

    invoke-static {v4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4}, Llyiahf/vczjk/o00O;->OooO()Llyiahf/vczjk/dt6;

    move-result-object v3

    invoke-virtual {v3, v1, v2}, Ljava/util/AbstractList;->subList(II)Ljava/util/List;

    move-result-object v6

    invoke-interface {v6}, Ljava/util/List;->clear()V

    invoke-virtual {v3}, Llyiahf/vczjk/dt6;->OooO0o()Llyiahf/vczjk/o00O;

    move-result-object v3

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1

    iget-object v4, v0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v6, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v4, v6}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v6, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v6

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v7

    invoke-static {v4, v0, v7}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/qw8;

    const/4 v8, 0x1

    invoke-static {v4, v5, v3, v8}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v6

    invoke-static {v7, v0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v3, :cond_0

    goto :goto_0

    :catchall_0
    move-exception v0

    monitor-exit v6

    throw v0

    :cond_1
    :goto_0
    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    iget-object v0, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {v0}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result v0

    iput v0, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    return-void

    :catchall_1
    move-exception v0

    monitor-exit v3

    throw v0

    :cond_2
    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/t79;->indexOf(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 2

    check-cast p1, Ljava/lang/Iterable;

    instance-of v0, p1, Ljava/util/Collection;

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Ljava/util/Collection;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    return v1

    :cond_0
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/t79;->contains(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_2
    return v1
.end method

.method public final get(I)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-static {p1, v0}, Llyiahf/vczjk/ng0;->OooO(II)V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr v0, p1

    iget-object p1, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tw8;->get(I)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final indexOf(Ljava/lang/Object;)I
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr v0, v1

    invoke-static {v1, v0}, Llyiahf/vczjk/vt6;->Oooo0oO(II)Llyiahf/vczjk/x14;

    move-result-object v0

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/n14;

    invoke-virtual {v2}, Llyiahf/vczjk/n14;->OooO00o()I

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/tw8;->get(I)Ljava/lang/Object;

    move-result-object v3

    invoke-static {p1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v3

    if-eqz v3, :cond_0

    sub-int/2addr v2, v1

    return v2

    :cond_1
    const/4 p1, -0x1

    return p1
.end method

.method public final isEmpty()Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/t79;->listIterator(I)Ljava/util/ListIterator;

    move-result-object v0

    return-object v0
.end method

.method public final lastIndexOf(Ljava/lang/Object;)I
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr v0, v1

    add-int/lit8 v0, v0, -0x1

    :goto_0
    if-lt v0, v1, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/tw8;->get(I)Ljava/lang/Object;

    move-result-object v2

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_0

    sub-int/2addr v0, v1

    return v0

    :cond_0
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    const/4 p1, -0x1

    return p1
.end method

.method public final listIterator()Ljava/util/ListIterator;
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/t79;->listIterator(I)Ljava/util/ListIterator;

    move-result-object v0

    return-object v0
.end method

.method public final listIterator(I)Ljava/util/ListIterator;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    new-instance v0, Llyiahf/vczjk/fl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    add-int/lit8 p1, p1, -0x1

    iput p1, v0, Llyiahf/vczjk/fl7;->element:I

    new-instance p1, Llyiahf/vczjk/ht7;

    invoke-direct {p1, v0, p0}, Llyiahf/vczjk/ht7;-><init>(Llyiahf/vczjk/fl7;Llyiahf/vczjk/t79;)V

    return-object p1
.end method

.method public final remove(I)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr v0, p1

    iget-object p1, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tw8;->remove(I)Ljava/lang/Object;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    add-int/lit8 v1, v1, -0x1

    iput v1, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-virtual {p1}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    return-object v0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/t79;->indexOf(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/t79;->remove(I)Ljava/lang/Object;

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 3

    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p1

    const/4 v0, 0x0

    :cond_0
    move v1, v0

    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {p0, v2}, Llyiahf/vczjk/t79;->remove(Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_1

    if-eqz v1, :cond_0

    :cond_1
    const/4 v1, 0x1

    goto :goto_0

    :cond_2
    return v1
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 10

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget-object v0, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOO:I

    iget v2, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    add-int/2addr v2, v1

    invoke-virtual {v0}, Llyiahf/vczjk/tw8;->size()I

    move-result v3

    :cond_0
    sget-object v4, Llyiahf/vczjk/ng0;->OooO0oO:Ljava/lang/Object;

    monitor-enter v4

    :try_start_0
    iget-object v5, v0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v6, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v5, v6}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v5}, Llyiahf/vczjk/vv8;->OooO(Llyiahf/vczjk/d39;)Llyiahf/vczjk/d39;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qw8;

    iget v6, v5, Llyiahf/vczjk/qw8;->OooO0Oo:I

    iget-object v5, v5, Llyiahf/vczjk/qw8;->OooO0OO:Llyiahf/vczjk/o00O;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    monitor-exit v4

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v5}, Llyiahf/vczjk/o00O;->OooO()Llyiahf/vczjk/dt6;

    move-result-object v4

    invoke-virtual {v4, v1, v2}, Ljava/util/AbstractList;->subList(II)Ljava/util/List;

    move-result-object v7

    invoke-interface {v7, p1}, Ljava/util/List;->retainAll(Ljava/util/Collection;)Z

    invoke-virtual {v4}, Llyiahf/vczjk/dt6;->OooO0o()Llyiahf/vczjk/o00O;

    move-result-object v4

    invoke-static {v4, v5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    const/4 v7, 0x1

    if-nez v5, :cond_1

    iget-object v5, v0, Llyiahf/vczjk/tw8;->OooOOO0:Llyiahf/vczjk/qw8;

    const-string v8, "null cannot be cast to non-null type androidx.compose.runtime.snapshots.SnapshotStateList.StateListStateRecord<T of androidx.compose.runtime.snapshots.SnapshotStateList>"

    invoke-static {v5, v8}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v8, Llyiahf/vczjk/vv8;->OooO0O0:Ljava/lang/Object;

    monitor-enter v8

    :try_start_1
    invoke-static {}, Llyiahf/vczjk/vv8;->OooOO0O()Llyiahf/vczjk/nv8;

    move-result-object v9

    invoke-static {v5, v0, v9}, Llyiahf/vczjk/vv8;->OooOo0o(Llyiahf/vczjk/d39;Llyiahf/vczjk/b39;Llyiahf/vczjk/nv8;)Llyiahf/vczjk/d39;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/qw8;

    invoke-static {v5, v6, v4, v7}, Llyiahf/vczjk/tw8;->OooO0o(Llyiahf/vczjk/qw8;ILlyiahf/vczjk/o00O;Z)Z

    move-result v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    monitor-exit v8

    invoke-static {v9, v0}, Llyiahf/vczjk/vv8;->OooOOO(Llyiahf/vczjk/nv8;Llyiahf/vczjk/b39;)V

    if-eqz v4, :cond_0

    goto :goto_0

    :catchall_0
    move-exception p1

    monitor-exit v8

    throw p1

    :cond_1
    :goto_0
    invoke-virtual {v0}, Llyiahf/vczjk/tw8;->size()I

    move-result p1

    sub-int/2addr v3, p1

    if-lez v3, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {p1}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result p1

    iput p1, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    iget p1, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    sub-int/2addr p1, v3

    iput p1, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    :cond_2
    if-lez v3, :cond_3

    return v7

    :cond_3
    const/4 p1, 0x0

    return p1

    :catchall_1
    move-exception p1

    monitor-exit v4

    throw p1
.end method

.method public final set(ILjava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    invoke-static {p1, v0}, Llyiahf/vczjk/ng0;->OooO(II)V

    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr p1, v0

    iget-object v0, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/tw8;->set(ILjava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/tw8;->OooOO0()I

    move-result p2

    iput p2, p0, Llyiahf/vczjk/t79;->OooOOOO:I

    return-object p1
.end method

.method public final size()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

    return v0
.end method

.method public final subList(II)Ljava/util/List;
    .locals 2

    if-ltz p1, :cond_0

    if-gt p1, p2, :cond_0

    iget v0, p0, Llyiahf/vczjk/t79;->OooOOOo:I

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
    invoke-virtual {p0}, Llyiahf/vczjk/t79;->OooO00o()V

    new-instance v0, Llyiahf/vczjk/t79;

    iget v1, p0, Llyiahf/vczjk/t79;->OooOOO:I

    add-int/2addr p1, v1

    add-int/2addr p2, v1

    iget-object v1, p0, Llyiahf/vczjk/t79;->OooOOO0:Llyiahf/vczjk/tw8;

    invoke-direct {v0, v1, p1, p2}, Llyiahf/vczjk/t79;-><init>(Llyiahf/vczjk/tw8;II)V

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
