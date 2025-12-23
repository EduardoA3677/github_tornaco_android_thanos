.class public abstract Llyiahf/vczjk/hp2;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public abstract bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V
.end method

.method public abstract createQuery()Ljava/lang/String;
.end method

.method public final insert(Llyiahf/vczjk/j48;Ljava/lang/Iterable;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/lang/Iterable<",
            "Ljava/lang/Object;",
            ">;)V"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p2, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object p1

    :try_start_0
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_1
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {p1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {p1}, Llyiahf/vczjk/l48;->reset()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p2

    goto :goto_1

    :cond_2
    const/4 p2, 0x0

    invoke-static {p1, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-void

    :goto_1
    :try_start_1
    throw p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v0

    invoke-static {p1, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final insert(Llyiahf/vczjk/j48;Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/lang/Object;",
            ")V"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p2, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object p1

    :try_start_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {p1}, Llyiahf/vczjk/l48;->o000000()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 p2, 0x0

    invoke-static {p1, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-void

    :catchall_0
    move-exception p2

    :try_start_1
    throw p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v0

    invoke-static {p1, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final insert(Llyiahf/vczjk/j48;[Ljava/lang/Object;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "[",
            "Ljava/lang/Object;",
            ")V"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p2, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object p1

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object p2

    :cond_1
    :goto_0
    invoke-virtual {p2}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {p1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {p1}, Llyiahf/vczjk/l48;->reset()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p2

    goto :goto_1

    :cond_2
    const/4 p2, 0x0

    invoke-static {p1, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-void

    :goto_1
    :try_start_1
    throw p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception v0

    invoke-static {p1, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw v0
.end method

.method public final insertAndReturnId(Llyiahf/vczjk/j48;Ljava/lang/Object;)J
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/lang/Object;",
            ")J"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p2, :cond_0

    const-wide/16 p1, -0x1

    return-wide p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v0

    :try_start_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/l48;->o000000()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 p2, 0x0

    invoke-static {v0, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo00(Llyiahf/vczjk/j48;)J

    move-result-wide p1

    return-wide p1

    :catchall_0
    move-exception p1

    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p2

    invoke-static {v0, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final insertAndReturnIdsArray(Llyiahf/vczjk/j48;Ljava/util/Collection;)[J
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/util/Collection<",
            "Ljava/lang/Object;",
            ">;)[J"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-nez p2, :cond_0

    new-array p1, v0, [J

    return-object p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v2

    new-array v3, v2, [J

    :goto_0
    if-ge v0, v2, :cond_2

    move-object v4, p2

    check-cast v4, Ljava/lang/Iterable;

    check-cast v4, Ljava/util/Collection;

    invoke-static {v0, v4}, Llyiahf/vczjk/d21;->o00O0O(ILjava/util/Collection;)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-virtual {p0, v1, v4}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo00(Llyiahf/vczjk/j48;)J

    move-result-wide v4

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_1
    const-wide/16 v4, -0x1

    :goto_1
    aput-wide v4, v3, v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-object v3

    :goto_2
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p2

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final insertAndReturnIdsArray(Llyiahf/vczjk/j48;[Ljava/lang/Object;)[J
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "[",
            "Ljava/lang/Object;",
            ")[J"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-nez p2, :cond_0

    new-array p1, v0, [J

    return-object p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    array-length v2, p2

    new-array v3, v2, [J

    :goto_0
    if-ge v0, v2, :cond_2

    aget-object v4, p2, v0

    if-eqz v4, :cond_1

    invoke-virtual {p0, v1, v4}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo00(Llyiahf/vczjk/j48;)J

    move-result-wide v4

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_1
    const-wide/16 v4, -0x1

    :goto_1
    aput-wide v4, v3, v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-object v3

    :goto_2
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p2

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final insertAndReturnIdsArrayBox(Llyiahf/vczjk/j48;Ljava/util/Collection;)[Ljava/lang/Long;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/util/Collection<",
            "Ljava/lang/Object;",
            ">;)[",
            "Ljava/lang/Long;"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-nez p2, :cond_0

    new-array p1, v0, [Ljava/lang/Long;

    return-object p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result v2

    new-array v3, v2, [Ljava/lang/Long;

    :goto_0
    if-ge v0, v2, :cond_2

    move-object v4, p2

    check-cast v4, Ljava/lang/Iterable;

    check-cast v4, Ljava/util/Collection;

    invoke-static {v0, v4}, Llyiahf/vczjk/d21;->o00O0O(ILjava/util/Collection;)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_1

    invoke-virtual {p0, v1, v4}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo00(Llyiahf/vczjk/j48;)J

    move-result-wide v4

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_1
    const-wide/16 v4, -0x1

    :goto_1
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    aput-object v4, v3, v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-object v3

    :goto_2
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p2

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final insertAndReturnIdsArrayBox(Llyiahf/vczjk/j48;[Ljava/lang/Object;)[Ljava/lang/Long;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "[",
            "Ljava/lang/Object;",
            ")[",
            "Ljava/lang/Long;"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-nez p2, :cond_0

    new-array p1, v0, [Ljava/lang/Long;

    return-object p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    array-length v2, p2

    new-array v3, v2, [Ljava/lang/Long;

    :goto_0
    if-ge v0, v2, :cond_2

    aget-object v4, p2, v0

    if-eqz v4, :cond_1

    invoke-virtual {p0, v1, v4}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo00(Llyiahf/vczjk/j48;)J

    move-result-wide v4

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_1
    const-wide/16 v4, -0x1

    :goto_1
    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    aput-object v4, v3, v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return-object v3

    :goto_2
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p2

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final insertAndReturnIdsList(Llyiahf/vczjk/j48;Ljava/util/Collection;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/util/Collection<",
            "Ljava/lang/Object;",
            ">;)",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p2, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    check-cast p2, Ljava/lang/Iterable;

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {p0, v1, v2}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo00(Llyiahf/vczjk/j48;)J

    move-result-wide v2

    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_1
    const-wide/16 v2, -0x1

    invoke-static {v2, v3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    invoke-virtual {v0}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p1

    return-object p1

    :goto_1
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p2

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw p2
.end method

.method public final insertAndReturnIdsList(Llyiahf/vczjk/j48;[Ljava/lang/Object;)Ljava/util/List;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "[",
            "Ljava/lang/Object;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p2, :cond_0

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1

    :cond_0
    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/hp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    array-length v2, p2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_2

    aget-object v4, p2, v3

    if-eqz v4, :cond_1

    invoke-virtual {p0, v1, v4}, Llyiahf/vczjk/hp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo00(Llyiahf/vczjk/j48;)J

    move-result-wide v4

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_1
    const-wide/16 v4, -0x1

    invoke-static {v4, v5}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :goto_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    invoke-virtual {v0}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object p1

    return-object p1

    :goto_2
    :try_start_1
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :catchall_1
    move-exception p2

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    throw p2
.end method
