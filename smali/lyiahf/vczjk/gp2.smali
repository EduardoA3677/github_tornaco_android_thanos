.class public abstract Llyiahf/vczjk/gp2;
.super Ljava/lang/Object;
.source "SourceFile"


# virtual methods
.method public abstract bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V
.end method

.method public abstract createQuery()Ljava/lang/String;
.end method

.method public final handle(Llyiahf/vczjk/j48;Ljava/lang/Object;)I
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/lang/Object;",
            ")I"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    if-nez p2, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/gp2;->createQuery()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p1, v0}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v0

    :try_start_0
    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/gp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v0}, Llyiahf/vczjk/l48;->o000000()Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 p2, 0x0

    invoke-static {v0, p2}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo0(Llyiahf/vczjk/j48;)I

    move-result p1

    return p1

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

.method public final handleMultiple(Llyiahf/vczjk/j48;Ljava/lang/Iterable;)I
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "Ljava/lang/Iterable<",
            "Ljava/lang/Object;",
            ">;)I"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-nez p2, :cond_0

    return v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/gp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :cond_1
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {p0, v1, v2}, Llyiahf/vczjk/gp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo0(Llyiahf/vczjk/j48;)I

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    add-int/2addr v0, v2

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return v0

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

.method public final handleMultiple(Llyiahf/vczjk/j48;[Ljava/lang/Object;)I
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/j48;",
            "[",
            "Ljava/lang/Object;",
            ")I"
        }
    .end annotation

    const-string v0, "connection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    if-nez p2, :cond_0

    return v0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/gp2;->createQuery()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p1, v1}, Llyiahf/vczjk/j48;->o00000OO(Ljava/lang/String;)Llyiahf/vczjk/l48;

    move-result-object v1

    :try_start_0
    invoke-static {p2}, Llyiahf/vczjk/bua;->OooOooo([Ljava/lang/Object;)Llyiahf/vczjk/o00O000;

    move-result-object p2

    :cond_1
    :goto_0
    invoke-virtual {p2}, Llyiahf/vczjk/o00O000;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/o00O000;->next()Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {p0, v1, v2}, Llyiahf/vczjk/gp2;->bind(Llyiahf/vczjk/l48;Ljava/lang/Object;)V

    invoke-interface {v1}, Llyiahf/vczjk/l48;->o000000()Z

    invoke-interface {v1}, Llyiahf/vczjk/l48;->reset()V

    invoke-static {p1}, Llyiahf/vczjk/rd3;->OooOo0(Llyiahf/vczjk/j48;)I

    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    add-int/2addr v0, v2

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_2
    const/4 p1, 0x0

    invoke-static {v1, p1}, Llyiahf/vczjk/cp7;->OooOO0(Llyiahf/vczjk/l48;Ljava/lang/Throwable;)V

    return v0

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
