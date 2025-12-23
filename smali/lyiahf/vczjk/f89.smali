.class public final Llyiahf/vczjk/f89;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Collection;
.implements Llyiahf/vczjk/cg4;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/bs5;


# direct methods
.method public constructor <init>()V
    .locals 2

    sget v0, Llyiahf/vczjk/mf6;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/bs5;

    const/4 v1, 0x6

    invoke-direct {v0, v1}, Llyiahf/vczjk/bs5;-><init>(I)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    return-void
.end method


# virtual methods
.method public final add(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bs5;->OooO0O0(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "Operation is not supported for read-only collection"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final clear()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v0}, Llyiahf/vczjk/bs5;->OooO0OO()V

    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/lf6;->OooO00o(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final containsAll(Ljava/util/Collection;)Z
    .locals 2

    check-cast p1, Ljava/lang/Iterable;

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/lf6;->OooO00o(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_1
    const/4 p1, 0x1

    return p1
.end method

.method public final isEmpty()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    iget v0, v0, Llyiahf/vczjk/lf6;->OooO0oO:I

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/es5;

    invoke-direct {v1, v0}, Llyiahf/vczjk/es5;-><init>(Llyiahf/vczjk/bs5;)V

    new-instance v0, Llyiahf/vczjk/ds5;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ds5;-><init>(Llyiahf/vczjk/es5;)V

    return-object v0
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bs5;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bs5;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final removeIf(Ljava/util/function/Predicate;)Z
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "Operation is not supported for read-only collection"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bs5;->OooO(Ljava/util/Collection;)Z

    move-result p1

    return p1
.end method

.method public final size()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/f89;->OooOOO0:Llyiahf/vczjk/bs5;

    iget v0, v0, Llyiahf/vczjk/lf6;->OooO0oO:I

    return v0
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
