.class public final Llyiahf/vczjk/zb5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Map;
.implements Llyiahf/vczjk/cg4;


# instance fields
.field public OooOOO:Llyiahf/vczjk/jp2;

.field public final OooOOO0:Llyiahf/vczjk/js5;

.field public OooOOOO:Llyiahf/vczjk/bk4;

.field public OooOOOo:Llyiahf/vczjk/xca;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/js5;)V
    .locals 1

    const-string v0, "parent"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    return-void
.end method


# virtual methods
.method public final clear()V
    .locals 2

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    const-string v1, "Operation is not supported for read-only collection"

    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final compute(Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final computeIfPresent(Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooO0OO(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final containsValue(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooO0Oo(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final entrySet()Ljava/util/Set;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO:Llyiahf/vczjk/jp2;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/jp2;

    iget-object v1, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-direct {v0, v1}, Llyiahf/vczjk/jp2;-><init>(Llyiahf/vczjk/js5;)V

    iput-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO:Llyiahf/vczjk/jp2;

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    if-eqz p1, :cond_2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    const-class v1, Llyiahf/vczjk/zb5;

    if-eq v1, v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Llyiahf/vczjk/zb5;

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    iget-object p1, p1, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_2
    :goto_0
    const/4 p1, 0x0

    return p1
.end method

.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0}, Llyiahf/vczjk/js5;->hashCode()I

    move-result v0

    return v0
.end method

.method public final isEmpty()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0}, Llyiahf/vczjk/js5;->OooO()Z

    move-result v0

    return v0
.end method

.method public final keySet()Ljava/util/Set;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOOO:Llyiahf/vczjk/bk4;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/bk4;

    iget-object v1, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-direct {v0, v1}, Llyiahf/vczjk/bk4;-><init>(Llyiahf/vczjk/js5;)V

    iput-object v0, p0, Llyiahf/vczjk/zb5;->OooOOOO:Llyiahf/vczjk/bk4;

    return-object v0
.end method

.method public final merge(Ljava/lang/Object;Ljava/lang/Object;Ljava/util/function/BiFunction;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final putAll(Ljava/util/Map;)V
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "Operation is not supported for read-only collection"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "Operation is not supported for read-only collection"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final remove(Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final replace(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final replace(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string p2, "Operation is not supported for read-only collection"

    invoke-direct {p1, p2}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final replaceAll(Ljava/util/function/BiFunction;)V
    .locals 1

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    const-string v0, "Operation is not supported for read-only collection"

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final size()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    iget v0, v0, Llyiahf/vczjk/js5;->OooO0o0:I

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-virtual {v0}, Llyiahf/vczjk/js5;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final values()Ljava/util/Collection;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zb5;->OooOOOo:Llyiahf/vczjk/xca;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/xca;

    iget-object v1, p0, Llyiahf/vczjk/zb5;->OooOOO0:Llyiahf/vczjk/js5;

    invoke-direct {v0, v1}, Llyiahf/vczjk/xca;-><init>(Llyiahf/vczjk/js5;)V

    iput-object v0, p0, Llyiahf/vczjk/zb5;->OooOOOo:Llyiahf/vczjk/xca;

    return-object v0
.end method
