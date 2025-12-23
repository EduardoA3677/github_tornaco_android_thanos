.class public abstract Llyiahf/vczjk/iw3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/Map;
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0xdecafL


# instance fields
.field public transient OooOOO:Llyiahf/vczjk/yn7;

.field public transient OooOOO0:Llyiahf/vczjk/xn7;

.field public transient OooOOOO:Llyiahf/vczjk/zn7;


# direct methods
.method private readObject(Ljava/io/ObjectInputStream;)V
    .locals 1

    new-instance p1, Ljava/io/InvalidObjectException;

    const-string v0, "Use SerializedForm"

    invoke-direct {p1, v0}, Ljava/io/InvalidObjectException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/kw3;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/iw3;->OooOOO0:Llyiahf/vczjk/xn7;

    if-nez v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ao7;

    new-instance v1, Llyiahf/vczjk/xn7;

    iget v2, v0, Llyiahf/vczjk/ao7;->OooOOo:I

    iget-object v3, v0, Llyiahf/vczjk/ao7;->OooOOo0:[Ljava/lang/Object;

    invoke-direct {v1, v0, v3, v2}, Llyiahf/vczjk/xn7;-><init>(Llyiahf/vczjk/iw3;[Ljava/lang/Object;I)V

    iput-object v1, p0, Llyiahf/vczjk/iw3;->OooOOO0:Llyiahf/vczjk/xn7;

    return-object v1

    :cond_0
    return-object v0
.end method

.method public final clear()V
    .locals 1

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw v0
.end method

.method public final containsKey(Ljava/lang/Object;)Z
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/iw3;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final containsValue(Ljava/lang/Object;)Z
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/iw3;->OooOOOO:Llyiahf/vczjk/zn7;

    if-nez v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ao7;

    new-instance v1, Llyiahf/vczjk/zn7;

    const/4 v2, 0x1

    iget v3, v0, Llyiahf/vczjk/ao7;->OooOOo:I

    iget-object v0, v0, Llyiahf/vczjk/ao7;->OooOOo0:[Ljava/lang/Object;

    invoke-direct {v1, v2, v3, v0}, Llyiahf/vczjk/zn7;-><init>(II[Ljava/lang/Object;)V

    iput-object v1, p0, Llyiahf/vczjk/iw3;->OooOOOO:Llyiahf/vczjk/zn7;

    move-object v0, v1

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw3;->contains(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final bridge synthetic entrySet()Ljava/util/Set;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/iw3;->OooO00o()Llyiahf/vczjk/kw3;

    move-result-object v0

    return-object v0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    instance-of v0, p1, Ljava/util/Map;

    if-eqz v0, :cond_1

    check-cast p1, Ljava/util/Map;

    invoke-virtual {p0}, Llyiahf/vczjk/iw3;->OooO00o()Llyiahf/vczjk/kw3;

    move-result-object v0

    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/kw3;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public abstract get(Ljava/lang/Object;)Ljava/lang/Object;
.end method

.method public final getOrDefault(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/iw3;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    return-object p2
.end method

.method public final hashCode()I
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/iw3;->OooO00o()Llyiahf/vczjk/kw3;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_0

    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    move-result v3

    goto :goto_1

    :cond_0
    move v3, v1

    :goto_1
    add-int/2addr v2, v3

    not-int v2, v2

    not-int v2, v2

    goto :goto_0

    :cond_1
    return v2
.end method

.method public final isEmpty()Z
    .locals 1

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ao7;

    invoke-virtual {v0}, Llyiahf/vczjk/ao7;->size()I

    move-result v0

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final keySet()Ljava/util/Set;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/iw3;->OooOOO:Llyiahf/vczjk/yn7;

    if-nez v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ao7;

    new-instance v1, Llyiahf/vczjk/zn7;

    const/4 v2, 0x0

    iget v3, v0, Llyiahf/vczjk/ao7;->OooOOo:I

    iget-object v4, v0, Llyiahf/vczjk/ao7;->OooOOo0:[Ljava/lang/Object;

    invoke-direct {v1, v2, v3, v4}, Llyiahf/vczjk/zn7;-><init>(II[Ljava/lang/Object;)V

    new-instance v2, Llyiahf/vczjk/yn7;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/yn7;-><init>(Llyiahf/vczjk/ao7;Llyiahf/vczjk/zn7;)V

    iput-object v2, p0, Llyiahf/vczjk/iw3;->OooOOO:Llyiahf/vczjk/yn7;

    return-object v2

    :cond_0
    return-object v0
.end method

.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final putAll(Ljava/util/Map;)V
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final remove(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ao7;

    const-string v1, "size"

    iget v0, v0, Llyiahf/vczjk/ao7;->OooOOo:I

    invoke-static {v0, v1}, Llyiahf/vczjk/ng0;->OooOOOO(ILjava/lang/String;)V

    new-instance v1, Ljava/lang/StringBuilder;

    int-to-long v2, v0

    const-wide/16 v4, 0x8

    mul-long/2addr v2, v4

    const-wide/32 v4, 0x40000000

    invoke-static {v2, v3, v4, v5}, Ljava/lang/Math;->min(JJ)J

    move-result-wide v2

    long-to-int v0, v2

    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    const/16 v0, 0x7b

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/iw3;->OooO00o()Llyiahf/vczjk/kw3;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xn7;

    invoke-virtual {v0}, Llyiahf/vczjk/xn7;->OooO0oo()Llyiahf/vczjk/e9a;

    move-result-object v0

    const/4 v2, 0x1

    :goto_0
    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/aw3;

    invoke-virtual {v3}, Llyiahf/vczjk/aw3;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/Map$Entry;

    if-nez v2, :cond_0

    const-string v2, ", "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    :cond_0
    invoke-interface {v3}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v2, 0x3d

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-interface {v3}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/4 v2, 0x0

    goto :goto_0

    :cond_1
    const/16 v0, 0x7d

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final values()Ljava/util/Collection;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/iw3;->OooOOOO:Llyiahf/vczjk/zn7;

    if-nez v0, :cond_0

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/ao7;

    new-instance v1, Llyiahf/vczjk/zn7;

    const/4 v2, 0x1

    iget v3, v0, Llyiahf/vczjk/ao7;->OooOOo:I

    iget-object v0, v0, Llyiahf/vczjk/ao7;->OooOOo0:[Ljava/lang/Object;

    invoke-direct {v1, v2, v3, v0}, Llyiahf/vczjk/zn7;-><init>(II[Ljava/lang/Object;)V

    iput-object v1, p0, Llyiahf/vczjk/iw3;->OooOOOO:Llyiahf/vczjk/zn7;

    return-object v1

    :cond_0
    return-object v0
.end method

.method public writeReplace()Ljava/lang/Object;
    .locals 1

    new-instance v0, Llyiahf/vczjk/hw3;

    invoke-direct {v0, p0}, Llyiahf/vczjk/hw3;-><init>(Llyiahf/vczjk/iw3;)V

    return-object v0
.end method
