.class public final Llyiahf/vczjk/hb5;
.super Llyiahf/vczjk/o00O0O0;
.source "SourceFile"


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/eb5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/eb5;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->size()I

    move-result v0

    return v0
.end method

.method public final add(Ljava/lang/Object;)Z
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final addAll(Ljava/util/Collection;)Z
    .locals 1

    const-string v0, "elements"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final clear()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->clear()V

    return-void
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/eb5;->containsValue(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final isEmpty()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->isEmpty()Z

    move-result v0

    return v0
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/bb5;

    const/4 v2, 0x2

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/bb5;-><init>(Llyiahf/vczjk/eb5;I)V

    return-object v1
.end method

.method public final remove(Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0o()V

    invoke-virtual {v0, p1}, Llyiahf/vczjk/eb5;->OooOOo(Ljava/lang/Object;)I

    move-result p1

    if-gez p1, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/eb5;->OooOo0o(I)V

    const/4 p1, 0x1

    return p1
.end method

.method public final removeAll(Ljava/util/Collection;)Z
    .locals 1

    const-string v0, "elements"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0o()V

    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    move-result p1

    return p1
.end method

.method public final retainAll(Ljava/util/Collection;)Z
    .locals 1

    const-string v0, "elements"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/hb5;->OooOOO0:Llyiahf/vczjk/eb5;

    invoke-virtual {v0}, Llyiahf/vczjk/eb5;->OooOO0o()V

    invoke-super {p0, p1}, Ljava/util/AbstractCollection;->retainAll(Ljava/util/Collection;)Z

    move-result p1

    return p1
.end method
