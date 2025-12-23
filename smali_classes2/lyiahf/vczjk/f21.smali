.class public abstract Llyiahf/vczjk/f21;
.super Llyiahf/vczjk/e21;
.source "SourceFile"


# direct methods
.method public static o000oOoO(Ljava/lang/Iterable;I)I
    .locals 1

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    instance-of v0, p0, Ljava/util/Collection;

    if-eqz v0, :cond_0

    check-cast p0, Ljava/util/Collection;

    invoke-interface {p0}, Ljava/util/Collection;->size()I

    move-result p0

    return p0

    :cond_0
    return p1
.end method
