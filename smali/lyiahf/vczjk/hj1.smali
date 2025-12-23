.class public abstract Llyiahf/vczjk/hj1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ss9;
.implements Ljava/lang/Comparable;


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/hj1;)I
    .locals 2

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    if-eq v0, v1, :cond_0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, v0}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    move-result p1

    return p1

    :cond_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/hj1;->OooO0Oo(Llyiahf/vczjk/hj1;)I

    move-result p1

    return p1
.end method

.method public abstract OooO0Oo(Llyiahf/vczjk/hj1;)I
.end method

.method public abstract OooO0o0()Ljava/lang/String;
.end method

.method public final bridge synthetic compareTo(Ljava/lang/Object;)I
    .locals 0

    check-cast p1, Llyiahf/vczjk/hj1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/hj1;->OooO0O0(Llyiahf/vczjk/hj1;)I

    move-result p1

    return p1
.end method
