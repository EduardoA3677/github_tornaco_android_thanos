.class public final Llyiahf/vczjk/qa7;
.super Llyiahf/vczjk/s66;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0O0(Ljava/lang/Class;)Llyiahf/vczjk/p66;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q66;->_scope:Ljava/lang/Class;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/qa7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/q66;-><init>(Ljava/lang/Class;)V

    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    new-instance p1, Ljava/lang/UnsupportedOperationException;

    invoke-direct {p1}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw p1
.end method

.method public final OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/o66;
    .locals 3

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/o66;

    const-class v1, Llyiahf/vczjk/qa7;

    iget-object v2, p0, Llyiahf/vczjk/q66;->_scope:Ljava/lang/Class;

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/o66;-><init>(Ljava/lang/Class;Ljava/lang/Object;Ljava/lang/Class;)V

    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/p66;
    .locals 0

    return-object p0
.end method
