.class public final Llyiahf/vczjk/i10;
.super Llyiahf/vczjk/pl7;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooOOOO(Ljava/lang/Object;Z)Llyiahf/vczjk/i10;
    .locals 8

    new-instance v0, Llyiahf/vczjk/i10;

    iget-object v2, p0, Llyiahf/vczjk/pl7;->_property:Llyiahf/vczjk/db0;

    iget-object v3, p0, Llyiahf/vczjk/pl7;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iget-object v4, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    iget-object v5, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    move-object v1, p0

    move-object v6, p1

    move v7, p2

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/pl7;-><init>(Llyiahf/vczjk/i10;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Llyiahf/vczjk/wt5;Ljava/lang/Object;Z)V

    return-object v0
.end method
