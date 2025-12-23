.class public final Llyiahf/vczjk/y11;
.super Llyiahf/vczjk/wy;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;)V
    .locals 6

    const-class v1, Ljava/util/Collection;

    move-object v0, p0

    move-object v2, p1

    move v3, p2

    move-object v4, p3

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wy;-><init>(Ljava/lang/Class;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 0

    check-cast p2, Ljava/util/Collection;

    invoke-interface {p2}, Ljava/util/Collection;->isEmpty()Z

    move-result p1

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    check-cast p1, Ljava/util/Collection;

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/wy;->_unwrapSingle:Ljava/lang/Boolean;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/ig8;->OooOooO:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-nez v1, :cond_1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/wy;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    if-ne v1, v2, :cond_2

    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/y11;->OooOOoo(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_2
    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/u94;->o0000o0O(ILjava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/y11;->OooOOoo(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000O()V

    return-void
.end method

.method public final OooOOO(Llyiahf/vczjk/d5a;)Llyiahf/vczjk/em1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/y11;

    iget-object v2, p0, Llyiahf/vczjk/wy;->_property:Llyiahf/vczjk/db0;

    iget-object v4, p0, Llyiahf/vczjk/wy;->_elementSerializer:Llyiahf/vczjk/zb4;

    iget-object v5, p0, Llyiahf/vczjk/wy;->_unwrapSingle:Ljava/lang/Boolean;

    move-object v1, p0

    move-object v3, p1

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wy;-><init>(Llyiahf/vczjk/wy;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V

    return-object v0
.end method

.method public final OooOOo(Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)Llyiahf/vczjk/wy;
    .locals 6

    new-instance v0, Llyiahf/vczjk/y11;

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v4, p3

    move-object v5, p4

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wy;-><init>(Llyiahf/vczjk/wy;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V

    return-object v0
.end method

.method public final bridge synthetic OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    check-cast p1, Ljava/util/Collection;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/y11;->OooOOoo(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method

.method public final OooOOoo(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 8

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/wy;->_elementSerializer:Llyiahf/vczjk/zb4;

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v3

    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_b

    iget-object v4, p0, Llyiahf/vczjk/wy;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    :cond_0
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_1

    :try_start_0
    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    goto :goto_0

    :catch_0
    move-exception p2

    goto :goto_1

    :cond_1
    if-nez v4, :cond_2

    invoke-virtual {v0, v5, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    goto :goto_0

    :cond_2
    invoke-virtual {v0, v5, p2, p3, v4}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :goto_0
    add-int/lit8 v2, v2, 0x1

    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-nez v5, :cond_0

    goto :goto_4

    :goto_1
    invoke-static {p3, p2, p1, v2}, Llyiahf/vczjk/b59;->OooOO0o(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;I)V

    throw v1

    :cond_3
    invoke-interface {p1}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-nez v3, :cond_4

    goto :goto_4

    :cond_4
    iget-object v3, p0, Llyiahf/vczjk/wy;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    iget-object v4, p0, Llyiahf/vczjk/wy;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    :cond_5
    :try_start_1
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    if-nez v5, :cond_6

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    goto :goto_3

    :catch_1
    move-exception p2

    goto :goto_5

    :cond_6
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v3, v6}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v7

    if-nez v7, :cond_9

    iget-object v7, p0, Llyiahf/vczjk/wy;->_elementType:Llyiahf/vczjk/x64;

    invoke-virtual {v7}, Llyiahf/vczjk/x64;->OoooOoO()Z

    move-result v7

    if-eqz v7, :cond_7

    iget-object v7, p0, Llyiahf/vczjk/wy;->_elementType:Llyiahf/vczjk/x64;

    invoke-virtual {p3, v6, v7}, Llyiahf/vczjk/tg8;->ooOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v6

    invoke-virtual {p0, v3, v6, p3}, Llyiahf/vczjk/wy;->OooOOOo(Llyiahf/vczjk/gb7;Llyiahf/vczjk/x64;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;

    move-result-object v3

    move-object v7, v3

    goto :goto_2

    :cond_7
    iget-object v7, p0, Llyiahf/vczjk/wy;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p3, v6, v7}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v7

    invoke-virtual {v3, v6, v7}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object v6

    if-eq v3, v6, :cond_8

    iput-object v6, p0, Llyiahf/vczjk/wy;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    :cond_8
    :goto_2
    iget-object v3, p0, Llyiahf/vczjk/wy;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    :cond_9
    if-nez v4, :cond_a

    invoke-virtual {v7, v5, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    goto :goto_3

    :cond_a
    invoke-virtual {v7, v5, p2, p3, v4}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    :goto_3
    add-int/lit8 v2, v2, 0x1

    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v5
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    if-nez v5, :cond_5

    :cond_b
    :goto_4
    return-void

    :goto_5
    invoke-static {p3, p2, p1, v2}, Llyiahf/vczjk/b59;->OooOO0o(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;I)V

    throw v1
.end method
