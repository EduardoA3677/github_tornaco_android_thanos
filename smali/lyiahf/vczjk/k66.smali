.class public final Llyiahf/vczjk/k66;
.super Llyiahf/vczjk/my;
.source "SourceFile"


# instance fields
.field protected _dynamicSerializers:Llyiahf/vczjk/gb7;

.field protected _elementSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _elementType:Llyiahf/vczjk/x64;

.field protected final _staticTyping:Z

.field protected final _valueTypeSerializer:Llyiahf/vczjk/d5a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k66;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1, p2, p5}, Llyiahf/vczjk/my;-><init>(Llyiahf/vczjk/my;Llyiahf/vczjk/db0;Ljava/lang/Boolean;)V

    iget-object p2, p1, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    iput-object p3, p0, Llyiahf/vczjk/k66;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iget-boolean p1, p1, Llyiahf/vczjk/k66;->_staticTyping:Z

    iput-boolean p1, p0, Llyiahf/vczjk/k66;->_staticTyping:Z

    sget-object p1, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p1, p0, Llyiahf/vczjk/k66;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    iput-object p4, p0, Llyiahf/vczjk/k66;->_elementSerializer:Llyiahf/vczjk/zb4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;ZLlyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V
    .locals 1

    const-class v0, [Ljava/lang/Object;

    invoke-direct {p0, v0}, Llyiahf/vczjk/my;-><init>(Ljava/lang/Class;)V

    iput-object p1, p0, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    iput-boolean p2, p0, Llyiahf/vczjk/k66;->_staticTyping:Z

    iput-object p3, p0, Llyiahf/vczjk/k66;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    sget-object p1, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p1, p0, Llyiahf/vczjk/k66;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    iput-object p4, p0, Llyiahf/vczjk/k66;->_elementSerializer:Llyiahf/vczjk/zb4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/k66;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p2}, Llyiahf/vczjk/d5a;->OooO00o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/d5a;

    move-result-object v0

    :cond_0
    move-object v4, v0

    const/4 v0, 0x0

    if-eqz p2, :cond_1

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v2

    if-eqz v1, :cond_1

    invoke-virtual {v2, v1}, Llyiahf/vczjk/yn;->OooO0Oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v1

    goto :goto_0

    :cond_1
    move-object v1, v0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v2}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object v2

    if-eqz v2, :cond_2

    sget-object v0, Llyiahf/vczjk/n94;->OooOOOO:Llyiahf/vczjk/n94;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/q94;->OooO0O0(Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v0

    :cond_2
    move-object v6, v0

    if-nez v1, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/k66;->_elementSerializer:Llyiahf/vczjk/zb4;

    :cond_3
    invoke-static {p1, p2, v1}, Llyiahf/vczjk/b59;->OooOO0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    if-eqz v1, :cond_4

    iget-boolean v2, p0, Llyiahf/vczjk/k66;->_staticTyping:Z

    if-eqz v2, :cond_4

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v1

    if-nez v1, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/tg8;->o00Ooo(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_4
    move-object v5, v0

    iget-object p1, p0, Llyiahf/vczjk/my;->_property:Llyiahf/vczjk/db0;

    if-ne p1, p2, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/k66;->_elementSerializer:Llyiahf/vczjk/zb4;

    if-ne v5, p1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/k66;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    if-ne p1, v4, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne p1, v6, :cond_5

    return-object p0

    :cond_5
    new-instance v1, Llyiahf/vczjk/k66;

    move-object v2, p0

    move-object v3, p2

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/k66;-><init>(Llyiahf/vczjk/k66;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V

    return-object v1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 0

    check-cast p2, [Ljava/lang/Object;

    array-length p1, p2

    if-nez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    check-cast p1, [Ljava/lang/Object;

    array-length v0, p1

    const/4 v1, 0x1

    if-ne v0, v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/ig8;->OooOooO:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-nez v1, :cond_1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    if-ne v1, v2, :cond_2

    :cond_1
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/k66;->OooOOo([Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_2
    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/u94;->o0000o0O(ILjava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/k66;->OooOOo([Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000O()V

    return-void
.end method

.method public final OooOOO(Llyiahf/vczjk/d5a;)Llyiahf/vczjk/em1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/k66;

    iget-object v1, p0, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    iget-boolean v2, p0, Llyiahf/vczjk/k66;->_staticTyping:Z

    iget-object v3, p0, Llyiahf/vczjk/k66;->_elementSerializer:Llyiahf/vczjk/zb4;

    invoke-direct {v0, v1, v2, p1, v3}, Llyiahf/vczjk/k66;-><init>(Llyiahf/vczjk/x64;ZLlyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V

    return-object v0
.end method

.method public final OooOOOo(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;
    .locals 6

    new-instance v0, Llyiahf/vczjk/k66;

    iget-object v3, p0, Llyiahf/vczjk/k66;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iget-object v4, p0, Llyiahf/vczjk/k66;->_elementSerializer:Llyiahf/vczjk/zb4;

    move-object v1, p0

    move-object v2, p1

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/k66;-><init>(Llyiahf/vczjk/k66;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V

    return-object v0
.end method

.method public final OooOOo([Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 8

    array-length v0, p1

    if-nez v0, :cond_0

    goto/16 :goto_9

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/k66;->_elementSerializer:Llyiahf/vczjk/zb4;

    const/4 v2, 0x0

    const/4 v3, 0x0

    if-eqz v1, :cond_3

    array-length v0, p1

    iget-object v4, p0, Llyiahf/vczjk/k66;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    move-object v5, v2

    :goto_0
    if-ge v3, v0, :cond_b

    :try_start_0
    aget-object v5, p1, v3

    if-nez v5, :cond_1

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_1
    if-nez v4, :cond_2

    invoke-virtual {v1, v5, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    goto :goto_1

    :cond_2
    invoke-virtual {v1, v5, p2, p3, v4}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :goto_1
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :goto_2
    invoke-static {p3, p1, v5, v3}, Llyiahf/vczjk/b59;->OooOO0o(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;I)V

    throw v2

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/k66;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    if-eqz v1, :cond_6

    array-length v0, p1

    :try_start_1
    iget-object v4, p0, Llyiahf/vczjk/k66;->_dynamicSerializers:Llyiahf/vczjk/gb7;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_2

    move-object v5, v2

    :goto_3
    if-ge v3, v0, :cond_b

    :try_start_2
    aget-object v5, p1, v3

    if-nez v5, :cond_4

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    goto :goto_4

    :catch_1
    move-exception p1

    goto :goto_5

    :cond_4
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v6

    invoke-virtual {v4, v6}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v7

    if-nez v7, :cond_5

    iget-object v7, p0, Llyiahf/vczjk/my;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p3, v6, v7}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v7

    invoke-virtual {v4, v6, v7}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object v6

    if-eq v4, v6, :cond_5

    iput-object v6, p0, Llyiahf/vczjk/k66;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    :cond_5
    invoke-virtual {v7, v5, p2, p3, v1}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    :goto_4
    add-int/lit8 v3, v3, 0x1

    goto :goto_3

    :catch_2
    move-exception p1

    move-object v5, v2

    :goto_5
    invoke-static {p3, p1, v5, v3}, Llyiahf/vczjk/b59;->OooOO0o(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;I)V

    throw v2

    :cond_6
    :try_start_3
    iget-object v1, p0, Llyiahf/vczjk/k66;->_dynamicSerializers:Llyiahf/vczjk/gb7;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_4

    move-object v4, v2

    :goto_6
    if-ge v3, v0, :cond_b

    :try_start_4
    aget-object v4, p1, v3

    if-nez v4, :cond_7

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    goto :goto_8

    :catch_3
    move-exception p1

    goto :goto_a

    :cond_7
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v5

    invoke-virtual {v1, v5}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v6

    if-nez v6, :cond_a

    iget-object v6, p0, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    invoke-virtual {v6}, Llyiahf/vczjk/x64;->OoooOoO()Z

    move-result v6

    if-eqz v6, :cond_9

    iget-object v6, p0, Llyiahf/vczjk/k66;->_elementType:Llyiahf/vczjk/x64;

    invoke-virtual {p3, v5, v6}, Llyiahf/vczjk/tg8;->ooOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/my;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {v1, v5, p3, v6}, Llyiahf/vczjk/gb7;->OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/a27;

    move-result-object v5

    iget-object v6, v5, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/gb7;

    if-eq v1, v6, :cond_8

    iput-object v6, p0, Llyiahf/vczjk/k66;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    :cond_8
    iget-object v5, v5, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/zb4;

    goto :goto_7

    :cond_9
    iget-object v6, p0, Llyiahf/vczjk/my;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p3, v5, v6}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v6

    invoke-virtual {v1, v5, v6}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object v5

    if-eq v1, v5, :cond_a

    iput-object v5, p0, Llyiahf/vczjk/k66;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    :cond_a
    :goto_7
    invoke-virtual {v6, v4, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_3

    :goto_8
    add-int/lit8 v3, v3, 0x1

    goto :goto_6

    :cond_b
    :goto_9
    return-void

    :catch_4
    move-exception p1

    move-object v4, v2

    :goto_a
    invoke-static {p3, p1, v4, v3}, Llyiahf/vczjk/b59;->OooOO0o(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;I)V

    throw v2
.end method

.method public final bridge synthetic OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    check-cast p1, [Ljava/lang/Object;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/k66;->OooOOo([Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method
