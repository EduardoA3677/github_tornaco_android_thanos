.class public Llyiahf/vczjk/xy;
.super Llyiahf/vczjk/v3a;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xy;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xy;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xy;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v3a;->_property:Llyiahf/vczjk/db0;

    if-ne p1, v0, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/xy;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/v3a;-><init>(Llyiahf/vczjk/v3a;Llyiahf/vczjk/db0;)V

    return-object v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xy;->OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooOO0()Llyiahf/vczjk/kc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/kc4;->OooOOOO:Llyiahf/vczjk/kc4;

    return-object v0
.end method

.method public final OooOOO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooO0oO()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000OO0()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/v3a;->OooOO0O(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v1

    const/4 v2, 0x0

    const/4 v3, 0x0

    if-nez v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    if-eqz v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    check-cast v1, Llyiahf/vczjk/e4a;

    iget-object v4, v1, Llyiahf/vczjk/e4a;->OooO0O0:Llyiahf/vczjk/x64;

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    invoke-interface {v1, v4, v2}, Llyiahf/vczjk/d4a;->OooO0Oo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    goto :goto_0

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    const-string v4, "need JSON Array to contain As.WRAPPER_ARRAY type information for class "

    invoke-virtual {v4, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    new-array v3, v3, [Ljava/lang/Object;

    invoke-virtual {p1, p2, v0, v1, v3}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v4, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    if-ne v1, v4, :cond_3

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    goto :goto_0

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/v3a;->_defaultImpl:Llyiahf/vczjk/x64;

    if-eqz v1, :cond_8

    iget-object v1, p0, Llyiahf/vczjk/v3a;->_idResolver:Llyiahf/vczjk/d4a;

    check-cast v1, Llyiahf/vczjk/e4a;

    iget-object v4, v1, Llyiahf/vczjk/e4a;->OooO0O0:Llyiahf/vczjk/x64;

    invoke-virtual {v4}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v4

    invoke-interface {v1, v4, v2}, Llyiahf/vczjk/d4a;->OooO0Oo(Ljava/lang/Class;Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    :goto_0
    invoke-virtual {p0, v1, p1}, Llyiahf/vczjk/v3a;->OooOOO0(Ljava/lang/String;Llyiahf/vczjk/v72;)Llyiahf/vczjk/e94;

    move-result-object v4

    iget-boolean v5, p0, Llyiahf/vczjk/v3a;->_typeIdVisible:Z

    if-eqz v5, :cond_4

    instance-of v5, p0, Llyiahf/vczjk/az;

    if-nez v5, :cond_4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v5}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v5

    if-eqz v5, :cond_4

    new-instance v5, Llyiahf/vczjk/tt9;

    invoke-direct {v5}, Llyiahf/vczjk/tt9;-><init>()V

    invoke-virtual {v5}, Llyiahf/vczjk/tt9;->o0000oO0()V

    iget-object v6, p0, Llyiahf/vczjk/v3a;->_typePropertyName:Ljava/lang/String;

    invoke-virtual {v5, v6}, Llyiahf/vczjk/tt9;->o0000Ooo(Ljava/lang/String;)V

    invoke-virtual {v5, v1}, Llyiahf/vczjk/tt9;->o0000ooO(Ljava/lang/String;)V

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOOOO()V

    invoke-virtual {v5, p2}, Llyiahf/vczjk/tt9;->o000O0O0(Llyiahf/vczjk/eb4;)Llyiahf/vczjk/rt9;

    move-result-object v1

    invoke-static {v1, p2}, Llyiahf/vczjk/gb4;->o000Oo0(Llyiahf/vczjk/rt9;Llyiahf/vczjk/eb4;)Llyiahf/vczjk/gb4;

    move-result-object p2

    invoke-virtual {p2}, Llyiahf/vczjk/gb4;->o0000oOO()Llyiahf/vczjk/gc4;

    :cond_4
    if-eqz v0, :cond_5

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOo()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v1, v5, :cond_5

    invoke-virtual {v4, p1}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_5
    invoke-virtual {v4, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v0, :cond_7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne p2, v0, :cond_6

    goto :goto_1

    :cond_6
    iget-object p2, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    const-string v1, "expected closing END_ARRAY after type information and deserialized value"

    new-array v3, v3, [Ljava/lang/Object;

    invoke-virtual {p1, p2, v0, v1, v3}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2

    :cond_7
    :goto_1
    return-object v1

    :cond_8
    iget-object p2, p0, Llyiahf/vczjk/v3a;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    filled-new-array {v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "need JSON String that contains type id (for subtype of %s)"

    invoke-virtual {p1, p2, v4, v1, v0}, Llyiahf/vczjk/v72;->o0000OOo(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2
.end method
