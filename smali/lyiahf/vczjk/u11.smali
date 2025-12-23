.class public Llyiahf/vczjk/u11;
.super Llyiahf/vczjk/ul1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;


# static fields
.field private static final serialVersionUID:J = -0x1L


# instance fields
.field protected final _delegateDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _valueDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _valueInstantiator:Llyiahf/vczjk/nca;

.field protected final _valueTypeDeserializer:Llyiahf/vczjk/u3a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a21;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;)V
    .locals 8

    const/4 v7, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/u11;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1, p6, p7}, Llyiahf/vczjk/ul1;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    iput-object p2, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p3, p0, Llyiahf/vczjk/u11;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iput-object p4, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object p5, p0, Llyiahf/vczjk/u11;->_delegateDeserializer:Llyiahf/vczjk/e94;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOO0()Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOoO0()Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_1

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v1

    :cond_0
    :goto_0
    move-object v3, v1

    goto :goto_1

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    filled-new-array {p2, v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v2, "Invalid delegate-creator definition for %s: value instantiator (%s) returned true for \'canCreateUsingDelegate()\', but null for \'getDelegateType()\'"

    invoke-static {v2, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooO0oo()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOo0O()Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_3

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v1

    goto :goto_0

    :cond_3
    iget-object p2, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    filled-new-array {p2, v0}, [Ljava/lang/Object;

    move-result-object v0

    const-string v2, "Invalid delegate-creator definition for %s: value instantiator (%s) returned true for \'canCreateUsingArrayDelegate()\', but null for \'getArrayDelegateType()\'"

    invoke-static {v2, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :goto_1
    sget-object v0, Llyiahf/vczjk/n94;->OooOOO0:Llyiahf/vczjk/n94;

    const-class v1, Ljava/util/Collection;

    invoke-static {p1, p2, v1, v0}, Llyiahf/vczjk/m49;->OoooO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Ljava/lang/Class;Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v7

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/m49;->OoooO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/e94;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v1

    if-nez v0, :cond_4

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    :goto_2
    move-object v4, v0

    goto :goto_3

    :cond_4
    invoke-virtual {p1, v0, p2, v1}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    goto :goto_2

    :goto_3
    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v0, :cond_5

    invoke-virtual {v0, p2}, Llyiahf/vczjk/u3a;->OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;

    move-result-object v0

    :cond_5
    move-object v5, v0

    invoke-static {p1, p2, v4}, Llyiahf/vczjk/m49;->OoooO00(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/u46;

    move-result-object v6

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne v7, p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    if-ne v6, p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/u11;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-ne v3, p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-ne v4, p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/u11;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eq v5, p1, :cond_7

    :cond_6
    move-object v2, p0

    goto :goto_4

    :cond_7
    return-object p0

    :goto_4
    invoke-virtual/range {v2 .. v7}, Llyiahf/vczjk/u11;->Ooooo0o(Llyiahf/vczjk/e94;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/u11;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/u11;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v1

    if-nez v1, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/nca;->OooOOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1

    :cond_1
    invoke-virtual {p0, p1}, Llyiahf/vczjk/u11;->OoooOoO(Llyiahf/vczjk/v72;)Ljava/util/Collection;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/u11;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public bridge synthetic OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p3, Ljava/util/Collection;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/u11;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/u11;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooOOO()Llyiahf/vczjk/e94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    return-object v0
.end method

.method public final OoooOOo()Llyiahf/vczjk/nca;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    return-object v0
.end method

.method public OoooOoO(Llyiahf/vczjk/v72;)Ljava/util/Collection;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1
.end method

.method public OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;
    .locals 6

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/u11;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o000OoO(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0}, Llyiahf/vczjk/e94;->OooOO0o()Llyiahf/vczjk/u66;

    move-result-object v1

    if-eqz v1, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/u11;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o000OoO(Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v1, p0, Llyiahf/vczjk/u11;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    new-instance v2, Llyiahf/vczjk/uqa;

    iget-object v3, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v3

    invoke-direct {v2, v3, p3}, Llyiahf/vczjk/uqa;-><init>(Ljava/lang/Class;Ljava/util/Collection;)V

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v3, v4, :cond_d

    :try_start_0
    sget-object v4, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v3, v4, :cond_3

    iget-boolean v3, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v3, :cond_2

    goto :goto_0

    :cond_2
    iget-object v3, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v3, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v3

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :catch_1
    move-exception v3

    goto :goto_4

    :cond_3
    if-nez v1, :cond_4

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v3

    goto :goto_1

    :cond_4
    invoke-virtual {v0, p1, p2, v1}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v3

    :goto_1
    invoke-virtual {v2, v3}, Llyiahf/vczjk/uqa;->OooO(Ljava/lang/Object;)V
    :try_end_0
    .catch Llyiahf/vczjk/l9a; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :goto_2
    if-eqz p2, :cond_6

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_5

    goto :goto_3

    :cond_5
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_6
    :goto_3
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    move-result p2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1

    :goto_4
    new-instance v4, Llyiahf/vczjk/t11;

    iget-object v5, v2, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v5, Ljava/lang/Class;

    invoke-direct {v4, v2, v3, v5}, Llyiahf/vczjk/t11;-><init>(Llyiahf/vczjk/uqa;Llyiahf/vczjk/l9a;Ljava/lang/Class;)V

    iget-object v5, v2, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v5, Ljava/util/ArrayList;

    invoke-virtual {v5, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {v3}, Llyiahf/vczjk/l9a;->OooOO0()Llyiahf/vczjk/bh7;

    move-result-object v3

    invoke-virtual {v3, v4}, Llyiahf/vczjk/bh7;->OooO00o(Llyiahf/vczjk/ah7;)V

    goto :goto_0

    :cond_7
    iget-object v1, p0, Llyiahf/vczjk/u11;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    :goto_5
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v2, v3, :cond_d

    :try_start_1
    sget-object v3, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v2, v3, :cond_9

    iget-boolean v2, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v2, :cond_8

    goto :goto_5

    :cond_8
    iget-object v2, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v2, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v2

    goto :goto_6

    :catch_2
    move-exception p1

    goto :goto_7

    :cond_9
    if-nez v1, :cond_a

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v2

    goto :goto_6

    :cond_a
    invoke-virtual {v0, p1, p2, v1}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v2

    :goto_6
    invoke-interface {p3, v2}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_2

    goto :goto_5

    :goto_7
    if-eqz p2, :cond_c

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_b

    goto :goto_8

    :cond_b
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_c
    :goto_8
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    move-result p2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1

    :cond_d
    return-object p3
.end method

.method public final Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    if-eq v0, v1, :cond_1

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object p3, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o00000(Llyiahf/vczjk/x64;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/u11;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v1, p0, Llyiahf/vczjk/u11;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    :try_start_0
    sget-object v2, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v2

    if-eqz v2, :cond_3

    iget-boolean p1, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz p1, :cond_2

    return-object p3

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {p1, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_3
    if-nez v1, :cond_4

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    goto :goto_1

    :cond_4
    invoke-virtual {v0, p1, p2, v1}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object p1
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :goto_1
    invoke-interface {p3, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    return-object p3

    :goto_2
    if-eqz p2, :cond_6

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo0:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result p2

    if-eqz p2, :cond_5

    goto :goto_3

    :cond_5
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOoO(Ljava/lang/Throwable;)V

    :cond_6
    :goto_3
    const-class p2, Ljava/lang/Object;

    invoke-interface {p3}, Ljava/util/Collection;->size()I

    move-result p3

    invoke-static {p1, p2, p3}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public Ooooo0o(Llyiahf/vczjk/e94;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)Llyiahf/vczjk/u11;
    .locals 8

    new-instance v0, Llyiahf/vczjk/u11;

    iget-object v1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v4, p0, Llyiahf/vczjk/u11;->_valueInstantiator:Llyiahf/vczjk/nca;

    move-object v5, p1

    move-object v2, p2

    move-object v3, p3

    move-object v6, p4

    move-object v7, p5

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/u11;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/nca;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v0
.end method
