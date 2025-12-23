.class public final Llyiahf/vczjk/m69;
.super Llyiahf/vczjk/ul1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;


# static fields
.field private static final serialVersionUID:J = 0x1L


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


# direct methods
.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/nca;Llyiahf/vczjk/e94;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1, p5, p6}, Llyiahf/vczjk/ul1;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    iput-object p4, p0, Llyiahf/vczjk/m69;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p2, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object p3, p0, Llyiahf/vczjk/m69;->_delegateDeserializer:Llyiahf/vczjk/e94;

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOo0()Llyiahf/vczjk/gn;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOo0O()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    :goto_0
    move-object v5, v0

    goto :goto_1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOo()Llyiahf/vczjk/gn;

    move-result-object v0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOoO0()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    goto :goto_0

    :cond_1
    move-object v5, v1

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v2, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v2

    if-nez v0, :cond_2

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/m49;->OoooO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/e94;

    move-result-object v0

    if-nez v0, :cond_3

    invoke-virtual {p1, v2, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    goto :goto_2

    :cond_2
    invoke-virtual {p1, v0, p2, v2}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    :cond_3
    :goto_2
    sget-object v2, Llyiahf/vczjk/n94;->OooOOO0:Llyiahf/vczjk/n94;

    const-class v3, Ljava/util/Collection;

    invoke-static {p1, p2, v3, v2}, Llyiahf/vczjk/m49;->OoooO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Ljava/lang/Class;Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v8

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/m49;->OoooO00(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/u46;

    move-result-object v7

    invoke-static {v0}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_4

    move-object v6, v1

    goto :goto_3

    :cond_4
    move-object v6, v0

    :goto_3
    iget-object p1, p0, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne p1, v8, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    if-ne p1, v7, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/m69;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-ne p1, v6, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/m69;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-ne p1, v5, :cond_5

    return-object p0

    :cond_5
    new-instance v2, Llyiahf/vczjk/m69;

    iget-object v3, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v4, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/m69;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/nca;Llyiahf/vczjk/e94;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object v2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/m69;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Collection;

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Collection;

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m69;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final bridge synthetic OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p3, Ljava/util/Collection;

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m69;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;

    return-object p3
.end method

.method public final OooOOO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/m69;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooOOO()Llyiahf/vczjk/e94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueDeserializer:Llyiahf/vczjk/e94;

    return-object v0
.end method

.method public final OoooOOo()Llyiahf/vczjk/nca;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueInstantiator:Llyiahf/vczjk/nca;

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Collection;)Ljava/util/Collection;
    .locals 3

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_5

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

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p3

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_3

    iget-boolean p1, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz p1, :cond_2

    goto/16 :goto_7

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {p1, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    goto :goto_1

    :cond_3
    if-nez v0, :cond_4

    :try_start_0
    invoke-static {p2, p1}, Llyiahf/vczjk/m49;->Oooo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/String;

    move-result-object p1

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_4
    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/String;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :goto_1
    invoke-interface {p3, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    return-object p3

    :goto_2
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    move-result p2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/m69;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_a

    :goto_3
    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO0()Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_9

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_6

    goto :goto_7

    :cond_6
    sget-object v2, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v1, v2, :cond_8

    iget-boolean v1, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v1, :cond_7

    goto :goto_3

    :cond_7
    iget-object v1, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v1, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_4

    :catch_1
    move-exception p1

    goto :goto_5

    :cond_8
    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    goto :goto_4

    :cond_9
    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    :goto_4
    invoke-interface {p3, v1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_3

    :goto_5
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    move-result p2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1

    :cond_a
    :goto_6
    :try_start_2
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO0()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_b

    invoke-interface {p3, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :catch_2
    move-exception p1

    goto :goto_9

    :cond_b
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_c

    :goto_7
    return-object p3

    :cond_c
    sget-object v1, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_e

    iget-boolean v0, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v0, :cond_d

    goto :goto_6

    :cond_d
    iget-object v0, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    goto :goto_8

    :cond_e
    invoke-static {p2, p1}, Llyiahf/vczjk/m49;->Oooo0(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/String;

    move-result-object v0

    :goto_8
    invoke-interface {p3, v0}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    goto :goto_6

    :goto_9
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    move-result p2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method
