.class public final Llyiahf/vczjk/jb5;
.super Llyiahf/vczjk/ul1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;
.implements Llyiahf/vczjk/nr7;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected _delegateDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _hasDefaultCreator:Z

.field protected _ignorableProperties:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field protected final _keyDeserializer:Llyiahf/vczjk/ti4;

.field protected _propertyBasedCreator:Llyiahf/vczjk/oa7;

.field protected _standardStringKey:Z

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
.method public constructor <init>(Llyiahf/vczjk/jb5;Llyiahf/vczjk/ti4;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/u46;Ljava/util/Set;)V
    .locals 1

    iget-object v0, p1, Llyiahf/vczjk/ul1;->_unwrapSingle:Ljava/lang/Boolean;

    invoke-direct {p0, p1, p5, v0}, Llyiahf/vczjk/ul1;-><init>(Llyiahf/vczjk/ul1;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    iput-object p2, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    iput-object p3, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p4, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iget-object p3, p1, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    iput-object p3, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    iget-object p3, p1, Llyiahf/vczjk/jb5;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iput-object p3, p0, Llyiahf/vczjk/jb5;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    iget-object p3, p1, Llyiahf/vczjk/jb5;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iput-object p3, p0, Llyiahf/vczjk/jb5;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iget-boolean p1, p1, Llyiahf/vczjk/jb5;->_hasDefaultCreator:Z

    iput-boolean p1, p0, Llyiahf/vczjk/jb5;->_hasDefaultCreator:Z

    iput-object p6, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-static {p1, p2}, Llyiahf/vczjk/jb5;->OoooOoO(Llyiahf/vczjk/x64;Llyiahf/vczjk/ti4;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/jb5;->_standardStringKey:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/wb5;Llyiahf/vczjk/nca;Llyiahf/vczjk/ti4;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0, v0}, Llyiahf/vczjk/ul1;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    iput-object p3, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    iput-object p4, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    iput-object p5, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    iput-object p2, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/nca;->OooO()Z

    move-result p2

    iput-boolean p2, p0, Llyiahf/vczjk/jb5;->_hasDefaultCreator:Z

    iput-object v0, p0, Llyiahf/vczjk/jb5;->_delegateDeserializer:Llyiahf/vczjk/e94;

    iput-object v0, p0, Llyiahf/vczjk/jb5;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    invoke-static {p1, p3}, Llyiahf/vczjk/jb5;->OoooOoO(Llyiahf/vczjk/x64;Llyiahf/vczjk/ti4;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/jb5;->_standardStringKey:Z

    return-void
.end method

.method public static OoooOoO(Llyiahf/vczjk/x64;Llyiahf/vczjk/ti4;)Z
    .locals 1

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object p0

    if-nez p0, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {p0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p0

    const-class v0, Ljava/lang/String;

    if-eq p0, v0, :cond_2

    const-class v0, Ljava/lang/Object;

    if-ne p0, v0, :cond_3

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_3

    :goto_0
    const/4 p0, 0x1

    return p0

    :cond_3
    const/4 p0, 0x0

    return p0
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/v72;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOO0()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOoO0()Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/jb5;->_delegateDeserializer:Llyiahf/vczjk/e94;

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v2, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    filled-new-array {v0, v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Invalid delegate-creator definition for %s: value instantiator (%s) returned true for \'canCreateUsingDelegate()\', but null for \'getDelegateType()\'"

    invoke-static {v3, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooO0oo()Z

    move-result v0

    if-eqz v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooOo0O()Llyiahf/vczjk/x64;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/jb5;->_delegateDeserializer:Llyiahf/vczjk/e94;

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v2, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    filled-new-array {v0, v2}, [Ljava/lang/Object;

    move-result-object v2

    const-string v3, "Invalid delegate-creator definition for %s: value instantiator (%s) returned true for \'canCreateUsingArrayDelegate()\', but null for \'getArrayDelegateType()\'"

    invoke-static {v3, v2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v1

    :cond_3
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0}, Llyiahf/vczjk/nca;->OooO0o()Z

    move-result v0

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0ooOO0()Llyiahf/vczjk/t72;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/nca;->OooOoO(Llyiahf/vczjk/t72;)[Llyiahf/vczjk/ph8;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    sget-object v2, Llyiahf/vczjk/gc5;->OooOooo:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/v72;->o0000O00(Llyiahf/vczjk/gc5;)Z

    move-result v2

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/oa7;->OooO0O0(Llyiahf/vczjk/v72;Llyiahf/vczjk/nca;[Llyiahf/vczjk/ph8;Z)Llyiahf/vczjk/oa7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/jb5;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    invoke-static {p1, v0}, Llyiahf/vczjk/jb5;->OoooOoO(Llyiahf/vczjk/x64;Llyiahf/vczjk/ti4;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/jb5;->_standardStringKey:Z

    return-void
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO0O()Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o00O0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/ti4;

    move-result-object v0

    :cond_0
    move-object v3, v0

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-eqz p2, :cond_1

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/m49;->OoooO0(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/e94;

    move-result-object v0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v1}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v1

    if-nez v0, :cond_2

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v0

    :goto_0
    move-object v4, v0

    goto :goto_1

    :cond_2
    invoke-virtual {p1, v0, p2, v1}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v0

    goto :goto_0

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-eqz v0, :cond_3

    invoke-virtual {v0, p2}, Llyiahf/vczjk/u3a;->OooO0o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/u3a;

    move-result-object v0

    :cond_3
    move-object v5, v0

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v1

    if-eqz v1, :cond_5

    if-eqz p2, :cond_5

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v2

    if-eqz v2, :cond_5

    invoke-virtual {v1, v2}, Llyiahf/vczjk/yn;->Oooo00o(Llyiahf/vczjk/u34;)Llyiahf/vczjk/ba4;

    move-result-object v1

    if-eqz v1, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/ba4;->OooO0O0()Ljava/util/Set;

    move-result-object v1

    invoke-interface {v1}, Ljava/util/Set;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_5

    if-nez v0, :cond_4

    new-instance v0, Ljava/util/HashSet;

    invoke-direct {v0}, Ljava/util/HashSet;-><init>()V

    goto :goto_2

    :cond_4
    new-instance v2, Ljava/util/HashSet;

    invoke-direct {v2, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    move-object v0, v2

    :goto_2
    invoke-interface {v1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-interface {v0, v2}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    goto :goto_3

    :cond_5
    move-object v7, v0

    invoke-static {p1, p2, v4}, Llyiahf/vczjk/m49;->OoooO00(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/u46;

    move-result-object v6

    iget-object p1, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    if-ne p1, v3, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-ne p1, v4, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-ne p1, v5, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    if-ne p1, v6, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    if-ne p1, v7, :cond_6

    return-object p0

    :cond_6
    new-instance v1, Llyiahf/vczjk/jb5;

    move-object v2, p0

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/jb5;-><init>(Llyiahf/vczjk/jb5;Llyiahf/vczjk/ti4;Llyiahf/vczjk/e94;Llyiahf/vczjk/u3a;Llyiahf/vczjk/u46;Ljava/util/Set;)V

    return-object v1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/jb5;->Ooooo00(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Map;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p3, Ljava/util/Map;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/eb4;->o000OoO(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    const/4 v2, 0x0

    if-eq v0, v1, :cond_1

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    iget-object p3, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {p3}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p3

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2

    :cond_1
    :goto_0
    iget-boolean v0, p0, Llyiahf/vczjk/jb5;->_standardStringKey:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_c

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v3, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    goto :goto_1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v4

    sget-object v5, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_3

    goto/16 :goto_9

    :cond_3
    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_b

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v1

    :goto_1
    if-eqz v1, :cond_16

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v4

    iget-object v5, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    if-eqz v5, :cond_4

    invoke-interface {v5, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_3

    :cond_4
    :try_start_0
    sget-object v5, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v4, v5, :cond_6

    iget-boolean v4, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v4, :cond_5

    goto :goto_3

    :cond_5
    iget-object v4, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v4, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v4

    invoke-interface {p3, v1, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_3

    :catch_0
    move-exception p1

    goto :goto_4

    :cond_6
    invoke-interface {p3, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    if-eqz v4, :cond_8

    if-nez v3, :cond_7

    invoke-virtual {v0, p1, p2, v4}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_2

    :cond_7
    invoke-virtual {v0, p1, p2, v3}, Llyiahf/vczjk/e94;->OooO0oO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_2

    :cond_8
    if-nez v3, :cond_9

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_2

    :cond_9
    invoke-virtual {v0, p1, p2, v3}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v5

    :goto_2
    if-eq v5, v4, :cond_a

    invoke-interface {p3, v1, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :cond_a
    :goto_3
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    goto :goto_1

    :goto_4
    invoke-static {p1, p3, v1}, Llyiahf/vczjk/ul1;->OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    throw v2

    :cond_b
    new-array p1, v1, [Ljava/lang/Object;

    invoke-virtual {p2, p0, v5, v2, p1}, Llyiahf/vczjk/v72;->o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2

    :cond_c
    iget-object v0, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    iget-object v3, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v4, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v5

    if-eqz v5, :cond_d

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    goto :goto_5

    :cond_d
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v5

    sget-object v6, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v5, v6, :cond_e

    goto :goto_9

    :cond_e
    sget-object v6, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v5, v6, :cond_17

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v1

    :goto_5
    if-eqz v1, :cond_16

    invoke-virtual {v0, v1, p2}, Llyiahf/vczjk/ti4;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v5

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    if-eqz v7, :cond_f

    invoke-interface {v7, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_f

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_7

    :cond_f
    :try_start_1
    sget-object v7, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v6, v7, :cond_11

    iget-boolean v6, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v6, :cond_10

    goto :goto_7

    :cond_10
    iget-object v6, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v6, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v6

    invoke-interface {p3, v5, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_7

    :catch_1
    move-exception p1

    goto :goto_8

    :cond_11
    invoke-interface {p3, v5}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    if-eqz v6, :cond_13

    if-nez v4, :cond_12

    invoke-virtual {v3, p1, p2, v6}, Llyiahf/vczjk/e94;->OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v7

    goto :goto_6

    :cond_12
    invoke-virtual {v3, p1, p2, v4}, Llyiahf/vczjk/e94;->OooO0oO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v7

    goto :goto_6

    :cond_13
    if-nez v4, :cond_14

    invoke-virtual {v3, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v7

    goto :goto_6

    :cond_14
    invoke-virtual {v3, p1, p2, v4}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v7

    :goto_6
    if-eq v7, v6, :cond_15

    invoke-interface {p3, v5, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    :cond_15
    :goto_7
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v1

    goto :goto_5

    :goto_8
    invoke-static {p1, p3, v1}, Llyiahf/vczjk/ul1;->OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    throw v2

    :cond_16
    :goto_9
    return-object p3

    :cond_17
    new-array p1, v1, [Ljava/lang/Object;

    invoke-virtual {p2, p0, v6, v2, p1}, Llyiahf/vczjk/v72;->o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v2
.end method

.method public final OooOOO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    if-nez v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OoooO()Llyiahf/vczjk/x64;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    return-object v0
.end method

.method public final OoooOOO()Llyiahf/vczjk/e94;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    return-object v0
.end method

.method public final OoooOOo()Llyiahf/vczjk/nca;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    return-object v0
.end method

.method public final OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Map;)V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    iget-object v1, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v2, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    invoke-virtual {v1}, Llyiahf/vczjk/e94;->OooOO0o()Llyiahf/vczjk/u66;

    move-result-object v3

    const/4 v4, 0x0

    if-eqz v3, :cond_0

    const/4 v3, 0x1

    goto :goto_0

    :cond_0
    move v3, v4

    :goto_0
    const/4 v5, 0x0

    if-eqz v3, :cond_1

    new-instance v6, Llyiahf/vczjk/uqa;

    iget-object v7, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v7}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v7

    invoke-virtual {v7}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v7

    invoke-direct {v6, v7, p3}, Llyiahf/vczjk/uqa;-><init>(Ljava/lang/Class;Ljava/util/Map;)V

    goto :goto_1

    :cond_1
    move-object v6, v5

    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v7

    if-eqz v7, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v4

    goto :goto_2

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-eq v7, v8, :cond_4

    sget-object p1, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v7, p1, :cond_3

    goto :goto_7

    :cond_3
    new-array p1, v4, [Ljava/lang/Object;

    invoke-virtual {p2, p0, v8, v5, p1}, Llyiahf/vczjk/v72;->o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v5

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v4

    :goto_2
    if-eqz v4, :cond_a

    invoke-virtual {v0, v4, p2}, Llyiahf/vczjk/ti4;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v7

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v8

    iget-object v9, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    if-eqz v9, :cond_5

    invoke-interface {v9, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v9

    if-eqz v9, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_6

    :cond_5
    :try_start_0
    sget-object v9, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v8, v9, :cond_7

    iget-boolean v8, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v8, :cond_6

    goto :goto_6

    :cond_6
    iget-object v8, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v8, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v8

    goto :goto_3

    :catch_0
    move-exception p1

    goto :goto_4

    :catch_1
    move-exception v4

    goto :goto_5

    :cond_7
    if-nez v2, :cond_8

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v8

    goto :goto_3

    :cond_8
    invoke-virtual {v1, p1, p2, v2}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v8

    :goto_3
    if-eqz v3, :cond_9

    invoke-virtual {v6, v7, v8}, Llyiahf/vczjk/uqa;->OooOoo0(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_6

    :cond_9
    invoke-interface {p3, v7, v8}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catch Llyiahf/vczjk/l9a; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_6

    :goto_4
    invoke-static {p1, p3, v4}, Llyiahf/vczjk/ul1;->OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    throw v5

    :goto_5
    invoke-virtual {p0, p2, v6, v7, v4}, Llyiahf/vczjk/jb5;->Ooooo0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/uqa;Ljava/lang/Object;Llyiahf/vczjk/l9a;)V

    :goto_6
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v4

    goto :goto_2

    :cond_a
    :goto_7
    return-void
.end method

.method public final Ooooo00(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Map;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_propertyBasedCreator:Llyiahf/vczjk/oa7;

    const/4 v1, 0x0

    if-eqz v0, :cond_9

    invoke-virtual {v0, p2, p1, v1}, Llyiahf/vczjk/oa7;->OooO0Oo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u66;)Llyiahf/vczjk/lb7;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v4, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v5

    goto :goto_0

    :cond_0
    sget-object v5, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v5}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v5

    if-eqz v5, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v5

    goto :goto_0

    :cond_1
    move-object v5, v1

    :goto_0
    if-eqz v5, :cond_8

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v6

    iget-object v7, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    if-eqz v7, :cond_2

    invoke-interface {v7, v5}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v7

    if-eqz v7, :cond_2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_2

    :cond_2
    invoke-virtual {v0, v5}, Llyiahf/vczjk/oa7;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/ph8;

    move-result-object v7

    if-eqz v7, :cond_3

    invoke-virtual {v7, p1, p2}, Llyiahf/vczjk/ph8;->OooO0oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v6

    invoke-virtual {v2, v7, v6}, Llyiahf/vczjk/lb7;->OooO0O0(Llyiahf/vczjk/ph8;Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_7

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    :try_start_0
    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/oa7;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/lb7;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/Map;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/jb5;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Map;)V

    return-object v0

    :catch_0
    move-exception v0

    move-object p1, v0

    iget-object p2, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    invoke-static {p1, p2, v5}, Llyiahf/vczjk/ul1;->OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    throw v1

    :cond_3
    iget-object v7, p0, Llyiahf/vczjk/jb5;->_keyDeserializer:Llyiahf/vczjk/ti4;

    invoke-virtual {v7, v5, p1}, Llyiahf/vczjk/ti4;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v7

    :try_start_1
    sget-object v8, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v6, v8, :cond_5

    iget-boolean v6, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v6, :cond_4

    goto :goto_2

    :cond_4
    iget-object v6, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v6, p1}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_1

    :catch_1
    move-exception v0

    move-object p1, v0

    goto :goto_3

    :cond_5
    if-nez v4, :cond_6

    invoke-virtual {v3, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v5

    goto :goto_1

    :cond_6
    invoke-virtual {v3, p2, p1, v4}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v5
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    :goto_1
    new-instance v6, Llyiahf/vczjk/kb7;

    iget-object v8, v2, Llyiahf/vczjk/lb7;->OooO0oo:Llyiahf/vczjk/o0O00o00;

    const/4 v9, 0x0

    invoke-direct {v6, v8, v5, v7, v9}, Llyiahf/vczjk/kb7;-><init>(Llyiahf/vczjk/o0O00o00;Ljava/lang/Object;Ljava/lang/Object;I)V

    iput-object v6, v2, Llyiahf/vczjk/lb7;->OooO0oo:Llyiahf/vczjk/o0O00o00;

    :cond_7
    :goto_2
    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v5

    goto :goto_0

    :goto_3
    iget-object p2, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    invoke-static {p1, p2, v5}, Llyiahf/vczjk/ul1;->OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    throw v1

    :cond_8
    :try_start_2
    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/oa7;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/lb7;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Map;
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_2

    return-object p1

    :catch_2
    move-exception v0

    move-object p1, v0

    iget-object p2, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p2

    invoke-static {p1, p2, v5}, Llyiahf/vczjk/ul1;->OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    throw v1

    :cond_9
    iget-object v0, p0, Llyiahf/vczjk/jb5;->_delegateDeserializer:Llyiahf/vczjk/e94;

    if-eqz v0, :cond_a

    iget-object v1, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {v1, p2, p1}, Llyiahf/vczjk/nca;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Map;

    return-object p1

    :cond_a
    iget-boolean v0, p0, Llyiahf/vczjk/jb5;->_hasDefaultCreator:Z

    const/4 v2, 0x0

    if-eqz v0, :cond_1c

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v5

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-eq v5, v0, :cond_f

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-eq v5, v0, :cond_f

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-eq v5, v0, :cond_f

    sget-object v0, Llyiahf/vczjk/gc4;->OooOo00:Llyiahf/vczjk/gc4;

    if-ne v5, v0, :cond_b

    iget-object v0, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/nca;->OooOOo0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Map;

    return-object p1

    :cond_b
    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    if-ne v5, v0, :cond_e

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v3, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-ne v0, v3, :cond_c

    sget-object v0, Llyiahf/vczjk/w72;->Oooo00O:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_e

    return-object v1

    :cond_c
    sget-object v0, Llyiahf/vczjk/w72;->OooOooO:Llyiahf/vczjk/w72;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_e

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/jb5;->Ooooo00(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Map;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object p2

    if-ne p2, v3, :cond_d

    check-cast v0, Ljava/util/Map;

    return-object v0

    :cond_d
    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->o000oOoO(Llyiahf/vczjk/v72;)V

    throw v1

    :cond_e
    invoke-virtual {p0, p1}, Llyiahf/vczjk/m49;->OoooOO0(Llyiahf/vczjk/v72;)Llyiahf/vczjk/x64;

    move-result-object v4

    const/4 v7, 0x0

    new-array v8, v2, [Ljava/lang/Object;

    move-object v3, p1

    move-object v6, p2

    invoke-virtual/range {v3 .. v8}, Llyiahf/vczjk/v72;->o00000O0(Llyiahf/vczjk/x64;Llyiahf/vczjk/gc4;Llyiahf/vczjk/eb4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :cond_f
    move-object v3, p1

    move-object v6, p2

    iget-object p1, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/nca;->OooOOoo(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/Map;

    iget-boolean p2, p0, Llyiahf/vczjk/jb5;->_standardStringKey:Z

    if-eqz p2, :cond_1b

    iget-object p2, p0, Llyiahf/vczjk/jb5;->_valueDeserializer:Llyiahf/vczjk/e94;

    iget-object v4, p0, Llyiahf/vczjk/jb5;->_valueTypeDeserializer:Llyiahf/vczjk/u3a;

    invoke-virtual {p2}, Llyiahf/vczjk/e94;->OooOO0o()Llyiahf/vczjk/u66;

    move-result-object v0

    if-eqz v0, :cond_10

    const/4 v0, 0x1

    move v5, v0

    goto :goto_4

    :cond_10
    move v5, v2

    :goto_4
    if-eqz v5, :cond_11

    new-instance v0, Llyiahf/vczjk/uqa;

    iget-object v7, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {v7}, Llyiahf/vczjk/x64;->Oooo0oo()Llyiahf/vczjk/x64;

    move-result-object v7

    invoke-virtual {v7}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v7

    invoke-direct {v0, v7, p1}, Llyiahf/vczjk/uqa;-><init>(Ljava/lang/Class;Ljava/util/Map;)V

    move-object v7, v0

    goto :goto_5

    :cond_11
    move-object v7, v1

    :goto_5
    invoke-virtual {v6}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v0

    if-eqz v0, :cond_12

    invoke-virtual {v6}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v0

    :goto_6
    move-object v2, v0

    goto :goto_7

    :cond_12
    invoke-virtual {v6}, Llyiahf/vczjk/eb4;->Oooooo0()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v8, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v8, :cond_13

    goto :goto_c

    :cond_13
    sget-object v8, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v8, :cond_1a

    invoke-virtual {v6}, Llyiahf/vczjk/eb4;->OoooOoo()Ljava/lang/String;

    move-result-object v0

    goto :goto_6

    :goto_7
    if-eqz v2, :cond_19

    invoke-virtual {v6}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    iget-object v8, p0, Llyiahf/vczjk/jb5;->_ignorableProperties:Ljava/util/Set;

    if-eqz v8, :cond_14

    invoke-interface {v8, v2}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_14

    invoke-virtual {v6}, Llyiahf/vczjk/eb4;->o000Ooo()Llyiahf/vczjk/eb4;

    goto :goto_b

    :cond_14
    :try_start_3
    sget-object v8, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v0, v8, :cond_16

    iget-boolean v0, p0, Llyiahf/vczjk/ul1;->_skipNullValues:Z

    if-eqz v0, :cond_15

    goto :goto_b

    :cond_15
    iget-object v0, p0, Llyiahf/vczjk/ul1;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, v3}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_8

    :catch_3
    move-exception v0

    move-object p2, v0

    goto :goto_9

    :catch_4
    move-exception v0

    goto :goto_a

    :cond_16
    if-nez v4, :cond_17

    invoke-virtual {p2, v3, v6}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    goto :goto_8

    :cond_17
    invoke-virtual {p2, v6, v3, v4}, Llyiahf/vczjk/e94;->OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;

    move-result-object v0

    :goto_8
    if-eqz v5, :cond_18

    invoke-virtual {v7, v2, v0}, Llyiahf/vczjk/uqa;->OooOoo0(Ljava/lang/Object;Ljava/lang/Object;)V

    goto :goto_b

    :cond_18
    invoke-interface {p1, v2, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_3
    .catch Llyiahf/vczjk/l9a; {:try_start_3 .. :try_end_3} :catch_4
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    goto :goto_b

    :goto_9
    invoke-static {p2, p1, v2}, Llyiahf/vczjk/ul1;->OoooOo0(Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    throw v1

    :goto_a
    invoke-virtual {p0, v3, v7, v2, v0}, Llyiahf/vczjk/jb5;->Ooooo0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/uqa;Ljava/lang/Object;Llyiahf/vczjk/l9a;)V

    :goto_b
    invoke-virtual {v6}, Llyiahf/vczjk/eb4;->o0000o()Ljava/lang/String;

    move-result-object v2

    goto :goto_7

    :cond_19
    :goto_c
    return-object p1

    :cond_1a
    new-array p1, v2, [Ljava/lang/Object;

    invoke-virtual {v3, p0, v8, v1, p1}, Llyiahf/vczjk/v72;->o0000Oo0(Llyiahf/vczjk/e94;Llyiahf/vczjk/gc4;Ljava/lang/String;[Ljava/lang/Object;)V

    throw v1

    :cond_1b
    invoke-virtual {p0, v6, v3, p1}, Llyiahf/vczjk/jb5;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/Map;)V

    return-object p1

    :cond_1c
    move-object v3, p1

    iget-object p1, p0, Llyiahf/vczjk/ul1;->_containerType:Llyiahf/vczjk/x64;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/jb5;->_valueInstantiator:Llyiahf/vczjk/nca;

    const-string v0, "no default constructor found"

    new-array v2, v2, [Ljava/lang/Object;

    invoke-virtual {v3, p1, p2, v0, v2}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    throw v1
.end method

.method public final Ooooo0o(Llyiahf/vczjk/v72;Llyiahf/vczjk/uqa;Ljava/lang/Object;Llyiahf/vczjk/l9a;)V
    .locals 1

    if-eqz p2, :cond_0

    new-instance p1, Llyiahf/vczjk/ib5;

    iget-object v0, p2, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/Class;

    invoke-direct {p1, p2, p4, v0, p3}, Llyiahf/vczjk/ib5;-><init>(Llyiahf/vczjk/uqa;Llyiahf/vczjk/l9a;Ljava/lang/Class;Ljava/lang/Object;)V

    iget-object p2, p2, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast p2, Ljava/util/ArrayList;

    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-virtual {p4}, Llyiahf/vczjk/l9a;->OooOO0()Llyiahf/vczjk/bh7;

    move-result-object p2

    invoke-virtual {p2, p1}, Llyiahf/vczjk/bh7;->OooO00o(Llyiahf/vczjk/ah7;)V

    return-void

    :cond_0
    new-instance p2, Ljava/lang/StringBuilder;

    const-string p3, "Unresolved forward reference but no identity info: "

    invoke-direct {p2, p3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    const/4 p3, 0x0

    new-array p3, p3, [Ljava/lang/Object;

    invoke-virtual {p1, p0, p2, p3}, Llyiahf/vczjk/v72;->o0000OO0(Llyiahf/vczjk/e94;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p1, 0x0

    throw p1
.end method
