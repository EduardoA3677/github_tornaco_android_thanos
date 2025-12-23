.class public final Llyiahf/vczjk/vp2;
.super Llyiahf/vczjk/m49;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected _enumDeserializer:Llyiahf/vczjk/e94;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/e94;"
        }
    .end annotation
.end field

.field protected final _enumType:Llyiahf/vczjk/x64;

.field protected final _nullProvider:Llyiahf/vczjk/u46;

.field protected final _skipNullValues:Z

.field protected final _unwrapSingle:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vp2;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/m49;-><init>(Llyiahf/vczjk/m49;)V

    iget-object p1, p1, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/vp2;->_enumDeserializer:Llyiahf/vczjk/e94;

    iput-object p3, p0, Llyiahf/vczjk/vp2;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-static {p3}, Llyiahf/vczjk/f56;->OooO00o(Llyiahf/vczjk/u46;)Z

    move-result p1

    iput-boolean p1, p0, Llyiahf/vczjk/vp2;->_skipNullValues:Z

    iput-object p4, p0, Llyiahf/vczjk/vp2;->_unwrapSingle:Ljava/lang/Boolean;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;)V
    .locals 3

    const-class v0, Ljava/util/EnumSet;

    invoke-direct {p0, v0}, Llyiahf/vczjk/m49;-><init>(Ljava/lang/Class;)V

    iput-object p1, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->Oooooo()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/vp2;->_enumDeserializer:Llyiahf/vczjk/e94;

    iput-object p1, p0, Llyiahf/vczjk/vp2;->_unwrapSingle:Ljava/lang/Boolean;

    iput-object p1, p0, Llyiahf/vczjk/vp2;->_nullProvider:Llyiahf/vczjk/u46;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/vp2;->_skipNullValues:Z

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Type "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " not Java Enum type"

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final OooO()Llyiahf/vczjk/o0OoO00O;
    .locals 1

    sget-object v0, Llyiahf/vczjk/o0OoO00O;->OooOOOO:Llyiahf/vczjk/o0OoO00O;

    return-object v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 3

    sget-object v0, Llyiahf/vczjk/n94;->OooOOO0:Llyiahf/vczjk/n94;

    const-class v1, Ljava/util/EnumSet;

    invoke-static {p1, p2, v1, v0}, Llyiahf/vczjk/m49;->OoooO0O(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Ljava/lang/Class;Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/vp2;->_enumDeserializer:Llyiahf/vczjk/e94;

    if-nez v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/v72;->o0OoOo0(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;

    move-result-object v1

    goto :goto_0

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v1, p2, v2}, Llyiahf/vczjk/v72;->o000000O(Llyiahf/vczjk/e94;Llyiahf/vczjk/db0;Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v1

    :goto_0
    invoke-static {p1, p2, v1}, Llyiahf/vczjk/m49;->OoooO00(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;Llyiahf/vczjk/e94;)Llyiahf/vczjk/u46;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/vp2;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne p2, v0, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/vp2;->_enumDeserializer:Llyiahf/vczjk/e94;

    if-ne p2, v1, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/vp2;->_nullProvider:Llyiahf/vczjk/u46;

    if-ne p2, v1, :cond_1

    return-object p0

    :cond_1
    new-instance p2, Llyiahf/vczjk/vp2;

    invoke-direct {p2, p0, v1, p1, v0}, Llyiahf/vczjk/vp2;-><init>(Llyiahf/vczjk/vp2;Llyiahf/vczjk/e94;Llyiahf/vczjk/u46;Ljava/lang/Boolean;)V

    return-object p2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-static {v0}, Ljava/util/EnumSet;->noneOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    move-result-object v0

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/vp2;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/EnumSet;)V

    return-object v0

    :cond_0
    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/vp2;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/EnumSet;)V

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p3, Ljava/util/EnumSet;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/vp2;->OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/EnumSet;)V

    return-object p3

    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/vp2;->OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/EnumSet;)V

    return-object p3
.end method

.method public final OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    invoke-static {p1}, Ljava/util/EnumSet;->noneOf(Ljava/lang/Class;)Ljava/util/EnumSet;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOO()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOOo()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    return v0

    :cond_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method

.method public final OoooOOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/EnumSet;)V
    .locals 2

    :cond_0
    :goto_0
    :try_start_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/gc4;->OooOOo0:Llyiahf/vczjk/gc4;

    if-eq v0, v1, :cond_3

    sget-object v1, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    if-ne v0, v1, :cond_2

    iget-boolean v0, p0, Llyiahf/vczjk/vp2;->_skipNullValues:Z

    if-eqz v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/vp2;->_nullProvider:Llyiahf/vczjk/u46;

    invoke-interface {v0, p2}, Llyiahf/vczjk/u46;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Enum;

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/vp2;->_enumDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Enum;

    :goto_1
    if-eqz v0, :cond_0

    invoke-virtual {p3, v0}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :cond_3
    return-void

    :goto_2
    invoke-virtual {p3}, Ljava/util/AbstractCollection;->size()I

    move-result p2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1
.end method

.method public final OoooOOo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/util/EnumSet;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/vp2;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    const/4 v2, 0x0

    if-eq v0, v1, :cond_1

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/w72;->OooOoo:Llyiahf/vczjk/w72;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/v72;->o0000(Llyiahf/vczjk/w72;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const-class p3, Ljava/util/EnumSet;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    throw v2

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOoO0:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-nez v0, :cond_3

    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/vp2;->_enumDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/e94;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Enum;

    if-eqz p1, :cond_2

    invoke-virtual {p3, p1}, Ljava/util/AbstractCollection;->add(Ljava/lang/Object;)Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p1

    goto :goto_1

    :cond_2
    return-void

    :goto_1
    invoke-virtual {p3}, Ljava/util/AbstractCollection;->size()I

    move-result p2

    invoke-static {p1, p3, p2}, Llyiahf/vczjk/na4;->OooO0oO(Ljava/lang/Throwable;Ljava/lang/Object;I)Llyiahf/vczjk/na4;

    move-result-object p1

    throw p1

    :cond_3
    iget-object p3, p0, Llyiahf/vczjk/vp2;->_enumType:Llyiahf/vczjk/x64;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o00000(Llyiahf/vczjk/x64;Llyiahf/vczjk/eb4;)V

    throw v2
.end method
