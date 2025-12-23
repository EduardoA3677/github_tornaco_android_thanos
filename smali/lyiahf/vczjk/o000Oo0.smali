.class public final Llyiahf/vczjk/o000Oo0;
.super Llyiahf/vczjk/e94;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wo1;
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public final transient OooOOO0:Ljava/util/LinkedHashMap;

.field protected final _acceptBoolean:Z

.field protected final _acceptDouble:Z

.field protected final _acceptInt:Z

.field protected final _acceptString:Z

.field protected final _backRefProperties:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Llyiahf/vczjk/ph8;",
            ">;"
        }
    .end annotation
.end field

.field protected final _baseType:Llyiahf/vczjk/x64;

.field protected final _objectIdReader:Llyiahf/vczjk/u66;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h90;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object p1, p1, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object v0, p0, Llyiahf/vczjk/o000Oo0;->_backRefProperties:Ljava/util/Map;

    invoke-virtual {p1}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    const-class v0, Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    iput-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptString:Z

    sget-object v0, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    const/4 v1, 0x1

    const/4 v2, 0x0

    if-eq p1, v0, :cond_1

    const-class v0, Ljava/lang/Boolean;

    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    move v0, v2

    goto :goto_1

    :cond_1
    :goto_0
    move v0, v1

    :goto_1
    iput-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptBoolean:Z

    sget-object v0, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    if-eq p1, v0, :cond_3

    const-class v0, Ljava/lang/Integer;

    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result v0

    if-eqz v0, :cond_2

    goto :goto_2

    :cond_2
    move v0, v2

    goto :goto_3

    :cond_3
    :goto_2
    move v0, v1

    :goto_3
    iput-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptInt:Z

    sget-object v0, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    if-eq p1, v0, :cond_5

    const-class v0, Ljava/lang/Double;

    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_4

    goto :goto_4

    :cond_4
    move v1, v2

    :cond_5
    :goto_4
    iput-boolean v1, p0, Llyiahf/vczjk/o000Oo0;->_acceptDouble:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/o000Oo0;Llyiahf/vczjk/u66;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object v0, p1, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/o000Oo0;->_backRefProperties:Ljava/util/Map;

    iput-object v0, p0, Llyiahf/vczjk/o000Oo0;->_backRefProperties:Ljava/util/Map;

    iget-boolean v0, p1, Llyiahf/vczjk/o000Oo0;->_acceptString:Z

    iput-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptString:Z

    iget-boolean v0, p1, Llyiahf/vczjk/o000Oo0;->_acceptBoolean:Z

    iput-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptBoolean:Z

    iget-boolean v0, p1, Llyiahf/vczjk/o000Oo0;->_acceptInt:Z

    iput-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptInt:Z

    iget-boolean p1, p1, Llyiahf/vczjk/o000Oo0;->_acceptDouble:Z

    iput-boolean p1, p0, Llyiahf/vczjk/o000Oo0;->_acceptDouble:Z

    iput-object p2, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/o000Oo0;->OooOOO0:Ljava/util/LinkedHashMap;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/za0;Llyiahf/vczjk/h90;Ljava/util/HashMap;Ljava/util/LinkedHashMap;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iget-object p2, p2, Llyiahf/vczjk/h90;->OooO00o:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    iget-object p1, p1, Llyiahf/vczjk/za0;->OooOO0:Ljava/io/Serializable;

    check-cast p1, Llyiahf/vczjk/u66;

    iput-object p1, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    iput-object p3, p0, Llyiahf/vczjk/o000Oo0;->_backRefProperties:Ljava/util/Map;

    iput-object p4, p0, Llyiahf/vczjk/o000Oo0;->OooOOO0:Ljava/util/LinkedHashMap;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object p1

    const-class p2, Ljava/lang/String;

    invoke-virtual {p1, p2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p2

    iput-boolean p2, p0, Llyiahf/vczjk/o000Oo0;->_acceptString:Z

    sget-object p2, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    const/4 p3, 0x1

    const/4 p4, 0x0

    if-eq p1, p2, :cond_1

    const-class p2, Ljava/lang/Boolean;

    invoke-virtual {p1, p2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p2

    if-eqz p2, :cond_0

    goto :goto_0

    :cond_0
    move p2, p4

    goto :goto_1

    :cond_1
    :goto_0
    move p2, p3

    :goto_1
    iput-boolean p2, p0, Llyiahf/vczjk/o000Oo0;->_acceptBoolean:Z

    sget-object p2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    if-eq p1, p2, :cond_3

    const-class p2, Ljava/lang/Integer;

    invoke-virtual {p1, p2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p2

    if-eqz p2, :cond_2

    goto :goto_2

    :cond_2
    move p2, p4

    goto :goto_3

    :cond_3
    :goto_2
    move p2, p3

    :goto_3
    iput-boolean p2, p0, Llyiahf/vczjk/o000Oo0;->_acceptInt:Z

    sget-object p2, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    if-eq p1, p2, :cond_5

    const-class p2, Ljava/lang/Double;

    invoke-virtual {p1, p2}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    move-result p1

    if-eqz p1, :cond_4

    goto :goto_4

    :cond_4
    move p3, p4

    :cond_5
    :goto_4
    iput-boolean p3, p0, Llyiahf/vczjk/o000Oo0;->_acceptDouble:Z

    return-void
.end method


# virtual methods
.method public final OooO0OO(Llyiahf/vczjk/v72;Llyiahf/vczjk/db0;)Llyiahf/vczjk/e94;
    .locals 10

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->oo000o()Llyiahf/vczjk/yn;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/o000Oo0;->OooOOO0:Ljava/util/LinkedHashMap;

    if-eqz p2, :cond_3

    if-eqz v0, :cond_3

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object p2

    if-eqz p2, :cond_3

    invoke-virtual {v0, p2}, Llyiahf/vczjk/yn;->OooOoO0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/t66;

    move-result-object v2

    if-eqz v2, :cond_3

    invoke-virtual {p1, v2}, Llyiahf/vczjk/mc4;->OoooOO0(Llyiahf/vczjk/t66;)V

    invoke-virtual {v0, p2, v2}, Llyiahf/vczjk/yn;->OooOoO(Llyiahf/vczjk/u34;Llyiahf/vczjk/t66;)Llyiahf/vczjk/t66;

    move-result-object p2

    iget-object v0, p2, Llyiahf/vczjk/t66;->OooO0O0:Ljava/lang/Class;

    const-class v2, Llyiahf/vczjk/s66;

    const/4 v3, 0x0

    iget-object v6, p2, Llyiahf/vczjk/t66;->OooO00o:Llyiahf/vczjk/xa7;

    if-ne v0, v2, :cond_2

    if-nez v1, :cond_0

    move-object v0, v3

    goto :goto_0

    :cond_0
    invoke-virtual {v6}, Llyiahf/vczjk/xa7;->OooO0OO()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v1, v0}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ph8;

    :goto_0
    if-eqz v0, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/ph8;->_type:Llyiahf/vczjk/x64;

    new-instance v2, Llyiahf/vczjk/qa7;

    iget-object p2, p2, Llyiahf/vczjk/t66;->OooO0Oo:Ljava/lang/Class;

    invoke-direct {v2, p2}, Llyiahf/vczjk/q66;-><init>(Ljava/lang/Class;)V

    move-object v9, v0

    :goto_1
    move-object v5, v1

    move-object v7, v2

    goto :goto_2

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Invalid Object Id definition for "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, ": cannot find property with name \'"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v0, "\'"

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/v72;->OoooOOO(Llyiahf/vczjk/x64;Ljava/lang/String;)Ljava/lang/Object;

    throw v3

    :cond_2
    invoke-virtual {p1, p2}, Llyiahf/vczjk/mc4;->OoooOO0(Llyiahf/vczjk/t66;)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/v72;->Oooooo(Ljava/lang/Class;)Llyiahf/vczjk/x64;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-class v1, Llyiahf/vczjk/p66;

    invoke-static {v1, v0}, Llyiahf/vczjk/a4a;->OooOOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)[Llyiahf/vczjk/x64;

    move-result-object v0

    const/4 v1, 0x0

    aget-object v1, v0, v1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mc4;->OoooO(Llyiahf/vczjk/t66;)Llyiahf/vczjk/p66;

    move-result-object v2

    move-object v9, v3

    goto :goto_1

    :goto_2
    invoke-virtual {p1, v5}, Llyiahf/vczjk/v72;->o00o0O(Llyiahf/vczjk/x64;)Llyiahf/vczjk/e94;

    move-result-object v8

    new-instance v4, Llyiahf/vczjk/u66;

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/u66;-><init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/xa7;Llyiahf/vczjk/p66;Llyiahf/vczjk/e94;Llyiahf/vczjk/ph8;)V

    new-instance p1, Llyiahf/vczjk/o000Oo0;

    invoke-direct {p1, p0, v4}, Llyiahf/vczjk/o000Oo0;-><init>(Llyiahf/vczjk/o000Oo0;Llyiahf/vczjk/u66;)V

    return-object p1

    :cond_3
    if-nez v1, :cond_4

    return-object p0

    :cond_4
    new-instance p1, Llyiahf/vczjk/o000Oo0;

    iget-object p2, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/o000Oo0;-><init>(Llyiahf/vczjk/o000Oo0;Llyiahf/vczjk/u66;)V

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 3

    new-instance p2, Llyiahf/vczjk/mca;

    iget-object v0, p0, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    invoke-direct {p2, v0}, Llyiahf/vczjk/mca;-><init>(Llyiahf/vczjk/x64;)V

    iget-object v0, p0, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "abstract types either need to be mapped to concrete types, have custom deserializer, or contain additional type information"

    invoke-virtual {p1, v0, p2, v2, v1}, Llyiahf/vczjk/v72;->o000OOo(Ljava/lang/Class;Llyiahf/vczjk/nca;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/u3a;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OooOo()Llyiahf/vczjk/gc4;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/gc4;->OooO0o0()Z

    move-result v2

    if-nez v2, :cond_1

    sget-object v2, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    if-ne v0, v2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oOO()Llyiahf/vczjk/gc4;

    move-result-object v0

    :cond_0
    sget-object v2, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    if-ne v0, v2, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object v0, v0, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto :goto_0

    :cond_1
    iget-object p3, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u66;->OooO00o(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    iget-object p3, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    iget-object p3, p3, Llyiahf/vczjk/u66;->generator:Llyiahf/vczjk/p66;

    invoke-virtual {p2, p1, p3}, Llyiahf/vczjk/v72;->o00Ooo(Ljava/lang/Object;Llyiahf/vczjk/p66;)Llyiahf/vczjk/bh7;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    throw v1

    :cond_2
    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->OooOoO()I

    move-result v0

    packed-switch v0, :pswitch_data_0

    goto :goto_1

    :pswitch_0
    iget-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptBoolean:Z

    if-eqz v0, :cond_3

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    goto :goto_1

    :pswitch_1
    iget-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptBoolean:Z

    if-eqz v0, :cond_3

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    goto :goto_1

    :pswitch_2
    iget-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptDouble:Z

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0ooOO0()D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    move-result-object v1

    goto :goto_1

    :pswitch_3
    iget-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptInt:Z

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o00000o0()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v1

    goto :goto_1

    :pswitch_4
    iget-boolean v0, p0, Llyiahf/vczjk/o000Oo0;->_acceptString:Z

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000oO()Ljava/lang/String;

    move-result-object v1

    :cond_3
    :goto_1
    if-eqz v1, :cond_4

    return-object v1

    :cond_4
    invoke-virtual {p3, p2, p1}, Llyiahf/vczjk/u3a;->OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x6
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0oo(Ljava/lang/String;)Llyiahf/vczjk/ph8;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o000Oo0;->_backRefProperties:Ljava/util/Map;

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    invoke-interface {v0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ph8;

    return-object p1
.end method

.method public final OooOO0o()Llyiahf/vczjk/u66;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o000Oo0;->_objectIdReader:Llyiahf/vczjk/u66;

    return-object v0
.end method

.method public final OooOOO0()Ljava/lang/Class;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o000Oo0;->_baseType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooO()Ljava/lang/Class;

    move-result-object v0

    return-object v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method
