.class public final Llyiahf/vczjk/pb5;
.super Llyiahf/vczjk/em1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected _dynamicValueSerializers:Llyiahf/vczjk/gb7;

.field protected final _entryType:Llyiahf/vczjk/x64;

.field protected _keySerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _keyType:Llyiahf/vczjk/x64;

.field protected final _property:Llyiahf/vczjk/db0;

.field protected final _suppressNulls:Z

.field protected final _suppressableValue:Ljava/lang/Object;

.field protected _valueSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _valueType:Llyiahf/vczjk/x64;

.field protected final _valueTypeIsStatic:Z

.field protected final _valueTypeSerializer:Llyiahf/vczjk/d5a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pb5;Llyiahf/vczjk/zb4;Llyiahf/vczjk/zb4;Ljava/lang/Object;Z)V
    .locals 2

    const-class v0, Ljava/util/Map;

    const/4 v1, 0x0

    invoke-direct {p0, v1, v0}, Llyiahf/vczjk/b59;-><init>(ILjava/lang/Class;)V

    iget-object v0, p1, Llyiahf/vczjk/pb5;->_entryType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/pb5;->_entryType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/pb5;->_keyType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/pb5;->_keyType:Llyiahf/vczjk/x64;

    iget-object v0, p1, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    iget-boolean v0, p1, Llyiahf/vczjk/pb5;->_valueTypeIsStatic:Z

    iput-boolean v0, p0, Llyiahf/vczjk/pb5;->_valueTypeIsStatic:Z

    iget-object v0, p1, Llyiahf/vczjk/pb5;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iput-object v0, p0, Llyiahf/vczjk/pb5;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iput-object p2, p0, Llyiahf/vczjk/pb5;->_keySerializer:Llyiahf/vczjk/zb4;

    iput-object p3, p0, Llyiahf/vczjk/pb5;->_valueSerializer:Llyiahf/vczjk/zb4;

    sget-object p2, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p2, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    iget-object p1, p1, Llyiahf/vczjk/pb5;->_property:Llyiahf/vczjk/db0;

    iput-object p1, p0, Llyiahf/vczjk/pb5;->_property:Llyiahf/vczjk/db0;

    iput-object p4, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    iput-boolean p5, p0, Llyiahf/vczjk/pb5;->_suppressNulls:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/db0;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/b59;-><init>(Llyiahf/vczjk/x64;)V

    iput-object p1, p0, Llyiahf/vczjk/pb5;->_entryType:Llyiahf/vczjk/x64;

    iput-object p2, p0, Llyiahf/vczjk/pb5;->_keyType:Llyiahf/vczjk/x64;

    iput-object p3, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    iput-boolean p4, p0, Llyiahf/vczjk/pb5;->_valueTypeIsStatic:Z

    iput-object p5, p0, Llyiahf/vczjk/pb5;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iput-object p6, p0, Llyiahf/vczjk/pb5;->_property:Llyiahf/vczjk/db0;

    sget-object p1, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p1, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/pb5;->_suppressNulls:Z

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 10

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v0

    const/4 v1, 0x0

    if-nez p2, :cond_0

    move-object v2, v1

    goto :goto_0

    :cond_0
    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v2

    :goto_0
    if-eqz v2, :cond_3

    if-eqz v0, :cond_3

    invoke-virtual {v0, v2}, Llyiahf/vczjk/yn;->OooOOoo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v3

    goto :goto_1

    :cond_1
    move-object v3, v1

    :goto_1
    invoke-virtual {v0, v2}, Llyiahf/vczjk/yn;->OooO0Oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {p1, v2, v0}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v0

    goto :goto_2

    :cond_2
    move-object v0, v1

    goto :goto_2

    :cond_3
    move-object v0, v1

    move-object v3, v0

    :goto_2
    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/pb5;->_valueSerializer:Llyiahf/vczjk/zb4;

    :cond_4
    invoke-static {p1, p2, v0}, Llyiahf/vczjk/b59;->OooOO0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_5

    iget-boolean v2, p0, Llyiahf/vczjk/pb5;->_valueTypeIsStatic:Z

    if-eqz v2, :cond_5

    iget-object v2, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v2

    if-nez v2, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/tg8;->o00Ooo(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_5
    move-object v7, v0

    if-nez v3, :cond_6

    iget-object v3, p0, Llyiahf/vczjk/pb5;->_keySerializer:Llyiahf/vczjk/zb4;

    :cond_6
    if-nez v3, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/pb5;->_keyType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/tg8;->o00o0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :goto_3
    move-object v6, v0

    goto :goto_4

    :cond_7
    invoke-virtual {p1, v3, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v0

    goto :goto_3

    :goto_4
    iget-object v0, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    iget-boolean v2, p0, Llyiahf/vczjk/pb5;->_suppressNulls:Z

    if-eqz p2, :cond_e

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object v3

    invoke-interface {p2, v3, v1}, Llyiahf/vczjk/db0;->OooO0Oo(Llyiahf/vczjk/gg8;Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object p2

    if-eqz p2, :cond_e

    invoke-virtual {p2}, Llyiahf/vczjk/fa4;->OooO0O0()Llyiahf/vczjk/ea4;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/ea4;->OooOOo0:Llyiahf/vczjk/ea4;

    if-eq v3, v4, :cond_e

    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    const/4 v2, 0x1

    if-eq v0, v2, :cond_8

    sget-object v3, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    const/4 v4, 0x2

    if-eq v0, v4, :cond_d

    const/4 v4, 0x3

    if-eq v0, v4, :cond_c

    const/4 v3, 0x4

    if-eq v0, v3, :cond_b

    const/4 v3, 0x5

    if-eq v0, v3, :cond_9

    const/4 v2, 0x0

    :cond_8
    :goto_5
    move-object v8, v1

    :goto_6
    move v9, v2

    goto :goto_7

    :cond_9
    invoke-virtual {p2}, Llyiahf/vczjk/fa4;->OooO00o()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/tg8;->o00000OO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_a

    goto :goto_5

    :cond_a
    invoke-virtual {p1, v1}, Llyiahf/vczjk/tg8;->o00000Oo(Ljava/lang/Object;)Z

    move-result v2

    goto :goto_5

    :cond_b
    iget-object p1, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo000(Llyiahf/vczjk/x64;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_8

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->isArray()Z

    move-result p1

    if-eqz p1, :cond_8

    invoke-static {v1}, Llyiahf/vczjk/ex9;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/yw;

    move-result-object v1

    goto :goto_5

    :cond_c
    move v9, v2

    move-object v8, v3

    goto :goto_7

    :cond_d
    iget-object p1, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {p1}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result p1

    if-eqz p1, :cond_8

    move-object v1, v3

    goto :goto_5

    :cond_e
    move-object v8, v0

    goto :goto_6

    :goto_7
    new-instance v4, Llyiahf/vczjk/pb5;

    move-object v5, p0

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/pb5;-><init>(Llyiahf/vczjk/pb5;Llyiahf/vczjk/zb4;Llyiahf/vczjk/zb4;Ljava/lang/Object;Z)V

    return-object v4
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 3

    check-cast p2, Ljava/util/Map$Entry;

    invoke-interface {p2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object p2

    if-nez p2, :cond_0

    iget-boolean p1, p0, Llyiahf/vczjk/pb5;->_suppressNulls:Z

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/pb5;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_4

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v1

    if-nez v1, :cond_3

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    iget-object v2, p0, Llyiahf/vczjk/pb5;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v2

    invoke-virtual {v1, v0, v2}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object v0

    if-eq v1, v0, :cond_2

    iput-object v0, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;
    :try_end_0
    .catch Llyiahf/vczjk/na4; {:try_start_0 .. :try_end_0} :catch_0

    :cond_2
    move-object v0, v2

    goto :goto_1

    :catch_0
    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_3
    move-object v0, v1

    :cond_4
    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    if-ne v1, v2, :cond_5

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/zb4;->OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_5
    invoke-virtual {v1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 0

    check-cast p1, Ljava/util/Map$Entry;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000oOO(Ljava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/pb5;->OooOOOO(Ljava/util/Map$Entry;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000o0()V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    check-cast p1, Ljava/util/Map$Entry;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOO:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, v0}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/pb5;->OooOOOO(Ljava/util/Map$Entry;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method

.method public final OooOOO(Llyiahf/vczjk/d5a;)Llyiahf/vczjk/em1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/pb5;

    iget-object v2, p0, Llyiahf/vczjk/pb5;->_keySerializer:Llyiahf/vczjk/zb4;

    iget-object v3, p0, Llyiahf/vczjk/pb5;->_valueSerializer:Llyiahf/vczjk/zb4;

    iget-object v4, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    iget-boolean v5, p0, Llyiahf/vczjk/pb5;->_suppressNulls:Z

    move-object v1, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/pb5;-><init>(Llyiahf/vczjk/pb5;Llyiahf/vczjk/zb4;Llyiahf/vczjk/zb4;Ljava/lang/Object;Z)V

    return-object v0
.end method

.method public final OooOOOO(Ljava/util/Map$Entry;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/pb5;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->o00ooo()Llyiahf/vczjk/zb4;

    move-result-object v2

    goto :goto_0

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/pb5;->_keySerializer:Llyiahf/vczjk/zb4;

    :goto_0
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v3

    if-nez v3, :cond_2

    iget-boolean v4, p0, Llyiahf/vczjk/pb5;->_suppressNulls:Z

    if-eqz v4, :cond_1

    goto :goto_2

    :cond_1
    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->o000000()Llyiahf/vczjk/zb4;

    move-result-object v4

    goto :goto_3

    :cond_2
    iget-object v4, p0, Llyiahf/vczjk/pb5;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v4, :cond_7

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v4

    iget-object v5, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    invoke-virtual {v5, v4}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v5

    if-nez v5, :cond_6

    iget-object v5, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {v5}, Llyiahf/vczjk/x64;->OoooOoO()Z

    move-result v5

    if-eqz v5, :cond_4

    iget-object v5, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    iget-object v6, p0, Llyiahf/vczjk/pb5;->_valueType:Llyiahf/vczjk/x64;

    invoke-virtual {p3, v4, v6}, Llyiahf/vczjk/tg8;->ooOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v4

    iget-object v6, p0, Llyiahf/vczjk/pb5;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {v5, v4, p3, v6}, Llyiahf/vczjk/gb7;->OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/a27;

    move-result-object v4

    iget-object v6, v4, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/gb7;

    if-eq v5, v6, :cond_3

    iput-object v6, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    :cond_3
    iget-object v4, v4, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/zb4;

    goto :goto_1

    :cond_4
    iget-object v5, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    iget-object v6, p0, Llyiahf/vczjk/pb5;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p3, v4, v6}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v6

    invoke-virtual {v5, v4, v6}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object v4

    if-eq v5, v4, :cond_5

    iput-object v4, p0, Llyiahf/vczjk/pb5;->_dynamicValueSerializers:Llyiahf/vczjk/gb7;

    :cond_5
    move-object v4, v6

    goto :goto_1

    :cond_6
    move-object v4, v5

    :cond_7
    :goto_1
    iget-object v5, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    if-eqz v5, :cond_9

    sget-object v6, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    if-ne v5, v6, :cond_8

    invoke-virtual {v4, p3, v3}, Llyiahf/vczjk/zb4;->OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_8

    goto :goto_2

    :cond_8
    iget-object v5, p0, Llyiahf/vczjk/pb5;->_suppressableValue:Ljava/lang/Object;

    invoke-virtual {v5, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_9

    :goto_2
    return-void

    :cond_9
    :goto_3
    invoke-virtual {v2, v1, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    if-nez v0, :cond_a

    :try_start_0
    invoke-virtual {v4, v3, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :catch_0
    move-exception p2

    goto :goto_4

    :cond_a
    invoke-virtual {v4, v3, p2, p3, v0}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :goto_4
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, ""

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {p3, p2, p1, v0}, Llyiahf/vczjk/b59;->OooOOO0(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method
