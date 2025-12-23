.class public abstract Llyiahf/vczjk/pl7;
.super Llyiahf/vczjk/b59;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field public transient OooOOO:Llyiahf/vczjk/gb7;

.field protected final _property:Llyiahf/vczjk/db0;

.field protected final _referredType:Llyiahf/vczjk/x64;

.field protected final _suppressNulls:Z

.field protected final _suppressableValue:Ljava/lang/Object;

.field protected final _unwrapper:Llyiahf/vczjk/wt5;

.field protected final _valueSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _valueTypeSerializer:Llyiahf/vczjk/d5a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/i10;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Llyiahf/vczjk/wt5;Ljava/lang/Object;Z)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/b59;-><init>(Llyiahf/vczjk/b59;)V

    iget-object p1, p1, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    iput-object p1, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    sget-object p1, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p1, p0, Llyiahf/vczjk/pl7;->OooOOO:Llyiahf/vczjk/gb7;

    iput-object p2, p0, Llyiahf/vczjk/pl7;->_property:Llyiahf/vczjk/db0;

    iput-object p3, p0, Llyiahf/vczjk/pl7;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iput-object p4, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    iput-object p5, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    iput-object p6, p0, Llyiahf/vczjk/pl7;->_suppressableValue:Ljava/lang/Object;

    iput-boolean p7, p0, Llyiahf/vczjk/pl7;->_suppressNulls:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/nl7;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/b59;-><init>(Llyiahf/vczjk/x64;)V

    invoke-virtual {p1}, Llyiahf/vczjk/nl7;->OoooOO0()Llyiahf/vczjk/x64;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/pl7;->_property:Llyiahf/vczjk/db0;

    iput-object p2, p0, Llyiahf/vczjk/pl7;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iput-object p3, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    iput-object p1, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    iput-object p1, p0, Llyiahf/vczjk/pl7;->_suppressableValue:Ljava/lang/Object;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/pl7;->_suppressNulls:Z

    sget-object p1, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p1, p0, Llyiahf/vczjk/pl7;->OooOOO:Llyiahf/vczjk/gb7;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/pl7;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

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
    const/4 v9, 0x0

    const/4 v10, 0x1

    if-nez v1, :cond_7

    iget-object v1, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_8

    iget-object v2, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v3

    if-eqz v3, :cond_2

    :goto_1
    move v2, v9

    goto :goto_3

    :cond_2
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->OoooooO()Z

    move-result v3

    if-eqz v3, :cond_3

    :goto_2
    move v2, v10

    goto :goto_3

    :cond_3
    invoke-virtual {v2}, Llyiahf/vczjk/x64;->o00ooo()Z

    move-result v2

    if-eqz v2, :cond_4

    goto :goto_2

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v2

    if-eqz v2, :cond_6

    if-eqz p2, :cond_6

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v3

    if-eqz v3, :cond_6

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v3

    invoke-virtual {v2, v3}, Llyiahf/vczjk/yn;->OoooO0(Llyiahf/vczjk/u34;)Llyiahf/vczjk/wb4;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/wb4;->OooOOO:Llyiahf/vczjk/wb4;

    if-ne v2, v3, :cond_5

    goto :goto_2

    :cond_5
    sget-object v3, Llyiahf/vczjk/wb4;->OooOOO0:Llyiahf/vczjk/wb4;

    if-ne v2, v3, :cond_6

    goto :goto_1

    :cond_6
    sget-object v2, Llyiahf/vczjk/gc5;->OooOoOO:Llyiahf/vczjk/gc5;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/tg8;->o00000o0(Llyiahf/vczjk/gc5;)Z

    move-result v2

    :goto_3
    if-eqz v2, :cond_7

    iget-object v1, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/tg8;->o00oO0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v1

    :cond_7
    :goto_4
    move-object v5, v1

    goto :goto_5

    :cond_8
    invoke-virtual {p1, v1, p2}, Llyiahf/vczjk/tg8;->o00000O0(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v1

    goto :goto_4

    :goto_5
    iget-object v1, p0, Llyiahf/vczjk/pl7;->_property:Llyiahf/vczjk/db0;

    if-ne v1, p2, :cond_9

    iget-object v1, p0, Llyiahf/vczjk/pl7;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    if-ne v1, v4, :cond_9

    iget-object v1, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-ne v1, v5, :cond_9

    move-object v1, p0

    move-object v3, p2

    goto :goto_6

    :cond_9
    iget-object v6, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    move-object v2, p0

    check-cast v2, Llyiahf/vczjk/i10;

    new-instance v1, Llyiahf/vczjk/i10;

    iget-object v7, v2, Llyiahf/vczjk/pl7;->_suppressableValue:Ljava/lang/Object;

    iget-boolean v8, v2, Llyiahf/vczjk/pl7;->_suppressNulls:Z

    move-object v3, p2

    invoke-direct/range {v1 .. v8}, Llyiahf/vczjk/pl7;-><init>(Llyiahf/vczjk/i10;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Llyiahf/vczjk/wt5;Ljava/lang/Object;Z)V

    :goto_6
    if-eqz v3, :cond_11

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o000OOo()Llyiahf/vczjk/gg8;

    move-result-object p2

    iget-object v2, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-interface {v3, p2, v2}, Llyiahf/vczjk/db0;->OooO0Oo(Llyiahf/vczjk/gg8;Ljava/lang/Class;)Llyiahf/vczjk/fa4;

    move-result-object p2

    if-eqz p2, :cond_11

    invoke-virtual {p2}, Llyiahf/vczjk/fa4;->OooO0O0()Llyiahf/vczjk/ea4;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/ea4;->OooOOo0:Llyiahf/vczjk/ea4;

    if-eq v2, v3, :cond_11

    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    if-eq v2, v10, :cond_b

    sget-object v3, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    const/4 v4, 0x2

    if-eq v2, v4, :cond_f

    const/4 v4, 0x3

    if-eq v2, v4, :cond_e

    const/4 v3, 0x4

    if-eq v2, v3, :cond_d

    const/4 v3, 0x5

    if-eq v2, v3, :cond_a

    goto :goto_9

    :cond_a
    invoke-virtual {p2}, Llyiahf/vczjk/fa4;->OooO00o()Ljava/lang/Class;

    move-result-object p2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/tg8;->o00000OO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_c

    :cond_b
    :goto_7
    move v9, v10

    goto :goto_9

    :cond_c
    invoke-virtual {p1, v0}, Llyiahf/vczjk/tg8;->o00000Oo(Ljava/lang/Object;)Z

    move-result v9

    goto :goto_9

    :cond_d
    iget-object p1, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo000(Llyiahf/vczjk/x64;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_b

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Class;->isArray()Z

    move-result p1

    if-eqz p1, :cond_b

    invoke-static {v0}, Llyiahf/vczjk/ex9;->OooO0OO(Ljava/lang/Object;)Llyiahf/vczjk/yw;

    move-result-object v0

    goto :goto_7

    :cond_e
    :goto_8
    move-object v0, v3

    goto :goto_7

    :cond_f
    iget-object p1, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    invoke-virtual {p1}, Llyiahf/vczjk/ok6;->OooOoO0()Z

    move-result p1

    if-eqz p1, :cond_b

    goto :goto_8

    :goto_9
    iget-object p1, p0, Llyiahf/vczjk/pl7;->_suppressableValue:Ljava/lang/Object;

    if-ne p1, v0, :cond_10

    iget-boolean p1, p0, Llyiahf/vczjk/pl7;->_suppressNulls:Z

    if-eq p1, v9, :cond_11

    :cond_10
    invoke-virtual {v1, v0, v9}, Llyiahf/vczjk/pl7;->OooOOOO(Ljava/lang/Object;Z)Llyiahf/vczjk/i10;

    move-result-object p1

    return-object p1

    :cond_11
    return-object v1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 3

    check-cast p2, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_4

    invoke-virtual {p2}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p2

    if-nez p2, :cond_0

    iget-boolean p1, p0, Llyiahf/vczjk/pl7;->_suppressNulls:Z

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/pl7;->_suppressableValue:Ljava/lang/Object;

    if-nez v0, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_2

    :try_start_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/pl7;->OooOOO(Llyiahf/vczjk/tg8;Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0
    :try_end_0
    .catch Llyiahf/vczjk/na4; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    new-instance p2, Llyiahf/vczjk/k61;

    invoke-direct {p2, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw p2

    :cond_2
    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/pl7;->_suppressableValue:Ljava/lang/Object;

    sget-object v2, Llyiahf/vczjk/ea4;->OooOOOO:Llyiahf/vczjk/ea4;

    if-ne v1, v2, :cond_3

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/zb4;->OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_3
    invoke-virtual {v1, p2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    return p1

    :cond_4
    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    check-cast p1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    if-nez p1, :cond_0

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    :cond_0
    return-void

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0, p3, v0}, Llyiahf/vczjk/pl7;->OooOOO(Llyiahf/vczjk/tg8;Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/pl7;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    if-eqz v1, :cond_3

    invoke-virtual {v0, p1, p2, p3, v1}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void

    :cond_3
    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method

.method public final OooO0o0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    check-cast p1, Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {p1}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    if-nez p1, :cond_0

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    :cond_0
    return-void

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p0, p3, v0}, Llyiahf/vczjk/pl7;->OooOOO(Llyiahf/vczjk/tg8;Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_2
    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void
.end method

.method public final OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zb4;->OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-ne v0, v1, :cond_0

    goto :goto_1

    :cond_0
    move-object v6, v0

    iget-object v0, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    if-nez v0, :cond_1

    move-object v7, p1

    goto :goto_0

    :cond_1
    new-instance v1, Llyiahf/vczjk/ut5;

    invoke-direct {v1, p1, v0}, Llyiahf/vczjk/ut5;-><init>(Llyiahf/vczjk/wt5;Llyiahf/vczjk/wt5;)V

    move-object v7, v1

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/pl7;->_valueSerializer:Llyiahf/vczjk/zb4;

    if-ne p1, v6, :cond_2

    if-ne v0, v7, :cond_2

    :goto_1
    return-object p0

    :cond_2
    iget-object v4, p0, Llyiahf/vczjk/pl7;->_property:Llyiahf/vczjk/db0;

    iget-object v5, p0, Llyiahf/vczjk/pl7;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/i10;

    new-instance v2, Llyiahf/vczjk/i10;

    iget-object v8, v3, Llyiahf/vczjk/pl7;->_suppressableValue:Ljava/lang/Object;

    iget-boolean v9, v3, Llyiahf/vczjk/pl7;->_suppressNulls:Z

    invoke-direct/range {v2 .. v9}, Llyiahf/vczjk/pl7;-><init>(Llyiahf/vczjk/i10;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Llyiahf/vczjk/wt5;Ljava/lang/Object;Z)V

    return-object v2
.end method

.method public final OooOOO(Llyiahf/vczjk/tg8;Ljava/lang/Class;)Llyiahf/vczjk/zb4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/pl7;->OooOOO:Llyiahf/vczjk/gb7;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/gb7;->OooO0OO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    if-nez v0, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    invoke-virtual {v0}, Llyiahf/vczjk/x64;->OoooOoO()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/pl7;->_referredType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/tg8;->ooOO(Ljava/lang/Class;Llyiahf/vczjk/x64;)Llyiahf/vczjk/x64;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/pl7;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/tg8;->o00oO0O(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/pl7;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/tg8;->o00oO0o(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p1

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/pl7;->_unwrapper:Llyiahf/vczjk/wt5;

    if-eqz v0, :cond_1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zb4;->OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;

    move-result-object p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/pl7;->OooOOO:Llyiahf/vczjk/gb7;

    invoke-virtual {v0, p2, p1}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/pl7;->OooOOO:Llyiahf/vczjk/gb7;

    return-object p1

    :cond_2
    return-object v0
.end method

.method public abstract OooOOOO(Ljava/lang/Object;Z)Llyiahf/vczjk/i10;
.end method
