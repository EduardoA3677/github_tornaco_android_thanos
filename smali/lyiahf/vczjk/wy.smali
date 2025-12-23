.class public abstract Llyiahf/vczjk/wy;
.super Llyiahf/vczjk/em1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected _dynamicSerializers:Llyiahf/vczjk/gb7;

.field protected final _elementSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _elementType:Llyiahf/vczjk/x64;

.field protected final _property:Llyiahf/vczjk/db0;

.field protected final _staticTyping:Z

.field protected final _unwrapSingle:Ljava/lang/Boolean;

.field protected final _valueTypeSerializer:Llyiahf/vczjk/d5a;


# direct methods
.method public constructor <init>(Ljava/lang/Class;Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/b59;-><init>(ILjava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/wy;->_elementType:Llyiahf/vczjk/x64;

    if-nez p3, :cond_0

    if-eqz p2, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/x64;->OoooooO()Z

    move-result p1

    if-eqz p1, :cond_1

    :cond_0
    const/4 v0, 0x1

    :cond_1
    iput-boolean v0, p0, Llyiahf/vczjk/wy;->_staticTyping:Z

    iput-object p4, p0, Llyiahf/vczjk/wy;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/wy;->_property:Llyiahf/vczjk/db0;

    iput-object p5, p0, Llyiahf/vczjk/wy;->_elementSerializer:Llyiahf/vczjk/zb4;

    sget-object p2, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p2, p0, Llyiahf/vczjk/wy;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    iput-object p1, p0, Llyiahf/vczjk/wy;->_unwrapSingle:Ljava/lang/Boolean;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/wy;Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)V
    .locals 2

    iget-object v0, p1, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-direct {p0, v1, v0}, Llyiahf/vczjk/b59;-><init>(ILjava/lang/Class;)V

    iget-object v0, p1, Llyiahf/vczjk/wy;->_elementType:Llyiahf/vczjk/x64;

    iput-object v0, p0, Llyiahf/vczjk/wy;->_elementType:Llyiahf/vczjk/x64;

    iget-boolean p1, p1, Llyiahf/vczjk/wy;->_staticTyping:Z

    iput-boolean p1, p0, Llyiahf/vczjk/wy;->_staticTyping:Z

    iput-object p3, p0, Llyiahf/vczjk/wy;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    iput-object p2, p0, Llyiahf/vczjk/wy;->_property:Llyiahf/vczjk/db0;

    iput-object p4, p0, Llyiahf/vczjk/wy;->_elementSerializer:Llyiahf/vczjk/zb4;

    sget-object p1, Llyiahf/vczjk/cb7;->OooO00o:Llyiahf/vczjk/cb7;

    iput-object p1, p0, Llyiahf/vczjk/wy;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    iput-object p5, p0, Llyiahf/vczjk/wy;->_unwrapSingle:Ljava/lang/Boolean;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/wy;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    if-eqz v0, :cond_0

    invoke-virtual {v0, p2}, Llyiahf/vczjk/d5a;->OooO00o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/d5a;

    move-result-object v0

    :cond_0
    const/4 v1, 0x0

    if-eqz p2, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v2

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v3

    if-eqz v3, :cond_1

    invoke-virtual {v2, v3}, Llyiahf/vczjk/yn;->OooO0Oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v2

    goto :goto_0

    :cond_1
    move-object v2, v1

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v3}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object v3

    if-eqz v3, :cond_2

    sget-object v1, Llyiahf/vczjk/n94;->OooOOOO:Llyiahf/vczjk/n94;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/q94;->OooO0O0(Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v1

    :cond_2
    if-nez v2, :cond_3

    iget-object v2, p0, Llyiahf/vczjk/wy;->_elementSerializer:Llyiahf/vczjk/zb4;

    :cond_3
    invoke-static {p1, p2, v2}, Llyiahf/vczjk/b59;->OooOO0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/zb4;

    move-result-object v2

    if-nez v2, :cond_4

    iget-object v3, p0, Llyiahf/vczjk/wy;->_elementType:Llyiahf/vczjk/x64;

    if-eqz v3, :cond_4

    iget-boolean v4, p0, Llyiahf/vczjk/wy;->_staticTyping:Z

    if-eqz v4, :cond_4

    invoke-virtual {v3}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v3

    if-nez v3, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/wy;->_elementType:Llyiahf/vczjk/x64;

    invoke-virtual {p1, v2, p2}, Llyiahf/vczjk/tg8;->o00Ooo(Llyiahf/vczjk/x64;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v2

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/wy;->_elementSerializer:Llyiahf/vczjk/zb4;

    if-ne v2, p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/wy;->_property:Llyiahf/vczjk/db0;

    if-ne p2, p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/wy;->_valueTypeSerializer:Llyiahf/vczjk/d5a;

    if-ne p1, v0, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/wy;->_unwrapSingle:Ljava/lang/Boolean;

    if-eq p1, v1, :cond_5

    goto :goto_1

    :cond_5
    return-object p0

    :cond_6
    :goto_1
    invoke-virtual {p0, p2, v0, v2, v1}, Llyiahf/vczjk/wy;->OooOOo(Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)Llyiahf/vczjk/wy;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, v0}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/wy;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method

.method public final OooOOOO(Llyiahf/vczjk/gb7;Ljava/lang/Class;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wy;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p3, p2, v0}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object p3

    invoke-virtual {p1, p2, p3}, Llyiahf/vczjk/gb7;->OooO0O0(Ljava/lang/Class;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/gb7;

    move-result-object p2

    if-eq p1, p2, :cond_0

    iput-object p2, p0, Llyiahf/vczjk/wy;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    :cond_0
    return-object p3
.end method

.method public final OooOOOo(Llyiahf/vczjk/gb7;Llyiahf/vczjk/x64;Llyiahf/vczjk/tg8;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wy;->_property:Llyiahf/vczjk/db0;

    invoke-virtual {p1, p2, p3, v0}, Llyiahf/vczjk/gb7;->OooO00o(Llyiahf/vczjk/x64;Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/a27;

    move-result-object p2

    iget-object p3, p2, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast p3, Llyiahf/vczjk/gb7;

    if-eq p1, p3, :cond_0

    iput-object p3, p0, Llyiahf/vczjk/wy;->_dynamicSerializers:Llyiahf/vczjk/gb7;

    :cond_0
    iget-object p1, p2, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/zb4;

    return-object p1
.end method

.method public abstract OooOOo(Llyiahf/vczjk/db0;Llyiahf/vczjk/d5a;Llyiahf/vczjk/zb4;Ljava/lang/Boolean;)Llyiahf/vczjk/wy;
.end method

.method public abstract OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
.end method
