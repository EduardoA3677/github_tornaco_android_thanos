.class public abstract Llyiahf/vczjk/my;
.super Llyiahf/vczjk/em1;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected final _property:Llyiahf/vczjk/db0;

.field protected final _unwrapSingle:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/lang/Class;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/b59;-><init>(Ljava/lang/Class;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/my;->_property:Llyiahf/vczjk/db0;

    iput-object p1, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/my;Llyiahf/vczjk/db0;Ljava/lang/Boolean;)V
    .locals 1

    iget-object p1, p1, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    const/4 v0, 0x0

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/b59;-><init>(ILjava/lang/Class;)V

    iput-object p2, p0, Llyiahf/vczjk/my;->_property:Llyiahf/vczjk/db0;

    iput-object p3, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    return-void
.end method


# virtual methods
.method public OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 1

    if-eqz p2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v0}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object p1

    if-eqz p1, :cond_0

    sget-object v0, Llyiahf/vczjk/n94;->OooOOOO:Llyiahf/vczjk/n94;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/q94;->OooO0O0(Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    if-eq p1, v0, :cond_0

    invoke-virtual {p0, p2, p1}, Llyiahf/vczjk/my;->OooOOOo(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_0
    return-object p0
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, v0}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/my;->OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method

.method public final OooOOOO(Llyiahf/vczjk/tg8;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/my;->_unwrapSingle:Ljava/lang/Boolean;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/ig8;->OooOooO:Llyiahf/vczjk/ig8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result p1

    return p1

    :cond_0
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    return p1
.end method

.method public abstract OooOOOo(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;
.end method

.method public abstract OooOOo0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
.end method
