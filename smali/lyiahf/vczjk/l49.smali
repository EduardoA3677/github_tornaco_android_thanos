.class public final Llyiahf/vczjk/l49;
.super Llyiahf/vczjk/b59;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;
.implements Llyiahf/vczjk/pr7;


# instance fields
.field protected final _converter:Llyiahf/vczjk/gp1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gp1;"
        }
    .end annotation
.end field

.field protected final _delegateSerializer:Llyiahf/vczjk/zb4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zb4;"
        }
    .end annotation
.end field

.field protected final _delegateType:Llyiahf/vczjk/x64;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;)V
    .locals 0

    invoke-direct {p0, p2}, Llyiahf/vczjk/b59;-><init>(Llyiahf/vczjk/x64;)V

    iput-object p1, p0, Llyiahf/vczjk/l49;->_converter:Llyiahf/vczjk/gp1;

    iput-object p2, p0, Llyiahf/vczjk/l49;->_delegateType:Llyiahf/vczjk/x64;

    iput-object p3, p0, Llyiahf/vczjk/l49;->_delegateSerializer:Llyiahf/vczjk/zb4;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/tg8;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/l49;->_delegateSerializer:Llyiahf/vczjk/zb4;

    if-eqz v0, :cond_0

    instance-of v1, v0, Llyiahf/vczjk/pr7;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/pr7;

    invoke-interface {v0, p1}, Llyiahf/vczjk/pr7;->OooO00o(Llyiahf/vczjk/tg8;)V

    :cond_0
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/l49;->_delegateSerializer:Llyiahf/vczjk/zb4;

    iget-object v1, p0, Llyiahf/vczjk/l49;->_delegateType:Llyiahf/vczjk/x64;

    if-nez v0, :cond_1

    if-nez v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/l49;->_converter:Llyiahf/vczjk/gp1;

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->Oooo0o0()Llyiahf/vczjk/a4a;

    check-cast v1, Llyiahf/vczjk/j74;

    iget-object v1, v1, Llyiahf/vczjk/j74;->OooO00o:Llyiahf/vczjk/x64;

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/x64;->o0OoOo0()Z

    move-result v2

    if-nez v2, :cond_1

    invoke-virtual {p1, v1}, Llyiahf/vczjk/tg8;->o0Oo0oo(Llyiahf/vczjk/x64;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_1
    instance-of v2, v0, Llyiahf/vczjk/xo1;

    if-eqz v2, :cond_2

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/tg8;->o00000O(Llyiahf/vczjk/zb4;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/l49;->_delegateSerializer:Llyiahf/vczjk/zb4;

    if-ne v0, p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/l49;->_delegateType:Llyiahf/vczjk/x64;

    if-ne v1, p1, :cond_3

    return-object p0

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/l49;->_converter:Llyiahf/vczjk/gp1;

    const-class p2, Llyiahf/vczjk/l49;

    const-string v2, "withDelegate"

    invoke-static {p2, p0, v2}, Llyiahf/vczjk/vy0;->OooOoOO(Ljava/lang/Class;Ljava/io/Serializable;Ljava/lang/String;)V

    new-instance p2, Llyiahf/vczjk/l49;

    invoke-direct {p2, p1, v1, v0}, Llyiahf/vczjk/l49;-><init>(Llyiahf/vczjk/gp1;Llyiahf/vczjk/x64;Llyiahf/vczjk/zb4;)V

    return-object p2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/l49;->_converter:Llyiahf/vczjk/gp1;

    check-cast v0, Llyiahf/vczjk/j74;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/j74;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    if-nez p2, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/l49;->_delegateSerializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_1

    const/4 p1, 0x0

    return p1

    :cond_1
    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/zb4;->OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z

    move-result p1

    return p1
.end method

.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/l49;->_converter:Llyiahf/vczjk/gp1;

    check-cast v0, Llyiahf/vczjk/j74;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/j74;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-nez p1, :cond_0

    invoke-virtual {p3, p2}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/l49;->_delegateSerializer:Llyiahf/vczjk/zb4;

    if-nez v0, :cond_1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0ooOoO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v0

    :cond_1
    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/zb4;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/l49;->_converter:Llyiahf/vczjk/gp1;

    check-cast v0, Llyiahf/vczjk/j74;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/j74;->OooO0O0(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/l49;->_delegateSerializer:Llyiahf/vczjk/zb4;

    if-nez v1, :cond_0

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object p1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/tg8;->o0ooOoO(Ljava/lang/Class;)Llyiahf/vczjk/zb4;

    move-result-object v1

    :cond_0
    invoke-virtual {v1, v0, p2, p3, p4}, Llyiahf/vczjk/zb4;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void
.end method
