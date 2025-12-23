.class public abstract Llyiahf/vczjk/k39;
.super Llyiahf/vczjk/b59;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xo1;


# instance fields
.field protected final _unwrapSingle:Ljava/lang/Boolean;


# direct methods
.method public constructor <init>(Ljava/lang/Class;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, v0, p1}, Llyiahf/vczjk/b59;-><init>(ILjava/lang/Class;)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/k39;->_unwrapSingle:Ljava/lang/Boolean;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/k39;Ljava/lang/Boolean;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/b59;-><init>(Llyiahf/vczjk/b59;)V

    iput-object p2, p0, Llyiahf/vczjk/k39;->_unwrapSingle:Ljava/lang/Boolean;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;
    .locals 5

    const/4 v0, 0x0

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->o0O0O00()Llyiahf/vczjk/yn;

    move-result-object v1

    invoke-interface {p2}, Llyiahf/vczjk/db0;->OooO00o()Llyiahf/vczjk/pm;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v1, v2}, Llyiahf/vczjk/yn;->OooO0Oo(Llyiahf/vczjk/u34;)Ljava/lang/Object;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {p1, v2, v1}, Llyiahf/vczjk/tg8;->o0000(Llyiahf/vczjk/u34;Ljava/lang/Object;)Llyiahf/vczjk/zb4;

    move-result-object v1

    goto :goto_0

    :cond_0
    move-object v1, v0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/b59;->_handledType:Ljava/lang/Class;

    invoke-static {p1, p2, v2}, Llyiahf/vczjk/b59;->OooOO0O(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Ljava/lang/Class;)Llyiahf/vczjk/q94;

    move-result-object v2

    if-eqz v2, :cond_1

    sget-object v3, Llyiahf/vczjk/n94;->OooOOOO:Llyiahf/vczjk/n94;

    invoke-virtual {v2, v3}, Llyiahf/vczjk/q94;->OooO0O0(Llyiahf/vczjk/n94;)Ljava/lang/Boolean;

    move-result-object v2

    goto :goto_1

    :cond_1
    move-object v2, v0

    :goto_1
    invoke-static {p1, p2, v1}, Llyiahf/vczjk/b59;->OooOO0(Llyiahf/vczjk/tg8;Llyiahf/vczjk/db0;Llyiahf/vczjk/zb4;)Llyiahf/vczjk/zb4;

    move-result-object v1

    const-class v3, Ljava/lang/String;

    if-nez v1, :cond_2

    invoke-virtual {p1, v3, p2}, Llyiahf/vczjk/tg8;->o00Oo0(Ljava/lang/Class;Llyiahf/vczjk/db0;)Llyiahf/vczjk/zb4;

    move-result-object v1

    :cond_2
    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOOoo(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/k39;->_unwrapSingle:Ljava/lang/Boolean;

    if-ne v2, p1, :cond_3

    return-object p0

    :cond_3
    invoke-virtual {p0, p2, v2}, Llyiahf/vczjk/k39;->OooOOO(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1

    :cond_4
    new-instance p2, Llyiahf/vczjk/y11;

    invoke-virtual {p1}, Llyiahf/vczjk/tg8;->Oooo0o0()Llyiahf/vczjk/a4a;

    move-result-object p1

    invoke-virtual {p1, v3}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object p1

    const/4 v2, 0x1

    invoke-direct {p2, p1, v2, v0, v1}, Llyiahf/vczjk/y11;-><init>(Llyiahf/vczjk/x64;ZLlyiahf/vczjk/e5a;Llyiahf/vczjk/zb4;)V

    return-object p2
.end method

.method public final OooO0Oo(Llyiahf/vczjk/tg8;Ljava/lang/Object;)Z
    .locals 0

    check-cast p2, Ljava/util/Collection;

    invoke-interface {p2}, Ljava/util/Collection;->size()I

    move-result p1

    if-nez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public abstract OooOOO(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;
.end method
