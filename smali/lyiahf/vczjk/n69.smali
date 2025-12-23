.class public final Llyiahf/vczjk/n69;
.super Llyiahf/vczjk/k39;
.source "SourceFile"


# static fields
.field public static final OooOOO:Llyiahf/vczjk/n69;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/n69;

    const-class v1, Ljava/util/Collection;

    invoke-direct {v0, v1}, Llyiahf/vczjk/k39;-><init>(Ljava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/n69;->OooOOO:Llyiahf/vczjk/n69;

    return-void
.end method

.method public static OooOOOO(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    const/4 v0, 0x0

    :try_start_0
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    if-nez v2, :cond_0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/tg8;->o00O0O(Llyiahf/vczjk/u94;)V

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_2

    :cond_0
    invoke-virtual {p1, v2}, Llyiahf/vczjk/u94;->o0000ooO(Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :goto_1
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return-void

    :goto_2
    invoke-static {p2, p1, p0, v0}, Llyiahf/vczjk/b59;->OooOO0o(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;I)V

    const/4 p0, 0x0

    throw p0
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 3

    check-cast p1, Ljava/util/Collection;

    invoke-interface {p1}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/k39;->_unwrapSingle:Ljava/lang/Boolean;

    if-nez v1, :cond_0

    sget-object v1, Llyiahf/vczjk/ig8;->OooOooO:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v1}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v1

    if-nez v1, :cond_1

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/k39;->_unwrapSingle:Ljava/lang/Boolean;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    if-ne v1, v2, :cond_2

    :cond_1
    invoke-static {p1, p2, p3}, Llyiahf/vczjk/n69;->OooOOOO(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_2
    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/u94;->o0000o0O(ILjava/lang/Object;)V

    invoke-static {p1, p2, p3}, Llyiahf/vczjk/n69;->OooOOOO(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000O()V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    check-cast p1, Ljava/util/Collection;

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, v0}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    invoke-static {p1, p2, p3}, Llyiahf/vczjk/n69;->OooOOOO(Ljava/util/Collection;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method

.method public final OooOOO(Llyiahf/vczjk/db0;Ljava/lang/Boolean;)Llyiahf/vczjk/zb4;
    .locals 0

    new-instance p1, Llyiahf/vczjk/n69;

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/k39;-><init>(Llyiahf/vczjk/k39;Ljava/lang/Boolean;)V

    return-object p1
.end method
