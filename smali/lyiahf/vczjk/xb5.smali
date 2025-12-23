.class public final Llyiahf/vczjk/xb5;
.super Llyiahf/vczjk/r1a;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/t1a;

.field public final OooO0O0:Llyiahf/vczjk/t1a;

.field public final OooO0OO:Llyiahf/vczjk/m66;

.field public final synthetic OooO0Oo:Llyiahf/vczjk/c21;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c21;Llyiahf/vczjk/t1a;Llyiahf/vczjk/t1a;Llyiahf/vczjk/m66;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xb5;->OooO0Oo:Llyiahf/vczjk/c21;

    iput-object p2, p0, Llyiahf/vczjk/xb5;->OooO00o:Llyiahf/vczjk/t1a;

    iput-object p3, p0, Llyiahf/vczjk/xb5;->OooO0O0:Llyiahf/vczjk/t1a;

    iput-object p4, p0, Llyiahf/vczjk/xb5;->OooO0OO:Llyiahf/vczjk/m66;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;
    .locals 5

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o0000()I

    move-result v0

    const/16 v1, 0x9

    if-ne v0, v1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o00000o0()V

    const/4 p1, 0x0

    return-object p1

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/xb5;->OooO0OO:Llyiahf/vczjk/m66;

    invoke-interface {v2}, Llyiahf/vczjk/m66;->OooOOo0()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/Map;

    const/4 v3, 0x1

    const-string v4, "duplicate key: "

    if-ne v0, v3, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0Oo()V

    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OoooO00()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0Oo()V

    iget-object v0, p0, Llyiahf/vczjk/xb5;->OooO00o:Llyiahf/vczjk/t1a;

    iget-object v0, v0, Llyiahf/vczjk/t1a;->OooO0O0:Llyiahf/vczjk/r1a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r1a;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/xb5;->OooO0O0:Llyiahf/vczjk/t1a;

    iget-object v1, v1, Llyiahf/vczjk/t1a;->OooO0O0:Llyiahf/vczjk/r1a;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/r1a;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object v1

    invoke-interface {v2, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooOoO()V

    goto :goto_0

    :cond_1
    new-instance p1, Llyiahf/vczjk/fc4;

    invoke-static {v0, v4}, Llyiahf/vczjk/u81;->OooOO0(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooOoO()V

    return-object v2

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0oO()V

    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OoooO00()Z

    move-result v0

    if-eqz v0, :cond_9

    sget-object v0, Llyiahf/vczjk/up3;->OooOo0O:Llyiahf/vczjk/up3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v0, p1, Llyiahf/vczjk/qb4;->OooOOoo:I

    if-nez v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooOo()I

    move-result v0

    :cond_4
    const/16 v3, 0xd

    if-ne v0, v3, :cond_5

    iput v1, p1, Llyiahf/vczjk/qb4;->OooOOoo:I

    goto :goto_2

    :cond_5
    const/16 v3, 0xc

    if-ne v0, v3, :cond_6

    const/16 v0, 0x8

    iput v0, p1, Llyiahf/vczjk/qb4;->OooOOoo:I

    goto :goto_2

    :cond_6
    const/16 v3, 0xe

    if-ne v0, v3, :cond_8

    const/16 v0, 0xa

    iput v0, p1, Llyiahf/vczjk/qb4;->OooOOoo:I

    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/xb5;->OooO00o:Llyiahf/vczjk/t1a;

    iget-object v0, v0, Llyiahf/vczjk/t1a;->OooO0O0:Llyiahf/vczjk/r1a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r1a;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object v0

    iget-object v3, p0, Llyiahf/vczjk/xb5;->OooO0O0:Llyiahf/vczjk/t1a;

    iget-object v3, v3, Llyiahf/vczjk/t1a;->OooO0O0:Llyiahf/vczjk/r1a;

    invoke-virtual {v3, p1}, Llyiahf/vczjk/r1a;->OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;

    move-result-object v3

    invoke-interface {v2, v0, v3}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    if-nez v3, :cond_7

    goto :goto_1

    :cond_7
    new-instance p1, Llyiahf/vczjk/fc4;

    invoke-static {v0, v4}, Llyiahf/vczjk/u81;->OooOO0(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_8
    const-string v0, "a name"

    invoke-virtual {p1, v0}, Llyiahf/vczjk/qb4;->o0000OO(Ljava/lang/String;)Ljava/lang/IllegalStateException;

    move-result-object p1

    throw p1

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooOoOO()V

    return-object v2
.end method

.method public final OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V
    .locals 3

    check-cast p2, Ljava/util/Map;

    if-nez p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OoooO00()Llyiahf/vczjk/zc4;

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xb5;->OooO0Oo:Llyiahf/vczjk/c21;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Llyiahf/vczjk/xb5;->OooO0O0:Llyiahf/vczjk/t1a;

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OooOOOO()V

    invoke-interface {p2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    move-result-object p2

    invoke-interface {p2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/Map$Entry;

    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zc4;->OooOooo(Ljava/lang/String;)V

    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/t1a;->OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V

    goto :goto_0

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OooOoOO()V

    return-void
.end method
