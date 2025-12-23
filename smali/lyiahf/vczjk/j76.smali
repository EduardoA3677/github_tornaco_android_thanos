.class public final Llyiahf/vczjk/j76;
.super Llyiahf/vczjk/r1a;
.source "SourceFile"


# static fields
.field public static final OooO0OO:Llyiahf/vczjk/e66;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/nk3;

.field public final OooO0O0:Llyiahf/vczjk/xs9;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    sget-object v0, Llyiahf/vczjk/xs9;->OooOOO0:Llyiahf/vczjk/ts9;

    new-instance v1, Llyiahf/vczjk/e66;

    const/4 v2, 0x1

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/e66;-><init>(Ljava/lang/Object;I)V

    sput-object v1, Llyiahf/vczjk/j76;->OooO0OO:Llyiahf/vczjk/e66;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/nk3;Llyiahf/vczjk/xs9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/j76;->OooO00o:Llyiahf/vczjk/nk3;

    iput-object p2, p0, Llyiahf/vczjk/j76;->OooO0O0:Llyiahf/vczjk/xs9;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/qb4;)Ljava/lang/Object;
    .locals 9

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o0000()I

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v1

    const/4 v2, 0x2

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz v1, :cond_1

    if-eq v1, v2, :cond_0

    move-object v1, v4

    goto :goto_0

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0oO()V

    new-instance v1, Llyiahf/vczjk/o05;

    invoke-direct {v1, v3}, Llyiahf/vczjk/o05;-><init>(Z)V

    goto :goto_0

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0Oo()V

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    :goto_0
    if-nez v1, :cond_2

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/j76;->OooO0Oo(Llyiahf/vczjk/qb4;I)Ljava/io/Serializable;

    move-result-object p1

    return-object p1

    :cond_2
    new-instance v0, Ljava/util/ArrayDeque;

    invoke-direct {v0}, Ljava/util/ArrayDeque;-><init>()V

    :cond_3
    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OoooO00()Z

    move-result v5

    if-eqz v5, :cond_a

    instance-of v5, v1, Ljava/util/Map;

    if-eqz v5, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o000OOo()Ljava/lang/String;

    move-result-object v5

    goto :goto_2

    :cond_4
    move-object v5, v4

    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o0000()I

    move-result v6

    invoke-static {v6}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v7

    if-eqz v7, :cond_6

    if-eq v7, v2, :cond_5

    move-object v7, v4

    goto :goto_3

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0oO()V

    new-instance v7, Llyiahf/vczjk/o05;

    invoke-direct {v7, v3}, Llyiahf/vczjk/o05;-><init>(Z)V

    goto :goto_3

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooO0Oo()V

    new-instance v7, Ljava/util/ArrayList;

    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    :goto_3
    if-eqz v7, :cond_7

    move v8, v3

    goto :goto_4

    :cond_7
    const/4 v8, 0x0

    :goto_4
    if-nez v7, :cond_8

    invoke-virtual {p0, p1, v6}, Llyiahf/vczjk/j76;->OooO0Oo(Llyiahf/vczjk/qb4;I)Ljava/io/Serializable;

    move-result-object v7

    :cond_8
    instance-of v6, v1, Ljava/util/List;

    if-eqz v6, :cond_9

    move-object v5, v1

    check-cast v5, Ljava/util/List;

    invoke-interface {v5, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_5

    :cond_9
    move-object v6, v1

    check-cast v6, Ljava/util/Map;

    invoke-interface {v6, v5, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    :goto_5
    if-eqz v8, :cond_3

    invoke-virtual {v0, v1}, Ljava/util/ArrayDeque;->addLast(Ljava/lang/Object;)V

    move-object v1, v7

    goto :goto_1

    :cond_a
    instance-of v5, v1, Ljava/util/List;

    if-eqz v5, :cond_b

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooOoO()V

    goto :goto_6

    :cond_b
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->OooOoOO()V

    :goto_6
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_c

    return-object v1

    :cond_c
    invoke-virtual {v0}, Ljava/util/ArrayDeque;->removeLast()Ljava/lang/Object;

    move-result-object v1

    goto :goto_1
.end method

.method public final OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V
    .locals 2

    if-nez p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OoooO00()Llyiahf/vczjk/zc4;

    return-void

    :cond_0
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/j76;->OooO00o:Llyiahf/vczjk/nk3;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/Class;)Lcom/google/gson/reflect/TypeToken;

    move-result-object v0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/nk3;->OooO0o0(Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object v0

    instance-of v1, v0, Llyiahf/vczjk/j76;

    if-eqz v1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OooOOOO()V

    invoke-virtual {p1}, Llyiahf/vczjk/zc4;->OooOoOO()V

    return-void

    :cond_1
    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/r1a;->OooO0OO(Llyiahf/vczjk/zc4;Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/qb4;I)Ljava/io/Serializable;
    .locals 2

    invoke-static {p2}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    const/4 v1, 0x5

    if-eq v0, v1, :cond_3

    const/4 v1, 0x6

    if-eq v0, v1, :cond_2

    const/4 v1, 0x7

    if-eq v0, v1, :cond_1

    const/16 v1, 0x8

    if-ne v0, v1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o00000o0()V

    const/4 p1, 0x0

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-static {p2}, Llyiahf/vczjk/u81;->OooOoo0(I)Ljava/lang/String;

    move-result-object p2

    const-string v0, "Unexpected token: "

    invoke-virtual {v0, p2}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->Oooooo0()Z

    move-result p1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :cond_2
    iget-object p2, p0, Llyiahf/vczjk/j76;->OooO0O0:Llyiahf/vczjk/xs9;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/xs9;->OooO00o(Llyiahf/vczjk/qb4;)Ljava/lang/Number;

    move-result-object p1

    return-object p1

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/qb4;->o00000oO()Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method
