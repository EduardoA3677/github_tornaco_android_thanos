.class public final Llyiahf/vczjk/va0;
.super Llyiahf/vczjk/ib0;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _defaultSerializer:Llyiahf/vczjk/ib0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hb0;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/z66;)V

    iput-object p1, p0, Llyiahf/vczjk/va0;->_defaultSerializer:Llyiahf/vczjk/ib0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/va0;Ljava/util/Set;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Ljava/util/Set;)V

    iput-object p1, p0, Llyiahf/vczjk/va0;->_defaultSerializer:Llyiahf/vczjk/ib0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/va0;Llyiahf/vczjk/z66;Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/ib0;-><init>(Llyiahf/vczjk/ib0;Llyiahf/vczjk/z66;Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/va0;->_defaultSerializer:Llyiahf/vczjk/ib0;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ig8;->OooOooO:Llyiahf/vczjk/ig8;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/tg8;->o0000Ooo(Llyiahf/vczjk/ig8;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_filteredProps:[Llyiahf/vczjk/gb0;

    if-eqz v0, :cond_0

    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->oo0o0Oo()Ljava/lang/Class;

    move-result-object v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_filteredProps:[Llyiahf/vczjk/gb0;

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/ib0;->_props:[Llyiahf/vczjk/gb0;

    :goto_0
    array-length v0, v0

    const/4 v1, 0x1

    if-ne v0, v1, :cond_1

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/va0;->OooOoO0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :cond_1
    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000o0o(Ljava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/va0;->OooOoO0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000O()V

    return-void
.end method

.method public final OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2, p3, p4}, Llyiahf/vczjk/ib0;->OooOOO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void

    :cond_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p0, p4, p1, v0}, Llyiahf/vczjk/ib0;->OooOOOo(Llyiahf/vczjk/d5a;Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object v0

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->OoooOO0(Ljava/lang/Object;)V

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/va0;->OooOoO0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    invoke-virtual {p4, p2, v0}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    return-void
.end method

.method public final OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/va0;->_defaultSerializer:Llyiahf/vczjk/ib0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zb4;->OooO0oo(Llyiahf/vczjk/wt5;)Llyiahf/vczjk/zb4;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOo0()Llyiahf/vczjk/ib0;
    .locals 0

    return-object p0
.end method

.method public final OooOo([Llyiahf/vczjk/gb0;[Llyiahf/vczjk/gb0;)Llyiahf/vczjk/ib0;
    .locals 0

    return-object p0
.end method

.method public final OooOo0(Ljava/lang/Object;)Llyiahf/vczjk/ib0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/va0;

    iget-object v1, p0, Llyiahf/vczjk/ib0;->_objectIdWriter:Llyiahf/vczjk/z66;

    invoke-direct {v0, p0, v1, p1}, Llyiahf/vczjk/va0;-><init>(Llyiahf/vczjk/va0;Llyiahf/vczjk/z66;Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOo0O(Ljava/util/Set;)Llyiahf/vczjk/ib0;
    .locals 1

    new-instance v0, Llyiahf/vczjk/va0;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/va0;-><init>(Llyiahf/vczjk/va0;Ljava/util/Set;)V

    return-object v0
.end method

.method public final OooOo0o(Llyiahf/vczjk/z66;)Llyiahf/vczjk/ib0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/va0;->_defaultSerializer:Llyiahf/vczjk/ib0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ib0;->OooOo0o(Llyiahf/vczjk/z66;)Llyiahf/vczjk/ib0;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO0(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 5

    const-string v0, "[anySetter]"

    iget-object v1, p0, Llyiahf/vczjk/ib0;->_filteredProps:[Llyiahf/vczjk/gb0;

    if-eqz v1, :cond_0

    invoke-virtual {p3}, Llyiahf/vczjk/tg8;->oo0o0Oo()Ljava/lang/Class;

    move-result-object v1

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/ib0;->_filteredProps:[Llyiahf/vczjk/gb0;

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/ib0;->_props:[Llyiahf/vczjk/gb0;

    :goto_0
    const/4 v2, 0x0

    :try_start_0
    array-length v3, v1

    :goto_1
    if-ge v2, v3, :cond_2

    aget-object v4, v1, v2

    if-nez v4, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/u94;->o00000oo()V

    goto :goto_2

    :catch_0
    move-exception p3

    goto :goto_3

    :catch_1
    move-exception p2

    goto :goto_5

    :cond_1
    invoke-virtual {v4, p1, p2, p3}, Llyiahf/vczjk/gb0;->OooOO0O(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/StackOverflowError; {:try_start_0 .. :try_end_0} :catch_0

    :goto_2
    add-int/lit8 v2, v2, 0x1

    goto :goto_1

    :cond_2
    return-void

    :goto_3
    new-instance v3, Llyiahf/vczjk/na4;

    const-string v4, "Infinite recursion (StackOverflowError)"

    invoke-direct {v3, p2, v4, p3}, Llyiahf/vczjk/na4;-><init>(Ljava/io/Closeable;Ljava/lang/String;Ljava/lang/Throwable;)V

    array-length p2, v1

    if-ne v2, p2, :cond_3

    goto :goto_4

    :cond_3
    aget-object p2, v1, v2

    invoke-virtual {p2}, Llyiahf/vczjk/gb0;->getName()Ljava/lang/String;

    move-result-object v0

    :goto_4
    new-instance p2, Llyiahf/vczjk/ma4;

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/ma4;-><init>(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v3, p2}, Llyiahf/vczjk/na4;->OooO0o(Llyiahf/vczjk/ma4;)V

    throw v3

    :goto_5
    array-length v3, v1

    if-ne v2, v3, :cond_4

    goto :goto_6

    :cond_4
    aget-object v0, v1, v2

    invoke-virtual {v0}, Llyiahf/vczjk/gb0;->getName()Ljava/lang/String;

    move-result-object v0

    :goto_6
    invoke-static {p3, p2, p1, v0}, Llyiahf/vczjk/b59;->OooOOO0(Llyiahf/vczjk/tg8;Ljava/lang/Exception;Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/b59;->OooO0OO()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    const-string v1, "BeanAsArraySerializer for "

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
