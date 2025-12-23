.class public final Llyiahf/vczjk/fc7;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public OooOOO:I

.field public OooOOOO:Llyiahf/vczjk/gc7;

.field public OooOOOo:Ljava/util/List;

.field public OooOOo:Llyiahf/vczjk/hc7;

.field public OooOOo0:Llyiahf/vczjk/nc7;


# direct methods
.method public static OooO0oO()Llyiahf/vczjk/fc7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/fc7;

    invoke-direct {v0}, Llyiahf/vczjk/og3;-><init>()V

    sget-object v1, Llyiahf/vczjk/gc7;->OooOOO0:Llyiahf/vczjk/gc7;

    iput-object v1, v0, Llyiahf/vczjk/fc7;->OooOOOO:Llyiahf/vczjk/gc7;

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    sget-object v1, Llyiahf/vczjk/nc7;->OooOOO0:Llyiahf/vczjk/nc7;

    iput-object v1, v0, Llyiahf/vczjk/fc7;->OooOOo0:Llyiahf/vczjk/nc7;

    sget-object v1, Llyiahf/vczjk/hc7;->OooOOO0:Llyiahf/vczjk/hc7;

    iput-object v1, v0, Llyiahf/vczjk/fc7;->OooOOo:Llyiahf/vczjk/hc7;

    return-object v0
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/fc7;->OooO0o0()Llyiahf/vczjk/ic7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ic7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/og3;
    .locals 2

    const/4 v0, 0x0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/ic7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/ic7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/ic7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/fc7;->OooO0oo(Llyiahf/vczjk/ic7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ic7;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catchall_1
    move-exception p1

    move-object v0, p2

    :goto_0
    if-eqz v0, :cond_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/fc7;->OooO0oo(Llyiahf/vczjk/ic7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/ic7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/fc7;->OooO0oo(Llyiahf/vczjk/ic7;)V

    return-object p0
.end method

.method public final OooO0o0()Llyiahf/vczjk/ic7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/ic7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ic7;-><init>(Llyiahf/vczjk/fc7;)V

    iget v1, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/fc7;->OooOOOO:Llyiahf/vczjk/gc7;

    invoke-static {v0, v2}, Llyiahf/vczjk/ic7;->OooO0Oo(Llyiahf/vczjk/ic7;Llyiahf/vczjk/gc7;)V

    iget v2, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    const/4 v4, 0x2

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    and-int/lit8 v2, v2, -0x3

    iput v2, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/ic7;->OooO0o(Llyiahf/vczjk/ic7;Ljava/util/List;)V

    and-int/lit8 v2, v1, 0x4

    const/4 v4, 0x4

    if-ne v2, v4, :cond_2

    or-int/lit8 v3, v3, 0x2

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/fc7;->OooOOo0:Llyiahf/vczjk/nc7;

    invoke-static {v0, v2}, Llyiahf/vczjk/ic7;->OooO0oO(Llyiahf/vczjk/ic7;Llyiahf/vczjk/nc7;)V

    const/16 v2, 0x8

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_3

    or-int/lit8 v3, v3, 0x4

    :cond_3
    iget-object v1, p0, Llyiahf/vczjk/fc7;->OooOOo:Llyiahf/vczjk/hc7;

    invoke-static {v0, v1}, Llyiahf/vczjk/ic7;->OooO0oo(Llyiahf/vczjk/ic7;Llyiahf/vczjk/hc7;)V

    invoke-static {v0, v3}, Llyiahf/vczjk/ic7;->OooO(Llyiahf/vczjk/ic7;I)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/ic7;)V
    .locals 4

    sget-object v0, Llyiahf/vczjk/ic7;->OooOOO0:Llyiahf/vczjk/ic7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ic7;->OooOOOO()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/ic7;->OooOO0o()Llyiahf/vczjk/gc7;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    iput-object v0, p0, Llyiahf/vczjk/fc7;->OooOOOO:Llyiahf/vczjk/gc7;

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/ic7;->OooO0o0(Llyiahf/vczjk/ic7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/ic7;->OooO0o0(Llyiahf/vczjk/ic7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    and-int/lit8 v0, v0, -0x3

    iput v0, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    goto :goto_0

    :cond_2
    iget v0, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_3

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/fc7;->OooOOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/ic7;->OooO0o0(Llyiahf/vczjk/ic7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_4
    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/ic7;->OooOOO()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/ic7;->OooOO0O()Llyiahf/vczjk/nc7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    const/4 v2, 0x4

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/fc7;->OooOOo0:Llyiahf/vczjk/nc7;

    sget-object v3, Llyiahf/vczjk/nc7;->OooOOO0:Llyiahf/vczjk/nc7;

    if-eq v1, v3, :cond_5

    invoke-static {}, Llyiahf/vczjk/lc7;->OooO0oO()Llyiahf/vczjk/lc7;

    move-result-object v3

    invoke-virtual {v3, v1}, Llyiahf/vczjk/lc7;->OooO0oo(Llyiahf/vczjk/nc7;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/lc7;->OooO0oo(Llyiahf/vczjk/nc7;)V

    invoke-virtual {v3}, Llyiahf/vczjk/lc7;->OooO0o0()Llyiahf/vczjk/nc7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fc7;->OooOOo0:Llyiahf/vczjk/nc7;

    goto :goto_1

    :cond_5
    iput-object v0, p0, Llyiahf/vczjk/fc7;->OooOOo0:Llyiahf/vczjk/nc7;

    :goto_1
    iget v0, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/ic7;->OooOOOo()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/ic7;->OooOOO0()Llyiahf/vczjk/hc7;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    or-int/lit8 v1, v1, 0x8

    iput v1, p0, Llyiahf/vczjk/fc7;->OooOOO:I

    iput-object v0, p0, Llyiahf/vczjk/fc7;->OooOOo:Llyiahf/vczjk/hc7;

    :cond_7
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/ic7;->OooOO0(Llyiahf/vczjk/ic7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/fc7;->OooO0oO()Llyiahf/vczjk/fc7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/fc7;->OooO0o0()Llyiahf/vczjk/ic7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/fc7;->OooO0oo(Llyiahf/vczjk/ic7;)V

    return-object v0
.end method
