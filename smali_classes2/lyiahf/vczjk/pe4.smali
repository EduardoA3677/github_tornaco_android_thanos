.class public final Llyiahf/vczjk/pe4;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public OooOOO:I

.field public OooOOOO:Ljava/util/List;

.field public OooOOOo:Ljava/util/List;


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/pe4;->OooO0o0()Llyiahf/vczjk/te4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/te4;->isInitialized()Z

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
    sget-object v1, Llyiahf/vczjk/te4;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/te4;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/te4;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/pe4;->OooO0oO(Llyiahf/vczjk/te4;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/te4;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/pe4;->OooO0oO(Llyiahf/vczjk/te4;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/te4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/pe4;->OooO0oO(Llyiahf/vczjk/te4;)V

    return-object p0
.end method

.method public final OooO0o0()Llyiahf/vczjk/te4;
    .locals 3

    new-instance v0, Llyiahf/vczjk/te4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/te4;-><init>(Llyiahf/vczjk/pe4;)V

    iget v1, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    and-int/lit8 v1, v1, -0x2

    iput v1, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/te4;->OooO0o0(Llyiahf/vczjk/te4;Ljava/util/List;)V

    iget v1, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    and-int/lit8 v1, v1, -0x3

    iput v1, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/te4;->OooO0oO(Llyiahf/vczjk/te4;Ljava/util/List;)V

    return-object v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/te4;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/te4;->OooOOO0:Llyiahf/vczjk/te4;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/te4;->OooO0Oo(Llyiahf/vczjk/te4;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/te4;->OooO0Oo(Llyiahf/vczjk/te4;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    goto :goto_0

    :cond_1
    iget v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/te4;->OooO0Oo(Llyiahf/vczjk/te4;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/te4;->OooO0o(Llyiahf/vczjk/te4;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/te4;->OooO0o(Llyiahf/vczjk/te4;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    and-int/lit8 v0, v0, -0x3

    iput v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    goto :goto_1

    :cond_4
    iget v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_5

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/pe4;->OooOOO:I

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/te4;->OooO0o(Llyiahf/vczjk/te4;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_6
    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/te4;->OooO0oo(Llyiahf/vczjk/te4;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/pe4;

    invoke-direct {v0}, Llyiahf/vczjk/og3;-><init>()V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/pe4;->OooOOOO:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/pe4;->OooOOOo:Ljava/util/List;

    invoke-virtual {p0}, Llyiahf/vczjk/pe4;->OooO0o0()Llyiahf/vczjk/te4;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pe4;->OooO0oO(Llyiahf/vczjk/te4;)V

    return-object v0
.end method
