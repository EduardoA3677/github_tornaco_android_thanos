.class public final Llyiahf/vczjk/sc7;
.super Llyiahf/vczjk/rg3;
.source "SourceFile"


# instance fields
.field public OooOOOo:I

.field public OooOOo:Ljava/util/List;

.field public OooOOo0:Ljava/util/List;

.field public OooOOoo:Ljava/util/List;

.field public OooOo0:Llyiahf/vczjk/ud7;

.field public OooOo00:Llyiahf/vczjk/nd7;


# direct methods
.method public static OooO0oo()Llyiahf/vczjk/sc7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/sc7;

    invoke-direct {v0}, Llyiahf/vczjk/rg3;-><init>()V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    sget-object v1, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    iput-object v1, v0, Llyiahf/vczjk/sc7;->OooOo00:Llyiahf/vczjk/nd7;

    sget-object v1, Llyiahf/vczjk/ud7;->OooOOO0:Llyiahf/vczjk/ud7;

    iput-object v1, v0, Llyiahf/vczjk/sc7;->OooOo0:Llyiahf/vczjk/ud7;

    return-object v0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/tc7;)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/tc7;->OooOOO0:Llyiahf/vczjk/tc7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOO(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOO(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    goto :goto_0

    :cond_1
    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOO(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3
    :goto_0
    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_6

    iget-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x3

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    goto :goto_1

    :cond_4
    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_5

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_5
    iget-object v0, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_6
    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_9

    iget-object v0, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    and-int/lit8 v0, v0, -0x5

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    goto :goto_2

    :cond_7
    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    const/4 v1, 0x4

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_8

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_8
    iget-object v0, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOOo(Llyiahf/vczjk/tc7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_9
    :goto_2
    invoke-virtual {p1}, Llyiahf/vczjk/tc7;->OooOoo()Z

    move-result v0

    if-eqz v0, :cond_b

    invoke-virtual {p1}, Llyiahf/vczjk/tc7;->OooOoOO()Llyiahf/vczjk/nd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    const/16 v2, 0x8

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_a

    iget-object v1, p0, Llyiahf/vczjk/sc7;->OooOo00:Llyiahf/vczjk/nd7;

    sget-object v3, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    if-eq v1, v3, :cond_a

    invoke-static {v1}, Llyiahf/vczjk/nd7;->OooOO0o(Llyiahf/vczjk/nd7;)Llyiahf/vczjk/vb7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    invoke-virtual {v1}, Llyiahf/vczjk/vb7;->OooO0oO()Llyiahf/vczjk/nd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOo00:Llyiahf/vczjk/nd7;

    goto :goto_3

    :cond_a
    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOo00:Llyiahf/vczjk/nd7;

    :goto_3
    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_b
    invoke-virtual {p1}, Llyiahf/vczjk/tc7;->OooOooO()Z

    move-result v0

    if-eqz v0, :cond_d

    invoke-virtual {p1}, Llyiahf/vczjk/tc7;->OooOoo0()Llyiahf/vczjk/ud7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    const/16 v2, 0x10

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_c

    iget-object v1, p0, Llyiahf/vczjk/sc7;->OooOo0:Llyiahf/vczjk/ud7;

    sget-object v3, Llyiahf/vczjk/ud7;->OooOOO0:Llyiahf/vczjk/ud7;

    if-eq v1, v3, :cond_c

    new-instance v3, Llyiahf/vczjk/dc7;

    const/4 v4, 0x2

    invoke-direct {v3, v4}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v4, v3, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    invoke-virtual {v3}, Llyiahf/vczjk/dc7;->OooO()Llyiahf/vczjk/ud7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOo0:Llyiahf/vczjk/ud7;

    goto :goto_4

    :cond_c
    iput-object v0, p0, Llyiahf/vczjk/sc7;->OooOo0:Llyiahf/vczjk/ud7;

    :goto_4
    iget v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_d
    invoke-virtual {p0, p1}, Llyiahf/vczjk/rg3;->OooO0o0(Llyiahf/vczjk/sg3;)V

    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/tc7;->OooOo0o(Llyiahf/vczjk/tc7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/sc7;->OooO0oO()Llyiahf/vczjk/tc7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/tc7;->isInitialized()Z

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
    sget-object v1, Llyiahf/vczjk/tc7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/tc7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/tc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/sc7;->OooO(Llyiahf/vczjk/tc7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/tc7;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/sc7;->OooO(Llyiahf/vczjk/tc7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/tc7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/sc7;->OooO(Llyiahf/vczjk/tc7;)V

    return-object p0
.end method

.method public final OooO0oO()Llyiahf/vczjk/tc7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/tc7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/tc7;-><init>(Llyiahf/vczjk/sc7;)V

    iget v1, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x2

    iput v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo0:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/tc7;->OooOOOO(Llyiahf/vczjk/tc7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    const/4 v4, 0x2

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_1

    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x3

    iput v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/tc7;->OooOOo0(Llyiahf/vczjk/tc7;Ljava/util/List;)V

    iget v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    const/4 v4, 0x4

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_2

    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    and-int/lit8 v2, v2, -0x5

    iput v2, p0, Llyiahf/vczjk/sc7;->OooOOOo:I

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOOoo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/tc7;->OooOOoo(Llyiahf/vczjk/tc7;Ljava/util/List;)V

    and-int/lit8 v2, v1, 0x8

    const/16 v4, 0x8

    if-ne v2, v4, :cond_3

    goto :goto_0

    :cond_3
    const/4 v3, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/sc7;->OooOo00:Llyiahf/vczjk/nd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/tc7;->OooOo00(Llyiahf/vczjk/tc7;Llyiahf/vczjk/nd7;)V

    const/16 v2, 0x10

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_4

    or-int/lit8 v3, v3, 0x2

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/sc7;->OooOo0:Llyiahf/vczjk/ud7;

    invoke-static {v0, v1}, Llyiahf/vczjk/tc7;->OooOo0(Llyiahf/vczjk/tc7;Llyiahf/vczjk/ud7;)V

    invoke-static {v0, v3}, Llyiahf/vczjk/tc7;->OooOo0O(Llyiahf/vczjk/tc7;I)V

    return-object v0
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/sc7;->OooO0oo()Llyiahf/vczjk/sc7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/sc7;->OooO0oO()Llyiahf/vczjk/tc7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/sc7;->OooO(Llyiahf/vczjk/tc7;)V

    return-object v0
.end method
