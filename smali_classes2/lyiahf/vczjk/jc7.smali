.class public final Llyiahf/vczjk/jc7;
.super Llyiahf/vczjk/rg3;
.source "SourceFile"


# instance fields
.field public OooOOOo:I

.field public OooOOo0:I


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 3

    new-instance v0, Llyiahf/vczjk/kc7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/kc7;-><init>(Llyiahf/vczjk/jc7;)V

    iget v1, p0, Llyiahf/vczjk/jc7;->OooOOOo:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    iget v1, p0, Llyiahf/vczjk/jc7;->OooOOo0:I

    invoke-static {v0, v1}, Llyiahf/vczjk/kc7;->OooOOO(Llyiahf/vczjk/kc7;I)V

    invoke-static {v0, v2}, Llyiahf/vczjk/kc7;->OooOOOO(Llyiahf/vczjk/kc7;I)V

    invoke-virtual {v0}, Llyiahf/vczjk/kc7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_1

    return-object v0

    :cond_1
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/og3;
    .locals 2

    const/4 v0, 0x0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/kc7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/kc7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/kc7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/jc7;->OooO0oO(Llyiahf/vczjk/kc7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/kc7;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/jc7;->OooO0oO(Llyiahf/vczjk/kc7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kc7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/jc7;->OooO0oO(Llyiahf/vczjk/kc7;)V

    return-object p0
.end method

.method public final OooO0oO(Llyiahf/vczjk/kc7;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/kc7;->OooOOO0:Llyiahf/vczjk/kc7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/kc7;->OooOOo()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/kc7;->OooOOo0()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/jc7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/jc7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/jc7;->OooOOo0:I

    :cond_1
    invoke-virtual {p0, p1}, Llyiahf/vczjk/rg3;->OooO0o0(Llyiahf/vczjk/sg3;)V

    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/kc7;->OooOOOo(Llyiahf/vczjk/kc7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 4

    new-instance v0, Llyiahf/vczjk/jc7;

    invoke-direct {v0}, Llyiahf/vczjk/rg3;-><init>()V

    new-instance v1, Llyiahf/vczjk/kc7;

    invoke-direct {v1, p0}, Llyiahf/vczjk/kc7;-><init>(Llyiahf/vczjk/jc7;)V

    iget v2, p0, Llyiahf/vczjk/jc7;->OooOOOo:I

    const/4 v3, 0x1

    and-int/2addr v2, v3

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/jc7;->OooOOo0:I

    invoke-static {v1, v2}, Llyiahf/vczjk/kc7;->OooOOO(Llyiahf/vczjk/kc7;I)V

    invoke-static {v1, v3}, Llyiahf/vczjk/kc7;->OooOOOO(Llyiahf/vczjk/kc7;I)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/jc7;->OooO0oO(Llyiahf/vczjk/kc7;)V

    return-object v0
.end method
