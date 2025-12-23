.class public final Llyiahf/vczjk/od7;
.super Llyiahf/vczjk/rg3;
.source "SourceFile"


# instance fields
.field public OooOOOo:I

.field public OooOOo:I

.field public OooOOo0:I

.field public OooOOoo:Llyiahf/vczjk/hd7;

.field public OooOo0:Llyiahf/vczjk/hd7;

.field public OooOo00:I

.field public OooOo0O:I


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/od7;->OooO0oO()Llyiahf/vczjk/pd7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/pd7;->isInitialized()Z

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
    sget-object v1, Llyiahf/vczjk/pd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/pd7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/pd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/od7;->OooO0oo(Llyiahf/vczjk/pd7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/pd7;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/od7;->OooO0oo(Llyiahf/vczjk/pd7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/pd7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/od7;->OooO0oo(Llyiahf/vczjk/pd7;)V

    return-object p0
.end method

.method public final OooO0oO()Llyiahf/vczjk/pd7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/pd7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/pd7;-><init>(Llyiahf/vczjk/od7;)V

    iget v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/od7;->OooOOo0:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pd7;->OooOOO(Llyiahf/vczjk/pd7;I)V

    and-int/lit8 v2, v1, 0x2

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget v2, p0, Llyiahf/vczjk/od7;->OooOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pd7;->OooOOOO(Llyiahf/vczjk/pd7;I)V

    and-int/lit8 v2, v1, 0x4

    const/4 v4, 0x4

    if-ne v2, v4, :cond_2

    or-int/lit8 v3, v3, 0x4

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/od7;->OooOOoo:Llyiahf/vczjk/hd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/pd7;->OooOOOo(Llyiahf/vczjk/pd7;Llyiahf/vczjk/hd7;)V

    and-int/lit8 v2, v1, 0x8

    const/16 v4, 0x8

    if-ne v2, v4, :cond_3

    or-int/lit8 v3, v3, 0x8

    :cond_3
    iget v2, p0, Llyiahf/vczjk/od7;->OooOo00:I

    invoke-static {v0, v2}, Llyiahf/vczjk/pd7;->OooOOo0(Llyiahf/vczjk/pd7;I)V

    and-int/lit8 v2, v1, 0x10

    const/16 v4, 0x10

    if-ne v2, v4, :cond_4

    or-int/lit8 v3, v3, 0x10

    :cond_4
    iget-object v2, p0, Llyiahf/vczjk/od7;->OooOo0:Llyiahf/vczjk/hd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/pd7;->OooOOo(Llyiahf/vczjk/pd7;Llyiahf/vczjk/hd7;)V

    const/16 v2, 0x20

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_5

    or-int/lit8 v3, v3, 0x20

    :cond_5
    iget v1, p0, Llyiahf/vczjk/od7;->OooOo0O:I

    invoke-static {v0, v1}, Llyiahf/vczjk/pd7;->OooOOoo(Llyiahf/vczjk/pd7;I)V

    invoke-static {v0, v3}, Llyiahf/vczjk/pd7;->OooOo00(Llyiahf/vczjk/pd7;I)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/pd7;)V
    .locals 4

    sget-object v0, Llyiahf/vczjk/pd7;->OooOOO0:Llyiahf/vczjk/pd7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOoOO()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->getFlags()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/od7;->OooOOo0:I

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOoo0()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOo0O()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/od7;->OooOOo:I

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOoo()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOo0o()Llyiahf/vczjk/hd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    const/4 v2, 0x4

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/od7;->OooOOoo:Llyiahf/vczjk/hd7;

    sget-object v3, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    if-eq v1, v3, :cond_3

    invoke-static {v1}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v1}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/od7;->OooOOoo:Llyiahf/vczjk/hd7;

    goto :goto_0

    :cond_3
    iput-object v0, p0, Llyiahf/vczjk/od7;->OooOOoo:Llyiahf/vczjk/hd7;

    :goto_0
    iget v0, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOooO()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x8

    iput v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/od7;->OooOo00:I

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOooo()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOoO0()Llyiahf/vczjk/hd7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    const/16 v2, 0x10

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/od7;->OooOo0:Llyiahf/vczjk/hd7;

    sget-object v3, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    if-eq v1, v3, :cond_6

    invoke-static {v1}, Llyiahf/vczjk/hd7;->Oooooo0(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/gd7;->OooO(Llyiahf/vczjk/hd7;)Llyiahf/vczjk/gd7;

    invoke-virtual {v1}, Llyiahf/vczjk/gd7;->OooO0oO()Llyiahf/vczjk/hd7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/od7;->OooOo0:Llyiahf/vczjk/hd7;

    goto :goto_1

    :cond_6
    iput-object v0, p0, Llyiahf/vczjk/od7;->OooOo0:Llyiahf/vczjk/hd7;

    :goto_1
    iget v0, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    :cond_7
    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->Oooo000()Z

    move-result v0

    if-eqz v0, :cond_8

    invoke-virtual {p1}, Llyiahf/vczjk/pd7;->OooOoO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    or-int/lit8 v1, v1, 0x20

    iput v1, p0, Llyiahf/vczjk/od7;->OooOOOo:I

    iput v0, p0, Llyiahf/vczjk/od7;->OooOo0O:I

    :cond_8
    invoke-virtual {p0, p1}, Llyiahf/vczjk/rg3;->OooO0o0(Llyiahf/vczjk/sg3;)V

    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/pd7;->OooOo0(Llyiahf/vczjk/pd7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/od7;

    invoke-direct {v0}, Llyiahf/vczjk/rg3;-><init>()V

    sget-object v1, Llyiahf/vczjk/hd7;->OooOOO0:Llyiahf/vczjk/hd7;

    iput-object v1, v0, Llyiahf/vczjk/od7;->OooOOoo:Llyiahf/vczjk/hd7;

    iput-object v1, v0, Llyiahf/vczjk/od7;->OooOo0:Llyiahf/vczjk/hd7;

    invoke-virtual {p0}, Llyiahf/vczjk/od7;->OooO0oO()Llyiahf/vczjk/pd7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/od7;->OooO0oo(Llyiahf/vczjk/pd7;)V

    return-object v0
.end method
