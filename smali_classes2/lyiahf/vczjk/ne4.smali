.class public final Llyiahf/vczjk/ne4;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public OooOOO:I

.field public OooOOOO:Llyiahf/vczjk/le4;

.field public OooOOOo:Llyiahf/vczjk/me4;

.field public OooOOo:Llyiahf/vczjk/me4;

.field public OooOOo0:Llyiahf/vczjk/me4;

.field public OooOOoo:Llyiahf/vczjk/me4;


# direct methods
.method public static OooO0oO()Llyiahf/vczjk/ne4;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ne4;

    invoke-direct {v0}, Llyiahf/vczjk/og3;-><init>()V

    sget-object v1, Llyiahf/vczjk/le4;->OooOOO0:Llyiahf/vczjk/le4;

    iput-object v1, v0, Llyiahf/vczjk/ne4;->OooOOOO:Llyiahf/vczjk/le4;

    sget-object v1, Llyiahf/vczjk/me4;->OooOOO0:Llyiahf/vczjk/me4;

    iput-object v1, v0, Llyiahf/vczjk/ne4;->OooOOOo:Llyiahf/vczjk/me4;

    iput-object v1, v0, Llyiahf/vczjk/ne4;->OooOOo0:Llyiahf/vczjk/me4;

    iput-object v1, v0, Llyiahf/vczjk/ne4;->OooOOo:Llyiahf/vczjk/me4;

    iput-object v1, v0, Llyiahf/vczjk/ne4;->OooOOoo:Llyiahf/vczjk/me4;

    return-object v0
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/ne4;->OooO0o0()Llyiahf/vczjk/oe4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/oe4;->isInitialized()Z

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
    sget-object v1, Llyiahf/vczjk/oe4;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/oe4;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/oe4;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/ne4;->OooO0oo(Llyiahf/vczjk/oe4;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/oe4;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ne4;->OooO0oo(Llyiahf/vczjk/oe4;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/oe4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ne4;->OooO0oo(Llyiahf/vczjk/oe4;)V

    return-object p0
.end method

.method public final OooO0o0()Llyiahf/vczjk/oe4;
    .locals 5

    new-instance v0, Llyiahf/vczjk/oe4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/oe4;-><init>(Llyiahf/vczjk/ne4;)V

    iget v1, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/ne4;->OooOOOO:Llyiahf/vczjk/le4;

    invoke-static {v0, v2}, Llyiahf/vczjk/oe4;->OooO0Oo(Llyiahf/vczjk/oe4;Llyiahf/vczjk/le4;)V

    and-int/lit8 v2, v1, 0x2

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/ne4;->OooOOOo:Llyiahf/vczjk/me4;

    invoke-static {v0, v2}, Llyiahf/vczjk/oe4;->OooO0o0(Llyiahf/vczjk/oe4;Llyiahf/vczjk/me4;)V

    and-int/lit8 v2, v1, 0x4

    const/4 v4, 0x4

    if-ne v2, v4, :cond_2

    or-int/lit8 v3, v3, 0x4

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/ne4;->OooOOo0:Llyiahf/vczjk/me4;

    invoke-static {v0, v2}, Llyiahf/vczjk/oe4;->OooO0o(Llyiahf/vczjk/oe4;Llyiahf/vczjk/me4;)V

    and-int/lit8 v2, v1, 0x8

    const/16 v4, 0x8

    if-ne v2, v4, :cond_3

    or-int/lit8 v3, v3, 0x8

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/ne4;->OooOOo:Llyiahf/vczjk/me4;

    invoke-static {v0, v2}, Llyiahf/vczjk/oe4;->OooO0oO(Llyiahf/vczjk/oe4;Llyiahf/vczjk/me4;)V

    const/16 v2, 0x10

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_4

    or-int/lit8 v3, v3, 0x10

    :cond_4
    iget-object v1, p0, Llyiahf/vczjk/ne4;->OooOOoo:Llyiahf/vczjk/me4;

    invoke-static {v0, v1}, Llyiahf/vczjk/oe4;->OooO0oo(Llyiahf/vczjk/oe4;Llyiahf/vczjk/me4;)V

    invoke-static {v0, v3}, Llyiahf/vczjk/oe4;->OooO(Llyiahf/vczjk/oe4;I)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/oe4;)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/oe4;->OooOOO0:Llyiahf/vczjk/oe4;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOOo0()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOO0o()Llyiahf/vczjk/le4;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/ne4;->OooOOOO:Llyiahf/vczjk/le4;

    sget-object v3, Llyiahf/vczjk/le4;->OooOOO0:Llyiahf/vczjk/le4;

    if-eq v1, v3, :cond_1

    new-instance v3, Llyiahf/vczjk/ke4;

    const/4 v4, 0x0

    invoke-direct {v3, v4}, Llyiahf/vczjk/ke4;-><init>(I)V

    invoke-virtual {v3, v1}, Llyiahf/vczjk/ke4;->OooO0oo(Llyiahf/vczjk/le4;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/ke4;->OooO0oo(Llyiahf/vczjk/le4;)V

    invoke-virtual {v3}, Llyiahf/vczjk/ke4;->OooO0o0()Llyiahf/vczjk/le4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOOO:Llyiahf/vczjk/le4;

    goto :goto_0

    :cond_1
    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOOO:Llyiahf/vczjk/le4;

    :goto_0
    iget v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOo00()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOOOO()Llyiahf/vczjk/me4;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_3

    iget-object v1, p0, Llyiahf/vczjk/ne4;->OooOOOo:Llyiahf/vczjk/me4;

    sget-object v3, Llyiahf/vczjk/me4;->OooOOO0:Llyiahf/vczjk/me4;

    if-eq v1, v3, :cond_3

    invoke-static {v1}, Llyiahf/vczjk/me4;->OooOO0o(Llyiahf/vczjk/me4;)Llyiahf/vczjk/ke4;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    invoke-virtual {v1}, Llyiahf/vczjk/ke4;->OooO0oO()Llyiahf/vczjk/me4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOOo:Llyiahf/vczjk/me4;

    goto :goto_1

    :cond_3
    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOOo:Llyiahf/vczjk/me4;

    :goto_1
    iget v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOOo()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOOO0()Llyiahf/vczjk/me4;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    const/4 v2, 0x4

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_5

    iget-object v1, p0, Llyiahf/vczjk/ne4;->OooOOo0:Llyiahf/vczjk/me4;

    sget-object v3, Llyiahf/vczjk/me4;->OooOOO0:Llyiahf/vczjk/me4;

    if-eq v1, v3, :cond_5

    invoke-static {v1}, Llyiahf/vczjk/me4;->OooOO0o(Llyiahf/vczjk/me4;)Llyiahf/vczjk/ke4;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    invoke-virtual {v1}, Llyiahf/vczjk/ke4;->OooO0oO()Llyiahf/vczjk/me4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOo0:Llyiahf/vczjk/me4;

    goto :goto_2

    :cond_5
    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOo0:Llyiahf/vczjk/me4;

    :goto_2
    iget v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOOoo()Z

    move-result v0

    if-eqz v0, :cond_8

    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOOO()Llyiahf/vczjk/me4;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    const/16 v2, 0x8

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_7

    iget-object v1, p0, Llyiahf/vczjk/ne4;->OooOOo:Llyiahf/vczjk/me4;

    sget-object v3, Llyiahf/vczjk/me4;->OooOOO0:Llyiahf/vczjk/me4;

    if-eq v1, v3, :cond_7

    invoke-static {v1}, Llyiahf/vczjk/me4;->OooOO0o(Llyiahf/vczjk/me4;)Llyiahf/vczjk/ke4;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    invoke-virtual {v1}, Llyiahf/vczjk/ke4;->OooO0oO()Llyiahf/vczjk/me4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOo:Llyiahf/vczjk/me4;

    goto :goto_3

    :cond_7
    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOo:Llyiahf/vczjk/me4;

    :goto_3
    iget v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    :cond_8
    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOOOo()Z

    move-result v0

    if-eqz v0, :cond_a

    invoke-virtual {p1}, Llyiahf/vczjk/oe4;->OooOO0O()Llyiahf/vczjk/me4;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    const/16 v2, 0x10

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_9

    iget-object v1, p0, Llyiahf/vczjk/ne4;->OooOOoo:Llyiahf/vczjk/me4;

    sget-object v3, Llyiahf/vczjk/me4;->OooOOO0:Llyiahf/vczjk/me4;

    if-eq v1, v3, :cond_9

    invoke-static {v1}, Llyiahf/vczjk/me4;->OooOO0o(Llyiahf/vczjk/me4;)Llyiahf/vczjk/ke4;

    move-result-object v1

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    invoke-virtual {v1}, Llyiahf/vczjk/ke4;->OooO0oO()Llyiahf/vczjk/me4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOoo:Llyiahf/vczjk/me4;

    goto :goto_4

    :cond_9
    iput-object v0, p0, Llyiahf/vczjk/ne4;->OooOOoo:Llyiahf/vczjk/me4;

    :goto_4
    iget v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/ne4;->OooOOO:I

    :cond_a
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/oe4;->OooOO0(Llyiahf/vczjk/oe4;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/ne4;->OooO0oO()Llyiahf/vczjk/ne4;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/ne4;->OooO0o0()Llyiahf/vczjk/oe4;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ne4;->OooO0oo(Llyiahf/vczjk/oe4;)V

    return-object v0
.end method
