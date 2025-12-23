.class public final Llyiahf/vczjk/yc7;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public OooOOO:I

.field public OooOOOO:I

.field public OooOOOo:I

.field public OooOOo0:Llyiahf/vczjk/zc7;


# direct methods
.method public static OooO0oO()Llyiahf/vczjk/yc7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yc7;

    invoke-direct {v0}, Llyiahf/vczjk/og3;-><init>()V

    const/4 v1, -0x1

    iput v1, v0, Llyiahf/vczjk/yc7;->OooOOOO:I

    sget-object v1, Llyiahf/vczjk/zc7;->OooOOO:Llyiahf/vczjk/zc7;

    iput-object v1, v0, Llyiahf/vczjk/yc7;->OooOOo0:Llyiahf/vczjk/zc7;

    return-object v0
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/yc7;->OooO0o0()Llyiahf/vczjk/ad7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ad7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/og3;
    .locals 1

    const/4 p2, 0x0

    :try_start_0
    sget-object v0, Llyiahf/vczjk/ad7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/ad7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/ad7;-><init>(Llyiahf/vczjk/h11;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/yc7;->OooO0oo(Llyiahf/vczjk/ad7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ad7;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :try_start_2
    throw p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    :catchall_1
    move-exception p1

    move-object p2, v0

    :goto_0
    if-eqz p2, :cond_0

    invoke-virtual {p0, p2}, Llyiahf/vczjk/yc7;->OooO0oo(Llyiahf/vczjk/ad7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/ad7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/yc7;->OooO0oo(Llyiahf/vczjk/ad7;)V

    return-object p0
.end method

.method public final OooO0o0()Llyiahf/vczjk/ad7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/ad7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ad7;-><init>(Llyiahf/vczjk/yc7;)V

    iget v1, p0, Llyiahf/vczjk/yc7;->OooOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/yc7;->OooOOOO:I

    invoke-static {v0, v2}, Llyiahf/vczjk/ad7;->OooO0oo(Llyiahf/vczjk/ad7;I)V

    and-int/lit8 v2, v1, 0x2

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget v2, p0, Llyiahf/vczjk/yc7;->OooOOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/ad7;->OooO0Oo(Llyiahf/vczjk/ad7;I)V

    const/4 v2, 0x4

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_2

    or-int/lit8 v3, v3, 0x4

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/yc7;->OooOOo0:Llyiahf/vczjk/zc7;

    invoke-static {v0, v1}, Llyiahf/vczjk/ad7;->OooO0o0(Llyiahf/vczjk/ad7;Llyiahf/vczjk/zc7;)V

    invoke-static {v0, v3}, Llyiahf/vczjk/ad7;->OooO0o(Llyiahf/vczjk/ad7;I)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/ad7;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/ad7;->OooOOO0:Llyiahf/vczjk/ad7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ad7;->OooOOO0()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/ad7;->OooOO0()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/yc7;->OooOOO:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/yc7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/yc7;->OooOOOO:I

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/ad7;->OooOOO()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/ad7;->OooOO0O()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/yc7;->OooOOO:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/yc7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/yc7;->OooOOOo:I

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/ad7;->OooOO0o()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/ad7;->OooO()Llyiahf/vczjk/zc7;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, p0, Llyiahf/vczjk/yc7;->OooOOO:I

    or-int/lit8 v1, v1, 0x4

    iput v1, p0, Llyiahf/vczjk/yc7;->OooOOO:I

    iput-object v0, p0, Llyiahf/vczjk/yc7;->OooOOo0:Llyiahf/vczjk/zc7;

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/ad7;->OooO0oO(Llyiahf/vczjk/ad7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/yc7;->OooO0oO()Llyiahf/vczjk/yc7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/yc7;->OooO0o0()Llyiahf/vczjk/ad7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yc7;->OooO0oo(Llyiahf/vczjk/ad7;)V

    return-object v0
.end method
