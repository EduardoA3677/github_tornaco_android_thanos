.class public final Llyiahf/vczjk/qd7;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public OooOOO:I

.field public OooOOOO:I

.field public OooOOOo:I

.field public OooOOo:I

.field public OooOOo0:Llyiahf/vczjk/rd7;

.field public OooOOoo:I

.field public OooOo00:Llyiahf/vczjk/sd7;


# direct methods
.method public static OooO0oO()Llyiahf/vczjk/qd7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/qd7;

    invoke-direct {v0}, Llyiahf/vczjk/og3;-><init>()V

    sget-object v1, Llyiahf/vczjk/rd7;->OooOOO:Llyiahf/vczjk/rd7;

    iput-object v1, v0, Llyiahf/vczjk/qd7;->OooOOo0:Llyiahf/vczjk/rd7;

    sget-object v1, Llyiahf/vczjk/sd7;->OooOOO0:Llyiahf/vczjk/sd7;

    iput-object v1, v0, Llyiahf/vczjk/qd7;->OooOo00:Llyiahf/vczjk/sd7;

    return-object v0
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/qd7;->OooO0o0()Llyiahf/vczjk/td7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/td7;->isInitialized()Z

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
    sget-object v0, Llyiahf/vczjk/td7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/td7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/td7;-><init>(Llyiahf/vczjk/h11;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/qd7;->OooO0oo(Llyiahf/vczjk/td7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/td7;
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

    invoke-virtual {p0, p2}, Llyiahf/vczjk/qd7;->OooO0oo(Llyiahf/vczjk/td7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/td7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/qd7;->OooO0oo(Llyiahf/vczjk/td7;)V

    return-object p0
.end method

.method public final OooO0o0()Llyiahf/vczjk/td7;
    .locals 5

    new-instance v0, Llyiahf/vczjk/td7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/td7;-><init>(Llyiahf/vczjk/qd7;)V

    iget v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/qd7;->OooOOOO:I

    invoke-static {v0, v2}, Llyiahf/vczjk/td7;->OooO0Oo(Llyiahf/vczjk/td7;I)V

    and-int/lit8 v2, v1, 0x2

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget v2, p0, Llyiahf/vczjk/qd7;->OooOOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/td7;->OooO0o0(Llyiahf/vczjk/td7;I)V

    and-int/lit8 v2, v1, 0x4

    const/4 v4, 0x4

    if-ne v2, v4, :cond_2

    or-int/lit8 v3, v3, 0x4

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/qd7;->OooOOo0:Llyiahf/vczjk/rd7;

    invoke-static {v0, v2}, Llyiahf/vczjk/td7;->OooO0o(Llyiahf/vczjk/td7;Llyiahf/vczjk/rd7;)V

    and-int/lit8 v2, v1, 0x8

    const/16 v4, 0x8

    if-ne v2, v4, :cond_3

    or-int/lit8 v3, v3, 0x8

    :cond_3
    iget v2, p0, Llyiahf/vczjk/qd7;->OooOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/td7;->OooO0oO(Llyiahf/vczjk/td7;I)V

    and-int/lit8 v2, v1, 0x10

    const/16 v4, 0x10

    if-ne v2, v4, :cond_4

    or-int/lit8 v3, v3, 0x10

    :cond_4
    iget v2, p0, Llyiahf/vczjk/qd7;->OooOOoo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/td7;->OooO0oo(Llyiahf/vczjk/td7;I)V

    const/16 v2, 0x20

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_5

    or-int/lit8 v3, v3, 0x20

    :cond_5
    iget-object v1, p0, Llyiahf/vczjk/qd7;->OooOo00:Llyiahf/vczjk/sd7;

    invoke-static {v0, v1}, Llyiahf/vczjk/td7;->OooO(Llyiahf/vczjk/td7;Llyiahf/vczjk/sd7;)V

    invoke-static {v0, v3}, Llyiahf/vczjk/td7;->OooOO0(Llyiahf/vczjk/td7;I)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/td7;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/td7;->OooOOO0:Llyiahf/vczjk/td7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOo0()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOOOO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/qd7;->OooOOOO:I

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOo0O()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOOOo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/qd7;->OooOOOo:I

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOOoo()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOOO0()Llyiahf/vczjk/rd7;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    or-int/lit8 v1, v1, 0x4

    iput v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    iput-object v0, p0, Llyiahf/vczjk/qd7;->OooOOo0:Llyiahf/vczjk/rd7;

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOOo()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOO0o()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    or-int/lit8 v1, v1, 0x8

    iput v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/qd7;->OooOOo:I

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOo00()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOOO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    or-int/lit8 v1, v1, 0x10

    iput v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/qd7;->OooOOoo:I

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOo0o()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/td7;->OooOOo0()Llyiahf/vczjk/sd7;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    or-int/lit8 v1, v1, 0x20

    iput v1, p0, Llyiahf/vczjk/qd7;->OooOOO:I

    iput-object v0, p0, Llyiahf/vczjk/qd7;->OooOo00:Llyiahf/vczjk/sd7;

    :cond_6
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/td7;->OooOO0O(Llyiahf/vczjk/td7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/qd7;->OooO0oO()Llyiahf/vczjk/qd7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/qd7;->OooO0o0()Llyiahf/vczjk/td7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/qd7;->OooO0oo(Llyiahf/vczjk/td7;)V

    return-object v0
.end method
