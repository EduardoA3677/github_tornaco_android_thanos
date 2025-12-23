.class public final Llyiahf/vczjk/ke4;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public final synthetic OooOOO:I

.field public OooOOOO:I

.field public OooOOOo:I

.field public OooOOo0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/ke4;->OooOOO:I

    invoke-direct {p0}, Llyiahf/vczjk/og3;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/me4;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/me4;->OooOOO0:Llyiahf/vczjk/me4;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/me4;->OooOO0O()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/me4;->OooO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/ke4;->OooOOOo:I

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/me4;->OooOO0()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/me4;->OooO0oo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/ke4;->OooOOo0:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/me4;->OooO0oO(Llyiahf/vczjk/me4;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ke4;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p0}, Llyiahf/vczjk/ke4;->OooO0oO()Llyiahf/vczjk/me4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/me4;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0

    :pswitch_0
    invoke-virtual {p0}, Llyiahf/vczjk/ke4;->OooO0o0()Llyiahf/vczjk/le4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/le4;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_1

    return-object v0

    :cond_1
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/og3;
    .locals 1

    iget p2, p0, Llyiahf/vczjk/ke4;->OooOOO:I

    packed-switch p2, :pswitch_data_0

    const/4 p2, 0x0

    :try_start_0
    sget-object v0, Llyiahf/vczjk/me4;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/me4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/me4;-><init>(Llyiahf/vczjk/h11;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/me4;
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

    invoke-virtual {p0, p2}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    :cond_0
    throw p1

    :pswitch_0
    const/4 p2, 0x0

    :try_start_3
    sget-object v0, Llyiahf/vczjk/le4;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/le4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/le4;-><init>(Llyiahf/vczjk/h11;)V
    :try_end_3
    .catch Llyiahf/vczjk/i44; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {p0, v0}, Llyiahf/vczjk/ke4;->OooO0oo(Llyiahf/vczjk/le4;)V

    return-object p0

    :catchall_2
    move-exception p1

    goto :goto_1

    :catch_1
    move-exception p1

    :try_start_4
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/le4;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :try_start_5
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    :catchall_3
    move-exception p1

    move-object p2, v0

    :goto_1
    if-eqz p2, :cond_1

    invoke-virtual {p0, p2}, Llyiahf/vczjk/ke4;->OooO0oo(Llyiahf/vczjk/le4;)V

    :cond_1
    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/ke4;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/me4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    return-object p0

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/le4;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/ke4;->OooO0oo(Llyiahf/vczjk/le4;)V

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0o0()Llyiahf/vczjk/le4;
    .locals 4

    new-instance v0, Llyiahf/vczjk/le4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/le4;-><init>(Llyiahf/vczjk/ke4;)V

    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/ke4;->OooOOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/le4;->OooO0Oo(Llyiahf/vczjk/le4;I)V

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOo0:I

    invoke-static {v0, v1}, Llyiahf/vczjk/le4;->OooO0o0(Llyiahf/vczjk/le4;I)V

    invoke-static {v0, v3}, Llyiahf/vczjk/le4;->OooO0o(Llyiahf/vczjk/le4;I)V

    return-object v0
.end method

.method public OooO0oO()Llyiahf/vczjk/me4;
    .locals 4

    new-instance v0, Llyiahf/vczjk/me4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/me4;-><init>(Llyiahf/vczjk/ke4;)V

    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget v2, p0, Llyiahf/vczjk/ke4;->OooOOOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/me4;->OooO0Oo(Llyiahf/vczjk/me4;I)V

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOo0:I

    invoke-static {v0, v1}, Llyiahf/vczjk/me4;->OooO0o0(Llyiahf/vczjk/me4;I)V

    invoke-static {v0, v3}, Llyiahf/vczjk/me4;->OooO0o(Llyiahf/vczjk/me4;I)V

    return-object v0
.end method

.method public OooO0oo(Llyiahf/vczjk/le4;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/le4;->OooOOO0:Llyiahf/vczjk/le4;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/le4;->OooOO0O()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/le4;->OooO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/ke4;->OooOOOo:I

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/le4;->OooOO0()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/le4;->OooO0oo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/ke4;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/ke4;->OooOOo0:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/le4;->OooO0oO(Llyiahf/vczjk/le4;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/ke4;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/ke4;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/ke4;-><init>(I)V

    invoke-virtual {p0}, Llyiahf/vczjk/ke4;->OooO0oO()Llyiahf/vczjk/me4;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ke4;->OooO(Llyiahf/vczjk/me4;)V

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/ke4;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ke4;-><init>(I)V

    invoke-virtual {p0}, Llyiahf/vczjk/ke4;->OooO0o0()Llyiahf/vczjk/le4;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ke4;->OooO0oo(Llyiahf/vczjk/le4;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
