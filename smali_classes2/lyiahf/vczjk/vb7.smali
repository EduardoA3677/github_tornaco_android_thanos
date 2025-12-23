.class public final Llyiahf/vczjk/vb7;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public final synthetic OooOOO:I

.field public OooOOOO:I

.field public OooOOOo:Ljava/util/List;

.field public OooOOo0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/vb7;->OooOOO:I

    invoke-direct {p0}, Llyiahf/vczjk/og3;-><init>()V

    return-void
.end method

.method public static OooO0oo()Llyiahf/vczjk/vb7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/vb7;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/vb7;-><init>(I)V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    const/4 v1, -0x1

    iput v1, v0, Llyiahf/vczjk/vb7;->OooOOo0:I

    return-object v0
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/wb7;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/wb7;->OooOOO0:Llyiahf/vczjk/wb7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/wb7;->OooOO0o()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/wb7;->OooOO0O()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/vb7;->OooOOo0:I

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/wb7;->OooO0o0(Llyiahf/vczjk/wb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/wb7;->OooO0o0(Llyiahf/vczjk/wb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    and-int/lit8 v0, v0, -0x3

    iput v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    goto :goto_0

    :cond_2
    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    const/4 v1, 0x2

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_3

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    :cond_3
    iget-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/wb7;->OooO0o0(Llyiahf/vczjk/wb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_4
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/wb7;->OooO0oo(Llyiahf/vczjk/wb7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p0}, Llyiahf/vczjk/vb7;->OooO0oO()Llyiahf/vczjk/nd7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/nd7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0

    :pswitch_0
    invoke-virtual {p0}, Llyiahf/vczjk/vb7;->OooO0o0()Llyiahf/vczjk/wb7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/wb7;->isInitialized()Z

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
    .locals 2

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    const/4 v0, 0x0

    :try_start_0
    sget-object v1, Llyiahf/vczjk/nd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/nd7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/nd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/nd7;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    :cond_0
    throw p1

    :pswitch_0
    const/4 v0, 0x0

    :try_start_3
    sget-object v1, Llyiahf/vczjk/wb7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1, p1, p2}, Llyiahf/vczjk/je4;->OooO00o(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wb7;
    :try_end_3
    .catch Llyiahf/vczjk/i44; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    return-object p0

    :catchall_2
    move-exception p1

    goto :goto_1

    :catch_1
    move-exception p1

    :try_start_4
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/wb7;
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :try_start_5
    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    :catchall_3
    move-exception p1

    move-object v0, p2

    :goto_1
    if-eqz v0, :cond_1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

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

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/nd7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    return-object p0

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/wb7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0o0()Llyiahf/vczjk/wb7;
    .locals 4

    new-instance v0, Llyiahf/vczjk/wb7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wb7;-><init>(Llyiahf/vczjk/vb7;)V

    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOo0:I

    invoke-static {v0, v1}, Llyiahf/vczjk/wb7;->OooO0Oo(Llyiahf/vczjk/wb7;I)V

    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    const/4 v3, 0x2

    and-int/2addr v1, v3

    if-ne v1, v3, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    and-int/lit8 v1, v1, -0x3

    iput v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/wb7;->OooO0o(Llyiahf/vczjk/wb7;Ljava/util/List;)V

    invoke-static {v0, v2}, Llyiahf/vczjk/wb7;->OooO0oO(Llyiahf/vczjk/wb7;I)V

    return-object v0
.end method

.method public OooO0oO()Llyiahf/vczjk/nd7;
    .locals 4

    new-instance v0, Llyiahf/vczjk/nd7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/nd7;-><init>(Llyiahf/vczjk/vb7;)V

    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    and-int/lit8 v2, v2, -0x2

    iput v2, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    :cond_0
    iget-object v2, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/nd7;->OooO0o0(Llyiahf/vczjk/nd7;Ljava/util/List;)V

    const/4 v2, 0x2

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_1

    goto :goto_0

    :cond_1
    const/4 v3, 0x0

    :goto_0
    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOo0:I

    invoke-static {v0, v1}, Llyiahf/vczjk/nd7;->OooO0o(Llyiahf/vczjk/nd7;I)V

    invoke-static {v0, v3}, Llyiahf/vczjk/nd7;->OooO0oO(Llyiahf/vczjk/nd7;I)V

    return-object v0
.end method

.method public OooOO0(Llyiahf/vczjk/nd7;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/nd7;->OooOOO0:Llyiahf/vczjk/nd7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/nd7;->OooO0Oo(Llyiahf/vczjk/nd7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/nd7;->OooO0Oo(Llyiahf/vczjk/nd7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    goto :goto_0

    :cond_1
    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/nd7;->OooO0Oo(Llyiahf/vczjk/nd7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3
    :goto_0
    invoke-virtual {p1}, Llyiahf/vczjk/nd7;->OooOO0O()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/nd7;->OooO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    or-int/lit8 v1, v1, 0x2

    iput v1, p0, Llyiahf/vczjk/vb7;->OooOOOO:I

    iput v0, p0, Llyiahf/vczjk/vb7;->OooOOo0:I

    :cond_4
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/nd7;->OooO0oo(Llyiahf/vczjk/nd7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/vb7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-static {}, Llyiahf/vczjk/vb7;->OooO0oo()Llyiahf/vczjk/vb7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/vb7;->OooO0oO()Llyiahf/vczjk/nd7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/vb7;->OooOO0(Llyiahf/vczjk/nd7;)V

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/vb7;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/vb7;-><init>(I)V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-virtual {p0}, Llyiahf/vczjk/vb7;->OooO0o0()Llyiahf/vczjk/wb7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
