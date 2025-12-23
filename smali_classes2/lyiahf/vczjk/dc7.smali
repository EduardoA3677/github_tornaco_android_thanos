.class public final Llyiahf/vczjk/dc7;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public final synthetic OooOOO:I

.field public OooOOOO:I

.field public OooOOOo:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/dc7;->OooOOO:I

    invoke-direct {p0}, Llyiahf/vczjk/og3;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO()Llyiahf/vczjk/ud7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ud7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ud7;-><init>(Llyiahf/vczjk/dc7;)V

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v1, v1, -0x2

    iput v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/ud7;->OooO0o0(Llyiahf/vczjk/ud7;Ljava/util/List;)V

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO0oo()Llyiahf/vczjk/cd7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/cd7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0

    :pswitch_0
    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO()Llyiahf/vczjk/ud7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ud7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_1

    return-object v0

    :cond_1
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0

    :pswitch_1
    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO0oO()Llyiahf/vczjk/bd7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/bd7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_2

    return-object v0

    :cond_2
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0

    :pswitch_2
    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO0o0()Llyiahf/vczjk/ec7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/ec7;->isInitialized()Z

    move-result v1

    if-eqz v1, :cond_3

    return-object v0

    :cond_3
    new-instance v0, Llyiahf/vczjk/v8a;

    invoke-direct {v0}, Llyiahf/vczjk/v8a;-><init>()V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)Llyiahf/vczjk/og3;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    const/4 p2, 0x0

    :try_start_0
    sget-object v0, Llyiahf/vczjk/cd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/cd7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/cd7;-><init>(Llyiahf/vczjk/h11;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/dc7;->OooOO0o(Llyiahf/vczjk/cd7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cd7;
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

    invoke-virtual {p0, p2}, Llyiahf/vczjk/dc7;->OooOO0o(Llyiahf/vczjk/cd7;)V

    :cond_0
    throw p1

    :pswitch_0
    const/4 v0, 0x0

    :try_start_3
    sget-object v1, Llyiahf/vczjk/ud7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/ud7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/ud7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_3
    .catch Llyiahf/vczjk/i44; {:try_start_3 .. :try_end_3} :catch_1
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    invoke-virtual {p0, v1}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    return-object p0

    :catchall_2
    move-exception p1

    goto :goto_1

    :catch_1
    move-exception p1

    :try_start_4
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ud7;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    :cond_1
    throw p1

    :pswitch_1
    const/4 v0, 0x0

    :try_start_6
    sget-object v1, Llyiahf/vczjk/bd7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/bd7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/bd7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_6
    .catch Llyiahf/vczjk/i44; {:try_start_6 .. :try_end_6} :catch_2
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    invoke-virtual {p0, v1}, Llyiahf/vczjk/dc7;->OooOO0O(Llyiahf/vczjk/bd7;)V

    return-object p0

    :catchall_4
    move-exception p1

    goto :goto_2

    :catch_2
    move-exception p1

    :try_start_7
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/bd7;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    :try_start_8
    throw p1
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    :catchall_5
    move-exception p1

    move-object v0, p2

    :goto_2
    if-eqz v0, :cond_2

    invoke-virtual {p0, v0}, Llyiahf/vczjk/dc7;->OooOO0O(Llyiahf/vczjk/bd7;)V

    :cond_2
    throw p1

    :pswitch_2
    const/4 v0, 0x0

    :try_start_9
    sget-object v1, Llyiahf/vczjk/ec7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/ec7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/ec7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_9
    .catch Llyiahf/vczjk/i44; {:try_start_9 .. :try_end_9} :catch_3
    .catchall {:try_start_9 .. :try_end_9} :catchall_6

    invoke-virtual {p0, v1}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    return-object p0

    :catchall_6
    move-exception p1

    goto :goto_3

    :catch_3
    move-exception p1

    :try_start_a
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/ec7;
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_6

    :try_start_b
    throw p1
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_7

    :catchall_7
    move-exception p1

    move-object v0, p2

    :goto_3
    if-eqz v0, :cond_3

    invoke-virtual {p0, v0}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    :cond_3
    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/cd7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dc7;->OooOO0o(Llyiahf/vczjk/cd7;)V

    return-object p0

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/ud7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    return-object p0

    :pswitch_1
    check-cast p1, Llyiahf/vczjk/bd7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dc7;->OooOO0O(Llyiahf/vczjk/bd7;)V

    return-object p0

    :pswitch_2
    check-cast p1, Llyiahf/vczjk/ec7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    return-object p0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0o0()Llyiahf/vczjk/ec7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ec7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ec7;-><init>(Llyiahf/vczjk/dc7;)V

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v1, v1, -0x2

    iput v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/ec7;->OooO0o0(Llyiahf/vczjk/ec7;Ljava/util/List;)V

    return-object v0
.end method

.method public OooO0oO()Llyiahf/vczjk/bd7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/bd7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/bd7;-><init>(Llyiahf/vczjk/dc7;)V

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v1, v1, -0x2

    iput v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {v0, v1}, Llyiahf/vczjk/bd7;->OooO0o0(Llyiahf/vczjk/bd7;Ljava/util/List;)V

    return-object v0
.end method

.method public OooO0oo()Llyiahf/vczjk/cd7;
    .locals 3

    new-instance v0, Llyiahf/vczjk/cd7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/cd7;-><init>(Llyiahf/vczjk/dc7;)V

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v2, 0x1

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    check-cast v1, Llyiahf/vczjk/tw4;

    invoke-interface {v1}, Llyiahf/vczjk/tw4;->getUnmodifiableView()Llyiahf/vczjk/g9a;

    move-result-object v1

    iput-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v1, v1, -0x2

    iput v1, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    check-cast v1, Llyiahf/vczjk/tw4;

    invoke-static {v0, v1}, Llyiahf/vczjk/cd7;->OooO0o0(Llyiahf/vczjk/cd7;Llyiahf/vczjk/tw4;)V

    return-object v0
.end method

.method public OooOO0(Llyiahf/vczjk/ec7;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/ec7;->OooOOO0:Llyiahf/vczjk/ec7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/ec7;->OooO0Oo(Llyiahf/vczjk/ec7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/ec7;->OooO0Oo(Llyiahf/vczjk/ec7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    goto :goto_0

    :cond_1
    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/ec7;->OooO0Oo(Llyiahf/vczjk/ec7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/ec7;->OooO0o(Llyiahf/vczjk/ec7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public OooOO0O(Llyiahf/vczjk/bd7;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/bd7;->OooOOO0:Llyiahf/vczjk/bd7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/bd7;->OooO0Oo(Llyiahf/vczjk/bd7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/bd7;->OooO0Oo(Llyiahf/vczjk/bd7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    goto :goto_0

    :cond_1
    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/bd7;->OooO0Oo(Llyiahf/vczjk/bd7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/bd7;->OooO0o(Llyiahf/vczjk/bd7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public OooOO0o(Llyiahf/vczjk/cd7;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/cd7;->OooOOO0:Llyiahf/vczjk/cd7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/cd7;->OooO0Oo(Llyiahf/vczjk/cd7;)Llyiahf/vczjk/tw4;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    check-cast v0, Llyiahf/vczjk/tw4;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/cd7;->OooO0Oo(Llyiahf/vczjk/cd7;)Llyiahf/vczjk/tw4;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    goto :goto_0

    :cond_1
    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2

    new-instance v0, Llyiahf/vczjk/sw4;

    iget-object v2, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    check-cast v2, Llyiahf/vczjk/tw4;

    invoke-direct {v0, v2}, Llyiahf/vczjk/sw4;-><init>(Llyiahf/vczjk/tw4;)V

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    check-cast v0, Llyiahf/vczjk/tw4;

    invoke-static {p1}, Llyiahf/vczjk/cd7;->OooO0Oo(Llyiahf/vczjk/cd7;)Llyiahf/vczjk/tw4;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/cd7;->OooO0o(Llyiahf/vczjk/cd7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public OooOOO0(Llyiahf/vczjk/ud7;)V
    .locals 3

    sget-object v0, Llyiahf/vczjk/ud7;->OooOOO0:Llyiahf/vczjk/ud7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/ud7;->OooO0Oo(Llyiahf/vczjk/ud7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/ud7;->OooO0Oo(Llyiahf/vczjk/ud7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    and-int/lit8 v0, v0, -0x2

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    goto :goto_0

    :cond_1
    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    const/4 v1, 0x1

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_2

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/dc7;->OooOOOO:I

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/ud7;->OooO0Oo(Llyiahf/vczjk/ud7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_3
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/ud7;->OooO0o(Llyiahf/vczjk/ud7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/dc7;->OooOOO:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/dc7;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v1, Llyiahf/vczjk/sw4;->OooOOO:Llyiahf/vczjk/g9a;

    iput-object v1, v0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO0oo()Llyiahf/vczjk/cd7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/dc7;->OooOO0o(Llyiahf/vczjk/cd7;)V

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/dc7;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO()Llyiahf/vczjk/ud7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/dc7;->OooOOO0(Llyiahf/vczjk/ud7;)V

    return-object v0

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/dc7;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO0oO()Llyiahf/vczjk/bd7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/dc7;->OooOO0O(Llyiahf/vczjk/bd7;)V

    return-object v0

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/dc7;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/dc7;-><init>(I)V

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/dc7;->OooOOOo:Ljava/util/List;

    invoke-virtual {p0}, Llyiahf/vczjk/dc7;->OooO0o0()Llyiahf/vczjk/ec7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/dc7;->OooOO0(Llyiahf/vczjk/ec7;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
