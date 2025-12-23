.class public final Llyiahf/vczjk/rb7;
.super Llyiahf/vczjk/og3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ri5;


# instance fields
.field public OooOOO:I

.field public OooOOOO:Llyiahf/vczjk/sb7;

.field public OooOOOo:J

.field public OooOOo:D

.field public OooOOo0:F

.field public OooOOoo:I

.field public OooOo:I

.field public OooOo0:I

.field public OooOo00:I

.field public OooOo0O:Llyiahf/vczjk/wb7;

.field public OooOo0o:Ljava/util/List;

.field public OooOoO0:I


# direct methods
.method public static OooO0oO()Llyiahf/vczjk/rb7;
    .locals 2

    new-instance v0, Llyiahf/vczjk/rb7;

    invoke-direct {v0}, Llyiahf/vczjk/og3;-><init>()V

    sget-object v1, Llyiahf/vczjk/sb7;->OooOOO0:Llyiahf/vczjk/sb7;

    iput-object v1, v0, Llyiahf/vczjk/rb7;->OooOOOO:Llyiahf/vczjk/sb7;

    sget-object v1, Llyiahf/vczjk/wb7;->OooOOO0:Llyiahf/vczjk/wb7;

    iput-object v1, v0, Llyiahf/vczjk/rb7;->OooOo0O:Llyiahf/vczjk/wb7;

    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v1, v0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    return-object v0
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/pi5;
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/rb7;->OooO0o0()Llyiahf/vczjk/tb7;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/tb7;->isInitialized()Z

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
    sget-object v1, Llyiahf/vczjk/tb7;->OooOOO:Llyiahf/vczjk/je4;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/tb7;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/tb7;-><init>(Llyiahf/vczjk/h11;Llyiahf/vczjk/iu2;)V
    :try_end_0
    .catch Llyiahf/vczjk/i44; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0, v1}, Llyiahf/vczjk/rb7;->OooO0oo(Llyiahf/vczjk/tb7;)V

    return-object p0

    :catchall_0
    move-exception p1

    goto :goto_0

    :catch_0
    move-exception p1

    :try_start_1
    invoke-virtual {p1}, Llyiahf/vczjk/i44;->OooO00o()Llyiahf/vczjk/pi5;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/tb7;
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

    invoke-virtual {p0, v0}, Llyiahf/vczjk/rb7;->OooO0oo(Llyiahf/vczjk/tb7;)V

    :cond_0
    throw p1
.end method

.method public final bridge synthetic OooO0Oo(Llyiahf/vczjk/vg3;)Llyiahf/vczjk/og3;
    .locals 0

    check-cast p1, Llyiahf/vczjk/tb7;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/rb7;->OooO0oo(Llyiahf/vczjk/tb7;)V

    return-object p0
.end method

.method public final OooO0o0()Llyiahf/vczjk/tb7;
    .locals 6

    new-instance v0, Llyiahf/vczjk/tb7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/tb7;-><init>(Llyiahf/vczjk/rb7;)V

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    and-int/lit8 v2, v1, 0x1

    const/4 v3, 0x1

    if-ne v2, v3, :cond_0

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/rb7;->OooOOOO:Llyiahf/vczjk/sb7;

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooO0Oo(Llyiahf/vczjk/tb7;Llyiahf/vczjk/sb7;)V

    and-int/lit8 v2, v1, 0x2

    const/4 v4, 0x2

    if-ne v2, v4, :cond_1

    or-int/lit8 v3, v3, 0x2

    :cond_1
    iget-wide v4, p0, Llyiahf/vczjk/rb7;->OooOOOo:J

    invoke-static {v0, v4, v5}, Llyiahf/vczjk/tb7;->OooO0o0(Llyiahf/vczjk/tb7;J)V

    and-int/lit8 v2, v1, 0x4

    const/4 v4, 0x4

    if-ne v2, v4, :cond_2

    or-int/lit8 v3, v3, 0x4

    :cond_2
    iget v2, p0, Llyiahf/vczjk/rb7;->OooOOo0:F

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooO0o(Llyiahf/vczjk/tb7;F)V

    and-int/lit8 v2, v1, 0x8

    const/16 v4, 0x8

    if-ne v2, v4, :cond_3

    or-int/lit8 v3, v3, 0x8

    :cond_3
    iget-wide v4, p0, Llyiahf/vczjk/rb7;->OooOOo:D

    invoke-static {v0, v4, v5}, Llyiahf/vczjk/tb7;->OooO0oO(Llyiahf/vczjk/tb7;D)V

    and-int/lit8 v2, v1, 0x10

    const/16 v4, 0x10

    if-ne v2, v4, :cond_4

    or-int/lit8 v3, v3, 0x10

    :cond_4
    iget v2, p0, Llyiahf/vczjk/rb7;->OooOOoo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooO0oo(Llyiahf/vczjk/tb7;I)V

    and-int/lit8 v2, v1, 0x20

    const/16 v4, 0x20

    if-ne v2, v4, :cond_5

    or-int/lit8 v3, v3, 0x20

    :cond_5
    iget v2, p0, Llyiahf/vczjk/rb7;->OooOo00:I

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooO(Llyiahf/vczjk/tb7;I)V

    and-int/lit8 v2, v1, 0x40

    const/16 v4, 0x40

    if-ne v2, v4, :cond_6

    or-int/lit8 v3, v3, 0x40

    :cond_6
    iget v2, p0, Llyiahf/vczjk/rb7;->OooOo0:I

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooOO0(Llyiahf/vczjk/tb7;I)V

    and-int/lit16 v2, v1, 0x80

    const/16 v4, 0x80

    if-ne v2, v4, :cond_7

    or-int/lit16 v3, v3, 0x80

    :cond_7
    iget-object v2, p0, Llyiahf/vczjk/rb7;->OooOo0O:Llyiahf/vczjk/wb7;

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooOO0O(Llyiahf/vczjk/tb7;Llyiahf/vczjk/wb7;)V

    iget v2, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    const/16 v4, 0x100

    and-int/2addr v2, v4

    if-ne v2, v4, :cond_8

    iget-object v2, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    invoke-static {v2}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object v2

    iput-object v2, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    iget v2, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    and-int/lit16 v2, v2, -0x101

    iput v2, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    :cond_8
    iget-object v2, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooOOO0(Llyiahf/vczjk/tb7;Ljava/util/List;)V

    and-int/lit16 v2, v1, 0x200

    const/16 v4, 0x200

    if-ne v2, v4, :cond_9

    or-int/lit16 v3, v3, 0x100

    :cond_9
    iget v2, p0, Llyiahf/vczjk/rb7;->OooOo:I

    invoke-static {v0, v2}, Llyiahf/vczjk/tb7;->OooOOO(Llyiahf/vczjk/tb7;I)V

    const/16 v2, 0x400

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_a

    or-int/lit16 v3, v3, 0x200

    :cond_a
    iget v1, p0, Llyiahf/vczjk/rb7;->OooOoO0:I

    invoke-static {v0, v1}, Llyiahf/vczjk/tb7;->OooOOOO(Llyiahf/vczjk/tb7;I)V

    invoke-static {v0, v3}, Llyiahf/vczjk/tb7;->OooOOOo(Llyiahf/vczjk/tb7;I)V

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/tb7;)V
    .locals 5

    sget-object v0, Llyiahf/vczjk/tb7;->OooOOO0:Llyiahf/vczjk/tb7;

    if-ne p1, v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->Oooo0o0()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOoo0()Llyiahf/vczjk/sb7;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit8 v1, v1, 0x1

    iput v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput-object v0, p0, Llyiahf/vczjk/rb7;->OooOOOO:Llyiahf/vczjk/sb7;

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->Oooo0O0()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOoO()J

    move-result-wide v0

    iget v2, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit8 v2, v2, 0x2

    iput v2, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput-wide v0, p0, Llyiahf/vczjk/rb7;->OooOOOo:J

    :cond_2
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->Oooo0()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOoO0()F

    move-result v0

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit8 v1, v1, 0x4

    iput v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOOo0:F

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->Oooo000()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOo0o()D

    move-result-wide v0

    iget v2, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit8 v2, v2, 0x8

    iput v2, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput-wide v0, p0, Llyiahf/vczjk/rb7;->OooOOo:D

    :cond_4
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->Oooo0OO()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOoOO()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit8 v1, v1, 0x10

    iput v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOOoo:I

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOooo()Z

    move-result v0

    if-eqz v0, :cond_6

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOo0O()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit8 v1, v1, 0x20

    iput v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOo00:I

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->Oooo00O()Z

    move-result v0

    if-eqz v0, :cond_7

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit8 v1, v1, 0x40

    iput v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOo0:I

    :cond_7
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOoo()Z

    move-result v0

    if-eqz v0, :cond_9

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOOo()Llyiahf/vczjk/wb7;

    move-result-object v0

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    const/16 v2, 0x80

    and-int/2addr v1, v2

    if-ne v1, v2, :cond_8

    iget-object v1, p0, Llyiahf/vczjk/rb7;->OooOo0O:Llyiahf/vczjk/wb7;

    sget-object v3, Llyiahf/vczjk/wb7;->OooOOO0:Llyiahf/vczjk/wb7;

    if-eq v1, v3, :cond_8

    new-instance v3, Llyiahf/vczjk/vb7;

    const/4 v4, 0x0

    invoke-direct {v3, v4}, Llyiahf/vczjk/vb7;-><init>(I)V

    sget-object v4, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    iput-object v4, v3, Llyiahf/vczjk/vb7;->OooOOOo:Ljava/util/List;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    invoke-virtual {v3, v0}, Llyiahf/vczjk/vb7;->OooO(Llyiahf/vczjk/wb7;)V

    invoke-virtual {v3}, Llyiahf/vczjk/vb7;->OooO0o0()Llyiahf/vczjk/wb7;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/rb7;->OooOo0O:Llyiahf/vczjk/wb7;

    goto :goto_0

    :cond_8
    iput-object v0, p0, Llyiahf/vczjk/rb7;->OooOo0O:Llyiahf/vczjk/wb7;

    :goto_0
    iget v0, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/2addr v0, v2

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    :cond_9
    invoke-static {p1}, Llyiahf/vczjk/tb7;->OooOO0o(Llyiahf/vczjk/tb7;)Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_c

    iget-object v0, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_a

    invoke-static {p1}, Llyiahf/vczjk/tb7;->OooOO0o(Llyiahf/vczjk/tb7;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    and-int/lit16 v0, v0, -0x101

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    goto :goto_1

    :cond_a
    iget v0, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    const/16 v1, 0x100

    and-int/2addr v0, v1

    if-eq v0, v1, :cond_b

    new-instance v0, Ljava/util/ArrayList;

    iget-object v2, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    iput-object v0, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    iget v0, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/2addr v0, v1

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    :cond_b
    iget-object v0, p0, Llyiahf/vczjk/rb7;->OooOo0o:Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/tb7;->OooOO0o(Llyiahf/vczjk/tb7;)Ljava/util/List;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->addAll(Ljava/util/Collection;)Z

    :cond_c
    :goto_1
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOooO()Z

    move-result v0

    if-eqz v0, :cond_d

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->OooOOoo()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit16 v1, v1, 0x200

    iput v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOo:I

    :cond_d
    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->Oooo00o()Z

    move-result v0

    if-eqz v0, :cond_e

    invoke-virtual {p1}, Llyiahf/vczjk/tb7;->getFlags()I

    move-result v0

    iget v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    or-int/lit16 v1, v1, 0x400

    iput v1, p0, Llyiahf/vczjk/rb7;->OooOOO:I

    iput v0, p0, Llyiahf/vczjk/rb7;->OooOoO0:I

    :cond_e
    iget-object v0, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    invoke-static {p1}, Llyiahf/vczjk/tb7;->OooOOo0(Llyiahf/vczjk/tb7;)Llyiahf/vczjk/im0;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/im0;->OooO0O0(Llyiahf/vczjk/im0;)Llyiahf/vczjk/im0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/og3;->OooOOO0:Llyiahf/vczjk/im0;

    return-void
.end method

.method public final clone()Ljava/lang/Object;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/rb7;->OooO0oO()Llyiahf/vczjk/rb7;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/rb7;->OooO0o0()Llyiahf/vczjk/tb7;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/rb7;->OooO0oo(Llyiahf/vczjk/tb7;)V

    return-object v0
.end method
