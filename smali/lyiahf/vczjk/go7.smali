.class public final Llyiahf/vczjk/go7;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/nr5;

.field public final OooO00o:Llyiahf/vczjk/ns5;

.field public final OooO0O0:Llyiahf/vczjk/ws5;

.field public OooO0OO:Llyiahf/vczjk/ws5;

.field public final OooO0Oo:Llyiahf/vczjk/ws5;

.field public OooO0o:Llyiahf/vczjk/ks5;

.field public final OooO0o0:Llyiahf/vczjk/ws5;

.field public final OooO0oO:Ljava/util/ArrayList;

.field public final OooO0oo:Llyiahf/vczjk/nr5;

.field public OooOO0:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ns5;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO00o:Llyiahf/vczjk/ns5;

    new-instance p1, Llyiahf/vczjk/ws5;

    const/16 v0, 0x10

    new-array v1, v0, [Llyiahf/vczjk/oo7;

    invoke-direct {p1, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO0O0:Llyiahf/vczjk/ws5;

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO0OO:Llyiahf/vczjk/ws5;

    new-instance p1, Llyiahf/vczjk/ws5;

    new-array v1, v0, [Ljava/lang/Object;

    invoke-direct {p1, v1}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO0Oo:Llyiahf/vczjk/ws5;

    new-instance p1, Llyiahf/vczjk/ws5;

    new-array v0, v0, [Llyiahf/vczjk/le3;

    invoke-direct {p1, v0}, Llyiahf/vczjk/ws5;-><init>([Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO0o0:Llyiahf/vczjk/ws5;

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO0oO:Ljava/util/ArrayList;

    new-instance p1, Llyiahf/vczjk/nr5;

    invoke-direct {p1}, Llyiahf/vczjk/nr5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO0oo:Llyiahf/vczjk/nr5;

    new-instance p1, Llyiahf/vczjk/nr5;

    invoke-direct {p1}, Llyiahf/vczjk/nr5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/go7;->OooO:Llyiahf/vczjk/nr5;

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/go7;->OooO00o:Llyiahf/vczjk/ns5;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_1

    const-string v1, "Compose:abandons"

    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :try_start_0
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/ms5;

    invoke-direct {v1, v0}, Llyiahf/vczjk/ms5;-><init>(Llyiahf/vczjk/ns5;)V

    iget-object v0, v1, Llyiahf/vczjk/ms5;->OooOOO:Llyiahf/vczjk/xf8;

    :goto_0
    invoke-virtual {v0}, Llyiahf/vczjk/xf8;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/xf8;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/no7;

    invoke-virtual {v1}, Llyiahf/vczjk/ms5;->remove()V

    invoke-interface {v2}, Llyiahf/vczjk/no7;->OooO00o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception v0

    goto :goto_1

    :cond_0
    invoke-static {}, Landroid/os/Trace;->endSection()V

    return-void

    :goto_1
    invoke-static {}, Landroid/os/Trace;->endSection()V

    throw v0

    :cond_1
    return-void
.end method

.method public final OooO0O0()V
    .locals 6

    const/high16 v0, -0x80000000

    invoke-virtual {p0, v0}, Llyiahf/vczjk/go7;->OooO0OO(I)V

    iget-object v0, p0, Llyiahf/vczjk/go7;->OooO0Oo:Llyiahf/vczjk/ws5;

    iget v1, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    iget-object v2, p0, Llyiahf/vczjk/go7;->OooO00o:Llyiahf/vczjk/ns5;

    if-eqz v1, :cond_4

    const-string v1, "Compose:onForgotten"

    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/go7;->OooO0o:Llyiahf/vczjk/ks5;

    iget v3, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    add-int/lit8 v3, v3, -0x1

    :goto_0
    const/4 v4, -0x1

    if-ge v4, v3, :cond_3

    iget-object v4, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    aget-object v4, v4, v3

    instance-of v5, v4, Llyiahf/vczjk/oo7;

    if-eqz v5, :cond_0

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/oo7;

    iget-object v5, v5, Llyiahf/vczjk/oo7;->OooO00o:Llyiahf/vczjk/no7;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/ns5;->remove(Ljava/lang/Object;)Z

    invoke-interface {v5}, Llyiahf/vczjk/no7;->OooO0O0()V

    goto :goto_1

    :catchall_0
    move-exception v0

    goto :goto_3

    :cond_0
    :goto_1
    instance-of v5, v4, Llyiahf/vczjk/ce1;

    if-eqz v5, :cond_2

    if-eqz v1, :cond_1

    invoke-virtual {v1, v4}, Llyiahf/vczjk/a88;->OooO00o(Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_1

    check-cast v4, Llyiahf/vczjk/ce1;

    invoke-interface {v4}, Llyiahf/vczjk/ce1;->OooO00o()V

    goto :goto_2

    :cond_1
    check-cast v4, Llyiahf/vczjk/ce1;

    invoke-interface {v4}, Llyiahf/vczjk/ce1;->OooO0O0()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_2
    :goto_2
    add-int/lit8 v3, v3, -0x1

    goto :goto_0

    :cond_3
    invoke-static {}, Landroid/os/Trace;->endSection()V

    goto :goto_4

    :goto_3
    invoke-static {}, Landroid/os/Trace;->endSection()V

    throw v0

    :cond_4
    :goto_4
    iget-object v0, p0, Llyiahf/vczjk/go7;->OooO0O0:Llyiahf/vczjk/ws5;

    iget v1, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    if-eqz v1, :cond_6

    const-string v1, "Compose:onRemembered"

    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    :try_start_1
    iget-object v1, v0, Llyiahf/vczjk/ws5;->OooOOO0:[Ljava/lang/Object;

    iget v0, v0, Llyiahf/vczjk/ws5;->OooOOOO:I

    const/4 v3, 0x0

    :goto_5
    if-ge v3, v0, :cond_5

    aget-object v4, v1, v3

    check-cast v4, Llyiahf/vczjk/oo7;

    iget-object v4, v4, Llyiahf/vczjk/oo7;->OooO00o:Llyiahf/vczjk/no7;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/ns5;->remove(Ljava/lang/Object;)Z

    invoke-interface {v4}, Llyiahf/vczjk/no7;->OooO0OO()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    add-int/lit8 v3, v3, 0x1

    goto :goto_5

    :cond_5
    invoke-static {}, Landroid/os/Trace;->endSection()V

    return-void

    :catchall_1
    move-exception v0

    invoke-static {}, Landroid/os/Trace;->endSection()V

    throw v0

    :cond_6
    return-void
.end method

.method public final OooO0OO(I)V
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/go7;->OooO0oO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_7

    const/4 v1, 0x0

    const/4 v2, 0x0

    move v5, v1

    move-object v3, v2

    move-object v4, v3

    :goto_0
    iget-object v6, p0, Llyiahf/vczjk/go7;->OooO:Llyiahf/vczjk/nr5;

    iget v7, v6, Llyiahf/vczjk/nr5;->OooO0O0:I

    const-string v8, "null cannot be cast to non-null type androidx.collection.MutableIntList"

    if-ge v5, v7, :cond_2

    invoke-virtual {v6, v5}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v7

    if-gt p1, v7, :cond_1

    invoke-virtual {v0, v5}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    move-result-object v7

    invoke-virtual {v6, v5}, Llyiahf/vczjk/nr5;->OooO0o(I)I

    move-result v6

    iget-object v9, p0, Llyiahf/vczjk/go7;->OooO0oo:Llyiahf/vczjk/nr5;

    invoke-virtual {v9, v5}, Llyiahf/vczjk/nr5;->OooO0o(I)I

    move-result v9

    if-nez v2, :cond_0

    filled-new-array {v7}, [Ljava/lang/Object;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/e21;->OoooO0([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v2

    new-instance v4, Llyiahf/vczjk/nr5;

    invoke-direct {v4}, Llyiahf/vczjk/nr5;-><init>()V

    invoke-virtual {v4, v6}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    new-instance v3, Llyiahf/vczjk/nr5;

    invoke-direct {v3}, Llyiahf/vczjk/nr5;-><init>()V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    goto :goto_0

    :cond_0
    invoke-static {v3, v8}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    invoke-virtual {v4, v6}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    invoke-virtual {v3, v9}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    goto :goto_0

    :cond_1
    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_2
    if-eqz v2, :cond_7

    invoke-static {v3, v8}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v4, v8}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result p1

    add-int/lit8 p1, p1, -0x1

    :goto_1
    if-ge v1, p1, :cond_6

    add-int/lit8 v0, v1, 0x1

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v5

    move v6, v0

    :goto_2
    if-ge v6, v5, :cond_5

    invoke-virtual {v4, v1}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v7

    invoke-virtual {v4, v6}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v8

    if-lt v7, v8, :cond_3

    if-ne v8, v7, :cond_4

    invoke-virtual {v3, v1}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v7

    invoke-virtual {v3, v6}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v8

    if-ge v7, v8, :cond_4

    :cond_3
    invoke-interface {v2, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v7

    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    invoke-interface {v2, v1, v8}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    invoke-interface {v2, v6, v7}, Ljava/util/List;->set(ILjava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v7

    invoke-virtual {v3, v6}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v8

    invoke-virtual {v3, v1, v8}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    invoke-virtual {v3, v6, v7}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    invoke-virtual {v4, v1}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v7

    invoke-virtual {v4, v6}, Llyiahf/vczjk/nr5;->OooO0OO(I)I

    move-result v8

    invoke-virtual {v4, v1, v8}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    invoke-virtual {v4, v6, v7}, Llyiahf/vczjk/nr5;->OooO0oO(II)V

    :cond_4
    add-int/lit8 v6, v6, 0x1

    goto :goto_2

    :cond_5
    move v1, v0

    goto :goto_1

    :cond_6
    iget-object p1, p0, Llyiahf/vczjk/go7;->OooO0Oo:Llyiahf/vczjk/ws5;

    iget v0, p1, Llyiahf/vczjk/ws5;->OooOOOO:I

    invoke-virtual {p1, v0, v2}, Llyiahf/vczjk/ws5;->OooO0OO(ILjava/util/List;)V

    :cond_7
    return-void
.end method

.method public final OooO0Oo(Ljava/lang/Object;III)V
    .locals 0

    invoke-virtual {p0, p2}, Llyiahf/vczjk/go7;->OooO0OO(I)V

    if-ltz p4, :cond_0

    if-ge p4, p2, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/go7;->OooO0oO:Ljava/util/ArrayList;

    invoke-virtual {p2, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    iget-object p1, p0, Llyiahf/vczjk/go7;->OooO0oo:Llyiahf/vczjk/nr5;

    invoke-virtual {p1, p3}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    iget-object p1, p0, Llyiahf/vczjk/go7;->OooO:Llyiahf/vczjk/nr5;

    invoke-virtual {p1, p4}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    return-void

    :cond_0
    iget-object p2, p0, Llyiahf/vczjk/go7;->OooO0Oo:Llyiahf/vczjk/ws5;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method
