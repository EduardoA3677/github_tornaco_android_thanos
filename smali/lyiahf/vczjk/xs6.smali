.class public final Llyiahf/vczjk/xs6;
.super Llyiahf/vczjk/o00OOOO0;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/qs6;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/qs6;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/xs6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/xs6;->OooOOO:Llyiahf/vczjk/qs6;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/xs6;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xs6;->OooOOO:Llyiahf/vczjk/qs6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v0, v0, Llyiahf/vczjk/qs6;->OooOOO:I

    return v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xs6;->OooOOO:Llyiahf/vczjk/qs6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v0, v0, Llyiahf/vczjk/qs6;->OooOOO:I

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final contains(Ljava/lang/Object;)Z
    .locals 3

    iget v0, p0, Llyiahf/vczjk/xs6;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/xs6;->OooOOO:Llyiahf/vczjk/qs6;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/qs6;->containsKey(Ljava/lang/Object;)Z

    move-result p1

    return p1

    :pswitch_0
    instance-of v0, p1, Ljava/util/Map$Entry;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    check-cast p1, Ljava/util/Map$Entry;

    if-nez p1, :cond_1

    goto :goto_0

    :cond_1
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object v0

    iget-object v2, p0, Llyiahf/vczjk/xs6;->OooOOO:Llyiahf/vczjk/qs6;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/qs6;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    goto :goto_0

    :cond_2
    invoke-interface {p1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    move-result-object v0

    if-nez v0, :cond_3

    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {v2, p1}, Llyiahf/vczjk/qs6;->containsKey(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_3

    const/4 v1, 0x1

    :cond_3
    :goto_0
    return v1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final iterator()Ljava/util/Iterator;
    .locals 7

    iget v0, p0, Llyiahf/vczjk/xs6;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/ys6;

    iget-object v1, p0, Llyiahf/vczjk/xs6;->OooOOO:Llyiahf/vczjk/qs6;

    const/16 v2, 0x8

    new-array v3, v2, [Llyiahf/vczjk/k0a;

    const/4 v4, 0x0

    :goto_0
    if-ge v4, v2, :cond_0

    new-instance v5, Llyiahf/vczjk/l0a;

    const/4 v6, 0x1

    invoke-direct {v5, v6}, Llyiahf/vczjk/l0a;-><init>(I)V

    aput-object v5, v3, v4

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    iget-object v1, v1, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    invoke-direct {v0, v1, v3}, Llyiahf/vczjk/rs6;-><init>(Llyiahf/vczjk/j0a;[Llyiahf/vczjk/k0a;)V

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/ys6;

    iget-object v1, p0, Llyiahf/vczjk/xs6;->OooOOO:Llyiahf/vczjk/qs6;

    const/16 v2, 0x8

    new-array v3, v2, [Llyiahf/vczjk/k0a;

    const/4 v4, 0x0

    :goto_1
    if-ge v4, v2, :cond_1

    new-instance v5, Llyiahf/vczjk/l0a;

    const/4 v6, 0x0

    invoke-direct {v5, v6}, Llyiahf/vczjk/l0a;-><init>(I)V

    aput-object v5, v3, v4

    add-int/lit8 v4, v4, 0x1

    goto :goto_1

    :cond_1
    iget-object v1, v1, Llyiahf/vczjk/qs6;->OooOOO0:Llyiahf/vczjk/j0a;

    invoke-direct {v0, v1, v3}, Llyiahf/vczjk/rs6;-><init>(Llyiahf/vczjk/j0a;[Llyiahf/vczjk/k0a;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
