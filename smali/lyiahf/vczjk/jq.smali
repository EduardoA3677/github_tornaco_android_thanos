.class public final Llyiahf/vczjk/jq;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Ljava/util/ArrayList;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    packed-switch p1, :pswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    return-void

    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/ArrayList;

    const/16 v0, 0x20

    invoke-direct {p1, v0}, Ljava/util/ArrayList;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 4

    const-string v0, "tag"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/ArrayList;

    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/u59;

    const-string v3, "Start"

    invoke-direct {v2, v3, v0, v1}, Llyiahf/vczjk/u59;-><init>(Ljava/lang/String;J)V

    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method


# virtual methods
.method public OooO()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    const/4 v2, 0x1

    :goto_0
    if-ge v2, v1, :cond_0

    add-int/lit8 v3, v2, -0x1

    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/u59;

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/u59;

    iget-wide v4, v4, Llyiahf/vczjk/u59;->OooO0O0:J

    iget-wide v3, v3, Llyiahf/vczjk/u59;->OooO0O0:J

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/u59;

    iget-wide v0, v0, Llyiahf/vczjk/u59;->OooO0O0:J

    return-void
.end method

.method public OooO00o(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Ljava/lang/String;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/qz0;

    invoke-direct {v1, p1, p2, p3}, Llyiahf/vczjk/qz0;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooO0O0()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    sget-object v1, Llyiahf/vczjk/hq6;->OooO0OO:Llyiahf/vczjk/hq6;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooO0OO(FFFFFF)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/iq6;

    move v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    move v6, p5

    move v7, p6

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/iq6;-><init>(FFFFFF)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooO0Oo(FFFFFF)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/qq6;

    move v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    move v6, p5

    move v7, p6

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/qq6;-><init>(FFFFFF)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooO0o(F)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/rq6;

    invoke-direct {v1, p1}, Llyiahf/vczjk/rq6;-><init>(F)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooO0o0(F)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/jq6;

    invoke-direct {v1, p1}, Llyiahf/vczjk/jq6;-><init>(F)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooO0oO(FF)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/kq6;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/kq6;-><init>(FF)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooO0oo(FF)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/sq6;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/sq6;-><init>(FF)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooOO0(FF)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/lq6;

    invoke-direct {v1, p1, p2}, Llyiahf/vczjk/lq6;-><init>(FF)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooOO0O(FFFF)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/nq6;

    invoke-direct {v1, p1, p2, p3, p4}, Llyiahf/vczjk/nq6;-><init>(FFFF)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooOO0o(FFFF)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/vq6;

    invoke-direct {v1, p1, p2, p3, p4}, Llyiahf/vczjk/vq6;-><init>(FFFF)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooOOO(F)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/yq6;

    invoke-direct {v1, p1}, Llyiahf/vczjk/yq6;-><init>(F)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooOOO0(Ljava/lang/String;)V
    .locals 4

    const-string v0, "name"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    iget-object v2, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v3, Llyiahf/vczjk/u59;

    invoke-direct {v3, p1, v0, v1}, Llyiahf/vczjk/u59;-><init>(Ljava/lang/String;J)V

    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method

.method public OooOOOO(F)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jq;->OooO00o:Ljava/util/ArrayList;

    new-instance v1, Llyiahf/vczjk/xq6;

    invoke-direct {v1, p1}, Llyiahf/vczjk/xq6;-><init>(F)V

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-void
.end method
