.class public final Llyiahf/vczjk/jq4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $measuredLineProvider:Llyiahf/vczjk/iq4;

.field final synthetic $spanLayoutProvider:Llyiahf/vczjk/yq4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yq4;Llyiahf/vczjk/iq4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jq4;->$spanLayoutProvider:Llyiahf/vczjk/yq4;

    iput-object p2, p0, Llyiahf/vczjk/jq4;->$measuredLineProvider:Llyiahf/vczjk/iq4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/jq4;->$spanLayoutProvider:Llyiahf/vczjk/yq4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yq4;->OooO0O0(I)Llyiahf/vczjk/w3;

    move-result-object p1

    new-instance v0, Ljava/util/ArrayList;

    iget-object v1, p1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v2

    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    iget-object v2, p0, Llyiahf/vczjk/jq4;->$measuredLineProvider:Llyiahf/vczjk/iq4;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v3

    const/4 v4, 0x0

    iget p1, p1, Llyiahf/vczjk/w3;->OooOOO0:I

    move v5, v4

    :goto_0
    if-ge v4, v3, :cond_0

    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/bk3;

    iget-wide v6, v6, Llyiahf/vczjk/bk3;->OooO00o:J

    long-to-int v6, v6

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v7

    invoke-virtual {v2, v5, v6}, Llyiahf/vczjk/sq4;->OooO00o(II)J

    move-result-wide v8

    new-instance v10, Llyiahf/vczjk/rk1;

    invoke-direct {v10, v8, v9}, Llyiahf/vczjk/rk1;-><init>(J)V

    new-instance v8, Llyiahf/vczjk/xn6;

    invoke-direct {v8, v7, v10}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v0, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 p1, p1, 0x1

    add-int/2addr v5, v6

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    return-object v0
.end method
