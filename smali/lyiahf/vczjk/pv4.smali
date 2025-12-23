.class public final Llyiahf/vczjk/pv4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $isLookingAhead:Z

.field final synthetic $positionedItems:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/tv4;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $stickingItems:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/tv4;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/util/List;Z)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pv4;->$positionedItems:Ljava/util/List;

    iput-object p2, p0, Llyiahf/vczjk/pv4;->$stickingItems:Ljava/util/List;

    iput-boolean p3, p0, Llyiahf/vczjk/pv4;->$isLookingAhead:Z

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/pv4;->$positionedItems:Ljava/util/List;

    iget-boolean v1, p0, Llyiahf/vczjk/pv4;->$isLookingAhead:Z

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v2

    const/4 v3, 0x0

    move v4, v3

    :goto_0
    if-ge v4, v2, :cond_0

    invoke-interface {v0, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/tv4;

    invoke-virtual {v5, p1, v1}, Llyiahf/vczjk/tv4;->OooOO0o(Llyiahf/vczjk/nw6;Z)V

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/pv4;->$stickingItems:Ljava/util/List;

    iget-boolean v1, p0, Llyiahf/vczjk/pv4;->$isLookingAhead:Z

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v2

    :goto_1
    if-ge v3, v2, :cond_1

    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/tv4;

    invoke-virtual {v4, p1, v1}, Llyiahf/vczjk/tv4;->OooOO0o(Llyiahf/vczjk/nw6;Z)V

    add-int/lit8 v3, v3, 0x1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
