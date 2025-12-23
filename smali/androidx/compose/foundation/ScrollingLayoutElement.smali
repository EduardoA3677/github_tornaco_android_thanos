.class public final Landroidx/compose/foundation/ScrollingLayoutElement;
.super Llyiahf/vczjk/tl5;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/tl5;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0000\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/ScrollingLayoutElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/t98;",
        "foundation_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooOOO:Z

.field public final OooOOO0:Llyiahf/vczjk/z98;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/z98;Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO0:Llyiahf/vczjk/z98;

    iput-boolean p2, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO:Z

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/t98;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iget-object v1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO0:Llyiahf/vczjk/z98;

    iput-object v1, v0, Llyiahf/vczjk/t98;->OooOoOO:Llyiahf/vczjk/z98;

    iget-boolean v1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO:Z

    iput-boolean v1, v0, Llyiahf/vczjk/t98;->OooOoo0:Z

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 1

    check-cast p1, Llyiahf/vczjk/t98;

    iget-object v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO0:Llyiahf/vczjk/z98;

    iput-object v0, p1, Llyiahf/vczjk/t98;->OooOoOO:Llyiahf/vczjk/z98;

    iget-boolean v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO:Z

    iput-boolean v0, p1, Llyiahf/vczjk/t98;->OooOoo0:Z

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    instance-of v0, p1, Landroidx/compose/foundation/ScrollingLayoutElement;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    check-cast p1, Landroidx/compose/foundation/ScrollingLayoutElement;

    iget-object v0, p1, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO0:Llyiahf/vczjk/z98;

    iget-object v1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO0:Llyiahf/vczjk/z98;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-boolean v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO:Z

    iget-boolean p1, p1, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO:Z

    if-ne v0, p1, :cond_1

    const/4 p1, 0x1

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO0:Llyiahf/vczjk/z98;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    const/4 v2, 0x0

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v0

    iget-boolean v1, p0, Landroidx/compose/foundation/ScrollingLayoutElement;->OooOOO:Z

    invoke-static {v1}, Ljava/lang/Boolean;->hashCode(Z)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
