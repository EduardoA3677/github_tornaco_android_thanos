.class final Landroidx/compose/foundation/gestures/ScrollableElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/gestures/ScrollableElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/ra8;",
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
.field public final OooOOO:Llyiahf/vczjk/nf6;

.field public final OooOOO0:Llyiahf/vczjk/sj9;

.field public final OooOOOO:Z

.field public final OooOOOo:Z

.field public final OooOOo0:Llyiahf/vczjk/rr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sj9;Llyiahf/vczjk/nf6;ZZLlyiahf/vczjk/rr5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO0:Llyiahf/vczjk/sj9;

    iput-object p2, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO:Llyiahf/vczjk/nf6;

    iput-boolean p3, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOO:Z

    iput-boolean p4, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOo:Z

    iput-object p5, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOo0:Llyiahf/vczjk/rr5;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 9

    new-instance v0, Llyiahf/vczjk/ra8;

    iget-object v2, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOo0:Llyiahf/vczjk/rr5;

    const/4 v5, 0x0

    iget-object v6, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO0:Llyiahf/vczjk/sj9;

    const/4 v4, 0x0

    const/4 v1, 0x0

    iget-object v3, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO:Llyiahf/vczjk/nf6;

    iget-boolean v7, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOO:Z

    iget-boolean v8, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOo:Z

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/ra8;-><init>(Llyiahf/vczjk/o23;Llyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;Llyiahf/vczjk/qg6;Llyiahf/vczjk/rk6;Llyiahf/vczjk/sa8;ZZ)V

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 9

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ra8;

    iget-object v2, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOo0:Llyiahf/vczjk/rr5;

    const/4 v5, 0x0

    iget-object v6, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO0:Llyiahf/vczjk/sj9;

    iget-object v3, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO:Llyiahf/vczjk/nf6;

    const/4 v4, 0x0

    iget-boolean v7, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOO:Z

    iget-boolean v8, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOo:Z

    const/4 v1, 0x0

    invoke-virtual/range {v0 .. v8}, Llyiahf/vczjk/ra8;->o000OO(Llyiahf/vczjk/o23;Llyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;Llyiahf/vczjk/qg6;Llyiahf/vczjk/rk6;Llyiahf/vczjk/sa8;ZZ)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Landroidx/compose/foundation/gestures/ScrollableElement;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Landroidx/compose/foundation/gestures/ScrollableElement;

    iget-object v0, p1, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO0:Llyiahf/vczjk/sj9;

    iget-object v1, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO0:Llyiahf/vczjk/sj9;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO:Llyiahf/vczjk/nf6;

    iget-object v1, p1, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO:Llyiahf/vczjk/nf6;

    if-eq v0, v1, :cond_3

    goto :goto_0

    :cond_3
    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOO:Z

    iget-boolean v1, p1, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOO:Z

    if-eq v0, v1, :cond_4

    goto :goto_0

    :cond_4
    iget-boolean v0, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOo:Z

    iget-boolean v1, p1, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOo:Z

    if-eq v0, v1, :cond_5

    goto :goto_0

    :cond_5
    iget-object v0, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOo0:Llyiahf/vczjk/rr5;

    iget-object p1, p1, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOo0:Llyiahf/vczjk/rr5;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_6

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_6
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 4

    iget-object v0, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO0:Llyiahf/vczjk/sj9;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget-object v2, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOO:Llyiahf/vczjk/nf6;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    const/16 v0, 0x3c1

    mul-int/2addr v2, v0

    iget-boolean v3, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOO:Z

    invoke-static {v2, v1, v3}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v2

    iget-boolean v3, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOOo:Z

    invoke-static {v2, v0, v3}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v0

    iget-object v2, p0, Landroidx/compose/foundation/gestures/ScrollableElement;->OooOOo0:Llyiahf/vczjk/rr5;

    if-eqz v2, :cond_0

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    add-int/2addr v0, v2

    mul-int/2addr v0, v1

    return v0
.end method
