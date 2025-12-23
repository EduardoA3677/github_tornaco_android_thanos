.class final Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;
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
        "Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/ns4;",
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
.field public final OooOOO:Llyiahf/vczjk/vz5;

.field public final OooOOO0:Llyiahf/vczjk/os4;

.field public final OooOOOO:Z

.field public final OooOOOo:Llyiahf/vczjk/nf6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/os4;Llyiahf/vczjk/vz5;ZLlyiahf/vczjk/nf6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO0:Llyiahf/vczjk/os4;

    iput-object p2, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO:Llyiahf/vczjk/vz5;

    iput-boolean p3, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOO:Z

    iput-object p4, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOo:Llyiahf/vczjk/nf6;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/ns4;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO0:Llyiahf/vczjk/os4;

    iput-object v1, v0, Llyiahf/vczjk/ns4;->OooOoOO:Llyiahf/vczjk/os4;

    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO:Llyiahf/vczjk/vz5;

    iput-object v1, v0, Llyiahf/vczjk/ns4;->OooOoo0:Llyiahf/vczjk/vz5;

    iget-boolean v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOO:Z

    iput-boolean v1, v0, Llyiahf/vczjk/ns4;->OooOoo:Z

    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOo:Llyiahf/vczjk/nf6;

    iput-object v1, v0, Llyiahf/vczjk/ns4;->OooOooO:Llyiahf/vczjk/nf6;

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 1

    check-cast p1, Llyiahf/vczjk/ns4;

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO0:Llyiahf/vczjk/os4;

    iput-object v0, p1, Llyiahf/vczjk/ns4;->OooOoOO:Llyiahf/vczjk/os4;

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO:Llyiahf/vczjk/vz5;

    iput-object v0, p1, Llyiahf/vczjk/ns4;->OooOoo0:Llyiahf/vczjk/vz5;

    iget-boolean v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOO:Z

    iput-boolean v0, p1, Llyiahf/vczjk/ns4;->OooOoo:Z

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOo:Llyiahf/vczjk/nf6;

    iput-object v0, p1, Llyiahf/vczjk/ns4;->OooOooO:Llyiahf/vczjk/nf6;

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;

    iget-object v1, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO0:Llyiahf/vczjk/os4;

    iget-object v3, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO0:Llyiahf/vczjk/os4;

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    return v2

    :cond_2
    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO:Llyiahf/vczjk/vz5;

    iget-object v3, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO:Llyiahf/vczjk/vz5;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    return v2

    :cond_3
    iget-boolean v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOO:Z

    iget-boolean v3, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOO:Z

    if-eq v1, v3, :cond_4

    return v2

    :cond_4
    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOo:Llyiahf/vczjk/nf6;

    iget-object p1, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOo:Llyiahf/vczjk/nf6;

    if-eq v1, p1, :cond_5

    return v2

    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO0:Llyiahf/vczjk/os4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget-object v2, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOO:Llyiahf/vczjk/vz5;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    mul-int/2addr v2, v1

    iget-boolean v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOO:Z

    invoke-static {v2, v1, v0}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v0

    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutBeyondBoundsModifierElement;->OooOOOo:Llyiahf/vczjk/nf6;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
