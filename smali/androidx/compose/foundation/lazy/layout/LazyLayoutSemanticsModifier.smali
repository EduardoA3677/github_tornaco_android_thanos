.class final Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;
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
        "Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/zu4;",
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
.field public final OooOOO:Llyiahf/vczjk/ru4;

.field public final OooOOO0:Llyiahf/vczjk/hh4;

.field public final OooOOOO:Llyiahf/vczjk/nf6;

.field public final OooOOOo:Z

.field public final OooOOo0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hh4;Llyiahf/vczjk/ru4;Llyiahf/vczjk/nf6;ZZ)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO0:Llyiahf/vczjk/hh4;

    iput-object p2, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO:Llyiahf/vczjk/ru4;

    iput-object p3, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOO:Llyiahf/vczjk/nf6;

    iput-boolean p4, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOo:Z

    iput-boolean p5, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOo0:Z

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 6

    new-instance v0, Llyiahf/vczjk/zu4;

    iget-boolean v4, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOo:Z

    iget-boolean v5, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOo0:Z

    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO0:Llyiahf/vczjk/hh4;

    iget-object v2, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO:Llyiahf/vczjk/ru4;

    iget-object v3, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOO:Llyiahf/vczjk/nf6;

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/zu4;-><init>(Llyiahf/vczjk/hh4;Llyiahf/vczjk/ru4;Llyiahf/vczjk/nf6;ZZ)V

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 3

    check-cast p1, Llyiahf/vczjk/zu4;

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO0:Llyiahf/vczjk/hh4;

    iput-object v0, p1, Llyiahf/vczjk/zu4;->OooOoOO:Llyiahf/vczjk/hh4;

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO:Llyiahf/vczjk/ru4;

    iput-object v0, p1, Llyiahf/vczjk/zu4;->OooOoo0:Llyiahf/vczjk/ru4;

    iget-object v0, p1, Llyiahf/vczjk/zu4;->OooOoo:Llyiahf/vczjk/nf6;

    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOO:Llyiahf/vczjk/nf6;

    if-eq v0, v1, :cond_0

    iput-object v1, p1, Llyiahf/vczjk/zu4;->OooOoo:Llyiahf/vczjk/nf6;

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    :cond_0
    iget-boolean v0, p1, Llyiahf/vczjk/zu4;->OooOooO:Z

    iget-boolean v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOo:Z

    iget-boolean v2, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOo0:Z

    if-ne v0, v1, :cond_2

    iget-boolean v0, p1, Llyiahf/vczjk/zu4;->OooOooo:Z

    if-eq v0, v2, :cond_1

    goto :goto_0

    :cond_1
    return-void

    :cond_2
    :goto_0
    iput-boolean v1, p1, Llyiahf/vczjk/zu4;->OooOooO:Z

    iput-boolean v2, p1, Llyiahf/vczjk/zu4;->OooOooo:Z

    invoke-virtual {p1}, Llyiahf/vczjk/zu4;->o00000OO()V

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;

    iget-object v0, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO0:Llyiahf/vczjk/hh4;

    iget-object v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO0:Llyiahf/vczjk/hh4;

    if-eq v1, v0, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO:Llyiahf/vczjk/ru4;

    iget-object v1, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO:Llyiahf/vczjk/ru4;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_0

    :cond_3
    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOO:Llyiahf/vczjk/nf6;

    iget-object v1, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOO:Llyiahf/vczjk/nf6;

    if-eq v0, v1, :cond_4

    goto :goto_0

    :cond_4
    iget-boolean v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOo:Z

    iget-boolean v1, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOo:Z

    if-eq v0, v1, :cond_5

    goto :goto_0

    :cond_5
    iget-boolean v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOo0:Z

    iget-boolean p1, p1, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOo0:Z

    if-eq v0, p1, :cond_6

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_6
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 3

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO0:Llyiahf/vczjk/hh4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    iget-object v2, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOO:Llyiahf/vczjk/ru4;

    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    move-result v2

    add-int/2addr v2, v0

    mul-int/2addr v2, v1

    iget-object v0, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOO:Llyiahf/vczjk/nf6;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v2

    mul-int/2addr v0, v1

    iget-boolean v2, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOOo:Z

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v0

    iget-boolean v1, p0, Landroidx/compose/foundation/lazy/layout/LazyLayoutSemanticsModifier;->OooOOo0:Z

    invoke-static {v1}, Ljava/lang/Boolean;->hashCode(Z)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method
