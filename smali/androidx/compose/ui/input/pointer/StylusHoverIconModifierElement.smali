.class public final Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0080\u0008\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/p79;",
        "ui_release"
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
.field public final OooOOO0:Llyiahf/vczjk/be2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/be2;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;->OooOOO0:Llyiahf/vczjk/be2;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 3

    new-instance v0, Llyiahf/vczjk/p79;

    sget-object v1, Llyiahf/vczjk/so8;->OooO0o0:Llyiahf/vczjk/bf;

    iget-object v2, p0, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;->OooOOO0:Llyiahf/vczjk/be2;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/vo3;-><init>(Llyiahf/vczjk/bf;Llyiahf/vczjk/be2;)V

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 2

    check-cast p1, Llyiahf/vczjk/p79;

    sget-object v0, Llyiahf/vczjk/so8;->OooO0o0:Llyiahf/vczjk/bf;

    iget-object v1, p1, Llyiahf/vczjk/vo3;->OooOoo0:Llyiahf/vczjk/bf;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_0

    iput-object v0, p1, Llyiahf/vczjk/vo3;->OooOoo0:Llyiahf/vczjk/bf;

    iget-boolean v0, p1, Llyiahf/vczjk/vo3;->OooOoo:Z

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/vo3;->o00000o0()V

    :cond_0
    iget-object v0, p0, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;->OooOOO0:Llyiahf/vczjk/be2;

    iput-object v0, p1, Llyiahf/vczjk/vo3;->OooOoOO:Llyiahf/vczjk/be2;

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/so8;->OooO0o0:Llyiahf/vczjk/bf;

    invoke-virtual {v0, v0}, Llyiahf/vczjk/bf;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;->OooOOO0:Llyiahf/vczjk/be2;

    iget-object p1, p1, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;->OooOOO0:Llyiahf/vczjk/be2;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_3

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_3
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 3

    const/16 v0, 0x3fe

    const/16 v1, 0x1f

    mul-int/2addr v0, v1

    const/4 v2, 0x0

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/q99;->OooO0O0(IIZ)I

    move-result v0

    iget-object v1, p0, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;->OooOOO0:Llyiahf/vczjk/be2;

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Llyiahf/vczjk/be2;->hashCode()I

    move-result v2

    :goto_0
    add-int/2addr v0, v2

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "StylusHoverIconModifierElement(icon="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    sget-object v1, Llyiahf/vczjk/so8;->OooO0o0:Llyiahf/vczjk/bf;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", overrideDescendants=false, touchBoundsExpansion="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;->OooOOO0:Llyiahf/vczjk/be2;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
