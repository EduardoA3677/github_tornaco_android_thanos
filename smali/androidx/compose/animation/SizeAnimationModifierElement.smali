.class final Landroidx/compose/animation/SizeAnimationModifierElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0082\u0008\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/animation/SizeAnimationModifierElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/xq8;",
        "animation_release"
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
.field public final OooOOO0:Llyiahf/vczjk/wz8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wz8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/animation/SizeAnimationModifierElement;->OooOOO0:Llyiahf/vczjk/wz8;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/xq8;

    iget-object v1, p0, Landroidx/compose/animation/SizeAnimationModifierElement;->OooOOO0:Llyiahf/vczjk/wz8;

    invoke-direct {v0, v1}, Llyiahf/vczjk/xq8;-><init>(Llyiahf/vczjk/wz8;)V

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 1

    check-cast p1, Llyiahf/vczjk/xq8;

    iget-object v0, p0, Landroidx/compose/animation/SizeAnimationModifierElement;->OooOOO0:Llyiahf/vczjk/wz8;

    iput-object v0, p1, Llyiahf/vczjk/xq8;->OooOoOO:Llyiahf/vczjk/wz8;

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Landroidx/compose/animation/SizeAnimationModifierElement;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Landroidx/compose/animation/SizeAnimationModifierElement;

    iget-object p1, p1, Landroidx/compose/animation/SizeAnimationModifierElement;->OooOOO0:Llyiahf/vczjk/wz8;

    iget-object v0, p0, Landroidx/compose/animation/SizeAnimationModifierElement;->OooOOO0:Llyiahf/vczjk/wz8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wz8;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_2

    goto :goto_0

    :cond_2
    sget-object p1, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {p1, p1}, Llyiahf/vczjk/ub0;->equals(Ljava/lang/Object;)Z

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

    iget-object v0, p0, Landroidx/compose/animation/SizeAnimationModifierElement;->OooOOO0:Llyiahf/vczjk/wz8;

    invoke-virtual {v0}, Llyiahf/vczjk/wz8;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    const/high16 v1, -0x40800000    # -1.0f

    invoke-static {v1}, Ljava/lang/Float;->hashCode(F)I

    move-result v2

    mul-int/lit8 v2, v2, 0x1f

    invoke-static {v1}, Ljava/lang/Float;->hashCode(F)I

    move-result v1

    add-int/2addr v1, v2

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "SizeAnimationModifierElement(animationSpec="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Landroidx/compose/animation/SizeAnimationModifierElement;->OooOOO0:Llyiahf/vczjk/wz8;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", alignment="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    sget-object v1, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", finishedListener=null)"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
