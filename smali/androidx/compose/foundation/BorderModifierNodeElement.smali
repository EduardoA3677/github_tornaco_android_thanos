.class public final Landroidx/compose/foundation/BorderModifierNodeElement;
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
        "Landroidx/compose/foundation/BorderModifierNodeElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/re0;",
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
.field public final OooOOO:Llyiahf/vczjk/gx8;

.field public final OooOOO0:F

.field public final OooOOOO:Llyiahf/vczjk/qj8;


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/gx8;Llyiahf/vczjk/qj8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO0:F

    iput-object p2, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO:Llyiahf/vczjk/gx8;

    iput-object p3, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOOO:Llyiahf/vczjk/qj8;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 4

    new-instance v0, Llyiahf/vczjk/re0;

    iget-object v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO:Llyiahf/vczjk/gx8;

    iget-object v2, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOOO:Llyiahf/vczjk/qj8;

    iget v3, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO0:F

    invoke-direct {v0, v3, v1, v2}, Llyiahf/vczjk/re0;-><init>(FLlyiahf/vczjk/gx8;Llyiahf/vczjk/qj8;)V

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 3

    check-cast p1, Llyiahf/vczjk/re0;

    iget v0, p1, Llyiahf/vczjk/re0;->OooOooO:F

    iget v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO0:F

    invoke-static {v0, v1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    iget-object v2, p1, Llyiahf/vczjk/re0;->Oooo00O:Llyiahf/vczjk/rm0;

    if-nez v0, :cond_0

    iput v1, p1, Llyiahf/vczjk/re0;->OooOooO:F

    invoke-virtual {v2}, Llyiahf/vczjk/rm0;->o00000OO()V

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/re0;->OooOooo:Llyiahf/vczjk/gx8;

    iget-object v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO:Llyiahf/vczjk/gx8;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    iput-object v1, p1, Llyiahf/vczjk/re0;->OooOooo:Llyiahf/vczjk/gx8;

    invoke-virtual {v2}, Llyiahf/vczjk/rm0;->o00000OO()V

    :cond_1
    iget-object v0, p1, Llyiahf/vczjk/re0;->Oooo000:Llyiahf/vczjk/qj8;

    iget-object v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOOO:Llyiahf/vczjk/qj8;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_2

    iput-object v1, p1, Llyiahf/vczjk/re0;->Oooo000:Llyiahf/vczjk/qj8;

    invoke-virtual {v2}, Llyiahf/vczjk/rm0;->o00000OO()V

    :cond_2
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Landroidx/compose/foundation/BorderModifierNodeElement;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    check-cast p1, Landroidx/compose/foundation/BorderModifierNodeElement;

    iget v0, p1, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO0:F

    iget v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO0:F

    invoke-static {v1, v0}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO:Llyiahf/vczjk/gx8;

    iget-object v1, p1, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO:Llyiahf/vczjk/gx8;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/gx8;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_3

    goto :goto_0

    :cond_3
    iget-object v0, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOOO:Llyiahf/vczjk/qj8;

    iget-object p1, p1, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOOO:Llyiahf/vczjk/qj8;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_4

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_4
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget v0, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO0:F

    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO:Llyiahf/vczjk/gx8;

    invoke-virtual {v1}, Llyiahf/vczjk/gx8;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    iget-object v0, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOOO:Llyiahf/vczjk/qj8;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "BorderModifierNodeElement(width="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO0:F

    const-string v2, ", brush="

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/ix8;->OooOOo(FLjava/lang/StringBuilder;Ljava/lang/String;)V

    iget-object v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOO:Llyiahf/vczjk/gx8;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", shape="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/compose/foundation/BorderModifierNodeElement;->OooOOOO:Llyiahf/vczjk/qj8;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
