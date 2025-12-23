.class final Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;
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
        "Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/cx4;",
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
.field public final OooOOO:Llyiahf/vczjk/lx4;

.field public final OooOOO0:Llyiahf/vczjk/fx4;

.field public final OooOOOO:Llyiahf/vczjk/mk9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fx4;Llyiahf/vczjk/lx4;Llyiahf/vczjk/mk9;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO0:Llyiahf/vczjk/fx4;

    iput-object p2, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO:Llyiahf/vczjk/lx4;

    iput-object p3, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOOO:Llyiahf/vczjk/mk9;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 4

    new-instance v0, Llyiahf/vczjk/cx4;

    iget-object v1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOOO:Llyiahf/vczjk/mk9;

    iget-object v2, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO:Llyiahf/vczjk/lx4;

    iget-object v3, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO0:Llyiahf/vczjk/fx4;

    invoke-direct {v0, v3, v2, v1}, Llyiahf/vczjk/cx4;-><init>(Llyiahf/vczjk/fx4;Llyiahf/vczjk/lx4;Llyiahf/vczjk/mk9;)V

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 2

    check-cast p1, Llyiahf/vczjk/cx4;

    iget-boolean v0, p1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_0

    iget-object v0, p1, Llyiahf/vczjk/cx4;->OooOoOO:Llyiahf/vczjk/fx4;

    check-cast v0, Llyiahf/vczjk/td;

    invoke-virtual {v0}, Llyiahf/vczjk/td;->OooO0o()V

    iget-object v0, p1, Llyiahf/vczjk/cx4;->OooOoOO:Llyiahf/vczjk/fx4;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fx4;->OooO(Llyiahf/vczjk/cx4;)V

    :cond_0
    iget-object v0, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO0:Llyiahf/vczjk/fx4;

    iput-object v0, p1, Llyiahf/vczjk/cx4;->OooOoOO:Llyiahf/vczjk/fx4;

    iget-boolean v1, p1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v1, :cond_2

    iget-object v1, v0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    const-string v1, "Expected textInputModifierNode to be null"

    invoke-static {v1}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :goto_0
    iput-object p1, v0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    :cond_2
    iget-object v0, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO:Llyiahf/vczjk/lx4;

    iput-object v0, p1, Llyiahf/vczjk/cx4;->OooOoo0:Llyiahf/vczjk/lx4;

    iget-object v0, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOOO:Llyiahf/vczjk/mk9;

    iput-object v0, p1, Llyiahf/vczjk/cx4;->OooOoo:Llyiahf/vczjk/mk9;

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;

    iget-object v1, p1, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO0:Llyiahf/vczjk/fx4;

    iget-object v3, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO0:Llyiahf/vczjk/fx4;

    invoke-static {v3, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_2

    return v2

    :cond_2
    iget-object v1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO:Llyiahf/vczjk/lx4;

    iget-object v3, p1, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO:Llyiahf/vczjk/lx4;

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    return v2

    :cond_3
    iget-object v1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOOO:Llyiahf/vczjk/mk9;

    iget-object p1, p1, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOOO:Llyiahf/vczjk/mk9;

    invoke-static {v1, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_4

    return v2

    :cond_4
    return v0
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO0:Llyiahf/vczjk/fx4;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    iget-object v1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO:Llyiahf/vczjk/lx4;

    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    move-result v1

    add-int/2addr v1, v0

    mul-int/lit8 v1, v1, 0x1f

    iget-object v0, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOOO:Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "LegacyAdaptingPlatformTextInputModifier(serviceAdapter="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO0:Llyiahf/vczjk/fx4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", legacyTextFieldState="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOO:Llyiahf/vczjk/lx4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", textFieldSelectionManager="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Landroidx/compose/foundation/text/input/internal/LegacyAdaptingPlatformTextInputModifier;->OooOOOO:Llyiahf/vczjk/mk9;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
