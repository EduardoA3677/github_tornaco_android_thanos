.class final Landroidx/compose/foundation/layout/OffsetPxElement;
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
        "Landroidx/compose/foundation/layout/OffsetPxElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/x86;",
        "foundation-layout_release"
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
.field public final OooOOO0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->OooOOO0:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/x86;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iget-object v1, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->OooOOO0:Llyiahf/vczjk/oe3;

    iput-object v1, v0, Llyiahf/vczjk/x86;->OooOoOO:Llyiahf/vczjk/oe3;

    const/4 v1, 0x1

    iput-boolean v1, v0, Llyiahf/vczjk/x86;->OooOoo0:Z

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 4

    check-cast p1, Llyiahf/vczjk/x86;

    iget-object v0, p1, Llyiahf/vczjk/x86;->OooOoOO:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->OooOOO0:Llyiahf/vczjk/oe3;

    const/4 v2, 0x1

    if-ne v0, v1, :cond_0

    iget-boolean v0, p1, Llyiahf/vczjk/x86;->OooOoo0:Z

    if-eq v0, v2, :cond_1

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    const/4 v3, 0x0

    invoke-virtual {v0, v3}, Llyiahf/vczjk/ro4;->o000oOoO(Z)V

    :cond_1
    iput-object v1, p1, Llyiahf/vczjk/x86;->OooOoOO:Llyiahf/vczjk/oe3;

    iput-boolean v2, p1, Llyiahf/vczjk/x86;->OooOoo0:Z

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Landroidx/compose/foundation/layout/OffsetPxElement;

    if-eqz v1, :cond_1

    check-cast p1, Landroidx/compose/foundation/layout/OffsetPxElement;

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_2

    goto :goto_1

    :cond_2
    iget-object v1, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->OooOOO0:Llyiahf/vczjk/oe3;

    iget-object p1, p1, Landroidx/compose/foundation/layout/OffsetPxElement;->OooOOO0:Llyiahf/vczjk/oe3;

    if-ne v1, p1, :cond_3

    return v0

    :cond_3
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 2

    iget-object v0, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    mul-int/lit8 v0, v0, 0x1f

    const/4 v1, 0x1

    invoke-static {v1}, Ljava/lang/Boolean;->hashCode(Z)I

    move-result v1

    add-int/2addr v1, v0

    return v1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "OffsetPxModifier(offset="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Landroidx/compose/foundation/layout/OffsetPxElement;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", rtlAware=true)"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
