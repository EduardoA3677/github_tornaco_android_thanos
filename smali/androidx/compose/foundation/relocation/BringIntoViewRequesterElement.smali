.class final Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;
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
        "Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/xh0;",
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
.field public final OooOOO0:Llyiahf/vczjk/th0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/th0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;->OooOOO0:Llyiahf/vczjk/th0;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/xh0;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iget-object v1, p0, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;->OooOOO0:Llyiahf/vczjk/th0;

    iput-object v1, v0, Llyiahf/vczjk/xh0;->OooOoOO:Llyiahf/vczjk/th0;

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 2

    check-cast p1, Llyiahf/vczjk/xh0;

    iget-object v0, p1, Llyiahf/vczjk/xh0;->OooOoOO:Llyiahf/vczjk/th0;

    instance-of v1, v0, Llyiahf/vczjk/wh0;

    if-eqz v1, :cond_0

    const-string v1, "null cannot be cast to non-null type androidx.compose.foundation.relocation.BringIntoViewRequesterImpl"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v0, Llyiahf/vczjk/wh0;

    iget-object v0, v0, Llyiahf/vczjk/wh0;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ws5;->OooOO0(Ljava/lang/Object;)Z

    :cond_0
    iget-object v0, p0, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;->OooOOO0:Llyiahf/vczjk/th0;

    instance-of v1, v0, Llyiahf/vczjk/wh0;

    if-eqz v1, :cond_1

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/wh0;

    iget-object v1, v1, Llyiahf/vczjk/wh0;->OooO00o:Llyiahf/vczjk/ws5;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ws5;->OooO0O0(Ljava/lang/Object;)V

    :cond_1
    iput-object v0, p1, Llyiahf/vczjk/xh0;->OooOoOO:Llyiahf/vczjk/th0;

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-eq p0, p1, :cond_1

    instance-of v0, p1, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;

    if-eqz v0, :cond_0

    check-cast p1, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;

    iget-object p1, p1, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;->OooOOO0:Llyiahf/vczjk/th0;

    iget-object v0, p0, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;->OooOOO0:Llyiahf/vczjk/th0;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Landroidx/compose/foundation/relocation/BringIntoViewRequesterElement;->OooOOO0:Llyiahf/vczjk/th0;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method
