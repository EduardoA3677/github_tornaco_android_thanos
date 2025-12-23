.class public final Landroidx/compose/material3/internal/ChildSemanticsNodeElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0001\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/material3/internal/ChildSemanticsNodeElement;",
        "Llyiahf/vczjk/tl5;",
        "Llyiahf/vczjk/rv0;",
        "material3_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/ow;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ow;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;->OooOOO0:Llyiahf/vczjk/ow;

    return-void
.end method


# virtual methods
.method public final OooOO0()Llyiahf/vczjk/jl5;
    .locals 2

    new-instance v0, Llyiahf/vczjk/rv0;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iget-object v1, p0, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;->OooOOO0:Llyiahf/vczjk/ow;

    iput-object v1, v0, Llyiahf/vczjk/rv0;->OooOoOO:Llyiahf/vczjk/ow;

    return-object v0
.end method

.method public final OooOO0O(Llyiahf/vczjk/jl5;)V
    .locals 1

    check-cast p1, Llyiahf/vczjk/rv0;

    iget-object v0, p0, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;->OooOOO0:Llyiahf/vczjk/ow;

    iput-object v0, p1, Llyiahf/vczjk/rv0;->OooOoOO:Llyiahf/vczjk/ow;

    invoke-static {p1}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    if-ne p0, p1, :cond_0

    goto :goto_0

    :cond_0
    instance-of v0, p1, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;

    if-nez v0, :cond_1

    goto :goto_1

    :cond_1
    check-cast p1, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;

    iget-object p1, p1, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;->OooOOO0:Llyiahf/vczjk/ow;

    iget-object v0, p0, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;->OooOOO0:Llyiahf/vczjk/ow;

    if-ne v0, p1, :cond_2

    :goto_0
    const/4 p1, 0x1

    return p1

    :cond_2
    :goto_1
    const/4 p1, 0x0

    return p1
.end method

.method public final hashCode()I
    .locals 1

    iget-object v0, p0, Landroidx/compose/material3/internal/ChildSemanticsNodeElement;->OooOOO0:Llyiahf/vczjk/ow;

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0
.end method
