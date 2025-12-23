.class abstract Landroidx/compose/material3/internal/BaseLinearWavyProgressElement;
.super Llyiahf/vczjk/tl5;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<N:",
        "Llyiahf/vczjk/i80;",
        ">",
        "Llyiahf/vczjk/tl5;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u0008\"\u0018\u0000*\u0008\u0008\u0000\u0010\u0002*\u00020\u00012\u0008\u0012\u0004\u0012\u00028\u00000\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Landroidx/compose/material3/internal/BaseLinearWavyProgressElement;",
        "Llyiahf/vczjk/i80;",
        "N",
        "Llyiahf/vczjk/tl5;",
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


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 5

    if-ne p0, p1, :cond_0

    goto :goto_1

    :cond_0
    instance-of v0, p1, Landroidx/compose/material3/internal/BaseLinearWavyProgressElement;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    move-object v0, p0

    check-cast v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;

    check-cast p1, Landroidx/compose/material3/internal/BaseLinearWavyProgressElement;

    check-cast p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;

    iget-wide v1, p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOo0:J

    iget-wide v3, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOo0:J

    invoke-static {v3, v4, v1, v2}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v1

    if-nez v1, :cond_2

    goto :goto_0

    :cond_2
    iget-wide v1, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOo:J

    iget-wide v3, p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOo:J

    invoke-static {v1, v2, v3, v4}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v1

    if-nez v1, :cond_3

    goto :goto_0

    :cond_3
    iget-object v1, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOoo:Llyiahf/vczjk/h79;

    iget-object v2, p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOoo:Llyiahf/vczjk/h79;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_4

    goto :goto_0

    :cond_4
    iget-object v1, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo00:Llyiahf/vczjk/h79;

    iget-object v2, p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo00:Llyiahf/vczjk/h79;

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_5

    goto :goto_0

    :cond_5
    iget v1, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0:F

    iget v2, p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0:F

    invoke-static {v1, v2}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v1

    if-nez v1, :cond_6

    goto :goto_0

    :cond_6
    iget v1, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0O:F

    iget v2, p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0O:F

    invoke-static {v1, v2}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result v1

    if-nez v1, :cond_7

    goto :goto_0

    :cond_7
    iget v0, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0o:F

    iget p1, p1, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0o:F

    invoke-static {v0, p1}, Llyiahf/vczjk/wd2;->OooO00o(FF)Z

    move-result p1

    if-nez p1, :cond_8

    :goto_0
    const/4 p1, 0x0

    return p1

    :cond_8
    :goto_1
    const/4 p1, 0x1

    return p1
.end method

.method public hashCode()I
    .locals 5

    move-object v0, p0

    check-cast v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;

    sget v1, Llyiahf/vczjk/n21;->OooOO0O:I

    iget-wide v1, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOo0:J

    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    move-result v1

    const/16 v2, 0x1f

    mul-int/2addr v1, v2

    iget-wide v3, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOo:J

    invoke-static {v1, v2, v3, v4}, Llyiahf/vczjk/ii5;->OooO0OO(IIJ)I

    move-result v1

    iget-object v3, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOOoo:Llyiahf/vczjk/h79;

    invoke-virtual {v3}, Llyiahf/vczjk/h79;->hashCode()I

    move-result v3

    add-int/2addr v3, v1

    mul-int/2addr v3, v2

    iget-object v1, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo00:Llyiahf/vczjk/h79;

    invoke-virtual {v1}, Llyiahf/vczjk/h79;->hashCode()I

    move-result v1

    add-int/2addr v1, v3

    mul-int/2addr v1, v2

    iget v3, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0:F

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v1

    iget v3, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0O:F

    invoke-static {v1, v3, v2}, Llyiahf/vczjk/u81;->OooO0OO(IFI)I

    move-result v1

    iget v0, v0, Landroidx/compose/material3/internal/IndeterminateLinearWavyProgressElement;->OooOo0o:F

    invoke-static {v0}, Ljava/lang/Float;->hashCode(F)I

    move-result v0

    add-int/2addr v0, v1

    return v0
.end method
