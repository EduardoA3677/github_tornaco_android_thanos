.class public final Llyiahf/vczjk/hy9;
.super Llyiahf/vczjk/mi;
.source "SourceFile"


# virtual methods
.method public final Oooo00O()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/mi;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/graphics/Matrix;

    invoke-virtual {v0}, Landroid/graphics/Matrix;->reset()V

    iget-object v1, p0, Llyiahf/vczjk/mi;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/eia;

    iget-object v2, v1, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    iget v2, v2, Landroid/graphics/RectF;->left:F

    iget v3, v1, Llyiahf/vczjk/eia;->OooO0Oo:F

    invoke-virtual {v1}, Llyiahf/vczjk/eia;->OooO0O0()F

    move-result v1

    sub-float/2addr v3, v1

    invoke-virtual {v0, v2, v3}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    return-void
.end method
