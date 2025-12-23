.class public final Llyiahf/vczjk/i79;
.super Llyiahf/vczjk/y80;
.source "SourceFile"


# instance fields
.field public final OooOOo:Ljava/lang/String;

.field public final OooOOo0:Llyiahf/vczjk/f80;

.field public final OooOOoo:Z

.field public OooOo0:Llyiahf/vczjk/bca;

.field public final OooOo00:Llyiahf/vczjk/q21;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Llyiahf/vczjk/qk8;)V
    .locals 12

    iget v0, p3, Llyiahf/vczjk/qk8;->OooO0oO:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    if-eq v0, v1, :cond_0

    sget-object v0, Landroid/graphics/Paint$Cap;->SQUARE:Landroid/graphics/Paint$Cap;

    :goto_0
    move-object v5, v0

    goto :goto_1

    :cond_0
    sget-object v0, Landroid/graphics/Paint$Cap;->ROUND:Landroid/graphics/Paint$Cap;

    goto :goto_0

    :cond_1
    sget-object v0, Landroid/graphics/Paint$Cap;->BUTT:Landroid/graphics/Paint$Cap;

    goto :goto_0

    :goto_1
    iget v0, p3, Llyiahf/vczjk/qk8;->OooO0oo:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    if-eqz v0, :cond_4

    if-eq v0, v1, :cond_3

    const/4 v1, 0x2

    if-eq v0, v1, :cond_2

    const/4 v0, 0x0

    :goto_2
    move-object v6, v0

    goto :goto_3

    :cond_2
    sget-object v0, Landroid/graphics/Paint$Join;->BEVEL:Landroid/graphics/Paint$Join;

    goto :goto_2

    :cond_3
    sget-object v0, Landroid/graphics/Paint$Join;->ROUND:Landroid/graphics/Paint$Join;

    goto :goto_2

    :cond_4
    sget-object v0, Landroid/graphics/Paint$Join;->MITER:Landroid/graphics/Paint$Join;

    goto :goto_2

    :goto_3
    iget-object v8, p3, Llyiahf/vczjk/qk8;->OooO0o0:Llyiahf/vczjk/hi;

    iget-object v10, p3, Llyiahf/vczjk/qk8;->OooO0OO:Ljava/util/ArrayList;

    iget-object v11, p3, Llyiahf/vczjk/qk8;->OooO0O0:Llyiahf/vczjk/ii;

    iget v7, p3, Llyiahf/vczjk/qk8;->OooO:F

    iget-object v9, p3, Llyiahf/vczjk/qk8;->OooO0o:Llyiahf/vczjk/ii;

    move-object v2, p0

    move-object v3, p1

    move-object v4, p2

    invoke-direct/range {v2 .. v11}, Llyiahf/vczjk/y80;-><init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Landroid/graphics/Paint$Cap;Landroid/graphics/Paint$Join;FLlyiahf/vczjk/hi;Llyiahf/vczjk/ii;Ljava/util/ArrayList;Llyiahf/vczjk/ii;)V

    iput-object v4, v2, Llyiahf/vczjk/i79;->OooOOo0:Llyiahf/vczjk/f80;

    iget-object p1, p3, Llyiahf/vczjk/qk8;->OooO00o:Ljava/lang/String;

    iput-object p1, v2, Llyiahf/vczjk/i79;->OooOOo:Ljava/lang/String;

    iget-boolean p1, p3, Llyiahf/vczjk/qk8;->OooOO0:Z

    iput-boolean p1, v2, Llyiahf/vczjk/i79;->OooOOoo:Z

    iget-object p1, p3, Llyiahf/vczjk/qk8;->OooO0Oo:Llyiahf/vczjk/hi;

    invoke-virtual {p1}, Llyiahf/vczjk/hi;->o0OOO0o()Llyiahf/vczjk/d80;

    move-result-object p1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/q21;

    iput-object p2, v2, Llyiahf/vczjk/i79;->OooOo00:Llyiahf/vczjk/q21;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-virtual {v4, p1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    return-void
.end method


# virtual methods
.method public final OooO0OO(Landroid/graphics/ColorFilter;Llyiahf/vczjk/n62;)V
    .locals 3

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/y80;->OooO0OO(Landroid/graphics/ColorFilter;Llyiahf/vczjk/n62;)V

    sget-object v0, Llyiahf/vczjk/c95;->OooO00o:Landroid/graphics/PointF;

    const/4 v0, 0x2

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/i79;->OooOo00:Llyiahf/vczjk/q21;

    if-ne p1, v0, :cond_0

    invoke-virtual {v1, p2}, Llyiahf/vczjk/d80;->OooOO0(Llyiahf/vczjk/n62;)V

    return-void

    :cond_0
    sget-object v0, Llyiahf/vczjk/c95;->Oooo000:Landroid/graphics/ColorFilter;

    if-ne p1, v0, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/i79;->OooOo0:Llyiahf/vczjk/bca;

    iget-object v0, p0, Llyiahf/vczjk/i79;->OooOOo0:Llyiahf/vczjk/f80;

    if-eqz p1, :cond_1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/f80;->OooOOOO(Llyiahf/vczjk/d80;)V

    :cond_1
    new-instance p1, Llyiahf/vczjk/bca;

    const/4 v2, 0x0

    invoke-direct {p1, p2, v2}, Llyiahf/vczjk/bca;-><init>(Llyiahf/vczjk/n62;Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/i79;->OooOo0:Llyiahf/vczjk/bca;

    invoke-virtual {p1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    :cond_2
    return-void
.end method

.method public final OooO0o(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILlyiahf/vczjk/bj2;)V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/i79;->OooOOoo:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/i79;->OooOo00:Llyiahf/vczjk/q21;

    iget-object v1, v0, Llyiahf/vczjk/d80;->OooO0OO:Llyiahf/vczjk/a80;

    invoke-interface {v1}, Llyiahf/vczjk/a80;->OooO0O0()Llyiahf/vczjk/pj4;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/d80;->OooO0OO()F

    move-result v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/q21;->OooOO0o(Llyiahf/vczjk/pj4;F)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/y80;->OooO:Llyiahf/vczjk/jl4;

    invoke-virtual {v1, v0}, Landroid/graphics/Paint;->setColor(I)V

    iget-object v0, p0, Llyiahf/vczjk/i79;->OooOo0:Llyiahf/vczjk/bca;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/bca;->OooO0o0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/graphics/ColorFilter;

    invoke-virtual {v1, v0}, Landroid/graphics/Paint;->setColorFilter(Landroid/graphics/ColorFilter;)Landroid/graphics/ColorFilter;

    :cond_1
    invoke-super {p0, p1, p2, p3, p4}, Llyiahf/vczjk/y80;->OooO0o(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILlyiahf/vczjk/bj2;)V

    return-void
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/i79;->OooOOo:Ljava/lang/String;

    return-object v0
.end method
