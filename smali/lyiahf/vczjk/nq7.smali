.class public final Llyiahf/vczjk/nq7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oi2;
.implements Llyiahf/vczjk/dq6;
.implements Llyiahf/vczjk/vj3;
.implements Llyiahf/vczjk/z70;
.implements Llyiahf/vczjk/hj4;


# instance fields
.field public final OooO:Llyiahf/vczjk/dy9;

.field public final OooO00o:Landroid/graphics/Matrix;

.field public final OooO0O0:Landroid/graphics/Path;

.field public final OooO0OO:Llyiahf/vczjk/v85;

.field public final OooO0Oo:Llyiahf/vczjk/f80;

.field public final OooO0o:Z

.field public final OooO0o0:Ljava/lang/String;

.field public final OooO0oO:Llyiahf/vczjk/w23;

.field public final OooO0oo:Llyiahf/vczjk/w23;

.field public OooOO0:Llyiahf/vczjk/om1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Llyiahf/vczjk/bk7;)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroid/graphics/Matrix;

    invoke-direct {v0}, Landroid/graphics/Matrix;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/nq7;->OooO00o:Landroid/graphics/Matrix;

    new-instance v0, Landroid/graphics/Path;

    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/nq7;->OooO0O0:Landroid/graphics/Path;

    iput-object p1, p0, Llyiahf/vczjk/nq7;->OooO0OO:Llyiahf/vczjk/v85;

    iput-object p2, p0, Llyiahf/vczjk/nq7;->OooO0Oo:Llyiahf/vczjk/f80;

    iget-object p1, p3, Llyiahf/vczjk/bk7;->OooO0O0:Ljava/lang/String;

    iput-object p1, p0, Llyiahf/vczjk/nq7;->OooO0o0:Ljava/lang/String;

    iget-boolean p1, p3, Llyiahf/vczjk/bk7;->OooO0Oo:Z

    iput-boolean p1, p0, Llyiahf/vczjk/nq7;->OooO0o:Z

    iget-object p1, p3, Llyiahf/vczjk/bk7;->OooO0OO:Llyiahf/vczjk/ii;

    invoke-virtual {p1}, Llyiahf/vczjk/ii;->o0000oo()Llyiahf/vczjk/w23;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nq7;->OooO0oO:Llyiahf/vczjk/w23;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    invoke-virtual {p1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    iget-object p1, p3, Llyiahf/vczjk/bk7;->OooO0o0:Llyiahf/vczjk/pi;

    check-cast p1, Llyiahf/vczjk/ii;

    invoke-virtual {p1}, Llyiahf/vczjk/ii;->o0000oo()Llyiahf/vczjk/w23;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nq7;->OooO0oo:Llyiahf/vczjk/w23;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/f80;->OooO0o0(Llyiahf/vczjk/d80;)V

    invoke-virtual {p1, p0}, Llyiahf/vczjk/d80;->OooO00o(Llyiahf/vczjk/z70;)V

    iget-object p1, p3, Llyiahf/vczjk/bk7;->OooO0o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ni;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p3, Llyiahf/vczjk/dy9;

    invoke-direct {p3, p1}, Llyiahf/vczjk/dy9;-><init>(Llyiahf/vczjk/ni;)V

    iput-object p3, p0, Llyiahf/vczjk/nq7;->OooO:Llyiahf/vczjk/dy9;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/dy9;->OooO00o(Llyiahf/vczjk/f80;)V

    invoke-virtual {p3, p0}, Llyiahf/vczjk/dy9;->OooO0O0(Llyiahf/vczjk/z70;)V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooO0OO:Llyiahf/vczjk/v85;

    invoke-virtual {v0}, Llyiahf/vczjk/v85;->invalidateSelf()V

    return-void
.end method

.method public final OooO0O0(Ljava/util/List;Ljava/util/List;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/om1;->OooO0O0(Ljava/util/List;Ljava/util/List;)V

    return-void
.end method

.method public final OooO0OO(Landroid/graphics/ColorFilter;Llyiahf/vczjk/n62;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooO:Llyiahf/vczjk/dy9;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/dy9;->OooO0OO(Landroid/graphics/ColorFilter;Llyiahf/vczjk/n62;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/c95;->OooOOOo:Ljava/lang/Float;

    if-ne p1, v0, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/nq7;->OooO0oO:Llyiahf/vczjk/w23;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/d80;->OooOO0(Llyiahf/vczjk/n62;)V

    return-void

    :cond_1
    sget-object v0, Llyiahf/vczjk/c95;->OooOOo0:Ljava/lang/Float;

    if-ne p1, v0, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/nq7;->OooO0oo:Llyiahf/vczjk/w23;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/d80;->OooOO0(Llyiahf/vczjk/n62;)V

    :cond_2
    :goto_0
    return-void
.end method

.method public final OooO0Oo(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    invoke-virtual {v0, p1, p2, p3}, Llyiahf/vczjk/om1;->OooO0Oo(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    return-void
.end method

.method public final OooO0o(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILlyiahf/vczjk/bj2;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooO0oO:Llyiahf/vczjk/w23;

    invoke-virtual {v0}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Float;

    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/nq7;->OooO0oo:Llyiahf/vczjk/w23;

    invoke-virtual {v1}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Float;

    invoke-virtual {v1}, Ljava/lang/Float;->floatValue()F

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/nq7;->OooO:Llyiahf/vczjk/dy9;

    iget-object v3, v2, Llyiahf/vczjk/dy9;->OooOOO0:Llyiahf/vczjk/d80;

    invoke-virtual {v3}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Float;

    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    move-result v3

    const/high16 v4, 0x42c80000    # 100.0f

    div-float/2addr v3, v4

    iget-object v5, v2, Llyiahf/vczjk/dy9;->OooOOO:Llyiahf/vczjk/d80;

    invoke-virtual {v5}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Float;

    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    move-result v5

    div-float/2addr v5, v4

    float-to-int v4, v0

    add-int/lit8 v4, v4, -0x1

    :goto_0
    if-ltz v4, :cond_0

    iget-object v6, p0, Llyiahf/vczjk/nq7;->OooO00o:Landroid/graphics/Matrix;

    invoke-virtual {v6, p2}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    int-to-float v7, v4

    add-float v8, v7, v1

    invoke-virtual {v2, v8}, Llyiahf/vczjk/dy9;->OooO0o(F)Landroid/graphics/Matrix;

    move-result-object v8

    invoke-virtual {v6, v8}, Landroid/graphics/Matrix;->preConcat(Landroid/graphics/Matrix;)Z

    int-to-float v8, p3

    div-float/2addr v7, v0

    invoke-static {v3, v5, v7}, Llyiahf/vczjk/pj5;->OooO0o(FFF)F

    move-result v7

    mul-float/2addr v7, v8

    iget-object v8, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    float-to-int v7, v7

    invoke-virtual {v8, p1, v6, v7, p4}, Llyiahf/vczjk/om1;->OooO0o(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILlyiahf/vczjk/bj2;)V

    add-int/lit8 v4, v4, -0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public final OooO0o0(Ljava/util/ListIterator;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    if-eqz v0, :cond_0

    return-void

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/ListIterator;->hasPrevious()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-interface {p1}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    move-result-object v0

    if-eq v0, p0, :cond_1

    goto :goto_0

    :cond_1
    new-instance v6, Ljava/util/ArrayList;

    invoke-direct {v6}, Ljava/util/ArrayList;-><init>()V

    :goto_1
    invoke-interface {p1}, Ljava/util/ListIterator;->hasPrevious()Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-interface {p1}, Ljava/util/ListIterator;->previous()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/fm1;

    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-interface {p1}, Ljava/util/ListIterator;->remove()V

    goto :goto_1

    :cond_2
    invoke-static {v6}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    new-instance v1, Llyiahf/vczjk/om1;

    iget-object v3, p0, Llyiahf/vczjk/nq7;->OooO0Oo:Llyiahf/vczjk/f80;

    const-string v4, "Repeater"

    iget-object v2, p0, Llyiahf/vczjk/nq7;->OooO0OO:Llyiahf/vczjk/v85;

    iget-boolean v5, p0, Llyiahf/vczjk/nq7;->OooO0o:Z

    const/4 v7, 0x0

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/om1;-><init>(Llyiahf/vczjk/v85;Llyiahf/vczjk/f80;Ljava/lang/String;ZLjava/util/ArrayList;Llyiahf/vczjk/ni;)V

    iput-object v1, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    return-void
.end method

.method public final OooO0oO()Landroid/graphics/Path;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    invoke-virtual {v0}, Llyiahf/vczjk/om1;->OooO0oO()Landroid/graphics/Path;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/nq7;->OooO0O0:Landroid/graphics/Path;

    invoke-virtual {v1}, Landroid/graphics/Path;->reset()V

    iget-object v2, p0, Llyiahf/vczjk/nq7;->OooO0oO:Llyiahf/vczjk/w23;

    invoke-virtual {v2}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Float;

    invoke-virtual {v2}, Ljava/lang/Float;->floatValue()F

    move-result v2

    iget-object v3, p0, Llyiahf/vczjk/nq7;->OooO0oo:Llyiahf/vczjk/w23;

    invoke-virtual {v3}, Llyiahf/vczjk/d80;->OooO0o0()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Float;

    invoke-virtual {v3}, Ljava/lang/Float;->floatValue()F

    move-result v3

    float-to-int v2, v2

    add-int/lit8 v2, v2, -0x1

    :goto_0
    if-ltz v2, :cond_0

    iget-object v4, p0, Llyiahf/vczjk/nq7;->OooO00o:Landroid/graphics/Matrix;

    int-to-float v5, v2

    add-float/2addr v5, v3

    iget-object v6, p0, Llyiahf/vczjk/nq7;->OooO:Llyiahf/vczjk/dy9;

    invoke-virtual {v6, v5}, Llyiahf/vczjk/dy9;->OooO0o(F)Landroid/graphics/Matrix;

    move-result-object v5

    invoke-virtual {v4, v5}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    invoke-virtual {v1, v0, v4}, Landroid/graphics/Path;->addPath(Landroid/graphics/Path;Landroid/graphics/Matrix;)V

    add-int/lit8 v2, v2, -0x1

    goto :goto_0

    :cond_0
    return-object v1
.end method

.method public final OooO0oo(Llyiahf/vczjk/fj4;ILjava/util/ArrayList;Llyiahf/vczjk/fj4;)V
    .locals 3

    invoke-static {p1, p2, p3, p4, p0}, Llyiahf/vczjk/pj5;->OooO0oO(Llyiahf/vczjk/fj4;ILjava/util/ArrayList;Llyiahf/vczjk/fj4;Llyiahf/vczjk/hj4;)V

    const/4 v0, 0x0

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    iget-object v1, v1, Llyiahf/vczjk/om1;->OooO:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ge v0, v1, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/nq7;->OooOO0:Llyiahf/vczjk/om1;

    iget-object v1, v1, Llyiahf/vczjk/om1;->OooO:Ljava/util/ArrayList;

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/fm1;

    instance-of v2, v1, Llyiahf/vczjk/hj4;

    if-eqz v2, :cond_0

    check-cast v1, Llyiahf/vczjk/hj4;

    invoke-static {p1, p2, p3, p4, v1}, Llyiahf/vczjk/pj5;->OooO0oO(Llyiahf/vczjk/fj4;ILjava/util/ArrayList;Llyiahf/vczjk/fj4;Llyiahf/vczjk/hj4;)V

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public final getName()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nq7;->OooO0o0:Ljava/lang/String;

    return-object v0
.end method
