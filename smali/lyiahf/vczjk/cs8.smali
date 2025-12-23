.class public final Llyiahf/vczjk/cs8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ag2;


# instance fields
.field public OooO:Z

.field public final OooO00o:I

.field public final OooO0O0:Llyiahf/vczjk/m01;

.field public final OooO0OO:Llyiahf/vczjk/lr5;

.field public OooO0Oo:Llyiahf/vczjk/oe3;

.field public final OooO0o:[F

.field public final OooO0o0:Z

.field public final OooO0oO:Llyiahf/vczjk/qr5;

.field public final OooO0oo:Llyiahf/vczjk/qr5;

.field public final OooOO0:Llyiahf/vczjk/qr5;

.field public final OooOO0O:Llyiahf/vczjk/qr5;

.field public final OooOO0o:Llyiahf/vczjk/nf6;

.field public final OooOOO:Llyiahf/vczjk/ku7;

.field public final OooOOO0:Llyiahf/vczjk/qs5;

.field public final OooOOOO:Llyiahf/vczjk/lr5;

.field public final OooOOOo:Llyiahf/vczjk/lr5;

.field public final OooOOo:Llyiahf/vczjk/ht5;

.field public final OooOOo0:Llyiahf/vczjk/w8;


# direct methods
.method public constructor <init>(FILlyiahf/vczjk/m01;)V
    .locals 6

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Llyiahf/vczjk/cs8;->OooO00o:I

    iput-object p3, p0, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/cs8;->OooO0OO:Llyiahf/vczjk/lr5;

    const/4 p3, 0x1

    iput-boolean p3, p0, Llyiahf/vczjk/cs8;->OooO0o0:Z

    const/4 v0, 0x0

    if-nez p2, :cond_0

    new-array p2, v0, [F

    goto :goto_1

    :cond_0
    add-int/lit8 v1, p2, 0x2

    new-array v2, v1, [F

    move v3, v0

    :goto_0
    if-ge v3, v1, :cond_1

    int-to-float v4, v3

    add-int/lit8 v5, p2, 0x1

    int-to-float v5, v5

    div-float/2addr v4, v5

    aput v4, v2, v3

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    move-object p2, v2

    :goto_1
    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooO0o:[F

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooO0oO:Llyiahf/vczjk/qr5;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooO0oo:Llyiahf/vczjk/qr5;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooOO0:Llyiahf/vczjk/qr5;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0oO(I)Llyiahf/vczjk/qr5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooOO0O:Llyiahf/vczjk/qr5;

    sget-object p2, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooOO0o:Llyiahf/vczjk/nf6;

    sget-object p2, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooOOO0:Llyiahf/vczjk/qs5;

    new-instance p2, Llyiahf/vczjk/ku7;

    const/16 p3, 0x9

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    iput-object p2, p0, Llyiahf/vczjk/cs8;->OooOOO:Llyiahf/vczjk/ku7;

    iget-object p2, p0, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    iget p3, p2, Llyiahf/vczjk/m01;->OooO00o:F

    iget p2, p2, Llyiahf/vczjk/m01;->OooO0O0:F

    sub-float/2addr p2, p3

    const/4 v0, 0x0

    cmpg-float v1, p2, v0

    if-nez v1, :cond_2

    move p1, v0

    goto :goto_2

    :cond_2
    sub-float/2addr p1, p3

    div-float/2addr p1, p2

    :goto_2
    const/high16 p2, 0x3f800000    # 1.0f

    invoke-static {p1, v0, p2}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    invoke-static {v0, v0, p1}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result p1

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/cs8;->OooOOOO:Llyiahf/vczjk/lr5;

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/cs8;->OooOOOo:Llyiahf/vczjk/lr5;

    new-instance p1, Llyiahf/vczjk/w8;

    const/4 p2, 0x3

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/w8;-><init>(Ljava/lang/Object;I)V

    iput-object p1, p0, Llyiahf/vczjk/cs8;->OooOOo0:Llyiahf/vczjk/w8;

    new-instance p1, Llyiahf/vczjk/ht5;

    invoke-direct {p1}, Llyiahf/vczjk/ht5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cs8;->OooOOo:Llyiahf/vczjk/ht5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/wf2;Llyiahf/vczjk/jf2;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/at5;->OooOOO:Llyiahf/vczjk/at5;

    new-instance v1, Llyiahf/vczjk/bs8;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v0, p1, v2}, Llyiahf/vczjk/bs8;-><init>(Llyiahf/vczjk/cs8;Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0O0(F)V
    .locals 6

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    iget-object v1, p0, Llyiahf/vczjk/cs8;->OooOO0o:Llyiahf/vczjk/nf6;

    const/4 v2, 0x0

    const/high16 v3, 0x40000000    # 2.0f

    if-ne v1, v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/cs8;->OooO0oo:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    int-to-float v0, v0

    iget-object v1, p0, Llyiahf/vczjk/cs8;->OooOO0O:Llyiahf/vczjk/qr5;

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/bw8;

    invoke-virtual {v4}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v4

    int-to-float v4, v4

    div-float/2addr v4, v3

    sub-float/2addr v0, v4

    invoke-static {v0, v2}, Ljava/lang/Math;->max(FF)F

    move-result v0

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    int-to-float v1, v1

    div-float/2addr v1, v3

    invoke-static {v1, v0}, Ljava/lang/Math;->min(FF)F

    move-result v1

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/cs8;->OooO0oO:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v0

    int-to-float v0, v0

    iget-object v1, p0, Llyiahf/vczjk/cs8;->OooOO0:Llyiahf/vczjk/qr5;

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/bw8;

    invoke-virtual {v4}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v4

    int-to-float v4, v4

    div-float/2addr v4, v3

    sub-float/2addr v0, v4

    invoke-static {v0, v2}, Ljava/lang/Math;->max(FF)F

    move-result v0

    check-cast v1, Llyiahf/vczjk/bw8;

    invoke-virtual {v1}, Llyiahf/vczjk/bw8;->OooOOoo()I

    move-result v1

    int-to-float v1, v1

    div-float/2addr v1, v3

    invoke-static {v1, v0}, Ljava/lang/Math;->min(FF)F

    move-result v1

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/cs8;->OooOOOO:Llyiahf/vczjk/lr5;

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/zv8;

    invoke-virtual {v4}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v4

    add-float/2addr v4, p1

    iget-object p1, p0, Llyiahf/vczjk/cs8;->OooOOOo:Llyiahf/vczjk/lr5;

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/zv8;

    invoke-virtual {v5}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v5

    add-float/2addr v5, v4

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/zv8;

    invoke-virtual {v4, v5}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    check-cast v3, Llyiahf/vczjk/zv8;

    invoke-virtual {v3}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result p1

    iget-object v3, p0, Llyiahf/vczjk/cs8;->OooO0o:[F

    invoke-static {p1, v1, v0, v3}, Llyiahf/vczjk/as8;->OooO0o0(FFF[F)F

    move-result p1

    iget-object v3, p0, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    iget v4, v3, Llyiahf/vczjk/m01;->OooO00o:F

    sub-float/2addr v0, v1

    cmpg-float v5, v0, v2

    if-nez v5, :cond_1

    move p1, v2

    goto :goto_1

    :cond_1
    sub-float/2addr p1, v1

    div-float/2addr p1, v0

    :goto_1
    const/high16 v0, 0x3f800000    # 1.0f

    invoke-static {p1, v2, v0}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    iget v0, v3, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-static {v4, v0, p1}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result p1

    invoke-virtual {p0}, Llyiahf/vczjk/cs8;->OooO0Oo()F

    move-result v0

    cmpg-float v0, p1, v0

    if-nez v0, :cond_2

    return-void

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/cs8;->OooO0Oo:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_3

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :cond_3
    invoke-virtual {p0, p1}, Llyiahf/vczjk/cs8;->OooO0o0(F)V

    return-void
.end method

.method public final OooO0OO()F
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    iget v1, v0, Llyiahf/vczjk/m01;->OooO00o:F

    iget v2, v0, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-virtual {p0}, Llyiahf/vczjk/cs8;->OooO0Oo()F

    move-result v3

    iget v4, v0, Llyiahf/vczjk/m01;->OooO00o:F

    iget v0, v0, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-static {v3, v4, v0}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v0

    sub-float/2addr v2, v1

    const/4 v3, 0x0

    cmpg-float v4, v2, v3

    if-nez v4, :cond_0

    move v0, v3

    goto :goto_0

    :cond_0
    sub-float/2addr v0, v1

    div-float/2addr v0, v2

    :goto_0
    const/high16 v1, 0x3f800000    # 1.0f

    invoke-static {v0, v3, v1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v0

    return v0
.end method

.method public final OooO0Oo()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/cs8;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    return v0
.end method

.method public final OooO0o0(F)V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/cs8;->OooO0o0:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    iget v1, v0, Llyiahf/vczjk/m01;->OooO00o:F

    iget v2, v0, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    iget-object v1, p0, Llyiahf/vczjk/cs8;->OooO0o:[F

    iget v0, v0, Llyiahf/vczjk/m01;->OooO00o:F

    invoke-static {p1, v0, v2, v1}, Llyiahf/vczjk/as8;->OooO0o0(FFF[F)F

    move-result p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/cs8;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-void
.end method
