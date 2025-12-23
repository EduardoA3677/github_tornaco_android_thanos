.class public abstract Llyiahf/vczjk/nh;
.super Landroid/view/ViewGroup;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qz5;
.implements Llyiahf/vczjk/ce1;
.implements Llyiahf/vczjk/ug6;
.implements Llyiahf/vczjk/u96;


# instance fields
.field public final OooOOO:Landroid/view/View;

.field public final OooOOO0:Llyiahf/vczjk/fz5;

.field public final OooOOOO:Llyiahf/vczjk/tg6;

.field public OooOOOo:Llyiahf/vczjk/le3;

.field public OooOOo:Llyiahf/vczjk/le3;

.field public OooOOo0:Z

.field public OooOOoo:Llyiahf/vczjk/le3;

.field public OooOo:Llyiahf/vczjk/uy4;

.field public OooOo0:Llyiahf/vczjk/oe3;

.field public OooOo00:Llyiahf/vczjk/kl5;

.field public OooOo0O:Llyiahf/vczjk/f62;

.field public OooOo0o:Llyiahf/vczjk/oe3;

.field public final OooOoO:[I

.field public OooOoO0:Llyiahf/vczjk/h68;

.field public OooOoOO:J

.field public final OooOoo:Llyiahf/vczjk/mh;

.field public OooOoo0:Llyiahf/vczjk/ioa;

.field public final OooOooO:Llyiahf/vczjk/lh;

.field public OooOooo:Llyiahf/vczjk/oe3;

.field public final Oooo0:Llyiahf/vczjk/yu2;

.field public final Oooo000:[I

.field public Oooo00O:I

.field public Oooo00o:I

.field public Oooo0O0:Z

.field public final Oooo0OO:Llyiahf/vczjk/ro4;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/lg1;ILlyiahf/vczjk/fz5;Landroid/view/View;Llyiahf/vczjk/tg6;)V
    .locals 17

    move-object/from16 v0, p0

    move-object/from16 v1, p2

    move-object/from16 v2, p4

    move-object/from16 v3, p5

    const/4 v4, 0x0

    invoke-direct/range {p0 .. p1}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;)V

    iput-object v2, v0, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    iput-object v3, v0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    move-object/from16 v5, p6

    iput-object v5, v0, Llyiahf/vczjk/nh;->OooOOOO:Llyiahf/vczjk/tg6;

    if-eqz v1, :cond_0

    sget-object v5, Llyiahf/vczjk/kpa;->OooO00o:Ljava/util/LinkedHashMap;

    sget v5, Landroidx/compose/ui/R$id;->androidx_compose_ui_view_composition_context:I

    invoke-virtual {v0, v5, v1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    :cond_0
    invoke-virtual {v0, v4}, Landroid/view/View;->setSaveFromParentEnabled(Z)V

    invoke-virtual {v0, v3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    new-instance v1, Llyiahf/vczjk/ah;

    move-object v3, v0

    check-cast v3, Llyiahf/vczjk/nga;

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/ah;-><init>(Landroid/view/ViewGroup;I)V

    invoke-static {v0, v1}, Llyiahf/vczjk/xfa;->OooOOo0(Landroid/view/View;Llyiahf/vczjk/i11;)V

    invoke-static {v0, v0}, Llyiahf/vczjk/ofa;->OooOOO0(Landroid/view/View;Llyiahf/vczjk/u96;)V

    sget-object v1, Llyiahf/vczjk/u;->OooOoo0:Llyiahf/vczjk/u;

    iput-object v1, v0, Llyiahf/vczjk/nh;->OooOOOo:Llyiahf/vczjk/le3;

    sget-object v1, Llyiahf/vczjk/u;->OooOoOO:Llyiahf/vczjk/u;

    iput-object v1, v0, Llyiahf/vczjk/nh;->OooOOo:Llyiahf/vczjk/le3;

    sget-object v1, Llyiahf/vczjk/u;->OooOoO:Llyiahf/vczjk/u;

    iput-object v1, v0, Llyiahf/vczjk/nh;->OooOOoo:Llyiahf/vczjk/le3;

    sget-object v1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iput-object v1, v0, Llyiahf/vczjk/nh;->OooOo00:Llyiahf/vczjk/kl5;

    invoke-static {}, Llyiahf/vczjk/vc6;->OooO0o0()Llyiahf/vczjk/i62;

    move-result-object v4

    iput-object v4, v0, Llyiahf/vczjk/nh;->OooOo0O:Llyiahf/vczjk/f62;

    const/4 v4, 0x2

    new-array v5, v4, [I

    iput-object v5, v0, Llyiahf/vczjk/nh;->OooOoO:[I

    const-wide/16 v5, 0x0

    iput-wide v5, v0, Llyiahf/vczjk/nh;->OooOoOO:J

    new-instance v5, Llyiahf/vczjk/mh;

    invoke-direct {v5, v3}, Llyiahf/vczjk/mh;-><init>(Llyiahf/vczjk/nga;)V

    iput-object v5, v0, Llyiahf/vczjk/nh;->OooOoo:Llyiahf/vczjk/mh;

    new-instance v5, Llyiahf/vczjk/lh;

    invoke-direct {v5, v3}, Llyiahf/vczjk/lh;-><init>(Llyiahf/vczjk/nga;)V

    iput-object v5, v0, Llyiahf/vczjk/nh;->OooOooO:Llyiahf/vczjk/lh;

    new-array v4, v4, [I

    iput-object v4, v0, Llyiahf/vczjk/nh;->Oooo000:[I

    const/high16 v4, -0x80000000

    iput v4, v0, Llyiahf/vczjk/nh;->Oooo00O:I

    iput v4, v0, Llyiahf/vczjk/nh;->Oooo00o:I

    new-instance v4, Llyiahf/vczjk/yu2;

    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    iput-object v4, v0, Llyiahf/vczjk/nh;->Oooo0:Llyiahf/vczjk/yu2;

    new-instance v4, Llyiahf/vczjk/ro4;

    const/4 v5, 0x3

    invoke-direct {v4, v5}, Llyiahf/vczjk/ro4;-><init>(I)V

    const/4 v5, 0x1

    iput-boolean v5, v4, Llyiahf/vczjk/ro4;->OooOOoo:Z

    iput-object v3, v4, Llyiahf/vczjk/ro4;->OooOoOO:Llyiahf/vczjk/nga;

    sget-object v6, Llyiahf/vczjk/v34;->OooO00o:Llyiahf/vczjk/oh;

    invoke-static {v1, v6, v2}, Landroidx/compose/ui/input/nestedscroll/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/o6;->OooOoO0:Llyiahf/vczjk/o6;

    invoke-static {v1, v5, v2}, Llyiahf/vczjk/me8;->OooO00o(Llyiahf/vczjk/kl5;ZLlyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/uy6;

    invoke-direct {v2}, Llyiahf/vczjk/uy6;-><init>()V

    new-instance v5, Llyiahf/vczjk/wy6;

    invoke-direct {v5, v3}, Llyiahf/vczjk/wy6;-><init>(Llyiahf/vczjk/nga;)V

    iput-object v5, v2, Llyiahf/vczjk/uy6;->OooOOO0:Llyiahf/vczjk/oe3;

    new-instance v5, Llyiahf/vczjk/er7;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    iget-object v6, v2, Llyiahf/vczjk/uy6;->OooOOO:Llyiahf/vczjk/er7;

    if-nez v6, :cond_1

    goto :goto_0

    :cond_1
    const/4 v7, 0x0

    iput-object v7, v6, Llyiahf/vczjk/er7;->OooOOO0:Llyiahf/vczjk/uy6;

    :goto_0
    iput-object v5, v2, Llyiahf/vczjk/uy6;->OooOOO:Llyiahf/vczjk/er7;

    iput-object v2, v5, Llyiahf/vczjk/er7;->OooOOO0:Llyiahf/vczjk/uy6;

    invoke-virtual {v0, v5}, Llyiahf/vczjk/nh;->setOnRequestDisallowInterceptTouchEvent$ui_release(Llyiahf/vczjk/oe3;)V

    invoke-interface {v1, v2}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v8

    const/4 v14, 0x0

    const/4 v15, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const v16, 0x1ffff

    invoke-static/range {v8 .. v16}, Landroidx/compose/ui/graphics/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;FFFFFLlyiahf/vczjk/qj8;ZI)Llyiahf/vczjk/kl5;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/hh;

    invoke-direct {v2, v3, v4, v3}, Llyiahf/vczjk/hh;-><init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;Llyiahf/vczjk/nga;)V

    invoke-static {v1, v2}, Landroidx/compose/ui/draw/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/ih;

    invoke-direct {v2, v3, v4}, Llyiahf/vczjk/ih;-><init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V

    invoke-static {v1, v2}, Landroidx/compose/ui/layout/OooO00o;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object v1

    iget-object v2, v0, Llyiahf/vczjk/nh;->OooOo00:Llyiahf/vczjk/kl5;

    invoke-interface {v2, v1}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-virtual {v4, v2}, Llyiahf/vczjk/ro4;->Ooooo0o(Llyiahf/vczjk/kl5;)V

    new-instance v2, Llyiahf/vczjk/bh;

    invoke-direct {v2, v4, v1}, Llyiahf/vczjk/bh;-><init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/kl5;)V

    iput-object v2, v0, Llyiahf/vczjk/nh;->OooOo0:Llyiahf/vczjk/oe3;

    iget-object v1, v0, Llyiahf/vczjk/nh;->OooOo0O:Llyiahf/vczjk/f62;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/ro4;->OoooOoO(Llyiahf/vczjk/f62;)V

    new-instance v1, Llyiahf/vczjk/ch;

    invoke-direct {v1, v4}, Llyiahf/vczjk/ch;-><init>(Llyiahf/vczjk/ro4;)V

    iput-object v1, v0, Llyiahf/vczjk/nh;->OooOo0o:Llyiahf/vczjk/oe3;

    new-instance v1, Llyiahf/vczjk/dh;

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/dh;-><init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V

    iput-object v1, v4, Llyiahf/vczjk/ro4;->OoooOo0:Llyiahf/vczjk/dh;

    new-instance v1, Llyiahf/vczjk/eh;

    invoke-direct {v1, v3}, Llyiahf/vczjk/eh;-><init>(Llyiahf/vczjk/nga;)V

    iput-object v1, v4, Llyiahf/vczjk/ro4;->OoooOoO:Llyiahf/vczjk/eh;

    new-instance v1, Llyiahf/vczjk/gh;

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/gh;-><init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V

    invoke-virtual {v4, v1}, Llyiahf/vczjk/ro4;->Ooooo00(Llyiahf/vczjk/lf5;)V

    iput-object v4, v0, Llyiahf/vczjk/nh;->Oooo0OO:Llyiahf/vczjk/ro4;

    return-void
.end method

.method public static final synthetic OooOO0(Llyiahf/vczjk/nh;)Llyiahf/vczjk/vg6;
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/nh;->getSnapshotObserver()Llyiahf/vczjk/vg6;

    move-result-object p0

    return-object p0
.end method

.method public static final OooOO0O(Llyiahf/vczjk/nga;III)I
    .locals 1

    const/high16 p0, 0x40000000    # 2.0f

    if-gez p3, :cond_3

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, -0x2

    const v0, 0x7fffffff

    if-ne p3, p1, :cond_1

    if-eq p2, v0, :cond_1

    const/high16 p0, -0x80000000

    invoke-static {p2, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p0

    return p0

    :cond_1
    const/4 p1, -0x1

    if-ne p3, p1, :cond_2

    if-eq p2, v0, :cond_2

    invoke-static {p2, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p0

    return p0

    :cond_2
    const/4 p0, 0x0

    invoke-static {p0, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p0

    return p0

    :cond_3
    :goto_0
    invoke-static {p3, p1, p2}, Llyiahf/vczjk/vt6;->OooOOo(III)I

    move-result p1

    invoke-static {p1, p0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p0

    return p0
.end method

.method public static OooOO0o(Llyiahf/vczjk/x04;IIII)Llyiahf/vczjk/x04;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/x04;->OooO00o:I

    sub-int/2addr v0, p1

    const/4 p1, 0x0

    if-gez v0, :cond_0

    move v0, p1

    :cond_0
    iget v1, p0, Llyiahf/vczjk/x04;->OooO0O0:I

    sub-int/2addr v1, p2

    if-gez v1, :cond_1

    move v1, p1

    :cond_1
    iget p2, p0, Llyiahf/vczjk/x04;->OooO0OO:I

    sub-int/2addr p2, p3

    if-gez p2, :cond_2

    move p2, p1

    :cond_2
    iget p0, p0, Llyiahf/vczjk/x04;->OooO0Oo:I

    sub-int/2addr p0, p4

    if-gez p0, :cond_3

    goto :goto_0

    :cond_3
    move p1, p0

    :goto_0
    invoke-static {v0, v1, p2, p1}, Llyiahf/vczjk/x04;->OooO0OO(IIII)Llyiahf/vczjk/x04;

    move-result-object p0

    return-object p0
.end method

.method private final getSnapshotObserver()Llyiahf/vczjk/vg6;
    .locals 1

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v0

    if-nez v0, :cond_0

    const-string v0, "Expected AndroidViewHolder to be attached when observing reads."

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOOO:Llyiahf/vczjk/tg6;

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getSnapshotObserver()Llyiahf/vczjk/vg6;

    move-result-object v0

    return-object v0
.end method


# virtual methods
.method public final OooO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v1

    if-eq v1, p0, :cond_0

    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOo:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final OooO00o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOoo:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final OooO0O0()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOo:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    invoke-virtual {p0}, Landroid/view/ViewGroup;->removeAllViewsInLayout()V

    return-void
.end method

.method public final OooO0OO(Landroid/view/View;IIIII[I)V
    .locals 12

    iget-object p1, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    move-result p1

    if-nez p1, :cond_0

    return-void

    :cond_0
    int-to-float p1, p2

    const/4 p2, -0x1

    int-to-float p2, p2

    mul-float/2addr p1, p2

    int-to-float p3, p3

    mul-float/2addr p3, p2

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v0, p1

    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v2, p1

    const/16 p1, 0x20

    shl-long/2addr v0, p1

    const-wide v4, 0xffffffffL

    and-long/2addr v2, v4

    or-long v8, v0, v2

    move/from16 p3, p4

    int-to-float p3, p3

    mul-float/2addr p3, p2

    move/from16 v0, p5

    int-to-float v0, v0

    mul-float/2addr v0, p2

    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p2

    int-to-long p2, p2

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v0, v0

    shl-long/2addr p2, p1

    and-long/2addr v0, v4

    or-long v10, p2, v0

    const/4 p2, 0x1

    if-nez p6, :cond_1

    move v7, p2

    goto :goto_0

    :cond_1
    const/4 p3, 0x2

    move v7, p3

    :goto_0
    iget-object p3, p0, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    iget-object p3, p3, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    const/4 v0, 0x0

    if-eqz p3, :cond_2

    iget-boolean v1, p3, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v1, :cond_2

    invoke-static {p3}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p3

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/jz5;

    :cond_2
    move-object v6, v0

    if-eqz v6, :cond_3

    invoke-virtual/range {v6 .. v11}, Llyiahf/vczjk/jz5;->Ooooooo(IJJ)J

    move-result-wide v0

    goto :goto_1

    :cond_3
    const-wide/16 v0, 0x0

    :goto_1
    shr-long v2, v0, p1

    long-to-int p1, v2

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/dn8;->Oooo00o(F)I

    move-result p1

    const/4 p3, 0x0

    aput p1, p7, p3

    and-long/2addr v0, v4

    long-to-int p1, v0

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/dn8;->Oooo00o(F)I

    move-result p1

    aput p1, p7, p2

    return-void
.end method

.method public final OooO0Oo(Landroid/view/View;IIIII)V
    .locals 11

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->isNestedScrollingEnabled()Z

    move-result v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    int-to-float v0, p2

    const/4 v1, -0x1

    int-to-float v1, v1

    mul-float/2addr v0, v1

    int-to-float v2, p3

    mul-float/2addr v2, v1

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v3, v0

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v5, v0

    const/16 v0, 0x20

    shl-long v2, v3, v0

    const-wide v7, 0xffffffffL

    and-long v4, v5, v7

    or-long/2addr v2, v4

    move v4, p4

    int-to-float v4, v4

    mul-float/2addr v4, v1

    move/from16 v5, p5

    int-to-float v5, v5

    mul-float/2addr v5, v1

    invoke-static {v4}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v9, v1

    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v4, v1

    shl-long v0, v9, v0

    and-long/2addr v4, v7

    or-long/2addr v0, v4

    if-nez p6, :cond_1

    const/4 v4, 0x1

    goto :goto_0

    :cond_1
    const/4 v4, 0x2

    :goto_0
    iget-object v5, p0, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    iget-object v5, v5, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    const/4 v6, 0x0

    if-eqz v5, :cond_2

    iget-boolean v7, v5, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v7, :cond_2

    invoke-static {v5}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object v5

    move-object v6, v5

    check-cast v6, Llyiahf/vczjk/jz5;

    :cond_2
    if-eqz v6, :cond_3

    move-wide/from16 p5, v0

    move-wide p3, v2

    move p2, v4

    move-object p1, v6

    invoke-virtual/range {p1 .. p6}, Llyiahf/vczjk/jz5;->Ooooooo(IJJ)J

    :cond_3
    return-void
.end method

.method public final OooO0o(Landroid/view/View;Landroid/view/View;II)V
    .locals 0

    const/4 p1, 0x1

    iget-object p2, p0, Llyiahf/vczjk/nh;->Oooo0:Llyiahf/vczjk/yu2;

    if-ne p4, p1, :cond_0

    iput p3, p2, Llyiahf/vczjk/yu2;->OooOOO:I

    return-void

    :cond_0
    iput p3, p2, Llyiahf/vczjk/yu2;->OooOOO0:I

    return-void
.end method

.method public final OooO0o0(Landroid/view/View;Landroid/view/View;II)Z
    .locals 0

    and-int/lit8 p1, p3, 0x2

    const/4 p2, 0x1

    if-nez p1, :cond_1

    and-int/lit8 p1, p3, 0x1

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    return p1

    :cond_1
    :goto_0
    return p2
.end method

.method public final OooO0oO(Landroid/view/View;I)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/nh;->Oooo0:Llyiahf/vczjk/yu2;

    const/4 v0, 0x1

    const/4 v1, 0x0

    if-ne p2, v0, :cond_0

    iput v1, p1, Llyiahf/vczjk/yu2;->OooOOO:I

    return-void

    :cond_0
    iput v1, p1, Llyiahf/vczjk/yu2;->OooOOO0:I

    return-void
.end method

.method public final OooO0oo(Landroid/view/View;II[II)V
    .locals 6

    iget-object p1, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    move-result p1

    if-nez p1, :cond_0

    return-void

    :cond_0
    int-to-float p1, p2

    const/4 p2, -0x1

    int-to-float p2, p2

    mul-float/2addr p1, p2

    int-to-float p3, p3

    mul-float/2addr p3, p2

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long p1, p1

    invoke-static {p3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p3

    int-to-long v0, p3

    const/16 p3, 0x20

    shl-long/2addr p1, p3

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    or-long/2addr p1, v0

    const/4 v0, 0x1

    if-nez p5, :cond_1

    move p5, v0

    goto :goto_0

    :cond_1
    const/4 p5, 0x2

    :goto_0
    iget-object v1, p0, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    iget-object v1, v1, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    const/4 v4, 0x0

    if-eqz v1, :cond_2

    iget-boolean v5, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v5, :cond_2

    invoke-static {v1}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object v1

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/jz5;

    :cond_2
    if-eqz v4, :cond_3

    invoke-virtual {v4, p5, p1, p2}, Llyiahf/vczjk/jz5;->Oooo00O(IJ)J

    move-result-wide p1

    goto :goto_1

    :cond_3
    const-wide/16 p1, 0x0

    :goto_1
    shr-long v4, p1, p3

    long-to-int p3, v4

    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p3

    invoke-static {p3}, Llyiahf/vczjk/dn8;->Oooo00o(F)I

    move-result p3

    const/4 p5, 0x0

    aput p3, p4, p5

    and-long/2addr p1, v2

    long-to-int p1, p1

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/dn8;->Oooo00o(F)I

    move-result p1

    aput p1, p4, v0

    return-void
.end method

.method public final OooOOO0(Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 14

    iget-object v0, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/4 v1, -0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/x04;->OooO0o0:Llyiahf/vczjk/x04;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/x04;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/16 v1, -0x9

    invoke-virtual {v0, v1}, Llyiahf/vczjk/foa;->OooO0oo(I)Llyiahf/vczjk/x04;

    move-result-object v1

    invoke-virtual {v1, v2}, Llyiahf/vczjk/x04;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooO0o()Llyiahf/vczjk/lc2;

    move-result-object v0

    if-eqz v0, :cond_6

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/nh;->Oooo0OO:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0OO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/b04;

    iget-object v1, v0, Llyiahf/vczjk/b04;->OoooOoO:Llyiahf/vczjk/cf9;

    iget-boolean v1, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v1, :cond_1

    goto :goto_1

    :cond_1
    const-wide/16 v1, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/v16;->OoooOO0(J)J

    move-result-wide v1

    invoke-static {v1, v2}, Llyiahf/vczjk/yi4;->o0ooOOo(J)J

    move-result-wide v1

    const/16 v3, 0x20

    shr-long v4, v1, v3

    long-to-int v4, v4

    const/4 v5, 0x0

    if-gez v4, :cond_2

    move v4, v5

    :cond_2
    const-wide v6, 0xffffffffL

    and-long/2addr v1, v6

    long-to-int v1, v1

    if-gez v1, :cond_3

    move v1, v5

    :cond_3
    invoke-static {v0}, Llyiahf/vczjk/ng0;->OooOo0o(Llyiahf/vczjk/xn4;)Llyiahf/vczjk/xn4;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/xn4;->OooOo00()J

    move-result-wide v8

    shr-long v10, v8, v3

    long-to-int v2, v10

    and-long/2addr v8, v6

    long-to-int v8, v8

    iget-wide v9, v0, Llyiahf/vczjk/ow6;->OooOOOO:J

    shr-long v11, v9, v3

    long-to-int v11, v11

    and-long/2addr v9, v6

    long-to-int v9, v9

    int-to-float v10, v11

    int-to-float v9, v9

    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v10

    int-to-long v10, v10

    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v9

    int-to-long v12, v9

    shl-long v9, v10, v3

    and-long v11, v12, v6

    or-long/2addr v9, v11

    invoke-virtual {v0, v9, v10}, Llyiahf/vczjk/v16;->OoooOO0(J)J

    move-result-wide v9

    invoke-static {v9, v10}, Llyiahf/vczjk/yi4;->o0ooOOo(J)J

    move-result-wide v9

    shr-long v11, v9, v3

    long-to-int v0, v11

    sub-int/2addr v2, v0

    if-gez v2, :cond_4

    move v2, v5

    :cond_4
    and-long/2addr v6, v9

    long-to-int v0, v6

    sub-int/2addr v8, v0

    if-gez v8, :cond_5

    goto :goto_0

    :cond_5
    move v5, v8

    :goto_0
    if-nez v4, :cond_7

    if-nez v1, :cond_7

    if-nez v2, :cond_7

    if-nez v5, :cond_7

    :cond_6
    :goto_1
    return-object p1

    :cond_7
    iget-object p1, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {p1, v4, v1, v2, v5}, Llyiahf/vczjk/foa;->OooOOO(IIII)Llyiahf/vczjk/ioa;

    move-result-object p1

    return-object p1
.end method

.method public final OooOOOo()Z
    .locals 1

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v0

    return v0
.end method

.method public final Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 0

    new-instance p1, Llyiahf/vczjk/ioa;

    invoke-direct {p1, p2}, Llyiahf/vczjk/ioa;-><init>(Llyiahf/vczjk/ioa;)V

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOoo0:Llyiahf/vczjk/ioa;

    invoke-virtual {p0, p2}, Llyiahf/vczjk/nh;->OooOOO0(Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;

    move-result-object p1

    return-object p1
.end method

.method public final gatherTransparentRegion(Landroid/graphics/Region;)Z
    .locals 9

    const/4 v0, 0x1

    if-nez p1, :cond_0

    return v0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/nh;->Oooo000:[I

    invoke-virtual {p0, v1}, Landroid/view/View;->getLocationInWindow([I)V

    const/4 v2, 0x0

    aget v4, v1, v2

    aget v5, v1, v0

    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    move-result v2

    add-int v6, v2, v4

    aget v1, v1, v0

    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    move-result v2

    add-int v7, v2, v1

    sget-object v8, Landroid/graphics/Region$Op;->DIFFERENCE:Landroid/graphics/Region$Op;

    move-object v3, p1

    invoke-virtual/range {v3 .. v8}, Landroid/graphics/Region;->op(IIIILandroid/graphics/Region$Op;)Z

    return v0
.end method

.method public getAccessibilityClassName()Ljava/lang/CharSequence;
    .locals 1

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

.method public final getDensity()Llyiahf/vczjk/f62;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo0O:Llyiahf/vczjk/f62;

    return-object v0
.end method

.method public final getInteropView()Landroid/view/View;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    return-object v0
.end method

.method public final getLayoutNode()Llyiahf/vczjk/ro4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->Oooo0OO:Llyiahf/vczjk/ro4;

    return-object v0
.end method

.method public getLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    if-nez v0, :cond_0

    new-instance v0, Landroid/view/ViewGroup$LayoutParams;

    const/4 v1, -0x1

    invoke-direct {v0, v1, v1}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    :cond_0
    return-object v0
.end method

.method public final getLifecycleOwner()Llyiahf/vczjk/uy4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo:Llyiahf/vczjk/uy4;

    return-object v0
.end method

.method public final getModifier()Llyiahf/vczjk/kl5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo00:Llyiahf/vczjk/kl5;

    return-object v0
.end method

.method public getNestedScrollAxes()I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/nh;->Oooo0:Llyiahf/vczjk/yu2;

    iget v1, v0, Llyiahf/vczjk/yu2;->OooOOO0:I

    iget v0, v0, Llyiahf/vczjk/yu2;->OooOOO:I

    or-int/2addr v0, v1

    return v0
.end method

.method public final getOnDensityChanged$ui_release()Llyiahf/vczjk/oe3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo0o:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final getOnModifierChanged$ui_release()Llyiahf/vczjk/oe3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo0:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final getOnRequestDisallowInterceptTouchEvent$ui_release()Llyiahf/vczjk/oe3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOooo:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final getRelease()Llyiahf/vczjk/le3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/le3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOoo:Llyiahf/vczjk/le3;

    return-object v0
.end method

.method public final getReset()Llyiahf/vczjk/le3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/le3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOo:Llyiahf/vczjk/le3;

    return-object v0
.end method

.method public final getSavedStateRegistryOwner()Llyiahf/vczjk/h68;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOoO0:Llyiahf/vczjk/h68;

    return-object v0
.end method

.method public final getUpdate()Llyiahf/vczjk/le3;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Llyiahf/vczjk/le3;"
        }
    .end annotation

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOOo:Llyiahf/vczjk/le3;

    return-object v0
.end method

.method public final getView()Landroid/view/View;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    return-object v0
.end method

.method public final invalidateChildInParent([ILandroid/graphics/Rect;)Landroid/view/ViewParent;
    .locals 1

    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->invalidateChildInParent([ILandroid/graphics/Rect;)Landroid/view/ViewParent;

    iget-boolean p1, p0, Llyiahf/vczjk/nh;->Oooo0O0:Z

    if-eqz p1, :cond_0

    new-instance p1, Llyiahf/vczjk/oO0O00o0;

    iget-object p2, p0, Llyiahf/vczjk/nh;->OooOooO:Llyiahf/vczjk/lh;

    const/16 v0, 0x8

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    iget-object p2, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {p2, p1}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/nh;->Oooo0OO:Llyiahf/vczjk/ro4;

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOoo()V

    :goto_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final isNestedScrollingEnabled()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->isNestedScrollingEnabled()Z

    move-result v0

    return v0
.end method

.method public final onAttachedToWindow()V
    .locals 1

    invoke-super {p0}, Landroid/view/ViewGroup;->onAttachedToWindow()V

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOoo:Llyiahf/vczjk/mh;

    invoke-virtual {v0}, Llyiahf/vczjk/mh;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final onDescendantInvalidated(Landroid/view/View;Landroid/view/View;)V
    .locals 1

    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->onDescendantInvalidated(Landroid/view/View;Landroid/view/View;)V

    iget-boolean p1, p0, Llyiahf/vczjk/nh;->Oooo0O0:Z

    if-eqz p1, :cond_0

    new-instance p1, Llyiahf/vczjk/oO0O00o0;

    iget-object p2, p0, Llyiahf/vczjk/nh;->OooOooO:Llyiahf/vczjk/lh;

    const/16 v0, 0x8

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    iget-object p2, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {p2, p1}, Landroid/view/View;->postOnAnimation(Ljava/lang/Runnable;)V

    return-void

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/nh;->Oooo0OO:Llyiahf/vczjk/ro4;

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOoo()V

    return-void
.end method

.method public final onDetachedFromWindow()V
    .locals 1

    invoke-super {p0}, Landroid/view/ViewGroup;->onDetachedFromWindow()V

    invoke-direct {p0}, Llyiahf/vczjk/nh;->getSnapshotObserver()Llyiahf/vczjk/vg6;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/vg6;->OooO00o:Llyiahf/vczjk/yw8;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/yw8;->OooO0OO(Ljava/lang/Object;)V

    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    sub-int/2addr p4, p2

    sub-int/2addr p5, p3

    iget-object p1, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    const/4 p2, 0x0

    invoke-virtual {p1, p2, p2, p4, p5}, Landroid/view/View;->layout(IIII)V

    return-void
.end method

.method public final onMeasure(II)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v1

    if-eq v1, p0, :cond_0

    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I

    move-result p1

    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getSize(I)I

    move-result p2

    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setMeasuredDimension(II)V

    return-void

    :cond_0
    invoke-virtual {v0}, Landroid/view/View;->getVisibility()I

    move-result v1

    const/16 v2, 0x8

    if-ne v1, v2, :cond_1

    const/4 p1, 0x0

    invoke-virtual {p0, p1, p1}, Landroid/view/View;->setMeasuredDimension(II)V

    return-void

    :cond_1
    invoke-virtual {v0, p1, p2}, Landroid/view/View;->measure(II)V

    invoke-virtual {v0}, Landroid/view/View;->getMeasuredWidth()I

    move-result v1

    invoke-virtual {v0}, Landroid/view/View;->getMeasuredHeight()I

    move-result v0

    invoke-virtual {p0, v1, v0}, Landroid/view/View;->setMeasuredDimension(II)V

    iput p1, p0, Llyiahf/vczjk/nh;->Oooo00O:I

    iput p2, p0, Llyiahf/vczjk/nh;->Oooo00o:I

    return-void
.end method

.method public final onNestedFling(Landroid/view/View;FFZ)Z
    .locals 7

    iget-object p1, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    move-result p1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    const/high16 p1, -0x40800000    # -1.0f

    mul-float/2addr p2, p1

    mul-float/2addr p3, p1

    invoke-static {p2, p3}, Llyiahf/vczjk/kh6;->OooO0o(FF)J

    move-result-wide v4

    iget-object p1, p0, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    invoke-virtual {p1}, Llyiahf/vczjk/fz5;->OooO0OO()Llyiahf/vczjk/xr1;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/jh;

    const/4 v6, 0x0

    move-object v3, p0

    move v2, p4

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/jh;-><init>(ZLlyiahf/vczjk/nh;JLlyiahf/vczjk/yo1;)V

    const/4 p2, 0x3

    const/4 p3, 0x0

    invoke-static {p1, p3, p3, v1, p2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return v0
.end method

.method public final onNestedPreFling(Landroid/view/View;FF)Z
    .locals 3

    iget-object p1, p0, Llyiahf/vczjk/nh;->OooOOO:Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->isNestedScrollingEnabled()Z

    move-result p1

    const/4 v0, 0x0

    if-nez p1, :cond_0

    return v0

    :cond_0
    const/high16 p1, -0x40800000    # -1.0f

    mul-float/2addr p2, p1

    mul-float/2addr p3, p1

    invoke-static {p2, p3}, Llyiahf/vczjk/kh6;->OooO0o(FF)J

    move-result-wide p1

    iget-object p3, p0, Llyiahf/vczjk/nh;->OooOOO0:Llyiahf/vczjk/fz5;

    invoke-virtual {p3}, Llyiahf/vczjk/fz5;->OooO0OO()Llyiahf/vczjk/xr1;

    move-result-object p3

    new-instance v1, Llyiahf/vczjk/kh;

    const/4 v2, 0x0

    invoke-direct {v1, p0, p1, p2, v2}, Llyiahf/vczjk/kh;-><init>(Llyiahf/vczjk/nh;JLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {p3, v2, v2, v1, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return v0
.end method

.method public final onWindowVisibilityChanged(I)V
    .locals 0

    invoke-super {p0, p1}, Landroid/view/View;->onWindowVisibilityChanged(I)V

    return-void
.end method

.method public final requestDisallowInterceptTouchEvent(Z)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOooo:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_0

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->requestDisallowInterceptTouchEvent(Z)V

    return-void
.end method

.method public final setDensity(Llyiahf/vczjk/f62;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo0O:Llyiahf/vczjk/f62;

    if-eq p1, v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOo0O:Llyiahf/vczjk/f62;

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo0o:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final setLifecycleOwner(Llyiahf/vczjk/uy4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo:Llyiahf/vczjk/uy4;

    if-eq p1, v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOo:Llyiahf/vczjk/uy4;

    invoke-static {p0, p1}, Llyiahf/vczjk/dr6;->OooOo0(Landroid/view/View;Llyiahf/vczjk/uy4;)V

    :cond_0
    return-void
.end method

.method public final setModifier(Llyiahf/vczjk/kl5;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo00:Llyiahf/vczjk/kl5;

    if-eq p1, v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOo00:Llyiahf/vczjk/kl5;

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOo0:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final setOnDensityChanged$ui_release(Llyiahf/vczjk/oe3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/oe3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOo0o:Llyiahf/vczjk/oe3;

    return-void
.end method

.method public final setOnModifierChanged$ui_release(Llyiahf/vczjk/oe3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/oe3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOo0:Llyiahf/vczjk/oe3;

    return-void
.end method

.method public final setOnRequestDisallowInterceptTouchEvent$ui_release(Llyiahf/vczjk/oe3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/oe3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOooo:Llyiahf/vczjk/oe3;

    return-void
.end method

.method public final setRelease(Llyiahf/vczjk/le3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/le3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOOoo:Llyiahf/vczjk/le3;

    return-void
.end method

.method public final setReset(Llyiahf/vczjk/le3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/le3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOOo:Llyiahf/vczjk/le3;

    return-void
.end method

.method public final setSavedStateRegistryOwner(Llyiahf/vczjk/h68;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/nh;->OooOoO0:Llyiahf/vczjk/h68;

    if-eq p1, v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOoO0:Llyiahf/vczjk/h68;

    invoke-static {p0, p1}, Llyiahf/vczjk/wr6;->OooOo0o(Landroid/view/View;Llyiahf/vczjk/h68;)V

    :cond_0
    return-void
.end method

.method public final setUpdate(Llyiahf/vczjk/le3;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Llyiahf/vczjk/le3;",
            ")V"
        }
    .end annotation

    iput-object p1, p0, Llyiahf/vczjk/nh;->OooOOOo:Llyiahf/vczjk/le3;

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/nh;->OooOOo0:Z

    iget-object p1, p0, Llyiahf/vczjk/nh;->OooOoo:Llyiahf/vczjk/mh;

    invoke-virtual {p1}, Llyiahf/vczjk/mh;->OooO00o()Ljava/lang/Object;

    return-void
.end method

.method public final shouldDelayChildPressedState()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method
