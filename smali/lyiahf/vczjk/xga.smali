.class public final Llyiahf/vczjk/xga;
.super Landroid/view/View;
.source "SourceFile"


# static fields
.field public static final OooOo0o:Llyiahf/vczjk/cb2;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/hq0;

.field public final OooOOO0:Llyiahf/vczjk/eg2;

.field public final OooOOOO:Llyiahf/vczjk/gq0;

.field public OooOOOo:Z

.field public OooOOo:Z

.field public OooOOo0:Landroid/graphics/Outline;

.field public OooOOoo:Llyiahf/vczjk/f62;

.field public OooOo0:Llyiahf/vczjk/rm4;

.field public OooOo00:Llyiahf/vczjk/yn4;

.field public OooOo0O:Llyiahf/vczjk/kj3;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/cb2;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/cb2;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/xga;->OooOo0o:Llyiahf/vczjk/cb2;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/eg2;Llyiahf/vczjk/hq0;Llyiahf/vczjk/gq0;)V
    .locals 1

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-direct {p0, v0}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    iput-object p1, p0, Llyiahf/vczjk/xga;->OooOOO0:Llyiahf/vczjk/eg2;

    iput-object p2, p0, Llyiahf/vczjk/xga;->OooOOO:Llyiahf/vczjk/hq0;

    iput-object p3, p0, Llyiahf/vczjk/xga;->OooOOOO:Llyiahf/vczjk/gq0;

    sget-object p1, Llyiahf/vczjk/xga;->OooOo0o:Llyiahf/vczjk/cb2;

    invoke-virtual {p0, p1}, Landroid/view/View;->setOutlineProvider(Landroid/view/ViewOutlineProvider;)V

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/xga;->OooOOo:Z

    sget-object p1, Llyiahf/vczjk/os9;->OooO0OO:Llyiahf/vczjk/i62;

    iput-object p1, p0, Llyiahf/vczjk/xga;->OooOOoo:Llyiahf/vczjk/f62;

    sget-object p1, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    iput-object p1, p0, Llyiahf/vczjk/xga;->OooOo00:Llyiahf/vczjk/yn4;

    sget-object p1, Llyiahf/vczjk/lj3;->OooO00o:Llyiahf/vczjk/xj0;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/mo2;->OooOoO:Llyiahf/vczjk/mo2;

    iput-object p1, p0, Llyiahf/vczjk/xga;->OooOo0:Llyiahf/vczjk/rm4;

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Landroid/view/View;->setWillNotDraw(Z)V

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Landroid/view/View;->setClipBounds(Landroid/graphics/Rect;)V

    return-void
.end method


# virtual methods
.method public final dispatchDraw(Landroid/graphics/Canvas;)V
    .locals 17

    move-object/from16 v1, p0

    iget-object v0, v1, Llyiahf/vczjk/xga;->OooOOO:Llyiahf/vczjk/hq0;

    iget-object v2, v0, Llyiahf/vczjk/hq0;->OooO00o:Llyiahf/vczjk/s9;

    iget-object v3, v2, Llyiahf/vczjk/s9;->OooO00o:Landroid/graphics/Canvas;

    move-object/from16 v4, p1

    iput-object v4, v2, Llyiahf/vczjk/s9;->OooO00o:Landroid/graphics/Canvas;

    iget-object v4, v1, Llyiahf/vczjk/xga;->OooOOoo:Llyiahf/vczjk/f62;

    iget-object v5, v1, Llyiahf/vczjk/xga;->OooOo00:Llyiahf/vczjk/yn4;

    invoke-virtual {v1}, Landroid/view/View;->getWidth()I

    move-result v6

    int-to-float v6, v6

    invoke-virtual {v1}, Landroid/view/View;->getHeight()I

    move-result v7

    int-to-float v7, v7

    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    int-to-long v8, v6

    invoke-static {v7}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v6

    int-to-long v6, v6

    const/16 v10, 0x20

    shl-long/2addr v8, v10

    const-wide v10, 0xffffffffL

    and-long/2addr v6, v10

    or-long/2addr v6, v8

    iget-object v8, v1, Llyiahf/vczjk/xga;->OooOo0O:Llyiahf/vczjk/kj3;

    iget-object v9, v1, Llyiahf/vczjk/xga;->OooOo0:Llyiahf/vczjk/rm4;

    iget-object v10, v1, Llyiahf/vczjk/xga;->OooOOOO:Llyiahf/vczjk/gq0;

    iget-object v11, v10, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v12, v11, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/gq0;

    iget-object v12, v12, Llyiahf/vczjk/gq0;->OooOOO0:Llyiahf/vczjk/fq0;

    iget-object v13, v12, Llyiahf/vczjk/fq0;->OooO00o:Llyiahf/vczjk/f62;

    iget-object v12, v12, Llyiahf/vczjk/fq0;->OooO0O0:Llyiahf/vczjk/yn4;

    invoke-virtual {v11}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v11

    iget-object v14, v10, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    move-object v15, v11

    move-object/from16 p1, v12

    invoke-virtual {v14}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v11

    move-object/from16 v16, v15

    iget-object v15, v14, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/kj3;

    invoke-virtual {v14, v4}, Llyiahf/vczjk/uqa;->Oooo00O(Llyiahf/vczjk/f62;)V

    invoke-virtual {v14, v5}, Llyiahf/vczjk/uqa;->Oooo00o(Llyiahf/vczjk/yn4;)V

    invoke-virtual {v14, v2}, Llyiahf/vczjk/uqa;->Oooo000(Llyiahf/vczjk/eq0;)V

    invoke-virtual {v14, v6, v7}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    iput-object v8, v14, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    invoke-virtual {v2}, Llyiahf/vczjk/s9;->OooO0oO()V

    :try_start_0
    invoke-interface {v9, v10}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v2}, Llyiahf/vczjk/s9;->OooOOo0()V

    invoke-virtual {v14, v13}, Llyiahf/vczjk/uqa;->Oooo00O(Llyiahf/vczjk/f62;)V

    move-object/from16 v4, p1

    invoke-virtual {v14, v4}, Llyiahf/vczjk/uqa;->Oooo00o(Llyiahf/vczjk/yn4;)V

    move-object/from16 v5, v16

    invoke-virtual {v14, v5}, Llyiahf/vczjk/uqa;->Oooo000(Llyiahf/vczjk/eq0;)V

    invoke-virtual {v14, v11, v12}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    iput-object v15, v14, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    iget-object v0, v0, Llyiahf/vczjk/hq0;->OooO00o:Llyiahf/vczjk/s9;

    iput-object v3, v0, Llyiahf/vczjk/s9;->OooO00o:Landroid/graphics/Canvas;

    const/4 v0, 0x0

    iput-boolean v0, v1, Llyiahf/vczjk/xga;->OooOOOo:Z

    return-void

    :catchall_0
    move-exception v0

    move-object/from16 v4, p1

    move-object/from16 v5, v16

    invoke-virtual {v2}, Llyiahf/vczjk/s9;->OooOOo0()V

    invoke-virtual {v14, v13}, Llyiahf/vczjk/uqa;->Oooo00O(Llyiahf/vczjk/f62;)V

    invoke-virtual {v14, v4}, Llyiahf/vczjk/uqa;->Oooo00o(Llyiahf/vczjk/yn4;)V

    invoke-virtual {v14, v5}, Llyiahf/vczjk/uqa;->Oooo000(Llyiahf/vczjk/eq0;)V

    invoke-virtual {v14, v11, v12}, Llyiahf/vczjk/uqa;->Oooo0(J)V

    iput-object v15, v14, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    throw v0
.end method

.method public final forceLayout()V
    .locals 0

    return-void
.end method

.method public final getCanUseCompositingLayer$ui_graphics_release()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/xga;->OooOOo:Z

    return v0
.end method

.method public final getCanvasHolder()Llyiahf/vczjk/hq0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xga;->OooOOO:Llyiahf/vczjk/hq0;

    return-object v0
.end method

.method public final getOwnerView()Landroid/view/View;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xga;->OooOOO0:Llyiahf/vczjk/eg2;

    return-object v0
.end method

.method public final hasOverlappingRendering()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/xga;->OooOOo:Z

    return v0
.end method

.method public final invalidate()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/xga;->OooOOOo:Z

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/xga;->OooOOOo:Z

    invoke-super {p0}, Landroid/view/View;->invalidate()V

    :cond_0
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    return-void
.end method

.method public final setCanUseCompositingLayer$ui_graphics_release(Z)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/xga;->OooOOo:Z

    if-eq v0, p1, :cond_0

    iput-boolean p1, p0, Llyiahf/vczjk/xga;->OooOOo:Z

    invoke-virtual {p0}, Llyiahf/vczjk/xga;->invalidate()V

    :cond_0
    return-void
.end method

.method public final setInvalidated(Z)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/xga;->OooOOOo:Z

    return-void
.end method
