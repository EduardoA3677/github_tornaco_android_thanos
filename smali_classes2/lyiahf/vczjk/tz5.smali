.class public final Llyiahf/vczjk/tz5;
.super Landroid/widget/FrameLayout;
.source "SourceFile"


# instance fields
.field public OooOOO:Landroid/view/WindowManager;

.field public OooOOO0:Landroid/graphics/Rect;

.field public OooOOOO:Landroid/view/WindowManager$LayoutParams;

.field public OooOOOo:I

.field public OooOOo:I

.field public OooOOo0:I

.field public OooOOoo:I

.field public OooOo:Llyiahf/vczjk/uk2;

.field public OooOo0:F

.field public OooOo00:I

.field public OooOo0O:Z

.field public OooOo0o:Llyiahf/vczjk/tg7;

.field public OooOoO:Landroid/widget/TextView;

.field public OooOoO0:Llyiahf/vczjk/wq0;

.field public OooOoOO:Ljava/lang/String;

.field public OooOoo:Llyiahf/vczjk/ra;

.field public OooOoo0:Landroid/os/Handler;

.field public OooOooO:Z

.field public OooOooo:Z


# virtual methods
.method public final bridge synthetic generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;
    .locals 1

    invoke-virtual {p0}, Landroid/widget/FrameLayout;->generateDefaultLayoutParams()Landroid/widget/FrameLayout$LayoutParams;

    move-result-object v0

    return-object v0
.end method

.method public final bridge synthetic generateLayoutParams(Landroid/util/AttributeSet;)Landroid/view/ViewGroup$LayoutParams;
    .locals 0

    invoke-virtual {p0, p1}, Landroid/widget/FrameLayout;->generateLayoutParams(Landroid/util/AttributeSet;)Landroid/widget/FrameLayout$LayoutParams;

    move-result-object p1

    return-object p1
.end method

.method public bridge synthetic getOverlay()Landroid/view/ViewOverlay;
    .locals 1

    invoke-virtual {p0}, Landroid/view/ViewGroup;->getOverlay()Landroid/view/ViewGroupOverlay;

    move-result-object v0

    return-object v0
.end method

.method public getText()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tz5;->OooOoOO:Ljava/lang/String;

    return-object v0
.end method

.method public final onScreenStateChanged(I)V
    .locals 0

    invoke-super {p0, p1}, Landroid/view/View;->onScreenStateChanged(I)V

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/tz5;->OooOoO0:Llyiahf/vczjk/wq0;

    invoke-virtual {p1}, Landroid/view/View;->clearAnimation()V

    :cond_0
    return-void
.end method

.method public setText(Ljava/lang/String;)V
    .locals 1

    invoke-virtual {p0}, Landroid/view/View;->getVisibility()I

    move-result v0

    if-nez v0, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/tz5;->OooOo0O:Z

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/tz5;->OooOoO:Landroid/widget/TextView;

    invoke-virtual {v0, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_0
    iput-object p1, p0, Llyiahf/vczjk/tz5;->OooOoOO:Ljava/lang/String;

    return-void
.end method
