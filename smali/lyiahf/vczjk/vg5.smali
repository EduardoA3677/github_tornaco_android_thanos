.class public final Llyiahf/vczjk/vg5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/content/DialogInterface$OnKeyListener;
.implements Landroid/content/DialogInterface$OnClickListener;
.implements Landroid/content/DialogInterface$OnDismissListener;
.implements Llyiahf/vczjk/ci5;


# instance fields
.field public OooOOO:Llyiahf/vczjk/x3;

.field public OooOOO0:Llyiahf/vczjk/u79;

.field public OooOOOO:Llyiahf/vczjk/g15;


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/sg5;Z)V
    .locals 0

    if-nez p2, :cond_0

    iget-object p2, p0, Llyiahf/vczjk/vg5;->OooOOO0:Llyiahf/vczjk/u79;

    if-ne p1, p2, :cond_1

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/vg5;->OooOOO:Llyiahf/vczjk/x3;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/x3;->dismiss()V

    :cond_1
    return-void
.end method

.method public final OoooO0(Llyiahf/vczjk/sg5;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final onClick(Landroid/content/DialogInterface;I)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/vg5;->OooOOOO:Llyiahf/vczjk/g15;

    iget-object v0, p1, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/f15;

    invoke-direct {v0, p1}, Llyiahf/vczjk/f15;-><init>(Llyiahf/vczjk/g15;)V

    iput-object v0, p1, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/f15;->OooO0O0(I)Llyiahf/vczjk/dh5;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/vg5;->OooOOO0:Llyiahf/vczjk/u79;

    const/4 v0, 0x0

    const/4 v1, 0x0

    invoke-virtual {p2, p1, v1, v0}, Llyiahf/vczjk/sg5;->OooOOo0(Landroid/view/MenuItem;Llyiahf/vczjk/di5;I)Z

    return-void
.end method

.method public final onDismiss(Landroid/content/DialogInterface;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/vg5;->OooOOOO:Llyiahf/vczjk/g15;

    iget-object v0, p0, Llyiahf/vczjk/vg5;->OooOOO0:Llyiahf/vczjk/u79;

    const/4 v1, 0x1

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/g15;->OooO0o0(Llyiahf/vczjk/sg5;Z)V

    return-void
.end method

.method public final onKey(Landroid/content/DialogInterface;ILandroid/view/KeyEvent;)Z
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/vg5;->OooOOO0:Llyiahf/vczjk/u79;

    const/16 v1, 0x52

    if-eq p2, v1, :cond_0

    const/4 v1, 0x4

    if-ne p2, v1, :cond_2

    :cond_0
    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I

    move-result v1

    const/4 v2, 0x1

    if-nez v1, :cond_1

    invoke-virtual {p3}, Landroid/view/KeyEvent;->getRepeatCount()I

    move-result v1

    if-nez v1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/vg5;->OooOOO:Llyiahf/vczjk/x3;

    invoke-virtual {p1}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object p1

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Landroid/view/View;->getKeyDispatcherState()Landroid/view/KeyEvent$DispatcherState;

    move-result-object p1

    if-eqz p1, :cond_2

    invoke-virtual {p1, p3, p0}, Landroid/view/KeyEvent$DispatcherState;->startTracking(Landroid/view/KeyEvent;Ljava/lang/Object;)V

    return v2

    :cond_1
    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I

    move-result v1

    if-ne v1, v2, :cond_2

    invoke-virtual {p3}, Landroid/view/KeyEvent;->isCanceled()Z

    move-result v1

    if-nez v1, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/vg5;->OooOOO:Llyiahf/vczjk/x3;

    invoke-virtual {v1}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v1

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v1

    if-eqz v1, :cond_2

    invoke-virtual {v1}, Landroid/view/View;->getKeyDispatcherState()Landroid/view/KeyEvent$DispatcherState;

    move-result-object v1

    if-eqz v1, :cond_2

    invoke-virtual {v1, p3}, Landroid/view/KeyEvent$DispatcherState;->isTracking(Landroid/view/KeyEvent;)Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-virtual {v0, v2}, Llyiahf/vczjk/sg5;->OooO0OO(Z)V

    invoke-interface {p1}, Landroid/content/DialogInterface;->dismiss()V

    return v2

    :cond_2
    const/4 p1, 0x0

    invoke-virtual {v0, p2, p3, p1}, Llyiahf/vczjk/sg5;->performShortcut(ILandroid/view/KeyEvent;I)Z

    move-result p1

    return p1
.end method
