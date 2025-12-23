.class public Llyiahf/vczjk/a71;
.super Landroid/app/Dialog;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/uy4;
.implements Llyiahf/vczjk/ia6;
.implements Llyiahf/vczjk/h68;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/f68;

.field public OooOOO0:Llyiahf/vczjk/wy4;

.field public final OooOOOO:Llyiahf/vczjk/ha6;


# direct methods
.method public constructor <init>(Landroid/content/Context;I)V
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1, p2}, Landroid/app/Dialog;-><init>(Landroid/content/Context;I)V

    new-instance p1, Llyiahf/vczjk/g68;

    new-instance p2, Llyiahf/vczjk/ku7;

    const/4 v0, 0x4

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/g68;-><init>(Llyiahf/vczjk/h68;Llyiahf/vczjk/ku7;)V

    new-instance p2, Llyiahf/vczjk/f68;

    invoke-direct {p2, p1}, Llyiahf/vczjk/f68;-><init>(Llyiahf/vczjk/g68;)V

    iput-object p2, p0, Llyiahf/vczjk/a71;->OooOOO:Llyiahf/vczjk/f68;

    new-instance p1, Llyiahf/vczjk/ha6;

    new-instance p2, Llyiahf/vczjk/oO0O00o0;

    const/16 v0, 0x11

    invoke-direct {p2, p0, v0}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    invoke-direct {p1, p2}, Llyiahf/vczjk/ha6;-><init>(Ljava/lang/Runnable;)V

    iput-object p1, p0, Llyiahf/vczjk/a71;->OooOOOO:Llyiahf/vczjk/ha6;

    return-void
.end method

.method public static OooO0O0(Llyiahf/vczjk/a71;)V
    .locals 0

    invoke-super {p0}, Landroid/app/Dialog;->onBackPressed()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/ha6;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a71;->OooOOOO:Llyiahf/vczjk/ha6;

    return-object v0
.end method

.method public final OooO0OO()V
    .locals 3

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    const-string v1, "window!!.decorView"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p0}, Llyiahf/vczjk/dr6;->OooOo0(Landroid/view/View;Llyiahf/vczjk/uy4;)V

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    sget v2, Landroidx/activity/R$id;->view_tree_on_back_pressed_dispatcher_owner:I

    invoke-virtual {v0, v2, p0}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object v0

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0, p0}, Llyiahf/vczjk/wr6;->OooOo0o(Landroid/view/View;Llyiahf/vczjk/h68;)V

    return-void
.end method

.method public addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    const-string v0, "view"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/a71;->OooO0OO()V

    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->addContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public final getLifecycle()Llyiahf/vczjk/ky4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/wy4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;)V

    iput-object v0, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    :cond_0
    return-object v0
.end method

.method public final getSavedStateRegistry()Llyiahf/vczjk/e68;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a71;->OooOOO:Llyiahf/vczjk/f68;

    iget-object v0, v0, Llyiahf/vczjk/f68;->OooO0O0:Llyiahf/vczjk/e68;

    return-object v0
.end method

.method public final onBackPressed()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a71;->OooOOOO:Llyiahf/vczjk/ha6;

    invoke-virtual {v0}, Llyiahf/vczjk/ha6;->OooO0OO()V

    return-void
.end method

.method public onCreate(Landroid/os/Bundle;)V
    .locals 2

    invoke-super {p0, p1}, Landroid/app/Dialog;->onCreate(Landroid/os/Bundle;)V

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x21

    if-lt v0, v1, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/oo0OOoo;->OooOOo0(Llyiahf/vczjk/a71;)Landroid/window/OnBackInvokedDispatcher;

    move-result-object v0

    const-string v1, "onBackInvokedDispatcher"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/a71;->OooOOOO:Llyiahf/vczjk/ha6;

    iput-object v0, v1, Llyiahf/vczjk/ha6;->OooO0o0:Landroid/window/OnBackInvokedDispatcher;

    iget-boolean v0, v1, Llyiahf/vczjk/ha6;->OooO0oO:Z

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ha6;->OooO0Oo(Z)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/a71;->OooOOO:Llyiahf/vczjk/f68;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/f68;->OooO00o(Landroid/os/Bundle;)V

    iget-object p1, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    if-nez p1, :cond_1

    new-instance p1, Llyiahf/vczjk/wy4;

    invoke-direct {p1, p0}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;)V

    iput-object p1, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    :cond_1
    sget-object v0, Llyiahf/vczjk/iy4;->ON_CREATE:Llyiahf/vczjk/iy4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onSaveInstanceState()Landroid/os/Bundle;
    .locals 2

    invoke-super {p0}, Landroid/app/Dialog;->onSaveInstanceState()Landroid/os/Bundle;

    move-result-object v0

    const-string v1, "super.onSaveInstanceState()"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/a71;->OooOOO:Llyiahf/vczjk/f68;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/f68;->OooO0O0(Landroid/os/Bundle;)V

    return-object v0
.end method

.method public final onStart()V
    .locals 2

    invoke-super {p0}, Landroid/app/Dialog;->onStart()V

    iget-object v0, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/wy4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;)V

    iput-object v0, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    :cond_0
    sget-object v1, Llyiahf/vczjk/iy4;->ON_RESUME:Llyiahf/vczjk/iy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    return-void
.end method

.method public onStop()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/wy4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/wy4;-><init>(Llyiahf/vczjk/uy4;)V

    iput-object v0, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    :cond_0
    sget-object v1, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/wy4;->OooO0o(Llyiahf/vczjk/iy4;)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/a71;->OooOOO0:Llyiahf/vczjk/wy4;

    invoke-super {p0}, Landroid/app/Dialog;->onStop()V

    return-void
.end method

.method public setContentView(I)V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/a71;->OooO0OO()V

    invoke-super {p0, p1}, Landroid/app/Dialog;->setContentView(I)V

    return-void
.end method

.method public setContentView(Landroid/view/View;)V
    .locals 1

    const-string v0, "view"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/a71;->OooO0OO()V

    invoke-super {p0, p1}, Landroid/app/Dialog;->setContentView(Landroid/view/View;)V

    return-void
.end method

.method public setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    const-string v0, "view"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p0}, Llyiahf/vczjk/a71;->OooO0OO()V

    invoke-super {p0, p1, p2}, Landroid/app/Dialog;->setContentView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method
