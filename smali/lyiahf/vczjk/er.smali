.class public final Llyiahf/vczjk/er;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/Window$Callback;


# instance fields
.field public OooOOO:Llyiahf/vczjk/wg7;

.field public final OooOOO0:Landroid/view/Window$Callback;

.field public OooOOOO:Z

.field public OooOOOo:Z

.field public final synthetic OooOOo:Llyiahf/vczjk/jr;

.field public OooOOo0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jr;Landroid/view/Window$Callback;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/er;->OooOOo:Llyiahf/vczjk/jr;

    if-eqz p2, :cond_0

    iput-object p2, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Window callback may not be null"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO00o(Landroid/view/Window$Callback;)V
    .locals 2

    const/4 v0, 0x1

    const/4 v1, 0x0

    :try_start_0
    iput-boolean v0, p0, Llyiahf/vczjk/er;->OooOOOO:Z

    invoke-interface {p1}, Landroid/view/Window$Callback;->onContentChanged()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iput-boolean v1, p0, Llyiahf/vczjk/er;->OooOOOO:Z

    return-void

    :catchall_0
    move-exception p1

    iput-boolean v1, p0, Llyiahf/vczjk/er;->OooOOOO:Z

    throw p1
.end method

.method public final OooO0O0(ILandroid/view/Menu;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1, p2}, Landroid/view/Window$Callback;->onMenuOpened(ILandroid/view/Menu;)Z

    move-result p1

    return p1
.end method

.method public final OooO0OO(ILandroid/view/Menu;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1, p2}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    return-void
.end method

.method public final OooO0Oo(Ljava/util/List;Landroid/view/Menu;I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-static {v0, p1, p2, p3}, Llyiahf/vczjk/wma;->OooO00o(Landroid/view/Window$Callback;Ljava/util/List;Landroid/view/Menu;I)V

    return-void
.end method

.method public final dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z

    move-result p1

    return p1
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/er;->OooOOOo:Z

    iget-object v1, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    if-eqz v0, :cond_0

    invoke-interface {v1, p1}, Landroid/view/Window$Callback;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    move-result p1

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOo:Llyiahf/vczjk/jr;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/jr;->OooOOoo(Landroid/view/KeyEvent;)Z

    move-result v0

    if-nez v0, :cond_2

    invoke-interface {v1, p1}, Landroid/view/Window$Callback;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    return p1

    :cond_2
    :goto_0
    const/4 p1, 0x1

    return p1
.end method

.method public final dispatchKeyShortcutEvent(Landroid/view/KeyEvent;)Z
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->dispatchKeyShortcutEvent(Landroid/view/KeyEvent;)Z

    move-result v0

    const/4 v1, 0x1

    if-nez v0, :cond_3

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v0

    iget-object v2, p0, Llyiahf/vczjk/er;->OooOOo:Llyiahf/vczjk/jr;

    invoke-virtual {v2}, Llyiahf/vczjk/jr;->OooOoOO()V

    iget-object v3, v2, Llyiahf/vczjk/jr;->OooOoOO:Llyiahf/vczjk/c6a;

    if-eqz v3, :cond_0

    invoke-virtual {v3, v0, p1}, Llyiahf/vczjk/c6a;->ooOO(ILandroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, v2, Llyiahf/vczjk/jr;->OoooOo0:Llyiahf/vczjk/ir;

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v3

    invoke-virtual {v2, v0, v3, p1}, Llyiahf/vczjk/jr;->Oooo000(Llyiahf/vczjk/ir;ILandroid/view/KeyEvent;)Z

    move-result v0

    if-eqz v0, :cond_1

    iget-object p1, v2, Llyiahf/vczjk/jr;->OoooOo0:Llyiahf/vczjk/ir;

    if-eqz p1, :cond_3

    iput-boolean v1, p1, Llyiahf/vczjk/ir;->OooOO0o:Z

    return v1

    :cond_1
    iget-object v0, v2, Llyiahf/vczjk/jr;->OoooOo0:Llyiahf/vczjk/ir;

    const/4 v3, 0x0

    if-nez v0, :cond_2

    invoke-virtual {v2, v3}, Llyiahf/vczjk/jr;->OooOoO0(I)Llyiahf/vczjk/ir;

    move-result-object v0

    invoke-virtual {v2, v0, p1}, Llyiahf/vczjk/jr;->Oooo00O(Llyiahf/vczjk/ir;Landroid/view/KeyEvent;)Z

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v4

    invoke-virtual {v2, v0, v4, p1}, Llyiahf/vczjk/jr;->Oooo000(Llyiahf/vczjk/ir;ILandroid/view/KeyEvent;)Z

    move-result p1

    iput-boolean v3, v0, Llyiahf/vczjk/ir;->OooOO0O:Z

    if-eqz p1, :cond_2

    goto :goto_0

    :cond_2
    return v3

    :cond_3
    :goto_0
    return v1
.end method

.method public final dispatchPopulateAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->dispatchPopulateAccessibilityEvent(Landroid/view/accessibility/AccessibilityEvent;)Z

    move-result p1

    return p1
.end method

.method public final dispatchTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->dispatchTouchEvent(Landroid/view/MotionEvent;)Z

    move-result p1

    return p1
.end method

.method public final dispatchTrackballEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->dispatchTrackballEvent(Landroid/view/MotionEvent;)Z

    move-result p1

    return p1
.end method

.method public final onActionModeFinished(Landroid/view/ActionMode;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->onActionModeFinished(Landroid/view/ActionMode;)V

    return-void
.end method

.method public final onActionModeStarted(Landroid/view/ActionMode;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->onActionModeStarted(Landroid/view/ActionMode;)V

    return-void
.end method

.method public final onAttachedToWindow()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0}, Landroid/view/Window$Callback;->onAttachedToWindow()V

    return-void
.end method

.method public final onContentChanged()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/er;->OooOOOO:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0}, Landroid/view/Window$Callback;->onContentChanged()V

    :cond_0
    return-void
.end method

.method public final onCreatePanelMenu(ILandroid/view/Menu;)Z
    .locals 1

    if-nez p1, :cond_0

    instance-of v0, p2, Llyiahf/vczjk/sg5;

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1, p2}, Landroid/view/Window$Callback;->onCreatePanelMenu(ILandroid/view/Menu;)Z

    move-result p1

    return p1
.end method

.method public final onCreatePanelView(I)Landroid/view/View;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO:Llyiahf/vczjk/wg7;

    if-eqz v0, :cond_1

    if-nez p1, :cond_0

    new-instance v1, Landroid/view/View;

    iget-object v0, v0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ww9;

    iget-object v0, v0, Llyiahf/vczjk/ww9;->Oooo00O:Landroidx/appcompat/widget/Oooo000;

    iget-object v0, v0, Landroidx/appcompat/widget/Oooo000;->OooO00o:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-direct {v1, v0}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    if-eqz v1, :cond_1

    return-object v1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->onCreatePanelView(I)Landroid/view/View;

    move-result-object p1

    return-object p1
.end method

.method public final onDetachedFromWindow()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0}, Landroid/view/Window$Callback;->onDetachedFromWindow()V

    return-void
.end method

.method public final onMenuItemSelected(ILandroid/view/MenuItem;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1, p2}, Landroid/view/Window$Callback;->onMenuItemSelected(ILandroid/view/MenuItem;)Z

    move-result p1

    return p1
.end method

.method public final onMenuOpened(ILandroid/view/Menu;)Z
    .locals 2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/er;->OooO0O0(ILandroid/view/Menu;)Z

    const/16 p2, 0x6c

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/er;->OooOOo:Llyiahf/vczjk/jr;

    if-ne p1, p2, :cond_0

    invoke-virtual {v1}, Llyiahf/vczjk/jr;->OooOoOO()V

    iget-object p1, v1, Llyiahf/vczjk/jr;->OooOoOO:Llyiahf/vczjk/c6a;

    if-eqz p1, :cond_1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/c6a;->Oooo0OO(Z)V

    goto :goto_0

    :cond_0
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1
    :goto_0
    return v0
.end method

.method public final onPanelClosed(ILandroid/view/Menu;)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/er;->OooOOo0:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1, p2}, Landroid/view/Window$Callback;->onPanelClosed(ILandroid/view/Menu;)V

    return-void

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/er;->OooO0OO(ILandroid/view/Menu;)V

    iget-object p2, p0, Llyiahf/vczjk/er;->OooOOo:Llyiahf/vczjk/jr;

    const/16 v0, 0x6c

    const/4 v1, 0x0

    if-ne p1, v0, :cond_1

    invoke-virtual {p2}, Llyiahf/vczjk/jr;->OooOoOO()V

    iget-object p1, p2, Llyiahf/vczjk/jr;->OooOoOO:Llyiahf/vczjk/c6a;

    if-eqz p1, :cond_2

    invoke-virtual {p1, v1}, Llyiahf/vczjk/c6a;->Oooo0OO(Z)V

    return-void

    :cond_1
    if-nez p1, :cond_3

    invoke-virtual {p2, p1}, Llyiahf/vczjk/jr;->OooOoO0(I)Llyiahf/vczjk/ir;

    move-result-object p1

    iget-boolean v0, p1, Llyiahf/vczjk/ir;->OooOOO0:Z

    if-eqz v0, :cond_2

    invoke-virtual {p2, p1, v1}, Llyiahf/vczjk/jr;->OooOOo0(Llyiahf/vczjk/ir;Z)V

    :cond_2
    return-void

    :cond_3
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method

.method public final onPointerCaptureChanged(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-static {v0, p1}, Llyiahf/vczjk/xma;->OooO00o(Landroid/view/Window$Callback;Z)V

    return-void
.end method

.method public final onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z
    .locals 5

    instance-of v0, p3, Llyiahf/vczjk/sg5;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/sg5;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    const/4 v1, 0x0

    if-nez p1, :cond_1

    if-nez v0, :cond_1

    return v1

    :cond_1
    const/4 v2, 0x1

    if-eqz v0, :cond_2

    iput-boolean v2, v0, Llyiahf/vczjk/sg5;->OooOo:Z

    :cond_2
    iget-object v3, p0, Llyiahf/vczjk/er;->OooOOO:Llyiahf/vczjk/wg7;

    if-eqz v3, :cond_3

    if-nez p1, :cond_3

    iget-object v3, v3, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ww9;

    iget-boolean v4, v3, Llyiahf/vczjk/ww9;->Oooo0O0:Z

    if-nez v4, :cond_3

    iget-object v4, v3, Llyiahf/vczjk/ww9;->Oooo00O:Landroidx/appcompat/widget/Oooo000;

    iput-boolean v2, v4, Landroidx/appcompat/widget/Oooo000;->OooOO0o:Z

    iput-boolean v2, v3, Llyiahf/vczjk/ww9;->Oooo0O0:Z

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v2, p1, p2, p3}, Landroid/view/Window$Callback;->onPreparePanel(ILandroid/view/View;Landroid/view/Menu;)Z

    move-result p1

    if-eqz v0, :cond_4

    iput-boolean v1, v0, Llyiahf/vczjk/sg5;->OooOo:Z

    :cond_4
    return p1
.end method

.method public final onProvideKeyboardShortcuts(Ljava/util/List;Landroid/view/Menu;I)V
    .locals 2

    const/4 v0, 0x0

    iget-object v1, p0, Llyiahf/vczjk/er;->OooOOo:Llyiahf/vczjk/jr;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/jr;->OooOoO0(I)Llyiahf/vczjk/ir;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ir;->OooO0oo:Llyiahf/vczjk/sg5;

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, v0, p3}, Llyiahf/vczjk/er;->OooO0Oo(Ljava/util/List;Landroid/view/Menu;I)V

    return-void

    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/er;->OooO0Oo(Ljava/util/List;Landroid/view/Menu;I)V

    return-void
.end method

.method public final onSearchRequested()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0}, Landroid/view/Window$Callback;->onSearchRequested()Z

    move-result v0

    return v0
.end method

.method public final onSearchRequested(Landroid/view/SearchEvent;)Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-static {v0, p1}, Llyiahf/vczjk/vma;->OooO00o(Landroid/view/Window$Callback;Landroid/view/SearchEvent;)Z

    move-result p1

    return p1
.end method

.method public final onWindowAttributesChanged(Landroid/view/WindowManager$LayoutParams;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->onWindowAttributesChanged(Landroid/view/WindowManager$LayoutParams;)V

    return-void
.end method

.method public final onWindowFocusChanged(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-interface {v0, p1}, Landroid/view/Window$Callback;->onWindowFocusChanged(Z)V

    return-void
.end method

.method public final onWindowStartingActionMode(Landroid/view/ActionMode$Callback;)Landroid/view/ActionMode;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public final onWindowStartingActionMode(Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;
    .locals 8

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/er;->OooOOo:Llyiahf/vczjk/jr;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz p2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/er;->OooOOO0:Landroid/view/Window$Callback;

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/vma;->OooO0O0(Landroid/view/Window$Callback;Landroid/view/ActionMode$Callback;I)Landroid/view/ActionMode;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p2, Llyiahf/vczjk/pb7;

    iget-object v2, v1, Llyiahf/vczjk/jr;->OooOo0o:Landroid/content/Context;

    invoke-direct {p2, v2, p1}, Llyiahf/vczjk/pb7;-><init>(Landroid/content/Context;Landroid/view/ActionMode$Callback;)V

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/oO0Oo0oo;->OooO0O0()V

    :cond_1
    new-instance p1, Llyiahf/vczjk/a27;

    const/4 v2, 0x5

    invoke-direct {p1, v2, v1, p2}, Llyiahf/vczjk/a27;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-virtual {v1}, Llyiahf/vczjk/jr;->OooOoOO()V

    iget-object v2, v1, Llyiahf/vczjk/jr;->OooOoOO:Llyiahf/vczjk/c6a;

    if-eqz v2, :cond_2

    invoke-virtual {v2, p1}, Llyiahf/vczjk/c6a;->o0OOO0o(Llyiahf/vczjk/a27;)Llyiahf/vczjk/oO0Oo0oo;

    move-result-object v2

    iput-object v2, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    :cond_2
    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    const/4 v3, 0x0

    if-nez v2, :cond_10

    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo0OO:Llyiahf/vczjk/fia;

    if-eqz v2, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/fia;->OooO0O0()V

    :cond_3
    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    if-eqz v2, :cond_4

    invoke-virtual {v2}, Llyiahf/vczjk/oO0Oo0oo;->OooO0O0()V

    :cond_4
    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    const/4 v4, 0x0

    if-nez v2, :cond_9

    iget-boolean v2, v1, Llyiahf/vczjk/jr;->OoooOO0:Z

    iget-object v5, v1, Llyiahf/vczjk/jr;->OooOo0o:Landroid/content/Context;

    if-eqz v2, :cond_6

    new-instance v2, Landroid/util/TypedValue;

    invoke-direct {v2}, Landroid/util/TypedValue;-><init>()V

    invoke-virtual {v5}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v6

    sget v7, Landroidx/appcompat/R$attr;->actionBarTheme:I

    invoke-virtual {v6, v7, v2, v0}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v7, v2, Landroid/util/TypedValue;->resourceId:I

    if-eqz v7, :cond_5

    invoke-virtual {v5}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v7

    invoke-virtual {v7}, Landroid/content/res/Resources;->newTheme()Landroid/content/res/Resources$Theme;

    move-result-object v7

    invoke-virtual {v7, v6}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    iget v6, v2, Landroid/util/TypedValue;->resourceId:I

    invoke-virtual {v7, v6, v0}, Landroid/content/res/Resources$Theme;->applyStyle(IZ)V

    new-instance v6, Llyiahf/vczjk/uo1;

    invoke-direct {v6, v5, v4}, Llyiahf/vczjk/uo1;-><init>(Landroid/content/Context;I)V

    invoke-virtual {v6}, Llyiahf/vczjk/uo1;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v5

    invoke-virtual {v5, v7}, Landroid/content/res/Resources$Theme;->setTo(Landroid/content/res/Resources$Theme;)V

    move-object v5, v6

    :cond_5
    new-instance v6, Landroidx/appcompat/widget/ActionBarContextView;

    invoke-direct {v6, v5, v3}, Landroidx/appcompat/widget/ActionBarContextView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    iput-object v6, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    new-instance v6, Landroid/widget/PopupWindow;

    sget v7, Landroidx/appcompat/R$attr;->actionModePopupWindowStyle:I

    invoke-direct {v6, v5, v3, v7}, Landroid/widget/PopupWindow;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    iput-object v6, v1, Llyiahf/vczjk/jr;->Oooo0:Landroid/widget/PopupWindow;

    const/4 v7, 0x2

    invoke-virtual {v6, v7}, Landroid/widget/PopupWindow;->setWindowLayoutType(I)V

    iget-object v6, v1, Llyiahf/vczjk/jr;->Oooo0:Landroid/widget/PopupWindow;

    iget-object v7, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v6, v7}, Landroid/widget/PopupWindow;->setContentView(Landroid/view/View;)V

    iget-object v6, v1, Llyiahf/vczjk/jr;->Oooo0:Landroid/widget/PopupWindow;

    const/4 v7, -0x1

    invoke-virtual {v6, v7}, Landroid/widget/PopupWindow;->setWidth(I)V

    invoke-virtual {v5}, Landroid/content/Context;->getTheme()Landroid/content/res/Resources$Theme;

    move-result-object v6

    sget v7, Landroidx/appcompat/R$attr;->actionBarSize:I

    invoke-virtual {v6, v7, v2, v0}, Landroid/content/res/Resources$Theme;->resolveAttribute(ILandroid/util/TypedValue;Z)Z

    iget v2, v2, Landroid/util/TypedValue;->data:I

    invoke-virtual {v5}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v5

    invoke-virtual {v5}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v5

    invoke-static {v2, v5}, Landroid/util/TypedValue;->complexToDimensionPixelSize(ILandroid/util/DisplayMetrics;)I

    move-result v2

    iget-object v5, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v5, v2}, Landroidx/appcompat/widget/ActionBarContextView;->setContentHeight(I)V

    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo0:Landroid/widget/PopupWindow;

    const/4 v5, -0x2

    invoke-virtual {v2, v5}, Landroid/widget/PopupWindow;->setHeight(I)V

    new-instance v2, Llyiahf/vczjk/yq;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/yq;-><init>(Llyiahf/vczjk/jr;I)V

    iput-object v2, v1, Llyiahf/vczjk/jr;->Oooo0O0:Llyiahf/vczjk/yq;

    goto :goto_2

    :cond_6
    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo0o:Landroid/view/ViewGroup;

    sget v6, Landroidx/appcompat/R$id;->action_mode_bar_stub:I

    invoke-virtual {v2, v6}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/widget/ViewStubCompat;

    if-eqz v2, :cond_9

    invoke-virtual {v1}, Llyiahf/vczjk/jr;->OooOoOO()V

    iget-object v6, v1, Llyiahf/vczjk/jr;->OooOoOO:Llyiahf/vczjk/c6a;

    if-eqz v6, :cond_7

    invoke-virtual {v6}, Llyiahf/vczjk/c6a;->Ooooo00()Landroid/content/Context;

    move-result-object v6

    goto :goto_0

    :cond_7
    move-object v6, v3

    :goto_0
    if-nez v6, :cond_8

    goto :goto_1

    :cond_8
    move-object v5, v6

    :goto_1
    invoke-static {v5}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v5

    invoke-virtual {v2, v5}, Landroidx/appcompat/widget/ViewStubCompat;->setLayoutInflater(Landroid/view/LayoutInflater;)V

    invoke-virtual {v2}, Landroidx/appcompat/widget/ViewStubCompat;->OooO00o()Landroid/view/View;

    move-result-object v2

    check-cast v2, Landroidx/appcompat/widget/ActionBarContextView;

    iput-object v2, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    :cond_9
    :goto_2
    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    if-eqz v2, :cond_f

    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo0OO:Llyiahf/vczjk/fia;

    if-eqz v2, :cond_a

    invoke-virtual {v2}, Llyiahf/vczjk/fia;->OooO0O0()V

    :cond_a
    iget-object v2, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v2}, Landroidx/appcompat/widget/ActionBarContextView;->OooO0o0()V

    new-instance v2, Llyiahf/vczjk/q09;

    iget-object v5, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v5}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v5

    iget-object v6, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-direct {v2}, Llyiahf/vczjk/oO0Oo0oo;-><init>()V

    iput-object v5, v2, Llyiahf/vczjk/q09;->OooOOOo:Landroid/content/Context;

    iput-object v6, v2, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    iput-object p1, v2, Llyiahf/vczjk/q09;->OooOOo:Llyiahf/vczjk/a27;

    new-instance v5, Llyiahf/vczjk/sg5;

    invoke-virtual {v6}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v6

    invoke-direct {v5, v6}, Llyiahf/vczjk/sg5;-><init>(Landroid/content/Context;)V

    iput v0, v5, Llyiahf/vczjk/sg5;->OooOO0o:I

    iput-object v5, v2, Llyiahf/vczjk/q09;->OooOo0:Llyiahf/vczjk/sg5;

    iput-object v2, v5, Llyiahf/vczjk/sg5;->OooO0o0:Llyiahf/vczjk/qg5;

    iget-object p1, p1, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/pb7;

    invoke-virtual {p1, v2, v5}, Llyiahf/vczjk/pb7;->OooOoO(Llyiahf/vczjk/oO0Oo0oo;Llyiahf/vczjk/sg5;)Z

    move-result p1

    if-eqz p1, :cond_e

    invoke-virtual {v2}, Llyiahf/vczjk/q09;->OooO()V

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1, v2}, Landroidx/appcompat/widget/ActionBarContextView;->OooO0OO(Llyiahf/vczjk/oO0Oo0oo;)V

    iput-object v2, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    iget-boolean p1, v1, Llyiahf/vczjk/jr;->Oooo0o0:Z

    if-eqz p1, :cond_b

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo0o:Landroid/view/ViewGroup;

    if-eqz p1, :cond_b

    invoke-virtual {p1}, Landroid/view/View;->isLaidOut()Z

    move-result p1

    if-eqz p1, :cond_b

    move p1, v0

    goto :goto_3

    :cond_b
    move p1, v4

    :goto_3
    const/high16 v2, 0x3f800000    # 1.0f

    if-eqz p1, :cond_c

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    const/4 v4, 0x0

    invoke-virtual {p1, v4}, Landroid/view/View;->setAlpha(F)V

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-static {p1}, Llyiahf/vczjk/xfa;->OooO00o(Landroid/view/View;)Llyiahf/vczjk/fia;

    move-result-object p1

    invoke-virtual {p1, v2}, Llyiahf/vczjk/fia;->OooO00o(F)V

    iput-object p1, v1, Llyiahf/vczjk/jr;->Oooo0OO:Llyiahf/vczjk/fia;

    new-instance v2, Llyiahf/vczjk/zq;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/zq;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v2}, Llyiahf/vczjk/fia;->OooO0Oo(Llyiahf/vczjk/hia;)V

    goto :goto_4

    :cond_c
    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1, v2}, Landroid/view/View;->setAlpha(F)V

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1, v4}, Landroidx/appcompat/widget/ActionBarContextView;->setVisibility(I)V

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    instance-of p1, p1, Landroid/view/View;

    if-eqz p1, :cond_d

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    check-cast p1, Landroid/view/View;

    sget-object v0, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    invoke-static {p1}, Llyiahf/vczjk/mfa;->OooO0OO(Landroid/view/View;)V

    :cond_d
    :goto_4
    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo0:Landroid/widget/PopupWindow;

    if-eqz p1, :cond_f

    iget-object p1, v1, Llyiahf/vczjk/jr;->OooOo:Landroid/view/Window;

    invoke-virtual {p1}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    iget-object v0, v1, Llyiahf/vczjk/jr;->Oooo0O0:Llyiahf/vczjk/yq;

    invoke-virtual {p1, v0}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    goto :goto_5

    :cond_e
    iput-object v3, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    :cond_f
    :goto_5
    invoke-virtual {v1}, Llyiahf/vczjk/jr;->Oooo0()V

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    iput-object p1, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    :cond_10
    invoke-virtual {v1}, Llyiahf/vczjk/jr;->Oooo0()V

    iget-object p1, v1, Llyiahf/vczjk/jr;->Oooo00O:Llyiahf/vczjk/oO0Oo0oo;

    if-eqz p1, :cond_11

    invoke-virtual {p2, p1}, Llyiahf/vczjk/pb7;->OooOOO0(Llyiahf/vczjk/oO0Oo0oo;)Llyiahf/vczjk/v99;

    move-result-object p1

    return-object p1

    :cond_11
    return-object v3
.end method
