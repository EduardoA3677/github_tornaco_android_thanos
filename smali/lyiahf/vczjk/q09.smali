.class public final Llyiahf/vczjk/q09;
.super Llyiahf/vczjk/oO0Oo0oo;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qg5;


# instance fields
.field public OooOOOo:Landroid/content/Context;

.field public OooOOo:Llyiahf/vczjk/a27;

.field public OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

.field public OooOOoo:Ljava/lang/ref/WeakReference;

.field public OooOo0:Llyiahf/vczjk/sg5;

.field public OooOo00:Z


# virtual methods
.method public final OooO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOo0:Llyiahf/vczjk/sg5;

    iget-object v1, p0, Llyiahf/vczjk/q09;->OooOOo:Llyiahf/vczjk/a27;

    invoke-virtual {v1, p0, v0}, Llyiahf/vczjk/a27;->OooOO0o(Llyiahf/vczjk/oO0Oo0oo;Llyiahf/vczjk/sg5;)Z

    return-void
.end method

.method public final OooO0O0()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/q09;->OooOo00:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/q09;->OooOo00:Z

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo:Llyiahf/vczjk/a27;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/a27;->OooOO0O(Llyiahf/vczjk/oO0Oo0oo;)V

    return-void
.end method

.method public final OooO0OO()Landroid/view/View;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOoo:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0o()Landroid/view/MenuInflater;
    .locals 2

    new-instance v0, Llyiahf/vczjk/y99;

    iget-object v1, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/y99;-><init>(Landroid/content/Context;)V

    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/sg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOo0:Llyiahf/vczjk/sg5;

    return-object v0
.end method

.method public final OooO0oO()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarContextView;->getSubtitle()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oo()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarContextView;->getTitle()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public final OooOO0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    iget-boolean v0, v0, Landroidx/appcompat/widget/ActionBarContextView;->OooOooo:Z

    return v0
.end method

.method public final OooOO0o(Landroid/view/View;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setCustomView(Landroid/view/View;)V

    if-eqz p1, :cond_0

    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/q09;->OooOOoo:Ljava/lang/ref/WeakReference;

    return-void
.end method

.method public final OooOOO(Ljava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setSubtitle(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOO0(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOOo:Landroid/content/Context;

    invoke-virtual {v0, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/q09;->OooOOO(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOOO(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOOo:Landroid/content/Context;

    invoke-virtual {v0, p1}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/q09;->OooOOOo(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOOo(Ljava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setTitle(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOo0(Z)V
    .locals 1

    iput-boolean p1, p0, Llyiahf/vczjk/oO0Oo0oo;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setTitleOptional(Z)V

    return-void
.end method

.method public final OooOo0O(Llyiahf/vczjk/sg5;Landroid/view/MenuItem;)Z
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/q09;->OooOOo:Llyiahf/vczjk/a27;

    iget-object p1, p1, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/pb7;

    invoke-virtual {p1, p0, p2}, Llyiahf/vczjk/pb7;->OooOoO0(Llyiahf/vczjk/oO0Oo0oo;Landroid/view/MenuItem;)Z

    move-result p1

    return p1
.end method

.method public final OooOoO(Llyiahf/vczjk/sg5;)V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/q09;->OooO()V

    iget-object p1, p0, Llyiahf/vczjk/q09;->OooOOo0:Landroidx/appcompat/widget/ActionBarContextView;

    iget-object p1, p1, Landroidx/appcompat/widget/ActionBarContextView;->OooOOOo:Landroidx/appcompat/widget/OooO0O0;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Landroidx/appcompat/widget/OooO0O0;->OooOOO()Z

    :cond_0
    return-void
.end method
