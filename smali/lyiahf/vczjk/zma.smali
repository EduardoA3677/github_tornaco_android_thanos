.class public final Llyiahf/vczjk/zma;
.super Llyiahf/vczjk/oO0Oo0oo;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qg5;


# instance fields
.field public final OooOOOo:Landroid/content/Context;

.field public OooOOo:Llyiahf/vczjk/a27;

.field public final OooOOo0:Llyiahf/vczjk/sg5;

.field public OooOOoo:Ljava/lang/ref/WeakReference;

.field public final synthetic OooOo00:Llyiahf/vczjk/ana;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ana;Landroid/content/Context;Llyiahf/vczjk/a27;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/oO0Oo0oo;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iput-object p2, p0, Llyiahf/vczjk/zma;->OooOOOo:Landroid/content/Context;

    iput-object p3, p0, Llyiahf/vczjk/zma;->OooOOo:Llyiahf/vczjk/a27;

    new-instance p1, Llyiahf/vczjk/sg5;

    invoke-direct {p1, p2}, Llyiahf/vczjk/sg5;-><init>(Landroid/content/Context;)V

    const/4 p2, 0x1

    iput p2, p1, Llyiahf/vczjk/sg5;->OooOO0o:I

    iput-object p1, p0, Llyiahf/vczjk/zma;->OooOOo0:Llyiahf/vczjk/sg5;

    iput-object p0, p1, Llyiahf/vczjk/sg5;->OooO0o0:Llyiahf/vczjk/qg5;

    return-void
.end method


# virtual methods
.method public final OooO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0oo:Llyiahf/vczjk/zma;

    if-eq v0, p0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOOo0:Llyiahf/vczjk/sg5;

    invoke-virtual {v0}, Llyiahf/vczjk/sg5;->OooOoO0()V

    :try_start_0
    iget-object v1, p0, Llyiahf/vczjk/zma;->OooOOo:Llyiahf/vczjk/a27;

    invoke-virtual {v1, p0, v0}, Llyiahf/vczjk/a27;->OooOO0o(Llyiahf/vczjk/oO0Oo0oo;Llyiahf/vczjk/sg5;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v0}, Llyiahf/vczjk/sg5;->OooOo()V

    return-void

    :catchall_0
    move-exception v1

    invoke-virtual {v0}, Llyiahf/vczjk/sg5;->OooOo()V

    throw v1
.end method

.method public final OooO0O0()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v1, v0, Llyiahf/vczjk/ana;->Oooo0oo:Llyiahf/vczjk/zma;

    if-eq v1, p0, :cond_0

    return-void

    :cond_0
    iget-boolean v1, v0, Llyiahf/vczjk/ana;->o000oOoO:Z

    if-eqz v1, :cond_1

    iput-object p0, v0, Llyiahf/vczjk/ana;->Oooo:Llyiahf/vczjk/zma;

    iget-object v1, p0, Llyiahf/vczjk/zma;->OooOOo:Llyiahf/vczjk/a27;

    iput-object v1, v0, Llyiahf/vczjk/ana;->OoooO00:Llyiahf/vczjk/a27;

    goto :goto_0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/zma;->OooOOo:Llyiahf/vczjk/a27;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/a27;->OooOO0O(Llyiahf/vczjk/oO0Oo0oo;)V

    :goto_0
    const/4 v1, 0x0

    iput-object v1, p0, Llyiahf/vczjk/zma;->OooOOo:Llyiahf/vczjk/a27;

    const/4 v2, 0x0

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ana;->o0OO00O(Z)V

    iget-object v2, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    iget-object v3, v2, Landroidx/appcompat/widget/ActionBarContextView;->OooOo0o:Landroid/view/View;

    if-nez v3, :cond_2

    invoke-virtual {v2}, Landroidx/appcompat/widget/ActionBarContextView;->OooO0o0()V

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/ana;->Oooo0:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    iget-boolean v3, v0, Llyiahf/vczjk/ana;->OoooOoo:Z

    invoke-virtual {v2, v3}, Landroidx/appcompat/widget/ActionBarOverlayLayout;->setHideOnContentScrollEnabled(Z)V

    iput-object v1, v0, Llyiahf/vczjk/ana;->Oooo0oo:Llyiahf/vczjk/zma;

    return-void
.end method

.method public final OooO0OO()Landroid/view/View;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOOoo:Ljava/lang/ref/WeakReference;

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

    iget-object v1, p0, Llyiahf/vczjk/zma;->OooOOOo:Landroid/content/Context;

    invoke-direct {v0, v1}, Llyiahf/vczjk/y99;-><init>(Landroid/content/Context;)V

    return-object v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/sg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOOo0:Llyiahf/vczjk/sg5;

    return-object v0
.end method

.method public final OooO0oO()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarContextView;->getSubtitle()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oo()Ljava/lang/CharSequence;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0}, Landroidx/appcompat/widget/ActionBarContextView;->getTitle()Ljava/lang/CharSequence;

    move-result-object v0

    return-object v0
.end method

.method public final OooOO0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    iget-boolean v0, v0, Landroidx/appcompat/widget/ActionBarContextView;->OooOooo:Z

    return v0
.end method

.method public final OooOO0o(Landroid/view/View;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setCustomView(Landroid/view/View;)V

    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, Llyiahf/vczjk/zma;->OooOOoo:Ljava/lang/ref/WeakReference;

    return-void
.end method

.method public final OooOOO(Ljava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setSubtitle(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOO0(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo00O:Landroid/content/Context;

    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/zma;->OooOOO(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOOO(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo00O:Landroid/content/Context;

    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    invoke-virtual {v0, p1}, Landroid/content/res/Resources;->getString(I)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/zma;->OooOOOo(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOOo(Ljava/lang/CharSequence;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setTitle(Ljava/lang/CharSequence;)V

    return-void
.end method

.method public final OooOOo0(Z)V
    .locals 1

    iput-boolean p1, p0, Llyiahf/vczjk/oO0Oo0oo;->OooOOO:Z

    iget-object v0, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object v0, v0, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ActionBarContextView;->setTitleOptional(Z)V

    return-void
.end method

.method public final OooOo0O(Llyiahf/vczjk/sg5;Landroid/view/MenuItem;)Z
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/zma;->OooOOo:Llyiahf/vczjk/a27;

    if-eqz p1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/a27;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/pb7;

    invoke-virtual {p1, p0, p2}, Llyiahf/vczjk/pb7;->OooOoO0(Llyiahf/vczjk/oO0Oo0oo;Landroid/view/MenuItem;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final OooOoO(Llyiahf/vczjk/sg5;)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/zma;->OooOOo:Llyiahf/vczjk/a27;

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/zma;->OooO()V

    iget-object p1, p0, Llyiahf/vczjk/zma;->OooOo00:Llyiahf/vczjk/ana;

    iget-object p1, p1, Llyiahf/vczjk/ana;->Oooo0o0:Landroidx/appcompat/widget/ActionBarContextView;

    iget-object p1, p1, Landroidx/appcompat/widget/ActionBarContextView;->OooOOOo:Landroidx/appcompat/widget/OooO0O0;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Landroidx/appcompat/widget/OooO0O0;->OooOOO()Z

    :cond_1
    :goto_0
    return-void
.end method
