.class public final Llyiahf/vczjk/g15;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/di5;
.implements Landroid/widget/AdapterView$OnItemClickListener;


# instance fields
.field public OooOOO:Landroid/view/LayoutInflater;

.field public OooOOO0:Landroid/content/Context;

.field public OooOOOO:Llyiahf/vczjk/sg5;

.field public OooOOOo:Landroidx/appcompat/view/menu/ExpandedMenuView;

.field public OooOOo:Llyiahf/vczjk/ci5;

.field public final OooOOo0:I

.field public OooOOoo:Llyiahf/vczjk/f15;


# direct methods
.method public constructor <init>(Landroid/content/ContextWrapper;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Llyiahf/vczjk/g15;->OooOOo0:I

    iput-object p1, p0, Llyiahf/vczjk/g15;->OooOOO0:Landroid/content/Context;

    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/g15;->OooOOO:Landroid/view/LayoutInflater;

    return-void
.end method


# virtual methods
.method public final OooO(Landroid/os/Parcelable;)V
    .locals 1

    check-cast p1, Landroid/os/Bundle;

    const-string v0, "android:menu:list"

    invoke-virtual {p1, v0}, Landroid/os/Bundle;->getSparseParcelableArray(Ljava/lang/String;)Landroid/util/SparseArray;

    move-result-object p1

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/g15;->OooOOOo:Landroidx/appcompat/view/menu/ExpandedMenuView;

    invoke-virtual {v0, p1}, Landroid/view/View;->restoreHierarchyState(Landroid/util/SparseArray;)V

    :cond_0
    return-void
.end method

.method public final OooO0O0(Llyiahf/vczjk/ci5;)V
    .locals 0

    const/4 p0, 0x0

    throw p0
.end method

.method public final OooO0OO(Z)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/f15;->notifyDataSetChanged()V

    :cond_0
    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/u79;)Z
    .locals 7

    invoke-virtual {p1}, Llyiahf/vczjk/sg5;->hasVisibleItems()Z

    move-result v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    new-instance v0, Llyiahf/vczjk/vg5;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object p1, v0, Llyiahf/vczjk/vg5;->OooOOO0:Llyiahf/vczjk/u79;

    new-instance v1, Llyiahf/vczjk/w3;

    iget-object v2, p1, Llyiahf/vczjk/sg5;->OooO00o:Landroid/content/Context;

    invoke-direct {v1, v2}, Llyiahf/vczjk/w3;-><init>(Landroid/content/Context;)V

    new-instance v3, Llyiahf/vczjk/g15;

    iget-object v4, v1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s3;

    iget-object v5, v4, Llyiahf/vczjk/s3;->OooO00o:Landroid/view/ContextThemeWrapper;

    sget v6, Landroidx/appcompat/R$layout;->abc_list_menu_item_layout:I

    invoke-direct {v3, v5, v6}, Llyiahf/vczjk/g15;-><init>(Landroid/content/ContextWrapper;I)V

    iput-object v3, v0, Llyiahf/vczjk/vg5;->OooOOOO:Llyiahf/vczjk/g15;

    iput-object v0, v3, Llyiahf/vczjk/g15;->OooOOo:Llyiahf/vczjk/ci5;

    invoke-virtual {p1, v3, v2}, Llyiahf/vczjk/sg5;->OooO0O0(Llyiahf/vczjk/di5;Landroid/content/Context;)V

    iget-object v2, v0, Llyiahf/vczjk/vg5;->OooOOOO:Llyiahf/vczjk/g15;

    iget-object v3, v2, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    if-nez v3, :cond_1

    new-instance v3, Llyiahf/vczjk/f15;

    invoke-direct {v3, v2}, Llyiahf/vczjk/f15;-><init>(Llyiahf/vczjk/g15;)V

    iput-object v3, v2, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    :cond_1
    iget-object v2, v2, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    iput-object v2, v4, Llyiahf/vczjk/s3;->OooOOo0:Ljava/lang/Object;

    iput-object v0, v4, Llyiahf/vczjk/s3;->OooOOo:Landroid/content/DialogInterface$OnClickListener;

    iget-object v2, p1, Llyiahf/vczjk/sg5;->OooOOOO:Landroid/view/View;

    if-eqz v2, :cond_2

    iput-object v2, v4, Llyiahf/vczjk/s3;->OooO0o0:Landroid/view/View;

    goto :goto_0

    :cond_2
    iget-object v2, p1, Llyiahf/vczjk/sg5;->OooOOO:Landroid/graphics/drawable/Drawable;

    iput-object v2, v4, Llyiahf/vczjk/s3;->OooO0OO:Landroid/graphics/drawable/Drawable;

    iget-object v2, p1, Llyiahf/vczjk/sg5;->OooOOO0:Ljava/lang/CharSequence;

    iput-object v2, v4, Llyiahf/vczjk/s3;->OooO0Oo:Ljava/lang/CharSequence;

    :goto_0
    iput-object v0, v4, Llyiahf/vczjk/s3;->OooOOOO:Llyiahf/vczjk/vg5;

    invoke-virtual {v1}, Llyiahf/vczjk/w3;->OooO0o0()Llyiahf/vczjk/x3;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/vg5;->OooOOO:Llyiahf/vczjk/x3;

    invoke-virtual {v1, v0}, Landroid/app/Dialog;->setOnDismissListener(Landroid/content/DialogInterface$OnDismissListener;)V

    iget-object v1, v0, Llyiahf/vczjk/vg5;->OooOOO:Llyiahf/vczjk/x3;

    invoke-virtual {v1}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object v1

    invoke-virtual {v1}, Landroid/view/Window;->getAttributes()Landroid/view/WindowManager$LayoutParams;

    move-result-object v1

    const/16 v2, 0x3eb

    iput v2, v1, Landroid/view/WindowManager$LayoutParams;->type:I

    iget v2, v1, Landroid/view/WindowManager$LayoutParams;->flags:I

    const/high16 v3, 0x20000

    or-int/2addr v2, v3

    iput v2, v1, Landroid/view/WindowManager$LayoutParams;->flags:I

    iget-object v0, v0, Llyiahf/vczjk/vg5;->OooOOO:Llyiahf/vczjk/x3;

    invoke-virtual {v0}, Landroid/app/Dialog;->show()V

    iget-object v0, p0, Llyiahf/vczjk/g15;->OooOOo:Llyiahf/vczjk/ci5;

    if-eqz v0, :cond_3

    invoke-interface {v0, p1}, Llyiahf/vczjk/ci5;->OoooO0(Llyiahf/vczjk/sg5;)Z

    :cond_3
    const/4 p1, 0x1

    return p1
.end method

.method public final OooO0o(Llyiahf/vczjk/dh5;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/sg5;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/g15;->OooOOo:Llyiahf/vczjk/ci5;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/ci5;->OooO0o0(Llyiahf/vczjk/sg5;Z)V

    :cond_0
    return-void
.end method

.method public final OooO0oO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooOO0(Landroid/content/Context;Llyiahf/vczjk/sg5;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/g15;->OooOOO0:Landroid/content/Context;

    if-eqz v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/g15;->OooOOO0:Landroid/content/Context;

    iget-object v0, p0, Llyiahf/vczjk/g15;->OooOOO:Landroid/view/LayoutInflater;

    if-nez v0, :cond_0

    invoke-static {p1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/g15;->OooOOO:Landroid/view/LayoutInflater;

    :cond_0
    iput-object p2, p0, Llyiahf/vczjk/g15;->OooOOOO:Llyiahf/vczjk/sg5;

    iget-object p1, p0, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/f15;->notifyDataSetChanged()V

    :cond_1
    return-void
.end method

.method public final OooOO0o()Landroid/os/Parcelable;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/g15;->OooOOOo:Landroidx/appcompat/view/menu/ExpandedMenuView;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    return-object v0

    :cond_0
    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    new-instance v1, Landroid/util/SparseArray;

    invoke-direct {v1}, Landroid/util/SparseArray;-><init>()V

    iget-object v2, p0, Llyiahf/vczjk/g15;->OooOOOo:Landroidx/appcompat/view/menu/ExpandedMenuView;

    if-eqz v2, :cond_1

    invoke-virtual {v2, v1}, Landroid/view/View;->saveHierarchyState(Landroid/util/SparseArray;)V

    :cond_1
    const-string v2, "android:menu:list"

    invoke-virtual {v0, v2, v1}, Landroid/os/Bundle;->putSparseParcelableArray(Ljava/lang/String;Landroid/util/SparseArray;)V

    return-object v0
.end method

.method public final OooOOO0(Llyiahf/vczjk/dh5;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final getId()I
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final onItemClick(Landroid/widget/AdapterView;Landroid/view/View;IJ)V
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/g15;->OooOOOO:Llyiahf/vczjk/sg5;

    iget-object p2, p0, Llyiahf/vczjk/g15;->OooOOoo:Llyiahf/vczjk/f15;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/f15;->OooO0O0(I)Llyiahf/vczjk/dh5;

    move-result-object p2

    const/4 p3, 0x0

    invoke-virtual {p1, p2, p0, p3}, Llyiahf/vczjk/sg5;->OooOOo0(Landroid/view/MenuItem;Llyiahf/vczjk/di5;I)Z

    return-void
.end method
