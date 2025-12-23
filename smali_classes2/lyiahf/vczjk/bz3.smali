.class public final Llyiahf/vczjk/bz3;
.super Landroidx/recyclerview/widget/OooOO0O;
.source "SourceFile"

# interfaces
.implements Lutil/Consumer;


# instance fields
.field public final OooO0Oo:Ljava/util/ArrayList;

.field public final OooO0o:Llyiahf/vczjk/ry3;

.field public final OooO0o0:Llyiahf/vczjk/vy3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/vy3;Llyiahf/vczjk/ry3;)V
    .locals 1

    invoke-direct {p0}, Landroidx/recyclerview/widget/OooOO0O;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/bz3;->OooO0Oo:Ljava/util/ArrayList;

    iput-object p1, p0, Llyiahf/vczjk/bz3;->OooO0o0:Llyiahf/vczjk/vy3;

    iput-object p2, p0, Llyiahf/vczjk/bz3;->OooO0o:Llyiahf/vczjk/ry3;

    return-void
.end method


# virtual methods
.method public final OooO(Landroid/view/ViewGroup;I)Landroidx/recyclerview/widget/o000oOoO;
    .locals 4

    new-instance p2, Llyiahf/vczjk/az3;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    sget v1, Llyiahf/vczjk/d54;->OooOOo:I

    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/R$layout;->item_infinite_z_app:I

    const/4 v3, 0x0

    invoke-static {v0, v2, p1, v3, v1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/d54;

    invoke-direct {p2, p1}, Llyiahf/vczjk/az3;-><init>(Llyiahf/vczjk/d54;)V

    return-object p2
.end method

.method public final OooO0OO()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bz3;->OooO0Oo:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    return v0
.end method

.method public final OooO0oo(Landroidx/recyclerview/widget/o000oOoO;I)V
    .locals 2

    check-cast p1, Llyiahf/vczjk/az3;

    iget-object v0, p0, Llyiahf/vczjk/bz3;->OooO0Oo:Ljava/util/ArrayList;

    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/wu;

    iget-object v0, p2, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v1, p1, Llyiahf/vczjk/az3;->Oooo00O:Llyiahf/vczjk/d54;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/d54;->OooO0o0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    iget-object v0, p0, Llyiahf/vczjk/bz3;->OooO0o0:Llyiahf/vczjk/vy3;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/d54;->OooO0o(Llyiahf/vczjk/xt;)V

    new-instance v0, Llyiahf/vczjk/zy3;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/zy3;-><init>(Llyiahf/vczjk/bz3;Llyiahf/vczjk/az3;Llyiahf/vczjk/wu;)V

    iget-object p1, v1, Llyiahf/vczjk/d54;->OooOOO0:Landroid/widget/RelativeLayout;

    invoke-virtual {p1, v0}, Landroid/view/View;->setOnLongClickListener(Landroid/view/View$OnLongClickListener;)V

    invoke-virtual {v1}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    return-void
.end method

.method public final accept(Ljava/lang/Object;)V
    .locals 1

    check-cast p1, Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/bz3;->OooO0Oo:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {p0}, Landroidx/recyclerview/widget/OooOO0O;->OooO0o()V

    return-void
.end method
