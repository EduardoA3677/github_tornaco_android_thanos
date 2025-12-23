.class public final Llyiahf/vczjk/sv;
.super Llyiahf/vczjk/hc8;
.source "SourceFile"

# interfaces
.implements Lutil/Consumer;


# instance fields
.field public final OooO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

.field public final OooOO0:Ljava/util/ArrayList;

.field public final OooOO0O:Lgithub/tornaco/thanos/android/ops/ops/by/app/AppOpsListActivity;


# direct methods
.method public constructor <init>(Lgithub/tornaco/thanos/android/ops/ops/by/app/AppOpsListActivity;Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/hc8;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/sv;->OooOO0:Ljava/util/ArrayList;

    iput-object p1, p0, Llyiahf/vczjk/sv;->OooOO0O:Lgithub/tornaco/thanos/android/ops/ops/by/app/AppOpsListActivity;

    iput-object p2, p0, Llyiahf/vczjk/sv;->OooO:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    return-void
.end method


# virtual methods
.method public final OooOOO(I)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sv;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oc6;

    iget-object p1, p1, Llyiahf/vczjk/oc6;->OooOOO:Ljava/util/ArrayList;

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result p1

    return p1
.end method

.method public final OooOOOO()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sv;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v0

    return v0
.end method

.method public final OooOOoo(Llyiahf/vczjk/dc8;I)V
    .locals 2

    check-cast p1, Llyiahf/vczjk/qv;

    iget-object v0, p1, Llyiahf/vczjk/qv;->Oooo00o:Llyiahf/vczjk/pm5;

    iget-object v1, p0, Llyiahf/vczjk/sv;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/oc6;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/pm5;->OooO0o0(Llyiahf/vczjk/oc6;)V

    iget-object p1, p1, Llyiahf/vczjk/qv;->Oooo00o:Llyiahf/vczjk/pm5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    return-void
.end method

.method public final OooOo0(Landroid/view/ViewGroup;)Llyiahf/vczjk/d6;
    .locals 5

    new-instance v0, Llyiahf/vczjk/d6;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v1

    sget v2, Llyiahf/vczjk/nm5;->OooOOO0:I

    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v2

    sget v3, Lgithub/tornaco/android/thanos/R$layout;->module_ops_item_footer:I

    const/4 v4, 0x0

    invoke-static {v1, v3, p1, v4, v2}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nm5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->getRoot()Landroid/view/View;

    move-result-object p1

    invoke-direct {v0, p1}, Landroidx/recyclerview/widget/o000oOoO;-><init>(Landroid/view/View;)V

    return-object v0
.end method

.method public final OooOo00(Llyiahf/vczjk/ec8;II)V
    .locals 7

    check-cast p1, Llyiahf/vczjk/rv;

    iget-object v0, p0, Llyiahf/vczjk/sv;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/oc6;

    iget-object v0, v0, Llyiahf/vczjk/oc6;->OooOOO:Ljava/util/ArrayList;

    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v0

    move-object v3, v0

    check-cast v3, Lgithub/tornaco/thanos/android/ops/model/Op;

    iget-object v0, p1, Llyiahf/vczjk/rv;->Oooo0:Llyiahf/vczjk/tm5;

    invoke-virtual {v0, v3}, Llyiahf/vczjk/tm5;->OooO0o0(Lgithub/tornaco/thanos/android/ops/model/Op;)V

    iget-object p1, p1, Llyiahf/vczjk/rv;->Oooo0:Llyiahf/vczjk/tm5;

    iget-object v0, p1, Llyiahf/vczjk/tm5;->OooOOO0:Landroid/widget/RelativeLayout;

    new-instance v1, Llyiahf/vczjk/nv;

    const/4 v6, 0x0

    move-object v2, p0

    move v4, p2

    move v5, p3

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/nv;-><init>(Llyiahf/vczjk/sv;Lgithub/tornaco/thanos/android/ops/model/Op;III)V

    invoke-virtual {v0, v1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    new-instance v1, Llyiahf/vczjk/nv;

    const/4 v6, 0x1

    move-object v2, p0

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/nv;-><init>(Llyiahf/vczjk/sv;Lgithub/tornaco/thanos/android/ops/model/Op;III)V

    iget-object p2, p1, Llyiahf/vczjk/tm5;->OooOOOO:Landroid/widget/ImageView;

    invoke-virtual {p2, v1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    return-void
.end method

.method public final OooOo0O(Landroid/view/ViewGroup;)Llyiahf/vczjk/dc8;
    .locals 5

    new-instance v0, Llyiahf/vczjk/qv;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v1

    sget v2, Llyiahf/vczjk/pm5;->OooOOO:I

    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v2

    sget v3, Lgithub/tornaco/android/thanos/R$layout;->module_ops_item_header:I

    const/4 v4, 0x0

    invoke-static {v1, v3, p1, v4, v2}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/pm5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->getRoot()Landroid/view/View;

    move-result-object v1

    invoke-direct {v0, v1}, Landroidx/recyclerview/widget/o000oOoO;-><init>(Landroid/view/View;)V

    iput-object p1, v0, Llyiahf/vczjk/qv;->Oooo00o:Llyiahf/vczjk/pm5;

    return-object v0
.end method

.method public final OooOo0o(Landroid/view/ViewGroup;)Llyiahf/vczjk/ec8;
    .locals 5

    new-instance v0, Llyiahf/vczjk/rv;

    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v1

    sget v2, Llyiahf/vczjk/tm5;->OooOOoo:I

    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v2

    sget v3, Lgithub/tornaco/android/thanos/R$layout;->module_ops_item_ops_checkable:I

    const/4 v4, 0x0

    invoke-static {v1, v3, p1, v4, v2}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tm5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->getRoot()Landroid/view/View;

    move-result-object v1

    invoke-direct {v0, v1}, Landroidx/recyclerview/widget/o000oOoO;-><init>(Landroid/view/View;)V

    iput-object p1, v0, Llyiahf/vczjk/rv;->Oooo0:Llyiahf/vczjk/tm5;

    return-object v0
.end method

.method public final accept(Ljava/lang/Object;)V
    .locals 1

    check-cast p1, Ljava/util/List;

    iget-object v0, p0, Llyiahf/vczjk/sv;->OooOO0:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    invoke-virtual {p0}, Llyiahf/vczjk/hc8;->OooOOo0()V

    return-void
.end method
