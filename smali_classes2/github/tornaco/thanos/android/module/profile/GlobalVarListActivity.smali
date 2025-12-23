.class public Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;
.super Lgithub/tornaco/android/thanos/theme/ThemeActivity;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yca;


# static fields
.field public static final synthetic Oooo:I


# instance fields
.field public Oooo0oO:Llyiahf/vczjk/ti3;

.field public Oooo0oo:Llyiahf/vczjk/kn5;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public final onCreate(Landroid/os/Bundle;)V
    .locals 4

    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;->onCreate(Landroid/os/Bundle;)V

    invoke-static {p0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object p1

    sget v0, Llyiahf/vczjk/kn5;->OooOOo:I

    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/R$layout;->module_profile_global_var_list_activity:I

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-static {p1, v1, v2, v3, v0}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/kn5;

    iput-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->getRoot()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->setContentView(Landroid/view/View;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    iget-object p1, p1, Llyiahf/vczjk/kn5;->OooOOOO:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->OooOo(Landroidx/appcompat/widget/Toolbar;)V

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->OooOo0o()Llyiahf/vczjk/c6a;

    move-result-object p1

    const/4 v0, 0x1

    if-eqz p1, :cond_0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/c6a;->oo000o(Z)V

    :cond_0
    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    iget-object p1, p1, Llyiahf/vczjk/kn5;->OooOOOo:Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;

    new-instance v1, Landroidx/recyclerview/widget/LinearLayoutManager;

    invoke-direct {v1, v0}, Landroidx/recyclerview/widget/LinearLayoutManager;-><init>(I)V

    invoke-virtual {p1, v1}, Landroidx/recyclerview/widget/RecyclerView;->setLayoutManager(Landroidx/recyclerview/widget/OooOo00;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    iget-object p1, p1, Llyiahf/vczjk/kn5;->OooOOOo:Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;

    new-instance v0, Llyiahf/vczjk/d1;

    invoke-direct {v0, p0}, Llyiahf/vczjk/d1;-><init>(Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;)V

    invoke-virtual {p1, v0}, Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;->setAdapter(Landroidx/recyclerview/widget/OooOO0O;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    iget-object p1, p1, Llyiahf/vczjk/kn5;->OooOOO:Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;

    new-instance v0, Llyiahf/vczjk/oOO000o;

    const/16 v1, 0x14

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/oOO000o;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;->setOnRefreshListener(Llyiahf/vczjk/ec9;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    iget-object p1, p1, Llyiahf/vczjk/kn5;->OooOOO:Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->getResources()Landroid/content/res/Resources;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/module/common/R$array;->common_swipe_refresh_colors:I

    invoke-virtual {v0, v1}, Landroid/content/res/Resources;->getIntArray(I)[I

    move-result-object v0

    invoke-virtual {p1, v0}, Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;->setColorSchemeColors([I)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    iget-object p1, p1, Llyiahf/vczjk/kn5;->OooOOO0:Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    new-instance v0, Llyiahf/vczjk/y0;

    const/4 v1, 0x5

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/y0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    invoke-virtual {p0}, Landroid/app/Activity;->getApplication()Landroid/app/Application;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vo6;->OooO0o(Landroid/app/Application;)Llyiahf/vczjk/gha;

    move-result-object p1

    invoke-virtual {p0}, Landroidx/activity/ComponentActivity;->getViewModelStore()Llyiahf/vczjk/kha;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    const-string v2, "defaultCreationExtras"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/pb7;

    invoke-direct {v2, v0, p1, v1}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/kha;Llyiahf/vczjk/hha;Llyiahf/vczjk/os1;)V

    const-class p1, Llyiahf/vczjk/ti3;

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_1

    const-string v1, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, p1, v0}, Llyiahf/vczjk/pb7;->OooOo0O(Llyiahf/vczjk/gf4;Ljava/lang/String;)Llyiahf/vczjk/dha;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ti3;

    iput-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oO:Llyiahf/vczjk/ti3;

    invoke-virtual {p1}, Llyiahf/vczjk/ti3;->OooO0o()V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    iget-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oO:Llyiahf/vczjk/ti3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kn5;->OooO0o0(Llyiahf/vczjk/ti3;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    invoke-virtual {p1, p0}, Landroidx/databinding/ViewDataBinding;->setLifecycleOwner(Llyiahf/vczjk/uy4;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oo:Llyiahf/vczjk/kn5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final onResume()V
    .locals 1

    invoke-super {p0}, Landroidx/fragment/app/FragmentActivity;->onResume()V

    iget-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;->Oooo0oO:Llyiahf/vczjk/ti3;

    invoke-virtual {v0}, Llyiahf/vczjk/ti3;->OooO0o()V

    return-void
.end method
