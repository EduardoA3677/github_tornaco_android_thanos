.class public Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;
.super Lgithub/tornaco/android/thanos/theme/ThemeActivity;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/fx7;


# static fields
.field public static final synthetic OoooO00:I


# instance fields
.field public Oooo:Llyiahf/vczjk/nx7;

.field public final Oooo0oO:Llyiahf/vczjk/cp8;

.field public Oooo0oo:Llyiahf/vczjk/mn5;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;-><init>()V

    new-instance v0, Llyiahf/vczjk/cp8;

    invoke-direct {v0, p0}, Llyiahf/vczjk/cp8;-><init>(Lgithub/tornaco/android/thanos/theme/ThemeActivity;)V

    iput-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oO:Llyiahf/vczjk/cp8;

    return-void
.end method


# virtual methods
.method public final onCreate(Landroid/os/Bundle;)V
    .locals 5

    const/4 v0, 0x0

    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;->onCreate(Landroid/os/Bundle;)V

    invoke-static {p0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object p1

    sget v1, Llyiahf/vczjk/mn5;->OooOOoo:I

    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/R$layout;->module_profile_rule_list_activity:I

    const/4 v3, 0x0

    invoke-static {p1, v2, v3, v0, v1}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mn5;

    iput-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->getRoot()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->setContentView(Landroid/view/View;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object p1, p1, Llyiahf/vczjk/mn5;->OooOOo0:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->OooOo(Landroidx/appcompat/widget/Toolbar;)V

    invoke-virtual {p0}, Lgithub/tornaco/android/thanos/BaseDefaultMenuItemHandlingAppCompatActivity;->OooOoO()V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object p1, p1, Llyiahf/vczjk/mn5;->OooOOO:Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;

    new-instance v1, Landroidx/recyclerview/widget/LinearLayoutManager;

    const/4 v2, 0x1

    invoke-direct {v1, v2}, Landroidx/recyclerview/widget/LinearLayoutManager;-><init>(I)V

    invoke-virtual {p1, v1}, Landroidx/recyclerview/widget/RecyclerView;->setLayoutManager(Landroidx/recyclerview/widget/OooOo00;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object p1, p1, Llyiahf/vczjk/mn5;->OooOOO:Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;

    new-instance v1, Llyiahf/vczjk/kx7;

    new-instance v3, Llyiahf/vczjk/gx7;

    invoke-direct {v3, p0}, Llyiahf/vczjk/gx7;-><init>(Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;)V

    new-instance v4, Llyiahf/vczjk/hx7;

    invoke-direct {v4, p0}, Llyiahf/vczjk/hx7;-><init>(Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;)V

    invoke-direct {v1, p0, v3, v4}, Llyiahf/vczjk/kx7;-><init>(Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;Llyiahf/vczjk/gx7;Llyiahf/vczjk/hx7;)V

    invoke-virtual {p1, v1}, Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;->setAdapter(Landroidx/recyclerview/widget/OooOO0O;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object p1, p1, Llyiahf/vczjk/mn5;->OooOOOO:Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;

    new-instance v1, Llyiahf/vczjk/gx7;

    invoke-direct {v1, p0}, Llyiahf/vczjk/gx7;-><init>(Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;)V

    invoke-virtual {p1, v1}, Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;->setOnRefreshListener(Llyiahf/vczjk/ec9;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object p1, p1, Llyiahf/vczjk/mn5;->OooOOOO:Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->getResources()Landroid/content/res/Resources;

    move-result-object v1

    sget v3, Lgithub/tornaco/android/thanos/module/common/R$array;->common_swipe_refresh_colors:I

    invoke-virtual {v1, v3}, Landroid/content/res/Resources;->getIntArray(I)[I

    move-result-object v1

    invoke-virtual {p1, v1}, Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;->setColorSchemeColors([I)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object p1, p1, Llyiahf/vczjk/mn5;->OooOOOo:Llyiahf/vczjk/am5;

    iget-object p1, p1, Llyiahf/vczjk/am5;->OooOOO0:Lgithub/tornaco/android/thanos/widget/SwitchBar;

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->common_switchbar_title_format:I

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_feature_name:I

    invoke-virtual {p0, v3}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {p0, v1, v3}, Landroid/content/Context;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Lgithub/tornaco/android/thanos/widget/SwitchBar;->setOnLabel(Ljava/lang/String;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->common_switchbar_title_format:I

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_feature_name:I

    invoke-virtual {p0, v3}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v3

    filled-new-array {v3}, [Ljava/lang/Object;

    move-result-object v3

    invoke-virtual {p0, v1, v3}, Landroid/content/Context;->getString(I[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Lgithub/tornaco/android/thanos/widget/SwitchBar;->setOffLabel(Ljava/lang/String;)V

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->isProfileEnabled()Z

    move-result v1

    if-eqz v1, :cond_0

    move v1, v2

    goto :goto_0

    :cond_0
    move v1, v0

    :goto_0
    invoke-virtual {p1, v1}, Lgithub/tornaco/android/thanos/widget/SwitchBar;->setChecked(Z)V

    new-instance v1, Llyiahf/vczjk/t0;

    const/4 v3, 0x4

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/t0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v1}, Lgithub/tornaco/android/thanos/widget/SwitchBar;->OooO00o(Llyiahf/vczjk/kc9;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object p1, p1, Llyiahf/vczjk/mn5;->OooOOO0:Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {p1, v2}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->OooOO0o(I)V

    invoke-virtual {p0}, Landroid/app/Activity;->getApplication()Landroid/app/Application;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vo6;->OooO0o(Landroid/app/Application;)Llyiahf/vczjk/gha;

    move-result-object p1

    invoke-virtual {p0}, Landroidx/activity/ComponentActivity;->getViewModelStore()Llyiahf/vczjk/kha;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    const-string v3, "defaultCreationExtras"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/pb7;

    invoke-direct {v3, v1, p1, v2}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/kha;Llyiahf/vczjk/hha;Llyiahf/vczjk/os1;)V

    const-class p1, Llyiahf/vczjk/nx7;

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_1

    const-string v2, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    invoke-virtual {v2, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, p1, v1}, Llyiahf/vczjk/pb7;->OooOo0O(Llyiahf/vczjk/gf4;Ljava/lang/String;)Llyiahf/vczjk/dha;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/nx7;

    iput-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo:Llyiahf/vczjk/nx7;

    invoke-virtual {p1}, Llyiahf/vczjk/nx7;->OooO0o()V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    iget-object v1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo:Llyiahf/vczjk/nx7;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/mn5;->OooO0o0(Llyiahf/vczjk/nx7;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    invoke-virtual {p1, p0}, Landroidx/databinding/ViewDataBinding;->setLifecycleOwner(Llyiahf/vczjk/uy4;)V

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oo:Llyiahf/vczjk/mn5;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    new-instance p1, Llyiahf/vczjk/jm4;

    const/16 v1, 0x10

    invoke-direct {p1, v1}, Llyiahf/vczjk/jm4;-><init>(I)V

    iget-object v1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oO:Llyiahf/vczjk/cp8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/cp8;->OooO0oO(Llyiahf/vczjk/ze3;)V

    new-instance p1, Llyiahf/vczjk/sj5;

    const/16 v2, 0x12

    invoke-direct {p1, p0, v2}, Llyiahf/vczjk/sj5;-><init>(Ljava/lang/Object;I)V

    new-instance v2, Llyiahf/vczjk/bp8;

    invoke-direct {v2, v0, v1, p1}, Llyiahf/vczjk/bp8;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    iget-object p1, v1, Llyiahf/vczjk/cp8;->OooO00o:Llyiahf/vczjk/yo8;

    iput-object v2, p1, Llyiahf/vczjk/yo8;->OooO0OO:Llyiahf/vczjk/bp8;

    return-void

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/R$menu;->module_profile_rule:I

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreateOptionsMenu(Landroid/view/Menu;)Z

    move-result p1

    return p1
.end method

.method public final onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 8

    const-string v0, "item"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_view_wiki:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    const/4 v2, 0x1

    if-ne v0, v1, :cond_0

    const-string p1, "https://tornaco.github.io/Thanox-Docs/zh/guide/profile.html"

    invoke-static {p0, p1}, Llyiahf/vczjk/jp8;->Oooo00O(Landroid/content/Context;Ljava/lang/String;)V

    return v2

    :cond_0
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_import_from_file:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    const/4 v3, 0x3

    const/high16 v4, 0x1040000

    const/4 v5, 0x0

    if-ne v0, v1, :cond_3

    sget-object p1, Llyiahf/vczjk/im4;->OooO0O0:Llyiahf/vczjk/zg9;

    invoke-virtual {p1}, Llyiahf/vczjk/zg9;->OooO0O0()Llyiahf/vczjk/q29;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cm4;

    iget-boolean p1, p1, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-nez p1, :cond_2

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo:Llyiahf/vczjk/nx7;

    iget-object p1, p1, Llyiahf/vczjk/nx7;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Ljava/util/AbstractCollection;->size()I

    move-result p1

    if-gt p1, v3, :cond_1

    goto :goto_0

    :cond_1
    new-instance p1, Llyiahf/vczjk/kd5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available_message:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOOo0(I)V

    invoke-virtual {p1, v4, v5}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_title:I

    new-instance v1, Llyiahf/vczjk/w0;

    const/4 v3, 0x2

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/w0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {p1}, Llyiahf/vczjk/kd5;->OooO0o0()Llyiahf/vczjk/x3;

    move-result-object p1

    invoke-virtual {p1}, Landroid/app/Dialog;->show()V

    return v2

    :cond_2
    :goto_0
    const-string p1, "application/json"

    filled-new-array {p1}, [Ljava/lang/String;

    move-result-object p1

    iget-object v0, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo0oO:Llyiahf/vczjk/cp8;

    const/16 v1, 0x270c

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/cp8;->OooO0o0([Ljava/lang/String;I)V

    return v2

    :cond_3
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_import_examples:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    if-ne v0, v1, :cond_4

    const-class p1, Lgithub/tornaco/thanos/android/module/profile/example/ProfileExampleActivity;

    invoke-static {p0, p1}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    return v2

    :cond_4
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_online:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    if-ne v0, v1, :cond_6

    sget-object p1, Llyiahf/vczjk/im4;->OooO0O0:Llyiahf/vczjk/zg9;

    invoke-virtual {p1}, Llyiahf/vczjk/zg9;->OooO0O0()Llyiahf/vczjk/q29;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cm4;

    iget-boolean p1, p1, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz p1, :cond_5

    const-class p1, Lgithub/tornaco/thanos/android/module/profile/online/OnlineProfileActivity;

    invoke-static {p0, p1}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    return v2

    :cond_5
    new-instance p1, Llyiahf/vczjk/kd5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available_message:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOOo0(I)V

    invoke-virtual {p1, v4, v5}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_title:I

    new-instance v1, Llyiahf/vczjk/w0;

    const/4 v3, 0x2

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/w0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {p1}, Llyiahf/vczjk/kd5;->OooO0o0()Llyiahf/vczjk/x3;

    move-result-object p1

    invoke-virtual {p1}, Landroid/app/Dialog;->show()V

    return v2

    :cond_6
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_global_var:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    if-ne v0, v1, :cond_7

    const-class p1, Lgithub/tornaco/thanos/android/module/profile/GlobalVarListActivity;

    invoke-static {p0, p1}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    return v2

    :cond_7
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_add:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    if-ne v0, v1, :cond_a

    sget-object p1, Llyiahf/vczjk/im4;->OooO0O0:Llyiahf/vczjk/zg9;

    invoke-virtual {p1}, Llyiahf/vczjk/zg9;->OooO0O0()Llyiahf/vczjk/q29;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cm4;

    iget-boolean p1, p1, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-nez p1, :cond_9

    iget-object p1, p0, Lgithub/tornaco/thanos/android/module/profile/RuleListActivity;->Oooo:Llyiahf/vczjk/nx7;

    iget-object p1, p1, Llyiahf/vczjk/nx7;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    if-eqz p1, :cond_8

    invoke-virtual {p1}, Ljava/util/AbstractCollection;->size()I

    move-result p1

    if-gt p1, v3, :cond_8

    goto :goto_1

    :cond_8
    new-instance p1, Llyiahf/vczjk/kd5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available_message:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOOo0(I)V

    invoke-virtual {p1, v4, v5}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_title:I

    new-instance v1, Llyiahf/vczjk/w0;

    const/4 v3, 0x2

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/w0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {p1}, Llyiahf/vczjk/kd5;->OooO0o0()Llyiahf/vczjk/x3;

    move-result-object p1

    invoke-virtual {p1}, Landroid/app/Dialog;->show()V

    return v2

    :cond_9
    :goto_1
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v0, 0x0

    invoke-direct {p1, v0}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    new-instance v1, Llyiahf/vczjk/kd5;

    invoke-direct {v1, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v3, Lgithub/tornaco/android/thanos/res/R$string;->module_profile_editor_select_format:I

    invoke-virtual {v1, v3}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    const-string v3, "JSON"

    const-string v6, "YAML"

    filled-new-array {v3, v6}, [Ljava/lang/String;

    move-result-object v3

    new-instance v6, Llyiahf/vczjk/w0;

    const/16 v7, 0xa

    invoke-direct {v6, p1, v7}, Llyiahf/vczjk/w0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v1, v3, v0, v6}, Llyiahf/vczjk/kd5;->OooOo0O([Ljava/lang/CharSequence;ILandroid/content/DialogInterface$OnClickListener;)V

    iget-object v0, v1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s3;

    iput-boolean v2, v0, Llyiahf/vczjk/s3;->OooOOO0:Z

    new-instance v0, Llyiahf/vczjk/x0;

    const/16 v3, 0x8

    invoke-direct {v0, v3, p0, p1}, Llyiahf/vczjk/x0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const p1, 0x104000a

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {v1, v4, v5}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {v1}, Llyiahf/vczjk/w3;->OooOOOO()Llyiahf/vczjk/x3;

    return v2

    :cond_a
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_rule_engine:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    if-ne v0, v1, :cond_b

    const-class p1, Lgithub/tornaco/thanos/android/module/profile/RuleEngineSettingsActivity;

    invoke-static {p0, p1}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    return v2

    :cond_b
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_rule_console:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    if-ne v0, v1, :cond_d

    sget-object p1, Llyiahf/vczjk/im4;->OooO0O0:Llyiahf/vczjk/zg9;

    invoke-virtual {p1}, Llyiahf/vczjk/zg9;->OooO0O0()Llyiahf/vczjk/q29;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/cm4;

    iget-boolean p1, p1, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz p1, :cond_c

    const-class p1, Lgithub/tornaco/thanos/android/module/profile/ConsoleActivity;

    invoke-static {p0, p1}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    return v2

    :cond_c
    new-instance p1, Llyiahf/vczjk/kd5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_donated_available_message:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOOo0(I)V

    invoke-virtual {p1, v4, v5}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->module_donate_title:I

    new-instance v1, Llyiahf/vczjk/w0;

    const/4 v3, 0x2

    invoke-direct {v1, p0, v3}, Llyiahf/vczjk/w0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {p1}, Llyiahf/vczjk/kd5;->OooO0o0()Llyiahf/vczjk/x3;

    move-result-object p1

    invoke-virtual {p1}, Landroid/app/Dialog;->show()V

    return v2

    :cond_d
    sget v0, Lgithub/tornaco/android/thanos/R$id;->action_rule_log:I

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v1

    if-ne v0, v1, :cond_e

    const-class p1, Lgithub/tornaco/thanos/android/module/profile/LogActivity;

    invoke-static {p0, p1}, Llyiahf/vczjk/bua;->Oooo(Landroid/content/Context;Ljava/lang/Class;)V

    return v2

    :cond_e
    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/BaseDefaultMenuItemHandlingAppCompatActivity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result p1

    return p1
.end method
