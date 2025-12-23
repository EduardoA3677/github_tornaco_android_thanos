.class public Lnow/fortuitous/thanos/power/StandByRuleActivity;
.super Lgithub/tornaco/android/thanos/theme/ThemeActivity;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/a29;
.implements Llyiahf/vczjk/z09;


# static fields
.field public static final synthetic Oooo:I


# instance fields
.field public Oooo0oO:Llyiahf/vczjk/p09;

.field public Oooo0oo:Llyiahf/vczjk/n0;


# direct methods
.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/y19;)V
    .locals 0

    iget-object p1, p1, Llyiahf/vczjk/y19;->OooO00o:Ljava/lang/String;

    invoke-virtual {p0, p1}, Lnow/fortuitous/thanos/power/StandByRuleActivity;->OooOoOO(Ljava/lang/String;)V

    return-void
.end method

.method public final OooOoOO(Ljava/lang/String;)V
    .locals 9

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v5

    invoke-virtual {v5}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    new-instance v3, Landroidx/appcompat/widget/AppCompatEditText;

    const/4 v0, 0x0

    invoke-direct {v3, p0, v0}, Landroidx/appcompat/widget/AppCompatEditText;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    invoke-virtual {v3, p1}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    new-instance v7, Llyiahf/vczjk/kd5;

    invoke-direct {v7, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v1, Lgithub/tornaco/android/thanos/res/R$string;->menu_title_rules:I

    invoke-virtual {v7, v1}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/kd5;->OooOo(Landroid/view/View;)V

    const/4 v1, 0x0

    iget-object v2, v7, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    move-object v8, v2

    check-cast v8, Llyiahf/vczjk/s3;

    iput-boolean v1, v8, Llyiahf/vczjk/s3;->OooOOO0:Z

    new-instance v1, Llyiahf/vczjk/z0;

    const/4 v6, 0x2

    move-object v2, p0

    move-object v4, p1

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/z0;-><init>(Ljava/lang/Object;Landroid/widget/TextView;Ljava/lang/Object;Ljava/lang/Object;I)V

    const p1, 0x104000a

    invoke-virtual {v7, p1, v1}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    const/high16 p1, 0x1040000

    invoke-virtual {v7, p1, v0}, Llyiahf/vczjk/kd5;->OooOOo(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p1

    if-nez p1, :cond_1

    sget p1, Lgithub/tornaco/android/thanos/res/R$string;->common_menu_title_remove:I

    new-instance v0, Llyiahf/vczjk/a1;

    const/4 v1, 0x6

    invoke-direct {v0, v1, p0, v5, v4}, Llyiahf/vczjk/a1;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v1, v8, Llyiahf/vczjk/s3;->OooO00o:Landroid/view/ContextThemeWrapper;

    invoke-virtual {v1, p1}, Landroid/content/Context;->getText(I)Ljava/lang/CharSequence;

    move-result-object p1

    iput-object p1, v8, Llyiahf/vczjk/s3;->OooOO0O:Ljava/lang/CharSequence;

    iput-object v0, v8, Llyiahf/vczjk/s3;->OooOO0o:Landroid/content/DialogInterface$OnClickListener;

    :cond_1
    invoke-virtual {v7}, Llyiahf/vczjk/kd5;->OooO0o0()Llyiahf/vczjk/x3;

    move-result-object p1

    invoke-virtual {p1}, Landroid/app/Dialog;->show()V

    return-void
.end method

.method public final onCreate(Landroid/os/Bundle;)V
    .locals 4

    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/theme/ThemeActivity;->onCreate(Landroid/os/Bundle;)V

    invoke-static {p0}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object p1

    sget v0, Llyiahf/vczjk/n0;->OooOOoo:I

    invoke-static {}, Landroidx/databinding/DataBindingUtil;->getDefaultComponent()Landroidx/databinding/DataBindingComponent;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/R$layout;->activity_standby_rules:I

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-static {p1, v1, v2, v3, v0}, Landroidx/databinding/ViewDataBinding;->inflateInternal(Landroid/view/LayoutInflater;ILandroid/view/ViewGroup;ZLjava/lang/Object;)Landroidx/databinding/ViewDataBinding;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/n0;

    iput-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->getRoot()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->setContentView(Landroid/view/View;)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object p1, p1, Llyiahf/vczjk/n0;->OooOOo0:Landroidx/appcompat/widget/Toolbar;

    invoke-virtual {p0, p1}, Landroidx/appcompat/app/AppCompatActivity;->OooOo(Landroidx/appcompat/widget/Toolbar;)V

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->OooOo0o()Llyiahf/vczjk/c6a;

    move-result-object p1

    const/4 v0, 0x1

    if-eqz p1, :cond_0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/c6a;->oo000o(Z)V

    :cond_0
    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object p1, p1, Llyiahf/vczjk/n0;->OooOOO:Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;

    new-instance v1, Landroidx/recyclerview/widget/LinearLayoutManager;

    invoke-direct {v1, v0}, Landroidx/recyclerview/widget/LinearLayoutManager;-><init>(I)V

    invoke-virtual {p1, v1}, Landroidx/recyclerview/widget/RecyclerView;->setLayoutManager(Landroidx/recyclerview/widget/OooOo00;)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object p1, p1, Llyiahf/vczjk/n0;->OooOOO:Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;

    new-instance v1, Llyiahf/vczjk/d1;

    invoke-direct {v1, p0}, Llyiahf/vczjk/d1;-><init>(Lnow/fortuitous/thanos/power/StandByRuleActivity;)V

    invoke-virtual {p1, v1}, Lcom/simplecityapps/recyclerview_fastscroll/views/FastScrollRecyclerView;->setAdapter(Landroidx/recyclerview/widget/OooOO0O;)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object p1, p1, Llyiahf/vczjk/n0;->OooOOOO:Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;

    new-instance v1, Llyiahf/vczjk/n36;

    const/16 v2, 0xb

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/n36;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v1}, Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;->setOnRefreshListener(Llyiahf/vczjk/ec9;)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object p1, p1, Llyiahf/vczjk/n0;->OooOOOO:Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->getResources()Landroid/content/res/Resources;

    move-result-object v1

    sget v2, Lgithub/tornaco/android/thanos/module/common/R$array;->common_swipe_refresh_colors:I

    invoke-virtual {v1, v2}, Landroid/content/res/Resources;->getIntArray(I)[I

    move-result-object v1

    invoke-virtual {p1, v1}, Landroidx/swiperefreshlayout/widget/SwipeRefreshLayout;->setColorSchemeColors([I)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object p1, p1, Llyiahf/vczjk/n0;->OooOOO0:Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    new-instance v1, Llyiahf/vczjk/y0;

    const/16 v2, 0xc

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/y0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object p1, p1, Llyiahf/vczjk/n0;->OooOOOo:Llyiahf/vczjk/am5;

    iget-object p1, p1, Llyiahf/vczjk/am5;->OooOOO0:Lgithub/tornaco/android/thanos/widget/SwitchBar;

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    invoke-static {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->isStandbyRuleEnabled()Z

    move-result v1

    if-eqz v1, :cond_1

    move v3, v0

    :cond_1
    invoke-virtual {p1, v3}, Lgithub/tornaco/android/thanos/widget/SwitchBar;->setChecked(Z)V

    new-instance v0, Llyiahf/vczjk/t0;

    const/4 v1, 0x5

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/t0;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {p1, v0}, Lgithub/tornaco/android/thanos/widget/SwitchBar;->OooO00o(Llyiahf/vczjk/kc9;)V

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

    const-class p1, Llyiahf/vczjk/p09;

    invoke-static {p1}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_2

    const-string v1, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v2, p1, v0}, Llyiahf/vczjk/pb7;->OooOo0O(Llyiahf/vczjk/gf4;Ljava/lang/String;)Llyiahf/vczjk/dha;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/p09;

    iput-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oO:Llyiahf/vczjk/p09;

    invoke-virtual {p1}, Llyiahf/vczjk/p09;->OooO0o()V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    iget-object v0, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oO:Llyiahf/vczjk/p09;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/n0;->OooO0o0(Llyiahf/vczjk/p09;)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    invoke-virtual {p1, p0}, Landroidx/databinding/ViewDataBinding;->setLifecycleOwner(Llyiahf/vczjk/uy4;)V

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oo:Llyiahf/vczjk/n0;

    invoke-virtual {p1}, Landroidx/databinding/ViewDataBinding;->executePendingBindings()V

    return-void

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final onCreateOptionsMenu(Landroid/view/Menu;)Z
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/app/AppCompatActivity;->getMenuInflater()Landroid/view/MenuInflater;

    move-result-object v0

    sget v1, Lgithub/tornaco/android/thanos/R$menu;->start_rules_menu:I

    invoke-virtual {v0, v1, p1}, Landroid/view/MenuInflater;->inflate(ILandroid/view/Menu;)V

    invoke-super {p0, p1}, Landroid/app/Activity;->onCreateOptionsMenu(Landroid/view/Menu;)Z

    move-result p1

    return p1
.end method

.method public final onOptionsItemSelected(Landroid/view/MenuItem;)Z
    .locals 4

    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    sget v1, Lgithub/tornaco/android/thanos/R$id;->action_info:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-ne v0, v1, :cond_0

    new-instance p1, Llyiahf/vczjk/kd5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kd5;-><init>(Landroid/content/Context;)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->menu_title_rules:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOo0o(I)V

    sget v0, Lgithub/tornaco/android/thanos/res/R$string;->feature_summary_standby_restrict_rules:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/kd5;->OooOOo0(I)V

    iget-object v0, p1, Llyiahf/vczjk/w3;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s3;

    iput-boolean v2, v0, Llyiahf/vczjk/s3;->OooOOO0:Z

    const v0, 0x104000a

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/kd5;->OooOo00(ILandroid/content/DialogInterface$OnClickListener;)V

    invoke-virtual {p1}, Llyiahf/vczjk/w3;->OooOOOO()Llyiahf/vczjk/x3;

    return v3

    :cond_0
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    sget v1, Lgithub/tornaco/android/thanos/R$id;->action_import:I

    if-ne v0, v1, :cond_4

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oO:Llyiahf/vczjk/p09;

    invoke-virtual {p1}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    const-string v1, "clipboard"

    invoke-virtual {v0, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/content/ClipboardManager;

    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Landroid/content/ClipboardManager;->getPrimaryClip()Landroid/content/ClipData;

    move-result-object v0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    invoke-virtual {v0, v2}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;

    move-result-object v0

    invoke-virtual {v0}, Landroid/content/ClipData$Item;->getText()Ljava/lang/CharSequence;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_2

    goto :goto_0

    :cond_2
    :try_start_0
    const-string v1, "\\r?\\n"

    invoke-virtual {v0, v1}, Ljava/lang/String;->split(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Arrays;->toString([Ljava/lang/Object;)Ljava/lang/String;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/util/ArrayUtils;->isEmpty([Ljava/lang/Object;)Z

    move-result v1

    if-nez v1, :cond_3

    new-instance v1, Llyiahf/vczjk/wv;

    const/4 v2, 0x5

    invoke-direct {v1, p1, v2}, Llyiahf/vczjk/wv;-><init>(Ljava/lang/Object;I)V

    invoke-static {v0, v1}, Lutil/CollectionUtils;->consumeRemaining([Ljava/lang/Object;Lutil/Consumer;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {p0}, Llyiahf/vczjk/kh6;->Oooo0o(Landroid/content/Context;)V

    goto :goto_1

    :catchall_0
    move-exception p1

    invoke-static {p1}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/zsa;->Oooo0O0(Ljava/lang/String;)V

    :cond_3
    :goto_0
    invoke-static {p0}, Llyiahf/vczjk/kh6;->Oooo0OO(Landroid/content/Context;)V

    :goto_1
    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oO:Llyiahf/vczjk/p09;

    invoke-virtual {p1}, Llyiahf/vczjk/p09;->OooO0o()V

    return v3

    :cond_4
    invoke-interface {p1}, Landroid/view/MenuItem;->getItemId()I

    move-result v0

    sget v1, Lgithub/tornaco/android/thanos/R$id;->action_export:I

    if-ne v0, v1, :cond_6

    iget-object p1, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oO:Llyiahf/vczjk/p09;

    invoke-virtual {p1}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getAllStandbyRules()[Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Lcom/google/common/collect/Lists;->OooO0O0([Ljava/lang/Object;)Ljava/util/ArrayList;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_5

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-static {}, Ljava/lang/System;->lineSeparator()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    goto :goto_2

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object p1

    const-string v0, "rules"

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {p1, v0, v1}, Lgithub/tornaco/android/thanos/core/util/ClipboardUtils;->copyToClipboard(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/kh6;->Oooo0o(Landroid/content/Context;)V

    return v3

    :cond_6
    invoke-super {p0, p1}, Lgithub/tornaco/android/thanos/BaseDefaultMenuItemHandlingAppCompatActivity;->onOptionsItemSelected(Landroid/view/MenuItem;)Z

    move-result p1

    return p1
.end method

.method public final onResume()V
    .locals 1

    invoke-super {p0}, Landroidx/fragment/app/FragmentActivity;->onResume()V

    iget-object v0, p0, Lnow/fortuitous/thanos/power/StandByRuleActivity;->Oooo0oO:Llyiahf/vczjk/p09;

    invoke-virtual {v0}, Llyiahf/vczjk/p09;->OooO0o()V

    return-void
.end method
