.class public final Llyiahf/vczjk/pc0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j86;
.implements Llyiahf/vczjk/bja;
.implements Llyiahf/vczjk/up8;
.implements Llyiahf/vczjk/ci5;


# instance fields
.field public OooOOO:Z

.field public final synthetic OooOOO0:I

.field public OooOOOO:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Llyiahf/vczjk/pc0;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    return-void

    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/HashMap;

    const/4 v0, 0x2

    invoke-direct {p1, v0}, Ljava/util/HashMap;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    return-void

    :pswitch_data_0
    .packed-switch 0x6
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Z)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/pc0;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    iput-boolean p3, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/pc0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/up3;Z)V
    .locals 1

    const/16 v0, 0xa

    iput v0, p0, Llyiahf/vczjk/pc0;->OooOOO0:I

    const/16 v0, 0xa

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/pc0;-><init>(Ljava/lang/Object;I)V

    iput-boolean p2, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    return-void
.end method

.method public constructor <init>(ZLjava/lang/String;)V
    .locals 1

    const/16 v0, 0x9

    iput v0, p0, Llyiahf/vczjk/pc0;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    iput-object p2, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public static OooO0oo(Landroidx/fragment/app/Oooo0;Z)Llyiahf/vczjk/tc0;
    .locals 2

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Landroidx/fragment/app/Oooo0;->getActivity()Landroidx/fragment/app/FragmentActivity;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-nez p1, :cond_1

    invoke-virtual {p0}, Landroidx/fragment/app/Oooo0;->getParentFragment()Landroidx/fragment/app/Oooo0;

    move-result-object p1

    :cond_1
    if-eqz p1, :cond_3

    invoke-interface {p1}, Llyiahf/vczjk/lha;->getViewModelStore()Llyiahf/vczjk/kha;

    move-result-object p0

    invoke-interface {p1}, Llyiahf/vczjk/om3;->getDefaultViewModelProviderFactory()Llyiahf/vczjk/hha;

    move-result-object v0

    invoke-interface {p1}, Llyiahf/vczjk/om3;->getDefaultViewModelCreationExtras()Llyiahf/vczjk/os1;

    move-result-object p1

    const-string v1, "store"

    invoke-static {p0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "factory"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v1, "defaultCreationExtras"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/pb7;

    invoke-direct {v1, p0, v0, p1}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/kha;Llyiahf/vczjk/hha;Llyiahf/vczjk/os1;)V

    const-class p0, Llyiahf/vczjk/tc0;

    invoke-static {p0}, Llyiahf/vczjk/rs;->Oooo0O0(Ljava/lang/Class;)Llyiahf/vczjk/gf4;

    move-result-object p0

    invoke-interface {p0}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_2

    const-string v0, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    invoke-virtual {v0, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {v1, p0, p1}, Llyiahf/vczjk/pb7;->OooOo0O(Llyiahf/vczjk/gf4;Ljava/lang/String;)Llyiahf/vczjk/dha;

    move-result-object p0

    check-cast p0, Llyiahf/vczjk/tc0;

    return-object p0

    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "view model not found"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public OooO(ILjava/lang/CharSequence;)Z
    .locals 6

    const/4 v0, 0x1

    if-eqz p2, :cond_6

    if-ltz p1, :cond_6

    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    move-result v1

    sub-int/2addr v1, p1

    if-ltz v1, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/up3;

    if-nez v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/pc0;->OooO0oO()Z

    move-result p1

    return p1

    :cond_0
    const/4 v1, 0x0

    const/4 v2, 0x2

    move v3, v1

    move v4, v2

    :goto_0
    if-ge v3, p1, :cond_3

    if-ne v4, v2, :cond_3

    invoke-interface {p2, v3}, Ljava/lang/CharSequence;->charAt(I)C

    move-result v4

    invoke-static {v4}, Ljava/lang/Character;->getDirectionality(C)B

    move-result v4

    sget-object v5, Llyiahf/vczjk/ai9;->OooO00o:Llyiahf/vczjk/pc0;

    if-eqz v4, :cond_2

    if-eq v4, v0, :cond_1

    if-eq v4, v2, :cond_1

    packed-switch v4, :pswitch_data_0

    move v4, v2

    goto :goto_1

    :cond_1
    :pswitch_0
    move v4, v1

    goto :goto_1

    :cond_2
    :pswitch_1
    move v4, v0

    :goto_1
    add-int/2addr v3, v0

    goto :goto_0

    :cond_3
    if-eqz v4, :cond_5

    if-eq v4, v0, :cond_4

    invoke-virtual {p0}, Llyiahf/vczjk/pc0;->OooO0oO()Z

    move-result p1

    return p1

    :cond_4
    return v1

    :cond_5
    return v0

    :cond_6
    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-direct {p1}, Ljava/lang/IllegalArgumentException;-><init>()V

    throw p1

    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_1
        :pswitch_1
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method

.method public OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t41;

    iget-object v1, v0, Llyiahf/vczjk/t41;->OooO0o:Landroidx/databinding/ObservableField;

    iget-object v2, v0, Llyiahf/vczjk/t41;->OooOO0O:Ljava/util/ArrayList;

    iget-boolean v3, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-nez v3, :cond_0

    iget-object v3, v0, Llyiahf/vczjk/t41;->OooOO0o:Llyiahf/vczjk/s41;

    invoke-virtual {v1}, Landroidx/databinding/ObservableField;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/vr0;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-interface {v3, v1}, Llyiahf/vczjk/s41;->Oooo000(Llyiahf/vczjk/vr0;)Ljava/util/List;

    move-result-object v1

    invoke-virtual {v2}, Ljava/util/ArrayList;->clear()V

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    move-object v2, v1

    goto :goto_0

    :cond_0
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_1

    iget-object v3, v0, Llyiahf/vczjk/t41;->OooOO0o:Llyiahf/vczjk/s41;

    invoke-virtual {v1}, Landroidx/databinding/ObservableField;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/vr0;

    invoke-static {v1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-interface {v3, v1}, Llyiahf/vczjk/s41;->Oooo000(Llyiahf/vczjk/vr0;)Ljava/util/List;

    move-result-object v1

    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    :cond_1
    :goto_0
    iget-object v1, v0, Llyiahf/vczjk/t41;->OooO0oo:Landroidx/databinding/ObservableField;

    invoke-virtual {v1}, Landroidx/databinding/ObservableField;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/sw;

    if-eqz v1, :cond_5

    sget-object v3, Llyiahf/vczjk/sw;->OooOOOO:Llyiahf/vczjk/sw;

    if-eq v1, v3, :cond_2

    sget-object v3, Llyiahf/vczjk/sw;->OooOOO:Llyiahf/vczjk/sw;

    if-ne v1, v3, :cond_4

    :cond_2
    invoke-virtual {v0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v3

    invoke-static {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v3

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->isServiceInstalled()Z

    move-result v4

    if-eqz v4, :cond_4

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getUsageStatsManager()Lgithub/tornaco/android/thanos/core/app/usage/UsageStatsManager;

    move-result-object v3

    const-wide/16 v4, 0x0

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v6

    invoke-virtual {v3, v4, v5, v6, v7}, Lgithub/tornaco/android/thanos/core/app/usage/UsageStatsManager;->queryAndAggregateUsageStats(JJ)Ljava/util/Map;

    move-result-object v3

    invoke-interface {v2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v4

    :cond_3
    :goto_1
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    move-result v5

    if-eqz v5, :cond_4

    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/wu;

    iget-object v6, v5, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v6

    invoke-interface {v3, v6}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    move-result v6

    if-eqz v6, :cond_3

    iget-object v6, v5, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v6}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v6

    invoke-interface {v3, v6}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Landroid/app/usage/UsageStats;

    if-eqz v6, :cond_3

    invoke-virtual {v6}, Landroid/app/usage/UsageStats;->getLastTimeUsed()J

    move-result-wide v7

    iput-wide v7, v5, Llyiahf/vczjk/wu;->OooOOoo:J

    invoke-virtual {v6}, Landroid/app/usage/UsageStats;->getTotalTimeInForeground()J

    move-result-wide v6

    iput-wide v6, v5, Llyiahf/vczjk/wu;->OooOo00:J

    goto :goto_1

    :cond_4
    iget-object v1, v1, Llyiahf/vczjk/sw;->provider:Llyiahf/vczjk/rw;

    if-eqz v1, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v3

    invoke-interface {v1, v3}, Llyiahf/vczjk/rw;->OooOO0O(Landroid/app/Application;)Ljava/util/Comparator;

    move-result-object v1

    invoke-interface {v2, v1}, Ljava/util/List;->sort(Ljava/util/Comparator;)V

    iget-object v0, v0, Llyiahf/vczjk/t41;->OooO0oO:Landroidx/databinding/ObservableBoolean;

    invoke-virtual {v0}, Landroidx/databinding/ObservableBoolean;->get()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-static {v2}, Ljava/util/Collections;->reverse(Ljava/util/List;)V

    :cond_5
    invoke-virtual {p1, v2}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method

.method public OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    return-void
.end method

.method public OooO0OO(Ljava/lang/Throwable;)V
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j86;

    invoke-interface {v0, p1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    new-instance v0, Ljava/lang/AssertionError;

    const-string v1, "This should never happen! Report as a bug with the full stacktrace."

    invoke-direct {v0, v1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    invoke-virtual {v0, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    invoke-static {v0}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void
.end method

.method public OooO0Oo()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j86;

    invoke-interface {v0}, Llyiahf/vczjk/j86;->OooO0Oo()V

    :cond_0
    return-void
.end method

.method public OooO0o(Llyiahf/vczjk/ze9;)V
    .locals 4

    invoke-virtual {p1}, Llyiahf/vczjk/ze9;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Ljava/util/HashMap;

    invoke-virtual {v2, v1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_0

    invoke-virtual {v2, v1, p1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_1
    return-void
.end method

.method public OooO0o0(Llyiahf/vczjk/sg5;Z)V
    .locals 2

    iget-boolean p2, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-eqz p2, :cond_0

    return-void

    :cond_0
    const/4 p2, 0x1

    iput-boolean p2, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    iget-object p2, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/ww9;

    iget-object v0, p2, Llyiahf/vczjk/ww9;->Oooo00O:Landroidx/appcompat/widget/Oooo000;

    iget-object v0, v0, Landroidx/appcompat/widget/Oooo000;->OooO00o:Landroidx/appcompat/widget/Toolbar;

    iget-object v0, v0, Landroidx/appcompat/widget/Toolbar;->OooOOO0:Landroidx/appcompat/widget/ActionMenuView;

    if-eqz v0, :cond_1

    iget-object v0, v0, Landroidx/appcompat/widget/ActionMenuView;->Oooo000:Landroidx/appcompat/widget/OooO0O0;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroidx/appcompat/widget/OooO0O0;->OooO0oo()Z

    iget-object v0, v0, Landroidx/appcompat/widget/OooO0O0;->Oooo00O:Llyiahf/vczjk/oO000O0;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/wh5;->OooO0O0()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/wh5;->OooOO0:Llyiahf/vczjk/uh5;

    invoke-interface {v0}, Llyiahf/vczjk/gn8;->dismiss()V

    :cond_1
    iget-object p2, p2, Llyiahf/vczjk/ww9;->Oooo00o:Llyiahf/vczjk/er;

    const/16 v0, 0x6c

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/er;->onPanelClosed(ILandroid/view/Menu;)V

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    return-void
.end method

.method public OooO0oO()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    return v0
.end method

.method public OooOO0O(Ljava/lang/Object;)V
    .locals 5

    const/4 v0, 0x1

    check-cast p1, Llyiahf/vczjk/hs7;

    iget-object v1, p1, Llyiahf/vczjk/hs7;->OooO00o:Llyiahf/vczjk/is7;

    invoke-virtual {v1}, Llyiahf/vczjk/is7;->OooO0oO()Z

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/j86;

    if-eqz v1, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/hs7;->OooO0O0:Ljava/lang/Object;

    invoke-interface {v2, p1}, Llyiahf/vczjk/j86;->OooOO0O(Ljava/lang/Object;)V

    return-void

    :cond_0
    iput-boolean v0, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    new-instance v1, Llyiahf/vczjk/ar3;

    invoke-direct {v1, p1}, Llyiahf/vczjk/zq3;-><init>(Llyiahf/vczjk/hs7;)V

    :try_start_0
    invoke-interface {v2, v1}, Llyiahf/vczjk/j86;->OooO0OO(Ljava/lang/Throwable;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    move-exception p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->Oooo(Ljava/lang/Throwable;)V

    new-instance v2, Llyiahf/vczjk/fg1;

    const/4 v3, 0x2

    new-array v3, v3, [Ljava/lang/Throwable;

    const/4 v4, 0x0

    aput-object v1, v3, v4

    aput-object p1, v3, v0

    invoke-direct {v2, v3}, Llyiahf/vczjk/fg1;-><init>([Ljava/lang/Throwable;)V

    invoke-static {v2}, Llyiahf/vczjk/qu6;->OooOOOo(Ljava/lang/Throwable;)V

    return-void
.end method

.method public OooOOOO(Landroid/view/View;Llyiahf/vczjk/ioa;Llyiahf/vczjk/cja;)Llyiahf/vczjk/ioa;
    .locals 10

    iget-object v0, p2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v1, 0x207

    invoke-virtual {v0, v1}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v1

    const/16 v2, 0x20

    invoke-virtual {v0, v2}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v0

    iget v2, v1, Llyiahf/vczjk/x04;->OooO0O0:I

    iget-object v3, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    iput v2, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->Oooo0:I

    invoke-static {p1}, Llyiahf/vczjk/ls6;->OooOO0o(Landroid/view/View;)Z

    move-result v2

    invoke-virtual {p1}, Landroid/view/View;->getPaddingBottom()I

    move-result v4

    invoke-virtual {p1}, Landroid/view/View;->getPaddingLeft()I

    move-result v5

    invoke-virtual {p1}, Landroid/view/View;->getPaddingRight()I

    move-result v6

    iget-boolean v7, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OooOoOO:Z

    if-eqz v7, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/ioa;->OooO00o()I

    move-result v4

    iput v4, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->Oooo00o:I

    iget v7, p3, Llyiahf/vczjk/cja;->OooO0Oo:I

    add-int/2addr v4, v7

    :cond_0
    iget-boolean v7, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OooOoo0:Z

    iget v8, v1, Llyiahf/vczjk/x04;->OooO00o:I

    if-eqz v7, :cond_2

    if-eqz v2, :cond_1

    iget v5, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    goto :goto_0

    :cond_1
    iget v5, p3, Llyiahf/vczjk/cja;->OooO00o:I

    :goto_0
    add-int/2addr v5, v8

    :cond_2
    iget-boolean v7, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OooOoo:Z

    iget v9, v1, Llyiahf/vczjk/x04;->OooO0OO:I

    if-eqz v7, :cond_4

    if-eqz v2, :cond_3

    iget p3, p3, Llyiahf/vczjk/cja;->OooO00o:I

    goto :goto_1

    :cond_3
    iget p3, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    :goto_1
    add-int v6, p3, v9

    :cond_4
    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p3

    check-cast p3, Landroid/view/ViewGroup$MarginLayoutParams;

    iget-boolean v2, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OooOooo:Z

    const/4 v7, 0x1

    if-eqz v2, :cond_5

    iget v2, p3, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    if-eq v2, v8, :cond_5

    iput v8, p3, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    move v2, v7

    goto :goto_2

    :cond_5
    const/4 v2, 0x0

    :goto_2
    iget-boolean v8, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->Oooo000:Z

    if-eqz v8, :cond_6

    iget v8, p3, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    if-eq v8, v9, :cond_6

    iput v9, p3, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    move v2, v7

    :cond_6
    iget-boolean v8, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->Oooo00O:Z

    if-eqz v8, :cond_7

    iget v8, p3, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iget v1, v1, Llyiahf/vczjk/x04;->OooO0O0:I

    if-eq v8, v1, :cond_7

    iput v1, p3, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    goto :goto_3

    :cond_7
    move v7, v2

    :goto_3
    if-eqz v7, :cond_8

    invoke-virtual {p1, p3}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    :cond_8
    invoke-virtual {p1}, Landroid/view/View;->getPaddingTop()I

    move-result p3

    invoke-virtual {p1, v5, p3, v6, v4}, Landroid/view/View;->setPadding(IIII)V

    iget-boolean p1, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-eqz p1, :cond_9

    iget p3, v0, Llyiahf/vczjk/x04;->OooO0Oo:I

    iput p3, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OooOoO0:I

    :cond_9
    iget-boolean p3, v3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OooOoOO:Z

    if-nez p3, :cond_b

    if-eqz p1, :cond_a

    goto :goto_4

    :cond_a
    return-object p2

    :cond_b
    :goto_4
    invoke-virtual {v3}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OoooO00()V

    return-object p2
.end method

.method public OoooO0(Llyiahf/vczjk/sg5;)Z
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ww9;

    iget-object v0, v0, Llyiahf/vczjk/ww9;->Oooo00o:Llyiahf/vczjk/er;

    const/16 v1, 0x6c

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/er;->onMenuOpened(ILandroid/view/Menu;)Z

    const/4 p1, 0x1

    return p1
.end method

.method public toString()Ljava/lang/String;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/pc0;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-boolean v0, p0, Llyiahf/vczjk/pc0;->OooOOO:Z

    if-eqz v0, :cond_0

    const-string v0, "FALL_THROUGH"

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/pc0;->OooOOOO:Ljava/lang/Object;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    :goto_0
    return-object v0

    :pswitch_data_0
    .packed-switch 0x5
        :pswitch_0
    .end packed-switch
.end method
