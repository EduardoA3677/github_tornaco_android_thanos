.class public final Llyiahf/vczjk/e54;
.super Llyiahf/vczjk/d54;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/na6;


# instance fields
.field public final OooOOoo:Llyiahf/vczjk/o000O0Oo;

.field public OooOo00:J


# direct methods
.method public constructor <init>(Landroid/view/View;Landroidx/databinding/DataBindingComponent;)V
    .locals 9

    const/4 v0, 0x3

    const/4 v1, 0x0

    invoke-static {p2, p1, v0, v1, v1}, Landroidx/databinding/ViewDataBinding;->mapBindings(Landroidx/databinding/DataBindingComponent;Landroid/view/View;ILandroidx/databinding/ViewDataBinding$IncludedLayouts;Landroid/util/SparseIntArray;)[Ljava/lang/Object;

    move-result-object v0

    const/4 v2, 0x0

    aget-object v2, v0, v2

    move-object v6, v2

    check-cast v6, Landroid/widget/RelativeLayout;

    const/4 v2, 0x1

    aget-object v2, v0, v2

    move-object v7, v2

    check-cast v7, Landroidx/appcompat/widget/AppCompatImageView;

    const/4 v2, 0x2

    aget-object v0, v0, v2

    move-object v8, v0

    check-cast v8, Landroid/widget/TextView;

    move-object v3, p0

    move-object v5, p1

    move-object v4, p2

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/d54;-><init>(Landroidx/databinding/DataBindingComponent;Landroid/view/View;Landroid/widget/RelativeLayout;Landroidx/appcompat/widget/AppCompatImageView;Landroid/widget/TextView;)V

    const-wide/16 p1, -0x1

    iput-wide p1, v3, Llyiahf/vczjk/e54;->OooOo00:J

    iget-object p1, v3, Llyiahf/vczjk/d54;->OooOOO0:Landroid/widget/RelativeLayout;

    invoke-virtual {p1, v1}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    iget-object p1, v3, Llyiahf/vczjk/d54;->OooOOO:Landroidx/appcompat/widget/AppCompatImageView;

    invoke-virtual {p1, v1}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    iget-object p1, v3, Llyiahf/vczjk/d54;->OooOOOO:Landroid/widget/TextView;

    invoke-virtual {p1, v1}, Landroid/view/View;->setTag(Ljava/lang/Object;)V

    invoke-virtual {p0, v5}, Landroidx/databinding/ViewDataBinding;->setRootTag(Landroid/view/View;)V

    new-instance p1, Llyiahf/vczjk/o000O0Oo;

    const/16 p2, 0x8

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/o000O0Oo;-><init>(Ljava/lang/Object;I)V

    iput-object p1, v3, Llyiahf/vczjk/e54;->OooOOoo:Llyiahf/vczjk/o000O0Oo;

    invoke-virtual {p0}, Llyiahf/vczjk/e54;->invalidateAll()V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/d54;->OooOOOo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v1, p0, Llyiahf/vczjk/d54;->OooOOo0:Llyiahf/vczjk/xt;

    if-eqz v1, :cond_0

    invoke-interface {v1, v0}, Llyiahf/vczjk/xt;->OooO00o(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    :cond_0
    return-void
.end method

.method public final OooO0o(Llyiahf/vczjk/xt;)V
    .locals 4

    iput-object p1, p0, Llyiahf/vczjk/d54;->OooOOo0:Llyiahf/vczjk/xt;

    monitor-enter p0

    :try_start_0
    iget-wide v0, p0, Llyiahf/vczjk/e54;->OooOo00:J

    const-wide/16 v2, 0x2

    or-long/2addr v0, v2

    iput-wide v0, p0, Llyiahf/vczjk/e54;->OooOo00:J

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/16 p1, 0xb

    invoke-virtual {p0, p1}, Landroidx/databinding/BaseObservable;->notifyPropertyChanged(I)V

    invoke-super {p0}, Landroidx/databinding/ViewDataBinding;->requestRebind()V

    return-void

    :catchall_0
    move-exception p1

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public final OooO0o0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V
    .locals 4

    iput-object p1, p0, Llyiahf/vczjk/d54;->OooOOOo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    monitor-enter p0

    :try_start_0
    iget-wide v0, p0, Llyiahf/vczjk/e54;->OooOo00:J

    const-wide/16 v2, 0x1

    or-long/2addr v0, v2

    iput-wide v0, p0, Llyiahf/vczjk/e54;->OooOo00:J

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 p1, 0x1

    invoke-virtual {p0, p1}, Landroidx/databinding/BaseObservable;->notifyPropertyChanged(I)V

    invoke-super {p0}, Landroidx/databinding/ViewDataBinding;->requestRebind()V

    return-void

    :catchall_0
    move-exception p1

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public final executeBindings()V
    .locals 9

    monitor-enter p0

    :try_start_0
    iget-wide v0, p0, Llyiahf/vczjk/e54;->OooOo00:J

    const-wide/16 v2, 0x0

    iput-wide v2, p0, Llyiahf/vczjk/e54;->OooOo00:J

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v4, p0, Llyiahf/vczjk/d54;->OooOOOo:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    const-wide/16 v5, 0x5

    and-long/2addr v5, v0

    cmp-long v5, v5, v2

    if-eqz v5, :cond_0

    if-eqz v4, :cond_0

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object v6

    goto :goto_0

    :cond_0
    const/4 v6, 0x0

    :goto_0
    const-wide/16 v7, 0x4

    and-long/2addr v0, v7

    cmp-long v0, v0, v2

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/d54;->OooOOO0:Landroid/widget/RelativeLayout;

    iget-object v1, p0, Llyiahf/vczjk/e54;->OooOOoo:Llyiahf/vczjk/o000O0Oo;

    invoke-virtual {v0, v1}, Landroid/view/View;->setOnClickListener(Landroid/view/View$OnClickListener;)V

    :cond_1
    if-eqz v5, :cond_2

    iget-object v0, p0, Llyiahf/vczjk/d54;->OooOOO:Landroidx/appcompat/widget/AppCompatImageView;

    invoke-static {v0, v4}, Llyiahf/vczjk/qqa;->Oooo0oo(Landroid/widget/ImageView;Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    iget-object v0, p0, Llyiahf/vczjk/d54;->OooOOOO:Landroid/widget/TextView;

    invoke-static {v0, v6}, Landroidx/databinding/adapters/TextViewBindingAdapter;->setText(Landroid/widget/TextView;Ljava/lang/CharSequence;)V

    :cond_2
    return-void

    :catchall_0
    move-exception v0

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public final hasPendingBindings()Z
    .locals 4

    monitor-enter p0

    :try_start_0
    iget-wide v0, p0, Llyiahf/vczjk/e54;->OooOo00:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    monitor-exit p0

    return v0

    :catchall_0
    move-exception v0

    goto :goto_0

    :cond_0
    monitor-exit p0

    const/4 v0, 0x0

    return v0

    :goto_0
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public final invalidateAll()V
    .locals 2

    monitor-enter p0

    const-wide/16 v0, 0x4

    :try_start_0
    iput-wide v0, p0, Llyiahf/vczjk/e54;->OooOo00:J

    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {p0}, Landroidx/databinding/ViewDataBinding;->requestRebind()V

    return-void

    :catchall_0
    move-exception v0

    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw v0
.end method

.method public final onFieldChange(ILjava/lang/Object;I)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final setVariable(ILjava/lang/Object;)Z
    .locals 2

    const/4 v0, 0x1

    if-ne v0, p1, :cond_0

    check-cast p2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {p0, p2}, Llyiahf/vczjk/e54;->OooO0o0(Lgithub/tornaco/android/thanos/core/pm/AppInfo;)V

    return v0

    :cond_0
    const/16 v1, 0xb

    if-ne v1, p1, :cond_1

    check-cast p2, Llyiahf/vczjk/xt;

    invoke-virtual {p0, p2}, Llyiahf/vczjk/e54;->OooO0o(Llyiahf/vczjk/xt;)V

    return v0

    :cond_1
    const/4 p1, 0x0

    return p1
.end method
