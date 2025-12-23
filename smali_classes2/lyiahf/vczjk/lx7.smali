.class public final synthetic Llyiahf/vczjk/lx7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/up8;
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/o0oo0000;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/nx7;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/nx7;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/lx7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/lx7;->OooOOO:Llyiahf/vczjk/nx7;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/lx7;->OooOOO:Llyiahf/vczjk/nx7;

    iget-object v0, v0, Llyiahf/vczjk/nx7;->OooO0oO:Llyiahf/vczjk/lx7;

    iget-object v0, v0, Llyiahf/vczjk/lx7;->OooOOO:Llyiahf/vczjk/nx7;

    new-instance v1, Ljava/util/ArrayList;

    invoke-virtual {v0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getAllRules()[Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    new-instance v0, Llyiahf/vczjk/qw;

    const/16 v2, 0xc

    invoke-direct {v0, v2}, Llyiahf/vczjk/qw;-><init>(I)V

    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->sort(Ljava/util/Comparator;)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/lx7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    iget-object v0, p0, Llyiahf/vczjk/lx7;->OooOOO:Llyiahf/vczjk/nx7;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nx7;->OooO0oO(Lgithub/tornaco/android/thanos/core/profile/RuleInfo;)Llyiahf/vczjk/vx7;

    move-result-object p1

    iget-object v0, v0, Llyiahf/vczjk/nx7;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {v0, p1}, Landroidx/databinding/ObservableArrayList;->add(Ljava/lang/Object;)Z

    return-void

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/lx7;->OooOOO:Llyiahf/vczjk/nx7;

    iget-object p1, p1, Llyiahf/vczjk/nx7;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {p1}, Landroidx/databinding/ObservableArrayList;->clear()V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/lx7;->OooOOO:Llyiahf/vczjk/nx7;

    iget-object v0, v0, Llyiahf/vczjk/nx7;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    return-void
.end method
