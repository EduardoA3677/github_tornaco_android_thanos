.class public final synthetic Llyiahf/vczjk/si3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/up8;
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/o0oo0000;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/ti3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ti3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/si3;->OooOOO0:Llyiahf/vczjk/ti3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/si3;->OooOOO0:Llyiahf/vczjk/ti3;

    iget-object v0, v0, Llyiahf/vczjk/ti3;->OooO0o:Llyiahf/vczjk/si3;

    iget-object v0, v0, Llyiahf/vczjk/si3;->OooOOO0:Llyiahf/vczjk/ti3;

    new-instance v1, Ljava/util/ArrayList;

    invoke-virtual {v0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getAllGlobalRuleVar()[Lgithub/tornaco/android/thanos/core/profile/GlobalVar;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/si3;->OooOOO0:Llyiahf/vczjk/ti3;

    iget-object p1, p1, Llyiahf/vczjk/ti3;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {p1}, Landroidx/databinding/ObservableArrayList;->clear()V

    return-void
.end method

.method public run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/si3;->OooOOO0:Llyiahf/vczjk/ti3;

    iget-object v0, v0, Llyiahf/vczjk/ti3;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    return-void
.end method
