.class public final synthetic Llyiahf/vczjk/o09;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/up8;
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/o0oo0000;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/p09;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/p09;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/o09;->OooOOO0:Llyiahf/vczjk/p09;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/o09;->OooOOO0:Llyiahf/vczjk/p09;

    iget-object v0, v0, Llyiahf/vczjk/p09;->OooO0o:Llyiahf/vczjk/wg7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iget-object v0, v0, Llyiahf/vczjk/wg7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/p09;

    invoke-virtual {v0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getAllStandbyRules()[Ljava/lang/String;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/wv;

    const/4 v3, 0x4

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/wv;-><init>(Ljava/lang/Object;I)V

    invoke-static {v0, v2}, Lutil/CollectionUtils;->consumeRemaining([Ljava/lang/Object;Lutil/Consumer;)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/o09;->OooOOO0:Llyiahf/vczjk/p09;

    iget-object p1, p1, Llyiahf/vczjk/p09;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {p1}, Landroidx/databinding/ObservableArrayList;->clear()V

    return-void
.end method

.method public run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/o09;->OooOOO0:Llyiahf/vczjk/p09;

    iget-object v0, v0, Llyiahf/vczjk/p09;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    return-void
.end method
