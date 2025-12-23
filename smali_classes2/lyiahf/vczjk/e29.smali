.class public final synthetic Llyiahf/vczjk/e29;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/up8;
.implements Llyiahf/vczjk/nl1;
.implements Llyiahf/vczjk/o0oo0000;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/f29;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/f29;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e29;->OooOOO0:Llyiahf/vczjk/f29;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public OooO00o(Llyiahf/vczjk/kp8;)V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/e29;->OooOOO0:Llyiahf/vczjk/f29;

    iget-object v0, v0, Llyiahf/vczjk/f29;->OooO0o:Llyiahf/vczjk/as7;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    iget-object v0, v0, Llyiahf/vczjk/as7;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/f29;

    invoke-virtual {v0}, Llyiahf/vczjk/ph;->OooO0o0()Landroid/app/Application;

    move-result-object v0

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityManager()Lgithub/tornaco/android/thanos/core/app/ActivityManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ActivityManager;->getAllStartRules()[Ljava/lang/String;

    move-result-object v0

    array-length v2, v0

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    aget-object v4, v0, v3

    new-instance v5, Llyiahf/vczjk/y19;

    invoke-direct {v5, v4}, Llyiahf/vczjk/y19;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {p1, v1}, Llyiahf/vczjk/kp8;->OooO0O0(Ljava/lang/Object;)V

    return-void
.end method

.method public accept(Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/nc2;

    iget-object p1, p0, Llyiahf/vczjk/e29;->OooOOO0:Llyiahf/vczjk/f29;

    iget-object p1, p1, Llyiahf/vczjk/f29;->OooO0o0:Landroidx/databinding/ObservableArrayList;

    invoke-virtual {p1}, Landroidx/databinding/ObservableArrayList;->clear()V

    return-void
.end method

.method public run()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/e29;->OooOOO0:Llyiahf/vczjk/f29;

    iget-object v0, v0, Llyiahf/vczjk/f29;->OooO0OO:Landroidx/databinding/ObservableBoolean;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroidx/databinding/ObservableBoolean;->set(Z)V

    return-void
.end method
