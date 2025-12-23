.class public final Llyiahf/vczjk/ema;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/ema;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/ema;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/ema;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/ema;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/ema;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t3a;

    iget-object v0, v0, Llyiahf/vczjk/t3a;->OooO00o:Llyiahf/vczjk/u72;

    iget-object v1, v0, Llyiahf/vczjk/u72;->OooO00o:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s72;

    iget-object v1, v1, Llyiahf/vczjk/s72;->OooO0o0:Llyiahf/vczjk/hn;

    iget-object v0, v0, Llyiahf/vczjk/u72;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/rt5;

    iget-object v2, p0, Llyiahf/vczjk/ema;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/hd7;

    invoke-interface {v1, v2, v0}, Llyiahf/vczjk/zn;->OooO0oO(Llyiahf/vczjk/hd7;Llyiahf/vczjk/rt5;)Ljava/util/ArrayList;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/ema;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mka;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/ema;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Landroid/content/ComponentName;

    iget-object v2, v0, Llyiahf/vczjk/mka;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getActivityStackSupervisor()Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;

    move-result-object v2

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    invoke-virtual {v2, v1}, Lgithub/tornaco/android/thanos/core/app/activity/ActivityStackSupervisor;->removeAppLockWhiteListComponents(Ljava/util/List;)V

    invoke-virtual {v0}, Llyiahf/vczjk/mka;->OooO0o0()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
