.class public final synthetic Llyiahf/vczjk/tv;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/aw;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/aw;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/tv;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/tv;->OooOOO:Llyiahf/vczjk/aw;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/tv;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/tv;->OooOOO:Llyiahf/vczjk/aw;

    iget-object v0, v0, Llyiahf/vczjk/aw;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getOpsManager()Lgithub/tornaco/android/thanos/core/ops/OpsManager;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/tv;->OooOOO:Llyiahf/vczjk/aw;

    iget-object v0, v0, Llyiahf/vczjk/aw;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
