.class public final synthetic Llyiahf/vczjk/z45;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/l55;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/l55;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/z45;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/z45;->OooOOO:Llyiahf/vczjk/l55;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/z45;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/z45;->OooOOO:Llyiahf/vczjk/l55;

    iget-object v0, v0, Llyiahf/vczjk/l55;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/z45;->OooOOO:Llyiahf/vczjk/l55;

    invoke-virtual {v0}, Llyiahf/vczjk/l55;->OooO0o()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/z45;->OooOOO:Llyiahf/vczjk/l55;

    invoke-virtual {v0}, Llyiahf/vczjk/l55;->OooO0o0()Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->clearLogs()V

    invoke-virtual {v0}, Llyiahf/vczjk/l55;->OooO0o()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
