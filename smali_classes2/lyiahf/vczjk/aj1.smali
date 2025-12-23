.class public final synthetic Llyiahf/vczjk/aj1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/fj1;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/fj1;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/aj1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/aj1;->OooOOO:Llyiahf/vczjk/fj1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 6

    iget v0, p0, Llyiahf/vczjk/aj1;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/aj1;->OooOOO:Llyiahf/vczjk/fj1;

    iget-object v0, v0, Llyiahf/vczjk/fj1;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/aj1;->OooOOO:Llyiahf/vczjk/fj1;

    iget-object v1, v0, Llyiahf/vczjk/fj1;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/dj1;

    const-string v3, ""

    const/4 v4, 0x1

    const/4 v5, 0x0

    invoke-static {v2, v5, v3, v4}, Llyiahf/vczjk/dj1;->OooO00o(Llyiahf/vczjk/dj1;Ljava/lang/String;Ljava/lang/String;I)Llyiahf/vczjk/dj1;

    move-result-object v2

    invoke-virtual {v1, v5, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    iget-object v1, v0, Llyiahf/vczjk/fj1;->OooO0o0:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v1

    iget-object v0, v0, Llyiahf/vczjk/fj1;->OooO0Oo:Llyiahf/vczjk/gh7;

    iget-object v0, v0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dj1;

    iget-object v0, v0, Llyiahf/vczjk/dj1;->OooO00o:Ljava/lang/String;

    invoke-virtual {v1, v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->executeAction(Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
