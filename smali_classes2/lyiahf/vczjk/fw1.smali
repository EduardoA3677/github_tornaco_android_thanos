.class public final synthetic Llyiahf/vczjk/fw1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/lw1;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/lw1;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/fw1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/fw1;->OooOOO:Llyiahf/vczjk/lw1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 10

    iget v0, p0, Llyiahf/vczjk/fw1;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/fw1;->OooOOO:Llyiahf/vczjk/lw1;

    iget-object v0, v0, Llyiahf/vczjk/lw1;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/fw1;->OooOOO:Llyiahf/vczjk/lw1;

    iget-object v1, v0, Llyiahf/vczjk/lw1;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getDanmuUISettings()Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    move-result-object v1

    if-eqz v1, :cond_0

    new-instance v2, Llyiahf/vczjk/x6a;

    new-instance v3, Llyiahf/vczjk/w6a;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getAlpha()F

    move-result v4

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getBackgroundColor()I

    move-result v5

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextColor()I

    move-result v6

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getTextSizeSp()I

    move-result v7

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;->getDuration()J

    move-result-wide v8

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/w6a;-><init>(FIIIJ)V

    invoke-direct {v2, v3}, Llyiahf/vczjk/x6a;-><init>(Llyiahf/vczjk/w6a;)V

    iget-object v0, v0, Llyiahf/vczjk/lw1;->OooO0o0:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
