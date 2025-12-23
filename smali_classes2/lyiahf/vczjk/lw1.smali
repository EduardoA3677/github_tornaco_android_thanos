.class public final Llyiahf/vczjk/lw1;
.super Llyiahf/vczjk/dha;
.source "SourceFile"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "StaticFieldLeak"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\n\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0007\u0018\u00002\u00020\u0001\u00a8\u0006\u0002"
    }
    d2 = {
        "Llyiahf/vczjk/lw1;",
        "Llyiahf/vczjk/dha;",
        "app_prcRelease"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final OooO0O0:Landroid/content/Context;

.field public final OooO0OO:Llyiahf/vczjk/sc9;

.field public OooO0Oo:Llyiahf/vczjk/r09;

.field public final OooO0o:Llyiahf/vczjk/gh7;

.field public final OooO0o0:Llyiahf/vczjk/s29;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 7

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/lw1;->OooO0O0:Landroid/content/Context;

    new-instance p1, Llyiahf/vczjk/fw1;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/fw1;-><init>(Llyiahf/vczjk/lw1;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/lw1;->OooO0OO:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/x6a;

    new-instance v0, Llyiahf/vczjk/w6a;

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const-wide/16 v5, 0x0

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/w6a;-><init>(FIIIJ)V

    invoke-direct {p1, v0}, Llyiahf/vczjk/x6a;-><init>(Llyiahf/vczjk/w6a;)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/lw1;->OooO0o0:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/lw1;->OooO0o:Llyiahf/vczjk/gh7;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/w6a;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/lw1;->OooO0Oo:Llyiahf/vczjk/r09;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/lw1;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    new-instance v2, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;

    iget v4, p1, Llyiahf/vczjk/w6a;->OooO0O0:I

    iget v5, p1, Llyiahf/vczjk/w6a;->OooO0OO:I

    iget v3, p1, Llyiahf/vczjk/w6a;->OooO00o:F

    iget v6, p1, Llyiahf/vczjk/w6a;->OooO0Oo:I

    iget-wide v7, p1, Llyiahf/vczjk/w6a;->OooO0o0:J

    invoke-direct/range {v2 .. v8}, Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;-><init>(FIIIJ)V

    invoke-virtual {v0, v2}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->setDanmuUISettings(Lgithub/tornaco/android/thanos/core/profile/DanmuUISettings;)V

    new-instance v0, Llyiahf/vczjk/x6a;

    invoke-direct {v0, p1}, Llyiahf/vczjk/x6a;-><init>(Llyiahf/vczjk/w6a;)V

    iget-object p1, p0, Llyiahf/vczjk/lw1;->OooO0o0:Llyiahf/vczjk/s29;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/kw1;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/kw1;-><init>(Llyiahf/vczjk/lw1;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {p1, v1, v1, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/lw1;->OooO0Oo:Llyiahf/vczjk/r09;

    return-void
.end method
