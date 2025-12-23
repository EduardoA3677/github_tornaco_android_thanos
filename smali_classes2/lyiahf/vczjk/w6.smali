.class public final Llyiahf/vczjk/w6;
.super Llyiahf/vczjk/fy4;
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
        "Llyiahf/vczjk/w6;",
        "Llyiahf/vczjk/fy4;",
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
.field public final OooO0o:Llyiahf/vczjk/s29;

.field public final OooO0o0:Landroid/content/Context;

.field public final OooO0oO:Llyiahf/vczjk/gh7;

.field public final OooO0oo:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/fy4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w6;->OooO0o0:Landroid/content/Context;

    new-instance p1, Llyiahf/vczjk/t6;

    invoke-static {}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->dummy()Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/t6;-><init>(Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/util/List;)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/w6;->OooO0o:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/w6;->OooO0oO:Llyiahf/vczjk/gh7;

    new-instance p1, Llyiahf/vczjk/k1;

    const/4 v0, 0x4

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/w6;->OooO0oo:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO0oo()V
    .locals 4

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/v6;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/v6;-><init>(Llyiahf/vczjk/w6;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
