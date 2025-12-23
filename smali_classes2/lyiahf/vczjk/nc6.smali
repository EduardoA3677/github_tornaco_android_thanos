.class public final Llyiahf/vczjk/nc6;
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
        "Llyiahf/vczjk/nc6;",
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

.field public final OooO0OO:Llyiahf/vczjk/ec6;

.field public final OooO0Oo:Llyiahf/vczjk/s29;

.field public final OooO0o:Llyiahf/vczjk/jl8;

.field public final OooO0o0:Llyiahf/vczjk/gh7;

.field public final OooO0oO:Llyiahf/vczjk/sc9;

.field public final OooO0oo:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/ec6;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/nc6;->OooO0O0:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/nc6;->OooO0OO:Llyiahf/vczjk/ec6;

    new-instance p1, Llyiahf/vczjk/gc6;

    sget-object p2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const/4 v0, 0x1

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/gc6;-><init>(Ljava/util/List;Z)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nc6;->OooO0Oo:Llyiahf/vczjk/s29;

    new-instance p2, Llyiahf/vczjk/gh7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object p2, p0, Llyiahf/vczjk/nc6;->OooO0o0:Llyiahf/vczjk/gh7;

    const/4 p1, 0x7

    const/4 p2, 0x0

    invoke-static {p1, p2}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nc6;->OooO0o:Llyiahf/vczjk/jl8;

    new-instance p1, Llyiahf/vczjk/ub6;

    const/4 p2, 0x2

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/ub6;-><init>(Llyiahf/vczjk/nc6;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nc6;->OooO0oO:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/p35;

    const/16 p2, 0xc

    invoke-direct {p1, p2}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/nc6;->OooO0oo:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO0o(Llyiahf/vczjk/cc6;)V
    .locals 4

    const-string v0, "profile"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/nc6;->OooO0oO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    iget-object v1, p1, Llyiahf/vczjk/cc6;->OooO0O0:Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getRuleByName(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/profile/RuleInfo;

    move-result-object v1

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/core/profile/RuleInfo;->getId()I

    move-result v1

    invoke-virtual {v0, v1}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->deleteRule(I)V

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/kc6;

    const/4 v3, 0x0

    invoke-direct {v2, p0, p1, v0, v3}, Llyiahf/vczjk/kc6;-><init>(Llyiahf/vczjk/nc6;Llyiahf/vczjk/cc6;Llyiahf/vczjk/xr1;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v1, v3, v3, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final OooO0o0()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/nc6;->OooO0Oo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/gc6;

    iget-object v1, v1, Llyiahf/vczjk/gc6;->OooO0O0:Ljava/util/List;

    const-string v2, "files"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/gc6;

    const/4 v3, 0x1

    invoke-direct {v2, v1, v3}, Llyiahf/vczjk/gc6;-><init>(Ljava/util/List;Z)V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/mc6;

    invoke-direct {v2, p0, v1}, Llyiahf/vczjk/mc6;-><init>(Llyiahf/vczjk/nc6;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v1, v1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
