.class public final Llyiahf/vczjk/v89;
.super Llyiahf/vczjk/g39;
.source "SourceFile"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "StaticFieldLeak"
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Llyiahf/vczjk/g39;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0007\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Llyiahf/vczjk/v89;",
        "Llyiahf/vczjk/g39;",
        "Llyiahf/vczjk/g99;",
        "module_feature_launcher_release"
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
.field public final OooO:Llyiahf/vczjk/jl8;

.field public final OooO0o:Landroid/content/Context;

.field public final OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

.field public final OooO0oo:Llyiahf/vczjk/sc9;

.field public final OooOO0:Llyiahf/vczjk/eh7;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    new-instance v0, Llyiahf/vczjk/p35;

    const/16 v1, 0x1d

    invoke-direct {v0, v1}, Llyiahf/vczjk/p35;-><init>(I)V

    invoke-direct {p0, v0}, Llyiahf/vczjk/g39;-><init>(Llyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/v89;->OooO0o:Landroid/content/Context;

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "ShortX"

    invoke-direct {p1, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/v89;->OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance p1, Llyiahf/vczjk/ku7;

    const/16 v0, 0xd

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/ku7;-><init>(Ljava/lang/Object;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v89;->OooO0oo:Llyiahf/vczjk/sc9;

    const/4 p1, 0x7

    const/4 v0, 0x0

    invoke-static {p1, v0}, Llyiahf/vczjk/zsa;->OooOO0o(ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jl8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/v89;->OooO:Llyiahf/vczjk/jl8;

    new-instance v1, Llyiahf/vczjk/eh7;

    invoke-direct {v1, p1}, Llyiahf/vczjk/eh7;-><init>(Llyiahf/vczjk/os5;)V

    iput-object v1, p0, Llyiahf/vczjk/v89;->OooOO0:Llyiahf/vczjk/eh7;

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/q89;

    invoke-direct {v1, p0, v0}, Llyiahf/vczjk/q89;-><init>(Llyiahf/vczjk/v89;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {p1, v0, v0, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method


# virtual methods
.method public final OooO0oo()V
    .locals 9

    sget-object v0, Llyiahf/vczjk/im4;->OooO0O0:Llyiahf/vczjk/zg9;

    invoke-virtual {v0}, Llyiahf/vczjk/zg9;->OooO0O0()Llyiahf/vczjk/q29;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/q29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    iget-boolean v2, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    const/4 v7, 0x0

    if-eqz v2, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/cm4;->OooO0O0:Ljava/lang/String;

    if-eqz v0, :cond_1

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000O00()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    sget-object v0, Llyiahf/vczjk/e99;->OooO00o:Llyiahf/vczjk/e99;

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/d99;

    invoke-direct {v1, v0}, Llyiahf/vczjk/d99;-><init>(Ljava/lang/String;)V

    move-object v0, v1

    :goto_0
    move-object v3, v0

    goto :goto_1

    :cond_1
    move-object v3, v7

    :goto_1
    iget-object v0, p0, Llyiahf/vczjk/g39;->OooO0o0:Llyiahf/vczjk/xo8;

    iget-object v1, v0, Llyiahf/vczjk/xo8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/sc9;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v4

    move-object v8, v4

    check-cast v8, Llyiahf/vczjk/rs5;

    invoke-virtual {v1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rs5;

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/g99;

    const-string v4, "$this$updateState"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x0

    const/16 v6, 0xc

    const/4 v4, 0x0

    invoke-static/range {v1 .. v6}, Llyiahf/vczjk/g99;->OooO00o(Llyiahf/vczjk/g99;ZLlyiahf/vczjk/f99;Llyiahf/vczjk/r7a;Llyiahf/vczjk/r7a;I)Llyiahf/vczjk/g99;

    move-result-object v1

    check-cast v8, Llyiahf/vczjk/s29;

    invoke-virtual {v8, v1}, Llyiahf/vczjk/s29;->OooOOOO(Ljava/lang/Object;)V

    invoke-virtual {v0}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v1, Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/g99;

    iget-object v1, v1, Llyiahf/vczjk/g99;->OooO0O0:Llyiahf/vczjk/f99;

    instance-of v2, v1, Llyiahf/vczjk/d99;

    if-eqz v2, :cond_2

    check-cast v1, Llyiahf/vczjk/d99;

    iget-object v1, v1, Llyiahf/vczjk/d99;->OooO00o:Ljava/lang/String;

    invoke-virtual {v0}, Llyiahf/vczjk/xo8;->OooOO0()Llyiahf/vczjk/gh7;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/gh7;->OooOOO0:Llyiahf/vczjk/rs5;

    check-cast v0, Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/g99;

    iget-object v0, v0, Llyiahf/vczjk/g99;->OooO0Oo:Llyiahf/vczjk/r7a;

    instance-of v0, v0, Llyiahf/vczjk/p7a;

    if-nez v0, :cond_2

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/r89;

    invoke-direct {v2, p0, v1, v7}, Llyiahf/vczjk/r89;-><init>(Llyiahf/vczjk/v89;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    const/4 v1, 0x3

    invoke-static {v0, v7, v7, v2, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_2
    return-void
.end method
