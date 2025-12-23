.class public final Llyiahf/vczjk/h48;
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
        "Llyiahf/vczjk/h48;",
        "Llyiahf/vczjk/fy4;",
        "ui_prcRelease"
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
.field public final OooO:Llyiahf/vczjk/gh7;

.field public final OooO0o:Llyiahf/vczjk/e28;

.field public final OooO0o0:Llyiahf/vczjk/x58;

.field public final OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

.field public final OooO0oo:Llyiahf/vczjk/s29;

.field public final OooOO0:Llyiahf/vczjk/gh7;

.field public final OooOO0O:Llyiahf/vczjk/gh7;

.field public final OooOO0o:Llyiahf/vczjk/sc9;

.field public final OooOOO:Llyiahf/vczjk/sc9;

.field public final OooOOO0:Llyiahf/vczjk/sc9;

.field public final OooOOOO:Llyiahf/vczjk/gh7;

.field public final OooOOOo:Llyiahf/vczjk/gh7;

.field public final OooOOo:Llyiahf/vczjk/gh7;

.field public final OooOOo0:Llyiahf/vczjk/gh7;

.field public final OooOOoo:Llyiahf/vczjk/h38;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/x58;Llyiahf/vczjk/e28;)V
    .locals 3

    const-string p1, "savedStateHandle"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p1, "repo"

    invoke-static {p3, p1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Llyiahf/vczjk/fy4;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/h48;->OooO0o0:Llyiahf/vczjk/x58;

    iput-object p3, p0, Llyiahf/vczjk/h48;->OooO0o:Llyiahf/vczjk/e28;

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "SFVM"

    invoke-direct {p1, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance p1, Llyiahf/vczjk/i28;

    sget-object v0, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    const/4 v1, 0x0

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/i28;-><init>(Ljava/util/Set;Z)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooO0oo:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/h48;->OooO:Llyiahf/vczjk/gh7;

    const-string p1, "query"

    const-string v0, ""

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/x58;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooOO0:Llyiahf/vczjk/gh7;

    sget-object p1, Llyiahf/vczjk/v18;->OooO00o:Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    invoke-virtual {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->getId()Ljava/lang/String;

    move-result-object p1

    const-string v0, "set"

    invoke-virtual {p2, v0, p1}, Llyiahf/vczjk/x58;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooOO0O:Llyiahf/vczjk/gh7;

    new-instance p1, Llyiahf/vczjk/l08;

    const/4 p2, 0x6

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooOO0o:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/l08;

    const/4 p2, 0x7

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooOOO0:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/l08;

    const/16 p2, 0x8

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/l08;-><init>(Llyiahf/vczjk/h48;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooOOO:Llyiahf/vczjk/sc9;

    iget-object p1, p3, Llyiahf/vczjk/e28;->OooO00o:Llyiahf/vczjk/u18;

    iget-object p2, p1, Llyiahf/vczjk/u18;->OooO00o:Landroid/content/Context;

    invoke-static {p2}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p2

    invoke-interface {p2}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/wh;

    const/16 v0, 0x9

    invoke-direct {p3, p2, v0}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/ql8;->OooO0O0:Llyiahf/vczjk/e86;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {p3, p2, v0, v1}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/h48;->OooOOOO:Llyiahf/vczjk/gh7;

    iget-object p1, p1, Llyiahf/vczjk/u18;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p2

    invoke-interface {p2}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/wh;

    const/16 v2, 0xa

    invoke-direct {p3, p2, v2}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p2

    invoke-static {p3, p2, v0, v1}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/h48;->OooOOOo:Llyiahf/vczjk/gh7;

    invoke-static {p1}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p2

    invoke-interface {p2}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p2

    new-instance p3, Llyiahf/vczjk/wh;

    const/16 v2, 0x8

    invoke-direct {p3, p2, v2}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p2

    invoke-static {p3, p2, v0, v1}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/h48;->OooOOo0:Llyiahf/vczjk/gh7;

    invoke-static {p1}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/wh;

    const/4 p3, 0x7

    invoke-direct {p2, p1, p3}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    invoke-static {p2, p1, v0, v1}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooOOo:Llyiahf/vczjk/gh7;

    new-instance p1, Llyiahf/vczjk/h38;

    invoke-direct {p1, p0}, Llyiahf/vczjk/h38;-><init>(Llyiahf/vczjk/h48;)V

    iput-object p1, p0, Llyiahf/vczjk/h48;->OooOOoo:Llyiahf/vczjk/h38;

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/k28;

    const/4 p3, 0x0

    invoke-direct {p2, p0, p3}, Llyiahf/vczjk/k28;-><init>(Llyiahf/vczjk/h48;Llyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {p1, p3, p3, p2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method


# virtual methods
.method public final OooO(Lgithub/tornaco/android/thanos/core/pm/Pkg;Llyiahf/vczjk/zo1;)Ljava/lang/Comparable;
    .locals 4

    instance-of v0, p2, Llyiahf/vczjk/e38;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/e38;

    iget v1, v0, Llyiahf/vczjk/e38;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/e38;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/e38;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/e38;-><init>(Llyiahf/vczjk/h48;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/e38;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/e38;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/e38;->L$0:Ljava/lang/Object;

    check-cast p1, Lgithub/tornaco/android/thanos/core/pm/Pkg;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p2, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    iput-object p1, v0, Llyiahf/vczjk/e38;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/e38;->label:I

    invoke-virtual {p2, v0}, Llyiahf/vczjk/km8;->OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    check-cast p2, Lgithub/tornaco/android/thanos/core/IThanosLite;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getPkgName()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/Pkg;->getUserId()I

    move-result p1

    invoke-interface {p2, v0, p1}, Lgithub/tornaco/android/thanos/core/IThanosLite;->getAppInfoForUser(Ljava/lang/String;I)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/nm8;->OooO0O0:Lgithub/tornaco/android/thanos/core/IThanosLite;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/h48;->OooOOoo:Llyiahf/vczjk/h38;

    invoke-interface {v0, v1}, Lgithub/tornaco/android/thanos/core/IThanosLite;->unregisterPkgStateChangeListener(Lgithub/tornaco/android/thanos/core/IPkgChangeListener;)V

    :cond_0
    return-void
.end method

.method public final OooO0o()V
    .locals 1

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/fy4;->OooO0OO:Z

    iget-object v0, p0, Llyiahf/vczjk/h48;->OooO0o:Llyiahf/vczjk/e28;

    invoke-virtual {v0}, Llyiahf/vczjk/e28;->OooO0OO()V

    return-void
.end method

.method public final OooO0oo()V
    .locals 6

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/h48;->OooO0oo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/i28;

    sget-object v3, Llyiahf/vczjk/gn2;->OooOOO0:Llyiahf/vczjk/gn2;

    const/4 v4, 0x1

    const/4 v5, 0x0

    invoke-static {v2, v5, v3, v4}, Llyiahf/vczjk/i28;->OooO00o(Llyiahf/vczjk/i28;ZLjava/util/Set;I)Llyiahf/vczjk/i28;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    return-void
.end method

.method public final OooOO0(Lgithub/tornaco/android/thanos/core/pm/Pkg;)V
    .locals 6

    const-string v0, "pkg"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/h48;->OooO0oo:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/i28;

    iget-object v3, v2, Llyiahf/vczjk/i28;->OooO0O0:Ljava/util/Set;

    check-cast v3, Ljava/lang/Iterable;

    invoke-static {v3}, Llyiahf/vczjk/d21;->o0000OOO(Ljava/lang/Iterable;)Ljava/util/Set;

    move-result-object v3

    invoke-interface {v3, p1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-interface {v3, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    invoke-interface {v3, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    :goto_0
    const/4 v4, 0x3

    const/4 v5, 0x0

    invoke-static {v2, v5, v3, v4}, Llyiahf/vczjk/i28;->OooO00o(Llyiahf/vczjk/i28;ZLjava/util/Set;I)Llyiahf/vczjk/i28;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/i28;

    iget-object p1, p1, Llyiahf/vczjk/i28;->OooO0O0:Ljava/util/Set;

    invoke-interface {p1}, Ljava/util/Set;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/h48;->OooO0oo()V

    :cond_2
    return-void
.end method
