.class public final Llyiahf/vczjk/ua5;
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
        "Llyiahf/vczjk/ua5;",
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

.field public final OooO0o0:Landroid/content/Context;

.field public final OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

.field public final OooO0oo:Llyiahf/vczjk/s29;

.field public final OooOO0:Llyiahf/vczjk/gh7;

.field public final OooOO0O:Llyiahf/vczjk/gh7;

.field public final OooOO0o:Llyiahf/vczjk/gh7;

.field public final OooOOO:Llyiahf/vczjk/oa5;

.field public final OooOOO0:Llyiahf/vczjk/gh7;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/e28;Llyiahf/vczjk/o30;)V
    .locals 4

    const-string v0, "sfRepoImpl"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "bcRepoImpl"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Llyiahf/vczjk/fy4;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooO0o0:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/ua5;->OooO0o:Llyiahf/vczjk/e28;

    new-instance p1, Lgithub/tornaco/android/thanos/core/Logger;

    const-string v0, "MainVM"

    invoke-direct {p1, v0}, Lgithub/tornaco/android/thanos/core/Logger;-><init>(Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooO0oO:Lgithub/tornaco/android/thanos/core/Logger;

    new-instance p1, Llyiahf/vczjk/nw5;

    sget-object v0, Llyiahf/vczjk/y39;->OooO00o:Llyiahf/vczjk/x39;

    const/4 v1, 0x0

    invoke-direct {p1, v1, v0, v1, v1}, Llyiahf/vczjk/nw5;-><init>(ZLlyiahf/vczjk/x39;ZZ)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooO0oo:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/ua5;->OooO:Llyiahf/vczjk/gh7;

    invoke-virtual {p2}, Llyiahf/vczjk/e28;->OooO0O0()Llyiahf/vczjk/y63;

    move-result-object p1

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/ql8;->OooO00o:Llyiahf/vczjk/wp3;

    sget-object v3, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-static {p1, v0, v2, v3}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooOO0:Llyiahf/vczjk/gh7;

    invoke-virtual {p3}, Llyiahf/vczjk/o30;->OooO00o()Llyiahf/vczjk/y63;

    move-result-object p1

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    invoke-static {p1, v0, v2, v3}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooOO0O:Llyiahf/vczjk/gh7;

    invoke-virtual {p2}, Llyiahf/vczjk/e28;->OooO0O0()Llyiahf/vczjk/y63;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/ra5;

    const/4 v0, 0x0

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/ra5;-><init>(Llyiahf/vczjk/y63;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/w18;

    invoke-direct {v0, v1, v1, v1}, Llyiahf/vczjk/w18;-><init>(III)V

    invoke-static {p2, p1, v2, v0}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooOO0o:Llyiahf/vczjk/gh7;

    invoke-virtual {p3}, Llyiahf/vczjk/o30;->OooO00o()Llyiahf/vczjk/y63;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/ra5;

    const/4 p3, 0x1

    invoke-direct {p2, p1, p3}, Llyiahf/vczjk/ra5;-><init>(Llyiahf/vczjk/y63;I)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance p3, Llyiahf/vczjk/m30;

    invoke-direct {p3, v1}, Llyiahf/vczjk/m30;-><init>(I)V

    invoke-static {p2, p1, v2, p3}, Llyiahf/vczjk/rs;->OoooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/xr1;Llyiahf/vczjk/rl8;Ljava/lang/Object;)Llyiahf/vczjk/gh7;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooOOO0:Llyiahf/vczjk/gh7;

    new-instance p1, Llyiahf/vczjk/oa5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/oa5;-><init>(Llyiahf/vczjk/ua5;)V

    iput-object p1, p0, Llyiahf/vczjk/ua5;->OooOOO:Llyiahf/vczjk/oa5;

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/util/List;Z)V
    .locals 3

    const-string v0, "props"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/ma5;

    const/4 v2, 0x0

    invoke-direct {v1, p2, p0, p1, v2}, Llyiahf/vczjk/ma5;-><init>(ZLlyiahf/vczjk/ua5;Ljava/util/List;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v0, v2, v2, v1, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final OooO0o()V
    .locals 4

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/fy4;->OooO0OO:Z

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/na5;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/na5;-><init>(Llyiahf/vczjk/ua5;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final OooO0oO()V
    .locals 2

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/fy4;->OooO0OO:Z

    sget-object v0, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    invoke-static {}, Llyiahf/vczjk/km8;->OooO00o()Llyiahf/vczjk/nm8;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/nm8;->OooO0O0:Lgithub/tornaco/android/thanos/core/IThanosLite;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/ua5;->OooOOO:Llyiahf/vczjk/oa5;

    invoke-interface {v0, v1}, Lgithub/tornaco/android/thanos/core/IThanosLite;->unregisterPkgStateChangeListener(Lgithub/tornaco/android/thanos/core/IPkgChangeListener;)V

    :cond_0
    return-void
.end method

.method public final OooO0oo(Ljava/util/List;Llyiahf/vczjk/zo1;)V
    .locals 6

    instance-of v0, p2, Llyiahf/vczjk/ha5;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/ha5;

    iget v1, v0, Llyiahf/vczjk/ha5;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ha5;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ha5;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/ha5;-><init>(Llyiahf/vczjk/ua5;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/ha5;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ha5;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/ha5;->L$0:Ljava/lang/Object;

    check-cast p1, Ljava/util/List;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_3
    :goto_1
    iput-object p1, v0, Llyiahf/vczjk/ha5;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/ha5;->label:I

    const-wide/16 v4, 0x7d0

    invoke-static {v4, v5, v0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_4

    return-void

    :cond_4
    :goto_2
    iget-boolean p2, p0, Llyiahf/vczjk/fy4;->OooO0OO:Z

    if-eqz p2, :cond_3

    const/4 p2, 0x0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ua5;->OooO(Ljava/util/List;Z)V

    goto :goto_1
.end method
