.class public final Llyiahf/vczjk/dv;
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
        "Llyiahf/vczjk/dv;",
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

.field public final OooO0OO:Llyiahf/vczjk/s29;

.field public final OooO0Oo:Llyiahf/vczjk/gh7;

.field public final OooO0o:Llyiahf/vczjk/sc9;

.field public final OooO0o0:Llyiahf/vczjk/sc9;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 7

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dv;->OooO0O0:Landroid/content/Context;

    new-instance v0, Llyiahf/vczjk/xu;

    sget-object v2, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    const-string v4, ""

    const/4 v5, 0x0

    const/4 v1, 0x1

    const/high16 v3, -0x80000000

    move-object v6, v2

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/xu;-><init>(ZLjava/util/List;ILjava/lang/String;Llyiahf/vczjk/nw;Ljava/util/List;)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dv;->OooO0OO:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/dv;->OooO0Oo:Llyiahf/vczjk/gh7;

    new-instance p1, Llyiahf/vczjk/pu;

    const/4 v0, 0x2

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/pu;-><init>(Llyiahf/vczjk/dv;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dv;->OooO0o0:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/pu;

    const/4 v0, 0x3

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/pu;-><init>(Llyiahf/vczjk/dv;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/dv;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/zu;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/zu;-><init>(Llyiahf/vczjk/dv;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {p1, v1, v1, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public static final OooO0o0(Llyiahf/vczjk/dv;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 13

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p1, Llyiahf/vczjk/av;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/av;

    iget v1, v0, Llyiahf/vczjk/av;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/av;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/av;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/av;-><init>(Llyiahf/vczjk/dv;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/av;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/av;->label:I

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput v3, v0, Llyiahf/vczjk/av;->label:I

    iget-object p1, p0, Llyiahf/vczjk/dv;->OooO0O0:Landroid/content/Context;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v2, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v3, Llyiahf/vczjk/t25;

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/t25;-><init>(Lgithub/tornaco/android/thanos/core/app/ThanosManager;Llyiahf/vczjk/yo1;)V

    invoke-static {v2, v3, v0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    move-object v11, p1

    check-cast v11, Ljava/util/List;

    iget-object p0, p0, Llyiahf/vczjk/dv;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {p0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object p1

    move-object v5, p1

    check-cast v5, Llyiahf/vczjk/xu;

    invoke-interface {v11}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_4
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/nw;

    iget-object v1, v1, Llyiahf/vczjk/nw;->OooO00o:Ljava/lang/String;

    const-string v2, "D878029F-1D75-42EF-9DEA-48B552172C3D"

    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    goto :goto_2

    :cond_5
    move-object v0, v4

    :goto_2
    move-object v10, v0

    check-cast v10, Llyiahf/vczjk/nw;

    const/4 v7, 0x0

    const/16 v12, 0xf

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/4 v9, 0x0

    invoke-static/range {v5 .. v12}, Llyiahf/vczjk/xu;->OooO00o(Llyiahf/vczjk/xu;ZLjava/util/ArrayList;ILjava/lang/String;Llyiahf/vczjk/nw;Ljava/util/List;I)Llyiahf/vczjk/xu;

    move-result-object p1

    invoke-virtual {p0, v4, p1}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final OooO0o()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/dv;->OooO0OO:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xu;

    iget v0, v0, Llyiahf/vczjk/xu;->OooO0OO:I

    if-gez v0, :cond_0

    return-void

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/cv;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/cv;-><init>(Llyiahf/vczjk/dv;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
