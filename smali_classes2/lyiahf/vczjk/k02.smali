.class public final Llyiahf/vczjk/k02;
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
        "Llyiahf/vczjk/k02;",
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

.field public final OooO0Oo:Llyiahf/vczjk/s29;

.field public final OooO0o0:Llyiahf/vczjk/gh7;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/dha;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/k02;->OooO0O0:Landroid/content/Context;

    new-instance p1, Llyiahf/vczjk/yz1;

    const/4 v0, 0x1

    invoke-direct {p1, p0, v0}, Llyiahf/vczjk/yz1;-><init>(Llyiahf/vczjk/k02;I)V

    invoke-static {p1}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/k02;->OooO0OO:Llyiahf/vczjk/sc9;

    new-instance p1, Llyiahf/vczjk/m02;

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    invoke-direct {p1, v0, v0}, Llyiahf/vczjk/m02;-><init>(Ljava/util/List;Ljava/util/List;)V

    invoke-static {p1}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/k02;->OooO0Oo:Llyiahf/vczjk/s29;

    new-instance v0, Llyiahf/vczjk/gh7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/gh7;-><init>(Llyiahf/vczjk/rs5;)V

    iput-object v0, p0, Llyiahf/vczjk/k02;->OooO0o0:Llyiahf/vczjk/gh7;

    return-void
.end method

.method public static final OooO0o0(Llyiahf/vczjk/k02;)Ljava/util/ArrayList;
    .locals 12

    iget-object p0, p0, Llyiahf/vczjk/k02;->OooO0O0:Landroid/content/Context;

    const-string v0, "context"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p0}, Llyiahf/vczjk/oqa;->OoooOoo(Landroid/content/Context;)Llyiahf/vczjk/oqa;

    move-result-object p0

    sget-object v0, Llyiahf/vczjk/lqa;->OooOOO0:Llyiahf/vczjk/lqa;

    sget-object v1, Llyiahf/vczjk/lqa;->OooOOO:Llyiahf/vczjk/lqa;

    filled-new-array {v0, v1}, [Llyiahf/vczjk/lqa;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    new-instance v3, Ljava/util/ArrayList;

    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    invoke-static {v0, v4}, Llyiahf/vczjk/j21;->OoooOo0(Ljava/lang/Iterable;Ljava/util/Collection;)V

    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {v3}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {v4}, Ljava/util/ArrayList;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string v0, "Must specify ids, uniqueNames, tags or states when building a WorkQuery"

    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    :goto_0
    new-instance v0, Llyiahf/vczjk/wqa;

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/wqa;-><init>(Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    iget-object v1, p0, Llyiahf/vczjk/oqa;->OooOOO:Landroidx/work/impl/WorkDatabase;

    const-string v2, "<this>"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p0, p0, Llyiahf/vczjk/oqa;->OooOOOO:Llyiahf/vczjk/rqa;

    const-string v2, "executor"

    invoke-static {p0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/z39;

    invoke-direct {v2, v0}, Llyiahf/vczjk/z39;-><init>(Llyiahf/vczjk/wqa;)V

    const-string v0, "executor.serialTaskExecutor"

    iget-object p0, p0, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/a49;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/a49;-><init>(Llyiahf/vczjk/z39;Landroidx/work/impl/WorkDatabase;)V

    new-instance v1, Llyiahf/vczjk/qd3;

    const-string v2, "loadStatusFuture"

    const/4 v3, 0x3

    invoke-direct {v1, p0, v2, v3, v0}, Llyiahf/vczjk/qd3;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo00(Llyiahf/vczjk/no0;)Llyiahf/vczjk/qo0;

    move-result-object p0

    iget-object p0, p0, Llyiahf/vczjk/qo0;->OooOOO:Llyiahf/vczjk/po0;

    invoke-virtual {p0}, Llyiahf/vczjk/o0o0Oo;->get()Ljava/lang/Object;

    move-result-object p0

    const-string v0, "get(...)"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p0, Ljava/lang/Iterable;

    new-instance v1, Ljava/util/ArrayList;

    const/16 v0, 0xa

    invoke-static {p0, v0}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v0

    invoke-direct {v1, v0}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/mqa;

    iget-object v2, v0, Llyiahf/vczjk/mqa;->OooO0OO:Ljava/util/HashSet;

    invoke-static {v2}, Llyiahf/vczjk/d21;->o00Ooo(Ljava/lang/Iterable;)Ljava/lang/Object;

    move-result-object v2

    move-object v5, v2

    check-cast v5, Ljava/lang/String;

    const-string v2, "-"

    filled-new-array {v2}, [Ljava/lang/String;

    move-result-object v2

    invoke-static {v5, v2}, Llyiahf/vczjk/z69;->OooooO0(Ljava/lang/CharSequence;[Ljava/lang/String;)Ljava/util/List;

    move-result-object v2

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v3

    const/4 v4, 0x3

    iget-object v7, v0, Llyiahf/vczjk/mqa;->OooO00o:Ljava/util/UUID;

    if-ne v3, v4, :cond_3

    const/4 v3, 0x1

    :try_start_0
    new-instance v6, Llyiahf/vczjk/cra;

    invoke-interface {v2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Ljava/lang/String;

    const/4 v0, 0x0

    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    invoke-static {v0}, Llyiahf/vczjk/o1a;->valueOf(Ljava/lang/String;)Llyiahf/vczjk/o1a;

    move-result-object v9

    const/4 v0, 0x2

    invoke-interface {v2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    invoke-static {v0}, Ljava/lang/Long;->parseLong(Ljava/lang/String;)J

    move-result-wide v10

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/cra;-><init>(Ljava/util/UUID;Ljava/lang/String;Llyiahf/vczjk/o1a;J)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception v0

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v6

    :goto_2
    invoke-static {v6}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v0

    if-nez v0, :cond_2

    goto :goto_3

    :cond_2
    const-string v4, "map to WorkState error"

    invoke-static {v4, v0}, Llyiahf/vczjk/zsa;->Oooo0OO(Ljava/lang/String;Ljava/lang/Throwable;)V

    new-instance v6, Llyiahf/vczjk/cra;

    invoke-interface {v2, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Ljava/lang/String;

    sget-object v9, Llyiahf/vczjk/o1a;->OooOOO:Llyiahf/vczjk/o1a;

    const-wide/16 v10, 0x0

    invoke-direct/range {v6 .. v11}, Llyiahf/vczjk/cra;-><init>(Ljava/util/UUID;Ljava/lang/String;Llyiahf/vczjk/o1a;J)V

    :goto_3
    check-cast v6, Llyiahf/vczjk/cra;

    goto :goto_4

    :cond_3
    new-instance v3, Llyiahf/vczjk/cra;

    sget-object v6, Llyiahf/vczjk/o1a;->OooOOO:Llyiahf/vczjk/o1a;

    move-object v4, v7

    const-wide/16 v7, 0x0

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/cra;-><init>(Ljava/util/UUID;Ljava/lang/String;Llyiahf/vczjk/o1a;J)V

    move-object v6, v3

    :goto_4
    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_4
    return-object v1
.end method


# virtual methods
.method public final OooO0o()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/k02;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getProfileManager()Lgithub/tornaco/android/thanos/core/profile/ProfileManager;

    move-result-object v0

    invoke-virtual {v0}, Lgithub/tornaco/android/thanos/core/profile/ProfileManager;->getAllAlarms()Ljava/util/List;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/k02;->OooO0Oo:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/m02;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/4 v3, 0x0

    const/4 v4, 0x1

    invoke-static {v2, v3, v0, v4}, Llyiahf/vczjk/m02;->OooO00o(Llyiahf/vczjk/m02;Ljava/util/ArrayList;Ljava/util/List;I)Llyiahf/vczjk/m02;

    move-result-object v0

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v1, v3, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    return-void
.end method

.method public final OooO0oO()V
    .locals 4

    invoke-static {p0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/j02;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/j02;-><init>(Llyiahf/vczjk/k02;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
