.class public final Llyiahf/vczjk/c46;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/hl1;

.field public final OooO0O0:Landroid/content/Context;

.field public final OooO0OO:Ljava/lang/String;

.field public final OooO0Oo:Lgithub/tornaco/android/thanos/core/app/ThanosManager;


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;)V
    .locals 2

    const-string v0, "keyword"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/hl1;

    const/4 v1, 0x3

    invoke-direct {v0, v1}, Llyiahf/vczjk/hl1;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/c46;->OooO00o:Llyiahf/vczjk/hl1;

    iput-object p1, p0, Llyiahf/vczjk/c46;->OooO0O0:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/c46;->OooO0OO:Ljava/lang/String;

    invoke-static {p1}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->from(Landroid/content/Context;)Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-result-object p1

    const-string p2, "from(...)"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/c46;->OooO0Oo:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    return-void
.end method


# virtual methods
.method public final OooO00o(Lgithub/tornaco/android/thanos/core/app/ThanosManager;IILjava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 10

    instance-of v0, p5, Llyiahf/vczjk/z36;

    if-eqz v0, :cond_0

    move-object v0, p5

    check-cast v0, Llyiahf/vczjk/z36;

    iget v1, v0, Llyiahf/vczjk/z36;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/z36;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/z36;

    invoke-direct {v0, p0, p5}, Llyiahf/vczjk/z36;-><init>(Llyiahf/vczjk/c46;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p5, v0, Llyiahf/vczjk/z36;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/z36;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p5, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object p5, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v4, Llyiahf/vczjk/a46;

    const/4 v9, 0x0

    move-object v7, p1

    move v5, p2

    move v6, p3

    move-object v8, p4

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/a46;-><init>(IILgithub/tornaco/android/thanos/core/app/ThanosManager;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput v3, v0, Llyiahf/vczjk/z36;->label:I

    invoke-static {p5, v4, v0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p5

    if-ne p5, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    const-string p1, "withContext(...)"

    invoke-static {p5, p1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p5
.end method

.method public final OooO0O0(Llyiahf/vczjk/on6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 8

    instance-of v0, p2, Llyiahf/vczjk/b46;

    const/high16 v1, -0x80000000

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/b46;

    iget v2, v0, Llyiahf/vczjk/b46;->label:I

    and-int v3, v2, v1

    if-eqz v3, :cond_0

    sub-int/2addr v2, v1

    iput v2, v0, Llyiahf/vczjk/b46;->label:I

    :goto_0
    move-object v7, v0

    goto :goto_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/b46;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/b46;-><init>(Llyiahf/vczjk/c46;Llyiahf/vczjk/zo1;)V

    goto :goto_0

    :goto_1
    iget-object p2, v7, Llyiahf/vczjk/b46;->result:Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v7, Llyiahf/vczjk/b46;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget p1, v7, Llyiahf/vczjk/b46;->I$0:I

    iget-object v0, v7, Llyiahf/vczjk/b46;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/on6;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v2, p0

    goto :goto_4

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/on6;->OooO00o()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ljava/lang/Integer;

    if-eqz p2, :cond_3

    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    :goto_2
    move v4, p2

    goto :goto_3

    :cond_3
    const/4 p2, 0x0

    goto :goto_2

    :goto_3
    iput-object p1, v7, Llyiahf/vczjk/b46;->L$0:Ljava/lang/Object;

    iput v4, v7, Llyiahf/vczjk/b46;->I$0:I

    iput v3, v7, Llyiahf/vczjk/b46;->label:I

    iget v5, p1, Llyiahf/vczjk/on6;->OooO00o:I

    iget-object v6, p0, Llyiahf/vczjk/c46;->OooO0OO:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/c46;->OooO0Oo:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    move-object v2, p0

    invoke-virtual/range {v2 .. v7}, Llyiahf/vczjk/c46;->OooO00o(Lgithub/tornaco/android/thanos/core/app/ThanosManager;IILjava/lang/String;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v0, :cond_4

    return-object v0

    :cond_4
    move-object v0, p1

    move p1, v4

    :goto_4
    check-cast p2, Ljava/util/List;

    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_5

    const/4 p1, 0x0

    goto :goto_5

    :cond_5
    iget v0, v0, Llyiahf/vczjk/on6;->OooO00o:I

    add-int/2addr p1, v0

    new-instance v0, Ljava/lang/Integer;

    invoke-direct {v0, p1}, Ljava/lang/Integer;-><init>(I)V

    move-object p1, v0

    :goto_5
    new-instance v0, Ljava/util/ArrayList;

    const/16 v3, 0xa

    invoke-static {p2, v3}, Llyiahf/vczjk/f21;->o000oOoO(Ljava/lang/Iterable;I)I

    move-result v3

    invoke-direct {v0, v3}, Ljava/util/ArrayList;-><init>(I)V

    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p2

    :goto_6
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_8

    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;

    new-instance v4, Ljava/util/Date;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getWhen()J

    move-result-wide v5

    invoke-direct {v4, v5, v6}, Ljava/util/Date;-><init>(J)V

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getContent()Ljava/lang/String;

    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    iget-object v4, v2, Llyiahf/vczjk/c46;->OooO0Oo:Lgithub/tornaco/android/thanos/core/app/ThanosManager;

    invoke-virtual {v4}, Lgithub/tornaco/android/thanos/core/app/ThanosManager;->getPkgManager()Lgithub/tornaco/android/thanos/core/pm/PackageManager;

    move-result-object v4

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getPkgName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Lgithub/tornaco/android/thanos/core/pm/PackageManager;->getAppInfo(Ljava/lang/String;)Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v4

    if-nez v4, :cond_6

    invoke-static {}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->dummy()Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    move-result-object v4

    iget-object v5, v2, Llyiahf/vczjk/c46;->OooO0O0:Landroid/content/Context;

    sget v6, Lgithub/tornaco/android/thanos/res/R$string;->module_notification_recorder_item_uninstalled_app:I

    invoke-virtual {v5, v6}, Landroid/content/Context;->getString(I)Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setAppLabel(Ljava/lang/String;)V

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getPkgName()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {v4, v5}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->setPkgName(Ljava/lang/String;)V

    :cond_6
    new-instance v5, Ljava/util/Date;

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getWhen()J

    move-result-wide v6

    invoke-direct {v5, v6, v7}, Ljava/util/Date;-><init>(J)V

    invoke-static {v5}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->isToday(Ljava/util/Date;)Z

    move-result v5

    if-eqz v5, :cond_7

    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getWhen()J

    move-result-wide v5

    invoke-static {v5, v6}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatShortForMessageTime(J)Ljava/lang/String;

    move-result-object v5

    goto :goto_7

    :cond_7
    invoke-virtual {v3}, Lgithub/tornaco/android/thanos/core/n/NotificationRecord;->getWhen()J

    move-result-wide v5

    invoke-static {v5, v6}, Lgithub/tornaco/android/thanos/core/util/DateUtils;->formatLongForMessageTime(J)Ljava/lang/String;

    move-result-object v5

    :goto_7
    new-instance v6, Llyiahf/vczjk/w36;

    invoke-static {v5}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-direct {v6, v3, v4, v5}, Llyiahf/vczjk/w36;-><init>(Lgithub/tornaco/android/thanos/core/n/NotificationRecord;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Ljava/lang/String;)V

    invoke-virtual {v0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_6

    :cond_8
    new-instance p2, Llyiahf/vczjk/pn6;

    invoke-direct {p2, v1, v1, p1, v0}, Llyiahf/vczjk/pn6;-><init>(IILjava/lang/Integer;Ljava/util/List;)V

    return-object p2
.end method
