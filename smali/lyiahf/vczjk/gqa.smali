.class public final Llyiahf/vczjk/gqa;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $context:Landroid/content/Context;

.field final synthetic $foregroundUpdater:Llyiahf/vczjk/rb3;

.field final synthetic $spec:Llyiahf/vczjk/ara;

.field final synthetic $worker:Llyiahf/vczjk/b25;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/b25;Llyiahf/vczjk/ara;Llyiahf/vczjk/rb3;Landroid/content/Context;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gqa;->$worker:Llyiahf/vczjk/b25;

    iput-object p2, p0, Llyiahf/vczjk/gqa;->$spec:Llyiahf/vczjk/ara;

    iput-object p3, p0, Llyiahf/vczjk/gqa;->$foregroundUpdater:Llyiahf/vczjk/rb3;

    iput-object p4, p0, Llyiahf/vczjk/gqa;->$context:Landroid/content/Context;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/gqa;

    iget-object v1, p0, Llyiahf/vczjk/gqa;->$worker:Llyiahf/vczjk/b25;

    iget-object v2, p0, Llyiahf/vczjk/gqa;->$spec:Llyiahf/vczjk/ara;

    iget-object v3, p0, Llyiahf/vczjk/gqa;->$foregroundUpdater:Llyiahf/vczjk/rb3;

    iget-object v4, p0, Llyiahf/vczjk/gqa;->$context:Landroid/content/Context;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/gqa;-><init>(Llyiahf/vczjk/b25;Llyiahf/vczjk/ara;Llyiahf/vczjk/rb3;Landroid/content/Context;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gqa;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gqa;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gqa;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/gqa;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/gqa;->$worker:Llyiahf/vczjk/b25;

    invoke-virtual {p1}, Llyiahf/vczjk/b25;->OooO00o()Llyiahf/vczjk/qo0;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/gqa;->$worker:Llyiahf/vczjk/b25;

    iput v3, p0, Llyiahf/vczjk/gqa;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/yra;->OooO00o(Llyiahf/vczjk/t15;Llyiahf/vczjk/b25;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/qb3;

    if-eqz v6, :cond_5

    sget-object p1, Llyiahf/vczjk/hqa;->OooO00o:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/gqa;->$spec:Llyiahf/vczjk/ara;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Updating notification for "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, p1, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/gqa;->$foregroundUpdater:Llyiahf/vczjk/rb3;

    iget-object v7, p0, Llyiahf/vczjk/gqa;->$context:Landroid/content/Context;

    iget-object v1, p0, Llyiahf/vczjk/gqa;->$worker:Llyiahf/vczjk/b25;

    iget-object v1, v1, Llyiahf/vczjk/b25;->OooO0O0:Landroidx/work/WorkerParameters;

    iget-object v5, v1, Landroidx/work/WorkerParameters;->OooO00o:Ljava/util/UUID;

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/iqa;

    iget-object p1, v4, Llyiahf/vczjk/iqa;->OooO00o:Llyiahf/vczjk/rqa;

    new-instance v3, Llyiahf/vczjk/c02;

    const/4 v8, 0x5

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/c02;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    const-string v1, "<this>"

    iget-object p1, p1, Llyiahf/vczjk/rqa;->OooO00o:Llyiahf/vczjk/vq;

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/qd3;

    const-string v4, "setForegroundAsync"

    const/4 v5, 0x3

    invoke-direct {v1, p1, v4, v5, v3}, Llyiahf/vczjk/qd3;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    invoke-static {v1}, Llyiahf/vczjk/r02;->OooOo00(Llyiahf/vczjk/no0;)Llyiahf/vczjk/qo0;

    move-result-object p1

    iput v2, p0, Llyiahf/vczjk/gqa;->label:I

    invoke-static {p1, p0}, Llyiahf/vczjk/dn8;->Oooo00O(Llyiahf/vczjk/t15;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    return-object p1

    :cond_5
    new-instance p1, Ljava/lang/StringBuilder;

    const-string v0, "Worker was marked important ("

    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/gqa;->$spec:Llyiahf/vczjk/ara;

    iget-object v0, v0, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    const-string v1, ") but did not provide ForegroundInfo"

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/ix8;->OooOO0(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
