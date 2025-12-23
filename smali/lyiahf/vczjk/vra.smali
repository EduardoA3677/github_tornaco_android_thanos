.class public final Llyiahf/vczjk/vra;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $foregroundUpdater:Llyiahf/vczjk/rb3;

.field final synthetic $worker:Llyiahf/vczjk/b25;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/wra;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/b25;Llyiahf/vczjk/rb3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vra;->this$0:Llyiahf/vczjk/wra;

    iput-object p2, p0, Llyiahf/vczjk/vra;->$worker:Llyiahf/vczjk/b25;

    iput-object p3, p0, Llyiahf/vczjk/vra;->$foregroundUpdater:Llyiahf/vczjk/rb3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance p1, Llyiahf/vczjk/vra;

    iget-object v0, p0, Llyiahf/vczjk/vra;->this$0:Llyiahf/vczjk/wra;

    iget-object v1, p0, Llyiahf/vczjk/vra;->$worker:Llyiahf/vczjk/b25;

    iget-object v2, p0, Llyiahf/vczjk/vra;->$foregroundUpdater:Llyiahf/vczjk/rb3;

    invoke-direct {p1, v0, v1, v2, p2}, Llyiahf/vczjk/vra;-><init>(Llyiahf/vczjk/wra;Llyiahf/vczjk/b25;Llyiahf/vczjk/rb3;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/vra;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/vra;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/vra;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/vra;->label:I

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

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/vra;->this$0:Llyiahf/vczjk/wra;

    iget-object v8, p1, Llyiahf/vczjk/wra;->OooO0O0:Landroid/content/Context;

    iget-object v6, p1, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget-object v5, p0, Llyiahf/vczjk/vra;->$worker:Llyiahf/vczjk/b25;

    iget-object v7, p0, Llyiahf/vczjk/vra;->$foregroundUpdater:Llyiahf/vczjk/rb3;

    iget-object p1, p1, Llyiahf/vczjk/wra;->OooO0Oo:Llyiahf/vczjk/rqa;

    iput v3, p0, Llyiahf/vczjk/vra;->label:I

    sget-object v1, Llyiahf/vczjk/hqa;->OooO00o:Ljava/lang/String;

    iget-boolean v1, v6, Llyiahf/vczjk/ara;->OooOOo0:Z

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz v1, :cond_4

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v4, 0x1f

    if-lt v1, v4, :cond_3

    goto :goto_0

    :cond_3
    const-string v1, "taskExecutor.mainThreadExecutor"

    iget-object p1, p1, Llyiahf/vczjk/rqa;->OooO0Oo:Llyiahf/vczjk/wd;

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p1}, Llyiahf/vczjk/dn8;->OoooOo0(Ljava/util/concurrent/Executor;)Llyiahf/vczjk/qr1;

    move-result-object p1

    new-instance v4, Llyiahf/vczjk/gqa;

    const/4 v9, 0x0

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/gqa;-><init>(Llyiahf/vczjk/b25;Llyiahf/vczjk/ara;Llyiahf/vczjk/rb3;Landroid/content/Context;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v4, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    move-object v3, p1

    :cond_4
    :goto_0
    if-ne v3, v0, :cond_5

    goto :goto_2

    :cond_5
    :goto_1
    sget-object p1, Llyiahf/vczjk/yra;->OooO00o:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/vra;->this$0:Llyiahf/vczjk/wra;

    invoke-static {}, Llyiahf/vczjk/o55;->OooOO0()Llyiahf/vczjk/o55;

    move-result-object v3

    new-instance v4, Ljava/lang/StringBuilder;

    const-string v5, "Starting work for "

    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, v1, Llyiahf/vczjk/wra;->OooO00o:Llyiahf/vczjk/ara;

    iget-object v1, v1, Llyiahf/vczjk/ara;->OooO0OO:Ljava/lang/String;

    invoke-virtual {v4, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v3, p1, v1}, Llyiahf/vczjk/o55;->OooO0O0(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/vra;->$worker:Llyiahf/vczjk/b25;

    invoke-virtual {p1}, Llyiahf/vczjk/b25;->OooO0O0()Llyiahf/vczjk/qo0;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/vra;->$worker:Llyiahf/vczjk/b25;

    iput v2, p0, Llyiahf/vczjk/vra;->label:I

    invoke-static {p1, v1, p0}, Llyiahf/vczjk/yra;->OooO00o(Llyiahf/vczjk/t15;Llyiahf/vczjk/b25;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    :goto_2
    return-object v0

    :cond_6
    return-object p1
.end method
