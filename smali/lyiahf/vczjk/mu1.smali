.class public final Llyiahf/vczjk/mu1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $oldJob:Llyiahf/vczjk/v74;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ou1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v74;Llyiahf/vczjk/ou1;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mu1;->$oldJob:Llyiahf/vczjk/v74;

    iput-object p2, p0, Llyiahf/vczjk/mu1;->this$0:Llyiahf/vczjk/ou1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/mu1;

    iget-object v0, p0, Llyiahf/vczjk/mu1;->$oldJob:Llyiahf/vczjk/v74;

    iget-object v1, p0, Llyiahf/vczjk/mu1;->this$0:Llyiahf/vczjk/ou1;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/mu1;-><init>(Llyiahf/vczjk/v74;Llyiahf/vczjk/ou1;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/mu1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mu1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/mu1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/mu1;->label:I

    const/4 v2, 0x0

    const-wide/16 v3, 0x1f4

    const/high16 v5, 0x3f800000    # 1.0f

    const/4 v6, 0x4

    const/4 v7, 0x3

    const/4 v8, 0x2

    const/4 v9, 0x1

    if-eqz v1, :cond_4

    if-eq v1, v9, :cond_3

    if-eq v1, v8, :cond_2

    if-eq v1, v7, :cond_1

    if-ne v1, v6, :cond_0

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_5

    :catchall_0
    move-exception p1

    goto/16 :goto_6

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    :try_start_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/mu1;->$oldJob:Llyiahf/vczjk/v74;

    if-eqz p1, :cond_6

    iput v9, p0, Llyiahf/vczjk/mu1;->label:I

    const/4 v1, 0x0

    invoke-interface {p1, v1}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    invoke-interface {p1, p0}, Llyiahf/vczjk/v74;->Oooooo0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    goto :goto_0

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    if-ne p1, v0, :cond_6

    goto :goto_4

    :cond_6
    :goto_1
    :try_start_2
    iget-object p1, p0, Llyiahf/vczjk/mu1;->this$0:Llyiahf/vczjk/ou1;

    iget-object p1, p1, Llyiahf/vczjk/ou1;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1, v5}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object p1, p0, Llyiahf/vczjk/mu1;->this$0:Llyiahf/vczjk/ou1;

    iget-boolean p1, p1, Llyiahf/vczjk/ou1;->OooO00o:Z

    if-nez p1, :cond_7

    iput v8, p0, Llyiahf/vczjk/mu1;->label:I

    invoke-static {p0}, Llyiahf/vczjk/yi4;->OooOooO(Llyiahf/vczjk/zo1;)V

    return-object v0

    :cond_7
    :goto_2
    iput v7, p0, Llyiahf/vczjk/mu1;->label:I

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    goto :goto_4

    :cond_8
    :goto_3
    iget-object p1, p0, Llyiahf/vczjk/mu1;->this$0:Llyiahf/vczjk/ou1;

    iget-object p1, p1, Llyiahf/vczjk/ou1;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iput v6, p0, Llyiahf/vczjk/mu1;->label:I

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_9

    :goto_4
    return-object v0

    :cond_9
    :goto_5
    iget-object p1, p0, Llyiahf/vczjk/mu1;->this$0:Llyiahf/vczjk/ou1;

    iget-object p1, p1, Llyiahf/vczjk/ou1;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1, v5}, Llyiahf/vczjk/zv8;->OooOo00(F)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    goto :goto_2

    :goto_6
    iget-object v0, p0, Llyiahf/vczjk/mu1;->this$0:Llyiahf/vczjk/ou1;

    iget-object v0, v0, Llyiahf/vczjk/ou1;->OooO0OO:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    throw p1
.end method
