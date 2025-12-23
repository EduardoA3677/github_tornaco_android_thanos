.class public final Llyiahf/vczjk/ina;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $activity:Landroid/app/Activity;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jna;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jna;Landroid/app/Activity;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ina;->this$0:Llyiahf/vczjk/jna;

    iput-object p2, p0, Llyiahf/vczjk/ina;->$activity:Landroid/app/Activity;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ina;

    iget-object v1, p0, Llyiahf/vczjk/ina;->this$0:Llyiahf/vczjk/jna;

    iget-object v2, p0, Llyiahf/vczjk/ina;->$activity:Landroid/app/Activity;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/ina;-><init>(Llyiahf/vczjk/jna;Landroid/app/Activity;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ina;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/s77;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ina;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ina;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ina;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ina;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ina;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s77;

    new-instance v1, Llyiahf/vczjk/j7a;

    const/4 v3, 0x2

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/j7a;-><init>(Llyiahf/vczjk/s77;I)V

    iget-object v3, p0, Llyiahf/vczjk/ina;->this$0:Llyiahf/vczjk/jna;

    iget-object v3, v3, Llyiahf/vczjk/jna;->OooO0O0:Llyiahf/vczjk/uma;

    iget-object v4, p0, Llyiahf/vczjk/ina;->$activity:Landroid/app/Activity;

    new-instance v5, Llyiahf/vczjk/ix;

    const/4 v6, 0x1

    invoke-direct {v5, v6}, Llyiahf/vczjk/ix;-><init>(I)V

    invoke-interface {v3, v4, v5, v1}, Llyiahf/vczjk/uma;->OooO00o(Landroid/content/Context;Ljava/util/concurrent/Executor;Llyiahf/vczjk/ol1;)V

    new-instance v3, Llyiahf/vczjk/hna;

    iget-object v4, p0, Llyiahf/vczjk/ina;->this$0:Llyiahf/vczjk/jna;

    invoke-direct {v3, v4, v1}, Llyiahf/vczjk/hna;-><init>(Llyiahf/vczjk/jna;Llyiahf/vczjk/j7a;)V

    iput v2, p0, Llyiahf/vczjk/ina;->label:I

    invoke-static {p1, v3, p0}, Llyiahf/vczjk/v34;->OooOOo(Llyiahf/vczjk/s77;Llyiahf/vczjk/le3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
