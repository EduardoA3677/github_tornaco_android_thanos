.class public final Llyiahf/vczjk/ee1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $onReady:Ljava/lang/Runnable;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ie1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ie1;Ljava/lang/Runnable;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ee1;->this$0:Llyiahf/vczjk/ie1;

    iput-object p2, p0, Llyiahf/vczjk/ee1;->$onReady:Ljava/lang/Runnable;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/ee1;

    iget-object v0, p0, Llyiahf/vczjk/ee1;->this$0:Llyiahf/vczjk/ie1;

    iget-object v1, p0, Llyiahf/vczjk/ee1;->$onReady:Ljava/lang/Runnable;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/ee1;-><init>(Llyiahf/vczjk/ie1;Ljava/lang/Runnable;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ee1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ee1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ee1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ee1;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ee1;->this$0:Llyiahf/vczjk/ie1;

    iget-object p1, p1, Llyiahf/vczjk/ie1;->OooO0o:Llyiahf/vczjk/fo7;

    iput v3, p0, Llyiahf/vczjk/ee1;->label:I

    iget v1, p1, Llyiahf/vczjk/fo7;->OooO0OO:F

    const/4 v3, 0x0

    sub-float/2addr v3, v1

    invoke-virtual {p1, v3, p0}, Llyiahf/vczjk/fo7;->OooO00o(FLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/ee1;->this$0:Llyiahf/vczjk/ie1;

    iget-object p1, p1, Llyiahf/vczjk/ie1;->OooO0OO:Llyiahf/vczjk/h87;

    iget-object p1, p1, Llyiahf/vczjk/h87;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/qs5;

    sget-object v0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ee1;->$onReady:Ljava/lang/Runnable;

    invoke-interface {p1}, Ljava/lang/Runnable;->run()V

    return-object v2
.end method
