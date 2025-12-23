.class public final Llyiahf/vczjk/t93;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $activity:Landroid/app/Activity;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/u93;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u93;Landroid/app/Activity;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t93;->this$0:Llyiahf/vczjk/u93;

    iput-object p2, p0, Llyiahf/vczjk/t93;->$activity:Landroid/app/Activity;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/t93;

    iget-object v0, p0, Llyiahf/vczjk/t93;->this$0:Llyiahf/vczjk/u93;

    iget-object v1, p0, Llyiahf/vczjk/t93;->$activity:Landroid/app/Activity;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/t93;-><init>(Llyiahf/vczjk/u93;Landroid/app/Activity;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/t93;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/t93;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/t93;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    const/4 v0, 0x1

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, p0, Llyiahf/vczjk/t93;->label:I

    if-eqz v2, :cond_1

    if-ne v2, v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/t93;->this$0:Llyiahf/vczjk/u93;

    iget-object p1, p1, Llyiahf/vczjk/u93;->OooO00o:Llyiahf/vczjk/jna;

    iget-object v2, p0, Llyiahf/vczjk/t93;->$activity:Landroid/app/Activity;

    const-string v3, "activity"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/ina;

    const/4 v4, 0x0

    invoke-direct {v3, p1, v2, v4}, Llyiahf/vczjk/ina;-><init>(Llyiahf/vczjk/jna;Landroid/app/Activity;Llyiahf/vczjk/yo1;)V

    invoke-static {v3}, Llyiahf/vczjk/rs;->OooOO0O(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/lo0;

    move-result-object p1

    sget-object v2, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v2, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    invoke-static {p1, v2}, Llyiahf/vczjk/rs;->OooOoo(Llyiahf/vczjk/f43;Llyiahf/vczjk/qr1;)Llyiahf/vczjk/f43;

    move-result-object p1

    iget-object v2, p0, Llyiahf/vczjk/t93;->this$0:Llyiahf/vczjk/u93;

    new-instance v3, Llyiahf/vczjk/x63;

    invoke-direct {v3, v0, p1, v2}, Llyiahf/vczjk/x63;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-static {v3}, Llyiahf/vczjk/rs;->OooOo0(Llyiahf/vczjk/f43;)Llyiahf/vczjk/f43;

    move-result-object p1

    iget-object v2, p0, Llyiahf/vczjk/t93;->this$0:Llyiahf/vczjk/u93;

    new-instance v3, Llyiahf/vczjk/od;

    const/4 v4, 0x7

    invoke-direct {v3, v2, v4}, Llyiahf/vczjk/od;-><init>(Ljava/lang/Object;I)V

    iput v0, p0, Llyiahf/vczjk/t93;->label:I

    invoke-interface {p1, v3, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_2

    return-object v1

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
