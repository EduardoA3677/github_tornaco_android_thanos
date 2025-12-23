.class public final Llyiahf/vczjk/fc9;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $dragConsumed:F

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/gc9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gc9;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fc9;->this$0:Llyiahf/vczjk/gc9;

    iput p2, p0, Llyiahf/vczjk/fc9;->$dragConsumed:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/fc9;

    iget-object v0, p0, Llyiahf/vczjk/fc9;->this$0:Llyiahf/vczjk/gc9;

    iget v1, p0, Llyiahf/vczjk/fc9;->$dragConsumed:F

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/fc9;-><init>(Llyiahf/vczjk/gc9;FLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/fc9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fc9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/fc9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/fc9;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/fc9;->this$0:Llyiahf/vczjk/gc9;

    iget-object p1, p1, Llyiahf/vczjk/gc9;->OooOOO0:Llyiahf/vczjk/jc9;

    iget v1, p0, Llyiahf/vczjk/fc9;->$dragConsumed:F

    iput v3, p0, Llyiahf/vczjk/fc9;->label:I

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v3, Llyiahf/vczjk/at5;->OooOOO:Llyiahf/vczjk/at5;

    new-instance v4, Llyiahf/vczjk/ic9;

    const/4 v5, 0x0

    invoke-direct {v4, p1, v1, v5}, Llyiahf/vczjk/ic9;-><init>(Llyiahf/vczjk/jc9;FLlyiahf/vczjk/yo1;)V

    iget-object p1, p1, Llyiahf/vczjk/jc9;->OooO0O0:Llyiahf/vczjk/ht5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/et5;

    invoke-direct {v1, v3, p1, v4, v5}, Llyiahf/vczjk/et5;-><init>(Llyiahf/vczjk/at5;Llyiahf/vczjk/ht5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, p0}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    return-object v2
.end method
