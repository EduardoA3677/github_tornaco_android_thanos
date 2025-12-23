.class public final Llyiahf/vczjk/af7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $offset:F

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/bf7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf7;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/af7;->this$0:Llyiahf/vczjk/bf7;

    iput p2, p0, Llyiahf/vczjk/af7;->$offset:F

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/af7;

    iget-object v0, p0, Llyiahf/vczjk/af7;->this$0:Llyiahf/vczjk/bf7;

    iget v1, p0, Llyiahf/vczjk/af7;->$offset:F

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/af7;-><init>(Llyiahf/vczjk/bf7;FLlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/af7;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/af7;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/af7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/af7;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/af7;->this$0:Llyiahf/vczjk/bf7;

    iget-object v1, p1, Llyiahf/vczjk/bf7;->OooO:Llyiahf/vczjk/ht5;

    new-instance v3, Llyiahf/vczjk/ze7;

    iget v4, p0, Llyiahf/vczjk/af7;->$offset:F

    const/4 v5, 0x0

    invoke-direct {v3, p1, v4, v5}, Llyiahf/vczjk/ze7;-><init>(Llyiahf/vczjk/bf7;FLlyiahf/vczjk/yo1;)V

    iput v2, p0, Llyiahf/vczjk/af7;->label:I

    invoke-static {v1, v3, p0}, Llyiahf/vczjk/ht5;->OooO0O0(Llyiahf/vczjk/ht5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
