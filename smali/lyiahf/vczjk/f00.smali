.class public final Llyiahf/vczjk/f00;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/j00;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j00;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/f00;->this$0:Llyiahf/vczjk/j00;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/f00;

    iget-object v0, p0, Llyiahf/vczjk/f00;->this$0:Llyiahf/vczjk/j00;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/f00;-><init>(Llyiahf/vczjk/j00;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/f00;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/f00;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/f00;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/f00;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/f00;->this$0:Llyiahf/vczjk/j00;

    new-instance v1, Llyiahf/vczjk/k1;

    const/16 v3, 0xa

    invoke-direct {v1, p1, v3}, Llyiahf/vczjk/k1;-><init>(Ljava/lang/Object;I)V

    invoke-static {v1}, Landroidx/compose/runtime/OooO0o;->OooOO0o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/s48;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/d00;

    iget-object v3, p0, Llyiahf/vczjk/f00;->this$0:Llyiahf/vczjk/j00;

    const/4 v4, 0x0

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/d00;-><init>(Llyiahf/vczjk/j00;Llyiahf/vczjk/yo1;)V

    sget v3, Llyiahf/vczjk/e63;->OooO00o:I

    new-instance v3, Llyiahf/vczjk/d63;

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/d63;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3}, Llyiahf/vczjk/rs;->OooooOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/et0;

    move-result-object p1

    iget-object v1, p0, Llyiahf/vczjk/f00;->this$0:Llyiahf/vczjk/j00;

    new-instance v3, Llyiahf/vczjk/e00;

    const/4 v4, 0x0

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/e00;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/f00;->label:I

    invoke-virtual {p1, v3, p0}, Llyiahf/vczjk/ys0;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
