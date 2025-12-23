.class public final Llyiahf/vczjk/si6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $remoteMediator:Llyiahf/vczjk/ap7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ap7;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ui6;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ui6;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/si6;->this$0:Llyiahf/vczjk/ui6;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/si6;

    iget-object v1, p0, Llyiahf/vczjk/si6;->this$0:Llyiahf/vczjk/ui6;

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/si6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V

    iput-object p1, v0, Llyiahf/vczjk/si6;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/uo8;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/si6;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/si6;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/si6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/si6;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/si6;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uo8;

    iget-object v1, p0, Llyiahf/vczjk/si6;->this$0:Llyiahf/vczjk/ui6;

    iget-object v1, v1, Llyiahf/vczjk/ui6;->OooO0OO:Llyiahf/vczjk/n62;

    iget-object v1, v1, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/i00;

    new-instance v3, Llyiahf/vczjk/oi6;

    const/4 v4, 0x2

    const/4 v5, 0x0

    invoke-direct {v3, v4, v5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v4, Llyiahf/vczjk/l53;

    invoke-direct {v4, v1, v3}, Llyiahf/vczjk/l53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    new-instance v1, Llyiahf/vczjk/pi6;

    iget-object v3, p0, Llyiahf/vczjk/si6;->this$0:Llyiahf/vczjk/ui6;

    invoke-direct {v1, v5, v3}, Llyiahf/vczjk/pi6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V

    new-instance v3, Llyiahf/vczjk/u43;

    invoke-direct {v3, v5, v4, v1, v5}, Llyiahf/vczjk/u43;-><init>(Ljava/lang/Object;Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    new-instance v1, Llyiahf/vczjk/s48;

    invoke-direct {v1, v3}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    new-instance v3, Llyiahf/vczjk/wh;

    const/4 v4, 0x4

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    iget-object v1, p0, Llyiahf/vczjk/si6;->this$0:Llyiahf/vczjk/ui6;

    new-instance v4, Llyiahf/vczjk/ri6;

    invoke-direct {v4, v5, v1}, Llyiahf/vczjk/ri6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V

    new-instance v1, Llyiahf/vczjk/w43;

    invoke-direct {v1, v3, v4, v5}, Llyiahf/vczjk/w43;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    invoke-static {v1}, Llyiahf/vczjk/ll6;->OooOOOo(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/f43;

    move-result-object v1

    new-instance v3, Llyiahf/vczjk/e00;

    const/4 v4, 0x1

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/e00;-><init>(Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/si6;->label:I

    invoke-interface {v1, v3, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
