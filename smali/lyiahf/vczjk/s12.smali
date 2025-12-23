.class public final Llyiahf/vczjk/s12;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/t12;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t12;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s12;->this$0:Llyiahf/vczjk/t12;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/s12;

    iget-object v0, p0, Llyiahf/vczjk/s12;->this$0:Llyiahf/vczjk/t12;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/s12;-><init>(Llyiahf/vczjk/t12;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/s12;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/s12;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/s12;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/s12;->label:I

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

    new-instance v4, Llyiahf/vczjk/fl7;

    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    new-instance v5, Llyiahf/vczjk/fl7;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    new-instance v6, Llyiahf/vczjk/fl7;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    iget-object p1, p0, Llyiahf/vczjk/s12;->this$0:Llyiahf/vczjk/t12;

    iget-object p1, p1, Llyiahf/vczjk/t12;->OooOoOO:Llyiahf/vczjk/n24;

    invoke-interface {p1}, Llyiahf/vczjk/n24;->OooO00o()Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/pp1;

    iget-object v7, p0, Llyiahf/vczjk/s12;->this$0:Llyiahf/vczjk/t12;

    const/4 v8, 0x1

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/pp1;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    iput v2, p0, Llyiahf/vczjk/s12;->label:I

    invoke-interface {p1, v3, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
