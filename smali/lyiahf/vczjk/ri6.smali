.class public final Llyiahf/vczjk/ri6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $remoteMediatorAccessor$inlined:Llyiahf/vczjk/bp7;

.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ui6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/ri6;->this$0:Llyiahf/vczjk/ui6;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/ri6;

    iget-object v1, p0, Llyiahf/vczjk/ri6;->this$0:Llyiahf/vczjk/ui6;

    invoke-direct {v0, p3, v1}, Llyiahf/vczjk/ri6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V

    iput-object p1, v0, Llyiahf/vczjk/ri6;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/ri6;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/ri6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ri6;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/ri6;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    iget-object v1, p0, Llyiahf/vczjk/ri6;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/mi6;

    iget-object v3, p0, Llyiahf/vczjk/ri6;->this$0:Llyiahf/vczjk/ui6;

    iget-object v4, v1, Llyiahf/vczjk/mi6;->OooO00o:Llyiahf/vczjk/pj6;

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/qi6;

    const/4 v5, 0x2

    const/4 v6, 0x0

    invoke-direct {v3, v5, v6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    new-instance v5, Llyiahf/vczjk/w53;

    iget-object v4, v4, Llyiahf/vczjk/pj6;->OooOO0:Llyiahf/vczjk/l53;

    const/4 v6, 0x1

    invoke-direct {v5, v4, v3, v6}, Llyiahf/vczjk/w53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;I)V

    new-instance v3, Llyiahf/vczjk/xm6;

    new-instance v4, Llyiahf/vczjk/a27;

    iget-object v6, p0, Llyiahf/vczjk/ri6;->this$0:Llyiahf/vczjk/ui6;

    iget-object v7, v6, Llyiahf/vczjk/ui6;->OooO0Oo:Llyiahf/vczjk/n62;

    invoke-direct {v4, v6, v7}, Llyiahf/vczjk/a27;-><init>(Llyiahf/vczjk/ui6;Llyiahf/vczjk/n62;)V

    new-instance v6, Llyiahf/vczjk/ni6;

    iget-object v1, v1, Llyiahf/vczjk/mi6;->OooO00o:Llyiahf/vczjk/pj6;

    invoke-direct {v6, v1}, Llyiahf/vczjk/ni6;-><init>(Llyiahf/vczjk/pj6;)V

    sget-object v1, Llyiahf/vczjk/o24;->OooOOoo:Llyiahf/vczjk/o24;

    invoke-direct {v3, v5, v4, v6, v1}, Llyiahf/vczjk/xm6;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/a27;Llyiahf/vczjk/ni6;Llyiahf/vczjk/le3;)V

    iput v2, p0, Llyiahf/vczjk/ri6;->label:I

    invoke-interface {p1, v3, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
