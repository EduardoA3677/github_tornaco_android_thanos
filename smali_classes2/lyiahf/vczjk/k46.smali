.class public final Llyiahf/vczjk/k46;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/l46;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/l46;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/k46;->this$0:Llyiahf/vczjk/l46;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/k46;

    iget-object v1, p0, Llyiahf/vczjk/k46;->this$0:Llyiahf/vczjk/l46;

    invoke-direct {v0, p3, v1}, Llyiahf/vczjk/k46;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/l46;)V

    iput-object p1, v0, Llyiahf/vczjk/k46;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/k46;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/k46;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/k46;->label:I

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

    iget-object p1, p0, Llyiahf/vczjk/k46;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    iget-object v1, p0, Llyiahf/vczjk/k46;->L$1:Ljava/lang/Object;

    check-cast v1, Ljava/lang/String;

    iget-object v4, p0, Llyiahf/vczjk/k46;->this$0:Llyiahf/vczjk/l46;

    iget-object v4, v4, Llyiahf/vczjk/l46;->OooO0OO:Llyiahf/vczjk/g46;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v5, Llyiahf/vczjk/o55;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    const/16 v6, 0x3c

    iput v6, v5, Llyiahf/vczjk/o55;->OooOOO0:I

    new-instance v6, Llyiahf/vczjk/oo0oO0;

    const/16 v7, 0x15

    invoke-direct {v6, v7, v4, v1}, Llyiahf/vczjk/oo0oO0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/ui6;

    new-instance v7, Llyiahf/vczjk/nk6;

    const/4 v8, 0x0

    invoke-direct {v7, v6, v8}, Llyiahf/vczjk/nk6;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/yo1;)V

    invoke-direct {v1, v7, v5}, Llyiahf/vczjk/ui6;-><init>(Llyiahf/vczjk/nk6;Llyiahf/vczjk/o55;)V

    iput v3, p0, Llyiahf/vczjk/k46;->label:I

    instance-of v3, p1, Llyiahf/vczjk/kr9;

    if-nez v3, :cond_5

    new-instance v3, Llyiahf/vczjk/e46;

    invoke-direct {v3, p1, v4}, Llyiahf/vczjk/e46;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/g46;)V

    iget-object p1, v1, Llyiahf/vczjk/ui6;->OooO0o0:Llyiahf/vczjk/f43;

    invoke-interface {p1, v3, p0}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    return-object v2

    :cond_5
    check-cast p1, Llyiahf/vczjk/kr9;

    iget-object p1, p1, Llyiahf/vczjk/kr9;->OooOOO0:Ljava/lang/Throwable;

    throw p1
.end method
