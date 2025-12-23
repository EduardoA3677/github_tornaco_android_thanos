.class public final Llyiahf/vczjk/eo8;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$flow:Llyiahf/vczjk/h43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h43;"
        }
    .end annotation
.end field

.field final synthetic $block:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/eo8;->$$this$flow:Llyiahf/vczjk/h43;

    iput-object p2, p0, Llyiahf/vczjk/eo8;->$block:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/eo8;

    iget-object v1, p0, Llyiahf/vczjk/eo8;->$$this$flow:Llyiahf/vczjk/h43;

    iget-object v2, p0, Llyiahf/vczjk/eo8;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/eo8;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/eo8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/eo8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/eo8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/eo8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/eo8;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v4, :cond_2

    if-ne v1, v3, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/eo8;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ej0;

    iget-object v5, p0, Llyiahf/vczjk/eo8;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/v74;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_0
    move-object p1, v5

    move-object v5, v1

    goto :goto_0

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object v1, p0, Llyiahf/vczjk/eo8;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ej0;

    iget-object v5, p0, Llyiahf/vczjk/eo8;->L$0:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/v74;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/eo8;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    const/4 v1, 0x0

    const/4 v5, 0x6

    invoke-static {v1, v5, v2}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v1

    new-instance v5, Llyiahf/vczjk/do8;

    iget-object v6, p0, Llyiahf/vczjk/eo8;->$block:Llyiahf/vczjk/ze3;

    invoke-direct {v5, v1, v6, v2}, Llyiahf/vczjk/do8;-><init>(Llyiahf/vczjk/rs0;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    const/4 v6, 0x3

    invoke-static {p1, v2, v2, v5, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    new-instance v5, Llyiahf/vczjk/ej0;

    invoke-direct {v5, v1}, Llyiahf/vczjk/ej0;-><init>(Llyiahf/vczjk/jj0;)V

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/eo8;->L$0:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/eo8;->L$1:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/eo8;->label:I

    invoke-virtual {v5, p0}, Llyiahf/vczjk/ej0;->OooO0O0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_4

    goto :goto_2

    :cond_4
    move-object v7, v5

    move-object v5, p1

    move-object p1, v1

    move-object v1, v7

    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_5

    invoke-virtual {v1}, Llyiahf/vczjk/ej0;->OooO0OO()Ljava/lang/Object;

    move-result-object p1

    iget-object v6, p0, Llyiahf/vczjk/eo8;->$$this$flow:Llyiahf/vczjk/h43;

    iput-object v5, p0, Llyiahf/vczjk/eo8;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/eo8;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/eo8;->label:I

    invoke-interface {v6, p1, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_0

    :goto_2
    return-object v0

    :cond_5
    invoke-interface {v5, v2}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
