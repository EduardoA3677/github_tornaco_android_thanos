.class public final Llyiahf/vczjk/wi6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $loadType$inlined:Llyiahf/vczjk/s25;

.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/pj6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/wi6;->this$0:Llyiahf/vczjk/pj6;

    iput-object p3, p0, Llyiahf/vczjk/wi6;->$loadType$inlined:Llyiahf/vczjk/s25;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/wi6;

    iget-object v1, p0, Llyiahf/vczjk/wi6;->this$0:Llyiahf/vczjk/pj6;

    iget-object v2, p0, Llyiahf/vczjk/wi6;->$loadType$inlined:Llyiahf/vczjk/s25;

    invoke-direct {v0, p3, v1, v2}, Llyiahf/vczjk/wi6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;)V

    iput-object p1, v0, Llyiahf/vczjk/wi6;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/wi6;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/wi6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/wi6;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget v1, p0, Llyiahf/vczjk/wi6;->I$0:I

    iget-object v4, p0, Llyiahf/vczjk/wi6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/jt5;

    iget-object v5, p0, Llyiahf/vczjk/wi6;->L$1:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/qj6;

    iget-object v6, p0, Llyiahf/vczjk/wi6;->L$0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/h43;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/wi6;->L$0:Ljava/lang/Object;

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/h43;

    iget-object p1, p0, Llyiahf/vczjk/wi6;->L$1:Ljava/lang/Object;

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result v1

    iget-object p1, p0, Llyiahf/vczjk/wi6;->this$0:Llyiahf/vczjk/pj6;

    iget-object v5, p1, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v4, v5, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v6, p0, Llyiahf/vczjk/wi6;->L$0:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/wi6;->L$1:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/wi6;->L$2:Ljava/lang/Object;

    iput v1, p0, Llyiahf/vczjk/wi6;->I$0:I

    iput v3, p0, Llyiahf/vczjk/wi6;->label:I

    invoke-virtual {v4, p0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto/16 :goto_3

    :cond_3
    :goto_0
    const/4 p1, 0x0

    :try_start_0
    iget-object v5, v5, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object v5, v5, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    iget-object v7, p0, Llyiahf/vczjk/wi6;->$loadType$inlined:Llyiahf/vczjk/s25;

    invoke-virtual {v5, v7}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;

    move-result-object v7

    sget-object v8, Llyiahf/vczjk/p25;->OooO0O0:Llyiahf/vczjk/p25;

    invoke-static {v7, v8}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    const/4 v8, 0x0

    if-eqz v7, :cond_4

    new-array v1, v8, [Llyiahf/vczjk/xg3;

    new-instance v3, Llyiahf/vczjk/y43;

    invoke-direct {v3, v1}, Llyiahf/vczjk/y43;-><init>([Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v4, p1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    goto :goto_2

    :catchall_0
    move-exception v0

    goto :goto_5

    :cond_4
    :try_start_1
    iget-object v7, p0, Llyiahf/vczjk/wi6;->$loadType$inlined:Llyiahf/vczjk/s25;

    invoke-virtual {v5, v7}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;

    iget-object v7, p0, Llyiahf/vczjk/wi6;->$loadType$inlined:Llyiahf/vczjk/s25;

    sget-object v9, Llyiahf/vczjk/p25;->OooO0OO:Llyiahf/vczjk/p25;

    invoke-virtual {v5, v7, v9}, Llyiahf/vczjk/ed5;->Oooo0oO(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    invoke-interface {v4, p1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    iget-object v4, p0, Llyiahf/vczjk/wi6;->this$0:Llyiahf/vczjk/pj6;

    iget-object v4, v4, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    iget-object v5, p0, Llyiahf/vczjk/wi6;->$loadType$inlined:Llyiahf/vczjk/s25;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const-string v7, "loadType"

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    const/4 v7, 0x1

    iget-object v4, v4, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ld9;

    if-eq v5, v7, :cond_6

    const/4 v7, 0x2

    if-ne v5, v7, :cond_5

    iget-object v4, v4, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/wn3;

    iget-object v4, v4, Llyiahf/vczjk/wn3;->OooO0O0:Llyiahf/vczjk/jl8;

    goto :goto_1

    :cond_5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "invalid load type for hints"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_6
    iget-object v4, v4, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/wn3;

    iget-object v4, v4, Llyiahf/vczjk/wn3;->OooO0O0:Llyiahf/vczjk/jl8;

    :goto_1
    if-nez v1, :cond_7

    move v3, v8

    :cond_7
    invoke-static {v4, v3}, Llyiahf/vczjk/rs;->OooOo0O(Llyiahf/vczjk/f43;I)Llyiahf/vczjk/t53;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/t53;

    const/4 v5, 0x1

    invoke-direct {v4, v3, v1, v5}, Llyiahf/vczjk/t53;-><init>(Llyiahf/vczjk/f43;II)V

    move-object v3, v4

    :goto_2
    iput-object p1, p0, Llyiahf/vczjk/wi6;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/wi6;->L$1:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/wi6;->L$2:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/wi6;->label:I

    invoke-static {v6, v3, p0}, Llyiahf/vczjk/rs;->OooOo0o(Llyiahf/vczjk/h43;Llyiahf/vczjk/f43;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_8

    :goto_3
    return-object v0

    :cond_8
    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :goto_5
    invoke-interface {v4, p1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0
.end method
