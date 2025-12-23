.class public final Llyiahf/vczjk/jj6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/pj6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/xr1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jj6;->OooOOO0:Llyiahf/vczjk/pj6;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 12

    instance-of v0, p1, Llyiahf/vczjk/ij6;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ij6;

    iget v1, v0, Llyiahf/vczjk/ij6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ij6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ij6;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/ij6;-><init>(Llyiahf/vczjk/jj6;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/ij6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ij6;->label:I

    sget-object v3, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    const/4 v4, 0x1

    const/4 v5, 0x0

    packed-switch v2, :pswitch_data_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    iget-object v1, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qj6;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    iget-object v0, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_5

    :pswitch_1
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s25;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/pj6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :pswitch_2
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pj6;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s25;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/jt5;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/qj6;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/s25;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/xr1;

    iget-object v10, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/pj6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_2

    :pswitch_3
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s25;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/xr1;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/pj6;

    :try_start_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    move-object v9, v7

    goto :goto_1

    :catchall_0
    move-exception p1

    goto/16 :goto_6

    :pswitch_4
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/qj6;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/s25;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/xr1;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/pj6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iget-object p1, v6, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    const/16 v6, 0xd

    iput v6, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {v9, p1, v7, v0}, Llyiahf/vczjk/pj6;->OooOO0(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p1, v1, :cond_1

    goto/16 :goto_13

    :cond_1
    move-object v6, v9

    move-object v9, v8

    move-object v8, v6

    move-object v6, v7

    :goto_1
    invoke-interface {v2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/hj6;->OooO00o:[I

    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    aget p1, p1, v2

    if-ne p1, v4, :cond_2

    move-object p1, v5

    move-object v2, v6

    move-object v4, v8

    goto :goto_3

    :cond_2
    iget-object v7, v8, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v7, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    const/16 v2, 0xe

    iput v2, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_3

    goto/16 :goto_13

    :cond_3
    move-object v4, v6

    move-object v2, v8

    move-object v10, v2

    move-object v6, p1

    move-object v8, v4

    :goto_2
    :try_start_2
    iget-object p1, v7, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooO:Ljava/util/LinkedHashMap;

    invoke-virtual {p1, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oja;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    invoke-interface {v6, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    move-object v6, v4

    move-object v4, v2

    move-object v2, v8

    move-object v8, v10

    :goto_3
    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    const/16 v7, 0xf

    iput v7, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-static {v4, v6, p1, v0}, Llyiahf/vczjk/pj6;->OooO0OO(Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/oja;Llyiahf/vczjk/ij6;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_4

    goto/16 :goto_13

    :cond_4
    move-object v6, v8

    move-object v4, v9

    :goto_4
    if-ne v2, v3, :cond_13

    iget-object v2, v6, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v2, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v4, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    const/16 v7, 0x10

    iput v7, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_5

    goto/16 :goto_13

    :cond_5
    move-object v1, p1

    move-object v0, v6

    :goto_5
    :try_start_3
    iget-object p1, v2, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    invoke-static {v0, v4}, Llyiahf/vczjk/pj6;->OooO0Oo(Llyiahf/vczjk/pj6;Llyiahf/vczjk/xr1;)V

    goto/16 :goto_17

    :catchall_1
    move-exception p1

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :catchall_2
    move-exception p1

    invoke-interface {v6, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :goto_6
    invoke-interface {v2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :pswitch_5
    iget-object v1, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qj6;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/pj6;

    iget-object v0, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_b

    :pswitch_6
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s25;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/pj6;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_a

    :pswitch_7
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$7:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pj6;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s25;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/jt5;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/qj6;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/s25;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/xr1;

    iget-object v10, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/pj6;

    iget-object v11, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_8

    :pswitch_8
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s25;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/xr1;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/pj6;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/r25;

    :try_start_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_3

    move-object v11, v9

    move-object v9, v7

    goto :goto_7

    :catchall_3
    move-exception p1

    goto/16 :goto_c

    :pswitch_9
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/qj6;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/s25;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/xr1;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/pj6;

    iget-object v10, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_5
    iget-object p1, v6, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iput-object v10, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    const/16 v6, 0x8

    iput v6, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {v9, p1, v7, v0}, Llyiahf/vczjk/pj6;->OooOO0(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    if-ne p1, v1, :cond_6

    goto/16 :goto_13

    :cond_6
    move-object v6, v9

    move-object v9, v8

    move-object v8, v6

    move-object v6, v7

    move-object v11, v10

    :goto_7
    invoke-interface {v2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/hj6;->OooO00o:[I

    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    aget p1, p1, v2

    if-ne p1, v4, :cond_7

    move-object p1, v5

    move-object v2, v6

    move-object v4, v8

    goto :goto_9

    :cond_7
    iget-object v7, v8, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v7, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v11, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$7:Ljava/lang/Object;

    const/16 v2, 0x9

    iput v2, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_8

    goto/16 :goto_13

    :cond_8
    move-object v4, v6

    move-object v2, v8

    move-object v10, v2

    move-object v6, p1

    move-object v8, v4

    :goto_8
    :try_start_6
    iget-object p1, v7, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooO:Ljava/util/LinkedHashMap;

    invoke-virtual {p1, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oja;
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    invoke-interface {v6, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    move-object v6, v4

    move-object v4, v2

    move-object v2, v8

    move-object v8, v10

    :goto_9
    iput-object v11, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$7:Ljava/lang/Object;

    const/16 v7, 0xa

    iput v7, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-static {v4, v6, p1, v0}, Llyiahf/vczjk/pj6;->OooO0OO(Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/oja;Llyiahf/vczjk/ij6;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_9

    goto/16 :goto_13

    :cond_9
    move-object v6, v8

    move-object v4, v9

    move-object v7, v11

    :goto_a
    if-ne v2, v3, :cond_12

    iget-object v2, v6, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v2, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v4, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    const/16 v8, 0xb

    iput v8, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_a

    goto/16 :goto_13

    :cond_a
    move-object v1, p1

    move-object v0, v7

    :goto_b
    :try_start_7
    iget-object p1, v2, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    invoke-static {v6, v4}, Llyiahf/vczjk/pj6;->OooO0Oo(Llyiahf/vczjk/pj6;Llyiahf/vczjk/xr1;)V

    move-object v7, v0

    goto/16 :goto_16

    :catchall_4
    move-exception p1

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :catchall_5
    move-exception p1

    invoke-interface {v6, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :goto_c
    invoke-interface {v2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :pswitch_a
    iget-object v1, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qj6;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/pj6;

    iget-object v0, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_11

    :pswitch_b
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/s25;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/pj6;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_10

    :pswitch_c
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$7:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pj6;

    iget-object v4, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/s25;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/jt5;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/qj6;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/s25;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/xr1;

    iget-object v10, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/pj6;

    iget-object v11, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_e

    :pswitch_d
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/s25;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/xr1;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/pj6;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/r25;

    :try_start_8
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_6

    move-object v11, v9

    move-object v9, v7

    goto :goto_d

    :catchall_6
    move-exception p1

    goto/16 :goto_12

    :pswitch_e
    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    iget-object v6, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/qj6;

    iget-object v7, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/s25;

    iget-object v8, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/xr1;

    iget-object v9, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/pj6;

    iget-object v10, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/r25;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_9
    iget-object p1, v6, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iput-object v10, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    const/4 v6, 0x3

    iput v6, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {v9, p1, v7, v0}, Llyiahf/vczjk/pj6;->OooOO0(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_6

    if-ne p1, v1, :cond_b

    goto/16 :goto_13

    :cond_b
    move-object v6, v9

    move-object v9, v8

    move-object v8, v6

    move-object v6, v7

    move-object v11, v10

    :goto_d
    invoke-interface {v2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/hj6;->OooO00o:[I

    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    move-result v2

    aget p1, p1, v2

    if-ne p1, v4, :cond_c

    move-object p1, v5

    move-object v2, v6

    move-object v4, v8

    goto :goto_f

    :cond_c
    iget-object v7, v8, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v7, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v11, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$7:Ljava/lang/Object;

    const/4 v2, 0x4

    iput v2, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_d

    goto/16 :goto_13

    :cond_d
    move-object v4, v6

    move-object v2, v8

    move-object v10, v2

    move-object v6, p1

    move-object v8, v4

    :goto_e
    :try_start_a
    iget-object p1, v7, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooO:Ljava/util/LinkedHashMap;

    invoke-virtual {p1, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/oja;
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_8

    invoke-interface {v6, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    move-object v6, v4

    move-object v4, v2

    move-object v2, v8

    move-object v8, v10

    :goto_f
    iput-object v11, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v9, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$5:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$6:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/ij6;->L$7:Ljava/lang/Object;

    const/4 v7, 0x5

    iput v7, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-static {v4, v6, p1, v0}, Llyiahf/vczjk/pj6;->OooO0OO(Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/oja;Llyiahf/vczjk/ij6;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_e

    goto/16 :goto_13

    :cond_e
    move-object v6, v8

    move-object v4, v9

    move-object v7, v11

    :goto_10
    if-ne v2, v3, :cond_11

    iget-object v2, v6, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v2, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v7, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v4, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ij6;->L$4:Ljava/lang/Object;

    const/4 v8, 0x6

    iput v8, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_f

    goto :goto_13

    :cond_f
    move-object v1, p1

    move-object v0, v7

    :goto_11
    :try_start_b
    iget-object p1, v2, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_7

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    invoke-static {v6, v4}, Llyiahf/vczjk/pj6;->OooO0Oo(Llyiahf/vczjk/pj6;Llyiahf/vczjk/xr1;)V

    move-object v7, v0

    goto :goto_15

    :catchall_7
    move-exception p1

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :catchall_8
    move-exception p1

    invoke-interface {v6, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :goto_12
    invoke-interface {v2, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    :pswitch_f
    iget-object v1, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v2, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pj6;

    iget-object v3, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/qj6;

    iget-object v0, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jj6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_14

    :pswitch_10
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, p0, Llyiahf/vczjk/jj6;->OooOOO0:Llyiahf/vczjk/pj6;

    iget-object v3, v2, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v3, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object p0, v0, Llyiahf/vczjk/ij6;->L$0:Ljava/lang/Object;

    iput-object v3, v0, Llyiahf/vczjk/ij6;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/ij6;->L$2:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/ij6;->L$3:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/ij6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_10

    :goto_13
    return-object v1

    :cond_10
    move-object v0, p0

    move-object v1, p1

    :goto_14
    :try_start_c
    iget-object p1, v3, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object v3, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {v3}, Llyiahf/vczjk/ed5;->Oooo0oo()Llyiahf/vczjk/r25;

    move-result-object v3

    iget-object v2, v2, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    iget-object v2, v2, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ld9;

    iget-object v2, v2, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/mja;

    invoke-virtual {p1, v2}, Llyiahf/vczjk/tj6;->OooO00o(Llyiahf/vczjk/mja;)Llyiahf/vczjk/rn6;

    move-result-object p1

    new-instance v2, Llyiahf/vczjk/xn6;

    invoke-direct {v2, v3, p1}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_9

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/r25;

    invoke-virtual {v2}, Llyiahf/vczjk/xn6;->OooO0O0()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rn6;

    iget-object v0, v0, Llyiahf/vczjk/jj6;->OooOOO0:Llyiahf/vczjk/pj6;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p1, Llyiahf/vczjk/r25;->OooO00o:Llyiahf/vczjk/q25;

    move-object v7, p1

    :cond_11
    :goto_15
    iget-object p1, v7, Llyiahf/vczjk/r25;->OooO0O0:Llyiahf/vczjk/q25;

    :cond_12
    :goto_16
    iget-object p1, v7, Llyiahf/vczjk/r25;->OooO0OO:Llyiahf/vczjk/q25;

    :cond_13
    :goto_17
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_9
    move-exception p1

    invoke-interface {v1, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final bridge synthetic emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/z8a;

    invoke-virtual {p0, p2}, Llyiahf/vczjk/jj6;->OooO00o(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
