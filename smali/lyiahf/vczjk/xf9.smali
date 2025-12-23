.class public final Llyiahf/vczjk/xf9;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$this$coroutineScope:Llyiahf/vczjk/xr1;

.field final synthetic $onDoubleTap:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $onLongPress:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $onPress:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $onTap:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $pressScope:Llyiahf/vczjk/o37;

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    iput-object p2, p0, Llyiahf/vczjk/xf9;->$onPress:Llyiahf/vczjk/bf3;

    iput-object p3, p0, Llyiahf/vczjk/xf9;->$onLongPress:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/xf9;->$onDoubleTap:Llyiahf/vczjk/oe3;

    iput-object p5, p0, Llyiahf/vczjk/xf9;->$onTap:Llyiahf/vczjk/oe3;

    iput-object p6, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {p0, p7}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 8

    new-instance v0, Llyiahf/vczjk/xf9;

    iget-object v1, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    iget-object v2, p0, Llyiahf/vczjk/xf9;->$onPress:Llyiahf/vczjk/bf3;

    iget-object v3, p0, Llyiahf/vczjk/xf9;->$onLongPress:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/xf9;->$onDoubleTap:Llyiahf/vczjk/oe3;

    iget-object v5, p0, Llyiahf/vczjk/xf9;->$onTap:Llyiahf/vczjk/oe3;

    iget-object v6, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    move-object v7, p2

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/xf9;-><init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xf9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xf9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/xf9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/xf9;->label:I

    sget-object v2, Llyiahf/vczjk/x55;->OooO00o:Llyiahf/vczjk/x55;

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x3

    const/4 v5, 0x0

    const/4 v6, 0x1

    packed-switch v1, :pswitch_data_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v74;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_c

    :pswitch_1
    iget-object v1, p0, Llyiahf/vczjk/xf9;->L$3:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ky6;

    iget-object v4, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ky6;

    iget-object v6, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/v74;

    iget-object v7, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v12, v4

    move-object v4, v1

    move-object v1, v6

    :goto_0
    move-object v6, v12

    goto/16 :goto_a

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ky6;

    iget-object v1, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_9

    :pswitch_3
    iget-object v1, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    iget-object v4, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ky6;

    iget-object v7, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_8

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v74;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :pswitch_5
    iget-object v1, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    iget-object v4, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/ky6;

    iget-object v7, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_3

    :pswitch_6
    iget-object v1, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/v74;

    iget-object v4, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :pswitch_7
    iget-object v1, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v7, v1

    goto :goto_1

    :pswitch_8
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kb9;

    iput-object p1, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput v6, p0, Llyiahf/vczjk/xf9;->label:I

    invoke-static {p1, p0, v4}, Llyiahf/vczjk/dg9;->OooO0OO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/rs7;I)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_0

    goto/16 :goto_b

    :cond_0
    move-object v7, p1

    move-object p1, v1

    :goto_1
    check-cast p1, Llyiahf/vczjk/ky6;

    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    iget-object v1, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    sget-object v8, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    sget-object v8, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v9, Llyiahf/vczjk/vf9;

    iget-object v10, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v9, v10, v5}, Llyiahf/vczjk/vf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v5, v8, v9, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v1

    iget-object v8, p0, Llyiahf/vczjk/xf9;->$onPress:Llyiahf/vczjk/bf3;

    sget-object v9, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    if-eq v8, v9, :cond_1

    iget-object v9, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v10, Llyiahf/vczjk/nf9;

    iget-object v11, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v10, v8, v11, p1, v5}, Llyiahf/vczjk/nf9;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/o37;Llyiahf/vczjk/ky6;Llyiahf/vczjk/yo1;)V

    invoke-static {v9, v1, v10}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    :cond_1
    iget-object v8, p0, Llyiahf/vczjk/xf9;->$onLongPress:Llyiahf/vczjk/oe3;

    if-nez v8, :cond_3

    iput-object v7, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    const/4 p1, 0x2

    iput p1, p0, Llyiahf/vczjk/xf9;->label:I

    sget-object p1, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-static {v7, p1, p0}, Llyiahf/vczjk/dg9;->OooO0oO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto/16 :goto_b

    :cond_2
    move-object v4, v7

    :goto_2
    check-cast p1, Llyiahf/vczjk/ky6;

    goto :goto_6

    :cond_3
    iput-object v7, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/xf9;->label:I

    sget-object v4, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-static {v7, v4, p0}, Llyiahf/vczjk/dg9;->OooO0o(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v0, :cond_4

    goto/16 :goto_b

    :cond_4
    move-object v12, v4

    move-object v4, p1

    move-object p1, v12

    :goto_3
    check-cast p1, Llyiahf/vczjk/y55;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v8

    if-eqz v8, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/xf9;->$onLongPress:Llyiahf/vczjk/oe3;

    iget-wide v8, v4, Llyiahf/vczjk/ky6;->OooO0OO:J

    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v8, v9}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {p1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    const/4 p1, 0x4

    iput p1, p0, Llyiahf/vczjk/xf9;->label:I

    invoke-static {v7, p0}, Llyiahf/vczjk/dg9;->OooO00o(Llyiahf/vczjk/kb9;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_5

    goto/16 :goto_b

    :cond_5
    move-object v0, v1

    :goto_4
    iget-object p1, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/of9;

    iget-object v2, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v1, v2, v5}, Llyiahf/vczjk/of9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    return-object v3

    :cond_6
    instance-of v4, p1, Llyiahf/vczjk/w55;

    if-eqz v4, :cond_7

    check-cast p1, Llyiahf/vczjk/w55;

    iget-object p1, p1, Llyiahf/vczjk/w55;->OooO00o:Llyiahf/vczjk/ky6;

    goto :goto_5

    :cond_7
    instance-of p1, p1, Llyiahf/vczjk/v55;

    if-eqz p1, :cond_16

    move-object p1, v5

    :goto_5
    move-object v4, v7

    :goto_6
    if-nez p1, :cond_8

    iget-object v7, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v8, Llyiahf/vczjk/pf9;

    iget-object v9, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v8, v9, v5}, Llyiahf/vczjk/pf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v7, v1, v8}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    move-result-object v1

    goto :goto_7

    :cond_8
    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    iget-object v7, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v8, Llyiahf/vczjk/qf9;

    iget-object v9, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v8, v9, v5}, Llyiahf/vczjk/qf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v7, v1, v8}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    move-result-object v1

    :goto_7
    if-eqz p1, :cond_15

    iget-object v7, p0, Llyiahf/vczjk/xf9;->$onDoubleTap:Llyiahf/vczjk/oe3;

    if-nez v7, :cond_9

    iget-object v0, p0, Llyiahf/vczjk/xf9;->$onTap:Llyiahf/vczjk/oe3;

    if-eqz v0, :cond_15

    new-instance v1, Llyiahf/vczjk/p86;

    iget-wide v4, p1, Llyiahf/vczjk/ky6;->OooO0OO:J

    invoke-direct {v1, v4, v5}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v3

    :cond_9
    iput-object v4, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    const/4 v7, 0x5

    iput v7, p0, Llyiahf/vczjk/xf9;->label:I

    invoke-virtual {v4}, Llyiahf/vczjk/kb9;->OooO0Oo()Llyiahf/vczjk/gga;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/gga;->OooO00o()J

    move-result-wide v7

    new-instance v9, Llyiahf/vczjk/ff9;

    invoke-direct {v9, p1, v5}, Llyiahf/vczjk/ff9;-><init>(Llyiahf/vczjk/ky6;Llyiahf/vczjk/yo1;)V

    invoke-virtual {v4, v7, v8, v9, p0}, Llyiahf/vczjk/kb9;->OooO0oO(JLlyiahf/vczjk/ff9;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v0, :cond_a

    goto/16 :goto_b

    :cond_a
    move-object v12, v4

    move-object v4, p1

    move-object p1, v7

    move-object v7, v12

    :goto_8
    check-cast p1, Llyiahf/vczjk/ky6;

    if-nez p1, :cond_b

    iget-object p1, p0, Llyiahf/vczjk/xf9;->$onTap:Llyiahf/vczjk/oe3;

    if-eqz p1, :cond_15

    iget-wide v0, v4, Llyiahf/vczjk/ky6;->OooO0OO:J

    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {p1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v3

    :cond_b
    iget-object v8, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    sget-object v9, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    sget-object v9, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v10, Llyiahf/vczjk/rf9;

    iget-object v11, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v10, v1, v11, v5}, Llyiahf/vczjk/rf9;-><init>(Llyiahf/vczjk/v74;Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v8, v5, v9, v10, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v1

    iget-object v6, p0, Llyiahf/vczjk/xf9;->$onPress:Llyiahf/vczjk/bf3;

    sget-object v8, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    if-eq v6, v8, :cond_c

    iget-object v8, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v9, Llyiahf/vczjk/sf9;

    iget-object v10, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v9, v6, v10, p1, v5}, Llyiahf/vczjk/sf9;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/o37;Llyiahf/vczjk/ky6;Llyiahf/vczjk/yo1;)V

    invoke-static {v8, v1, v9}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    :cond_c
    iget-object v6, p0, Llyiahf/vczjk/xf9;->$onLongPress:Llyiahf/vczjk/oe3;

    if-nez v6, :cond_e

    iput-object v1, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    const/4 p1, 0x6

    iput p1, p0, Llyiahf/vczjk/xf9;->label:I

    sget-object p1, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-static {v7, p1, p0}, Llyiahf/vczjk/dg9;->OooO0oO(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_d

    goto :goto_b

    :cond_d
    move-object v0, v4

    :goto_9
    check-cast p1, Llyiahf/vczjk/ky6;

    goto :goto_e

    :cond_e
    iput-object v7, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    iput-object v4, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/xf9;->L$3:Ljava/lang/Object;

    const/4 v6, 0x7

    iput v6, p0, Llyiahf/vczjk/xf9;->label:I

    sget-object v6, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-static {v7, v6, p0}, Llyiahf/vczjk/dg9;->OooO0o(Llyiahf/vczjk/kb9;Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v0, :cond_f

    goto :goto_b

    :cond_f
    move-object v12, v4

    move-object v4, p1

    move-object p1, v6

    goto/16 :goto_0

    :goto_a
    check-cast p1, Llyiahf/vczjk/y55;

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_11

    iget-object p1, p0, Llyiahf/vczjk/xf9;->$onLongPress:Llyiahf/vczjk/oe3;

    iget-wide v8, v4, Llyiahf/vczjk/ky6;->OooO0OO:J

    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v8, v9}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {p1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/xf9;->L$0:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/xf9;->L$1:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/xf9;->L$2:Ljava/lang/Object;

    iput-object v5, p0, Llyiahf/vczjk/xf9;->L$3:Ljava/lang/Object;

    const/16 p1, 0x8

    iput p1, p0, Llyiahf/vczjk/xf9;->label:I

    invoke-static {v7, p0}, Llyiahf/vczjk/dg9;->OooO00o(Llyiahf/vczjk/kb9;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_10

    :goto_b
    return-object v0

    :cond_10
    move-object v0, v1

    :goto_c
    iget-object p1, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/wf9;

    iget-object v2, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v1, v2, v5}, Llyiahf/vczjk/wf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0, v1}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    return-object v3

    :cond_11
    instance-of v0, p1, Llyiahf/vczjk/w55;

    if-eqz v0, :cond_12

    check-cast p1, Llyiahf/vczjk/w55;

    iget-object p1, p1, Llyiahf/vczjk/w55;->OooO00o:Llyiahf/vczjk/ky6;

    :goto_d
    move-object v0, v6

    goto :goto_e

    :cond_12
    instance-of p1, p1, Llyiahf/vczjk/v55;

    if-eqz p1, :cond_14

    move-object p1, v5

    goto :goto_d

    :goto_e
    if-eqz p1, :cond_13

    invoke-virtual {p1}, Llyiahf/vczjk/ky6;->OooO00o()V

    iget-object v0, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v2, Llyiahf/vczjk/tf9;

    iget-object v4, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/tf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    iget-object v0, p0, Llyiahf/vczjk/xf9;->$onDoubleTap:Llyiahf/vczjk/oe3;

    new-instance v1, Llyiahf/vczjk/p86;

    iget-wide v4, p1, Llyiahf/vczjk/ky6;->OooO0OO:J

    invoke-direct {v1, v4, v5}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v3

    :cond_13
    iget-object p1, p0, Llyiahf/vczjk/xf9;->$$this$coroutineScope:Llyiahf/vczjk/xr1;

    new-instance v2, Llyiahf/vczjk/uf9;

    iget-object v4, p0, Llyiahf/vczjk/xf9;->$pressScope:Llyiahf/vczjk/o37;

    invoke-direct {v2, v4, v5}, Llyiahf/vczjk/uf9;-><init>(Llyiahf/vczjk/o37;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/dg9;->OooO0o0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/r09;

    iget-object p1, p0, Llyiahf/vczjk/xf9;->$onTap:Llyiahf/vczjk/oe3;

    if-eqz p1, :cond_15

    iget-wide v0, v0, Llyiahf/vczjk/ky6;->OooO0OO:J

    new-instance v2, Llyiahf/vczjk/p86;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {p1, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-object v3

    :cond_14
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_15
    return-object v3

    :cond_16
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
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
