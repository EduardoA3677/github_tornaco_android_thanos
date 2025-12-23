.class public final Llyiahf/vczjk/qv8;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field I$0:I

.field I$1:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/rv8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/rv8;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qv8;->this$0:Llyiahf/vczjk/rv8;

    invoke-direct {p0, p2}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/qv8;

    iget-object v1, p0, Llyiahf/vczjk/qv8;->this$0:Llyiahf/vczjk/rv8;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/qv8;-><init>(Llyiahf/vczjk/rv8;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xf8;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qv8;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qv8;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qv8;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/qv8;->label:I

    const/4 v3, 0x0

    const/4 v6, 0x3

    const/4 v7, 0x2

    const/16 v8, 0x40

    const/4 v9, 0x0

    const-wide/16 v10, 0x0

    const/4 v12, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v12, :cond_2

    if-eq v2, v7, :cond_1

    if-ne v2, v6, :cond_0

    iget v2, v0, Llyiahf/vczjk/qv8;->I$0:I

    iget-object v7, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/xf8;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    const-wide/16 v16, 0x1

    goto/16 :goto_4

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    iget v2, v0, Llyiahf/vczjk/qv8;->I$0:I

    iget-object v13, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/xf8;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    const-wide/16 v16, 0x1

    goto :goto_2

    :cond_2
    iget v2, v0, Llyiahf/vczjk/qv8;->I$1:I

    iget v13, v0, Llyiahf/vczjk/qv8;->I$0:I

    iget-object v14, v0, Llyiahf/vczjk/qv8;->L$1:Ljava/lang/Object;

    check-cast v14, [J

    iget-object v15, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/xf8;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    add-int/2addr v13, v12

    goto :goto_0

    :cond_3
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    move-object v15, v2

    check-cast v15, Llyiahf/vczjk/xf8;

    iget-object v2, v0, Llyiahf/vczjk/qv8;->this$0:Llyiahf/vczjk/rv8;

    iget-object v14, v2, Llyiahf/vczjk/rv8;->OooOOOo:[J

    if-eqz v14, :cond_4

    array-length v2, v14

    move v13, v9

    :goto_0
    if-ge v13, v2, :cond_4

    aget-wide v3, v14, v13

    new-instance v5, Ljava/lang/Long;

    invoke-direct {v5, v3, v4}, Ljava/lang/Long;-><init>(J)V

    iput-object v15, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    iput-object v14, v0, Llyiahf/vczjk/qv8;->L$1:Ljava/lang/Object;

    iput v13, v0, Llyiahf/vczjk/qv8;->I$0:I

    iput v2, v0, Llyiahf/vczjk/qv8;->I$1:I

    iput v12, v0, Llyiahf/vczjk/qv8;->label:I

    invoke-virtual {v15, v5, v0}, Llyiahf/vczjk/xf8;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    return-object v1

    :cond_4
    iget-object v2, v0, Llyiahf/vczjk/qv8;->this$0:Llyiahf/vczjk/rv8;

    iget-wide v13, v2, Llyiahf/vczjk/rv8;->OooOOO:J

    cmp-long v2, v13, v10

    if-eqz v2, :cond_7

    move v2, v9

    move-object v13, v15

    :goto_1
    if-ge v2, v8, :cond_6

    iget-object v14, v0, Llyiahf/vczjk/qv8;->this$0:Llyiahf/vczjk/rv8;

    const-wide/16 v16, 0x1

    iget-wide v4, v14, Llyiahf/vczjk/rv8;->OooOOO:J

    shl-long v18, v16, v2

    and-long v4, v4, v18

    cmp-long v4, v4, v10

    if-eqz v4, :cond_5

    int-to-long v4, v2

    iget-wide v8, v14, Llyiahf/vczjk/rv8;->OooOOOO:J

    add-long/2addr v8, v4

    new-instance v4, Ljava/lang/Long;

    invoke-direct {v4, v8, v9}, Ljava/lang/Long;-><init>(J)V

    iput-object v13, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    iput-object v3, v0, Llyiahf/vczjk/qv8;->L$1:Ljava/lang/Object;

    iput v2, v0, Llyiahf/vczjk/qv8;->I$0:I

    iput v7, v0, Llyiahf/vczjk/qv8;->label:I

    invoke-virtual {v13, v4, v0}, Llyiahf/vczjk/xf8;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object v1

    :cond_5
    :goto_2
    add-int/2addr v2, v12

    goto :goto_1

    :cond_6
    move-object v15, v13

    :cond_7
    const-wide/16 v16, 0x1

    iget-object v2, v0, Llyiahf/vczjk/qv8;->this$0:Llyiahf/vczjk/rv8;

    iget-wide v4, v2, Llyiahf/vczjk/rv8;->OooOOO0:J

    cmp-long v2, v4, v10

    if-eqz v2, :cond_9

    move-object v7, v15

    :goto_3
    if-ge v9, v8, :cond_9

    iget-object v2, v0, Llyiahf/vczjk/qv8;->this$0:Llyiahf/vczjk/rv8;

    iget-wide v4, v2, Llyiahf/vczjk/rv8;->OooOOO0:J

    shl-long v13, v16, v9

    and-long/2addr v4, v13

    cmp-long v4, v4, v10

    if-eqz v4, :cond_8

    int-to-long v4, v9

    iget-wide v10, v2, Llyiahf/vczjk/rv8;->OooOOOO:J

    add-long/2addr v10, v4

    int-to-long v4, v8

    add-long/2addr v10, v4

    new-instance v2, Ljava/lang/Long;

    invoke-direct {v2, v10, v11}, Ljava/lang/Long;-><init>(J)V

    iput-object v7, v0, Llyiahf/vczjk/qv8;->L$0:Ljava/lang/Object;

    iput-object v3, v0, Llyiahf/vczjk/qv8;->L$1:Ljava/lang/Object;

    iput v9, v0, Llyiahf/vczjk/qv8;->I$0:I

    iput v6, v0, Llyiahf/vczjk/qv8;->label:I

    invoke-virtual {v7, v2, v0}, Llyiahf/vczjk/xf8;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object v1

    :cond_8
    move v2, v9

    :goto_4
    add-int/lit8 v9, v2, 0x1

    goto :goto_3

    :cond_9
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
