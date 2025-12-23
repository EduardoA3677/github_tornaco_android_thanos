.class public final Llyiahf/vczjk/ls5;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field I$0:I

.field I$1:I

.field I$2:I

.field I$3:I

.field J$0:J

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ns5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ns5;"
        }
    .end annotation
.end field

.field final synthetic this$1:Llyiahf/vczjk/ms5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ns5;Llyiahf/vczjk/ms5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ls5;->this$0:Llyiahf/vczjk/ns5;

    iput-object p2, p0, Llyiahf/vczjk/ls5;->this$1:Llyiahf/vczjk/ms5;

    invoke-direct {p0, p3}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/ls5;

    iget-object v1, p0, Llyiahf/vczjk/ls5;->this$0:Llyiahf/vczjk/ns5;

    iget-object v2, p0, Llyiahf/vczjk/ls5;->this$1:Llyiahf/vczjk/ms5;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/ls5;-><init>(Llyiahf/vczjk/ns5;Llyiahf/vczjk/ms5;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/ls5;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xf8;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ls5;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ls5;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ls5;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v0, p0

    const/4 v1, 0x1

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v3, v0, Llyiahf/vczjk/ls5;->label:I

    const/4 v4, 0x0

    const/16 v5, 0x8

    if-eqz v3, :cond_1

    if-ne v3, v1, :cond_0

    iget v3, v0, Llyiahf/vczjk/ls5;->I$3:I

    iget v6, v0, Llyiahf/vczjk/ls5;->I$2:I

    iget-wide v7, v0, Llyiahf/vczjk/ls5;->J$0:J

    iget v9, v0, Llyiahf/vczjk/ls5;->I$1:I

    iget v10, v0, Llyiahf/vczjk/ls5;->I$0:I

    iget-object v11, v0, Llyiahf/vczjk/ls5;->L$3:Ljava/lang/Object;

    check-cast v11, [J

    iget-object v12, v0, Llyiahf/vczjk/ls5;->L$2:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/ns5;

    iget-object v13, v0, Llyiahf/vczjk/ls5;->L$1:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/ms5;

    iget-object v14, v0, Llyiahf/vczjk/ls5;->L$0:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/xf8;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_2

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v3, v0, Llyiahf/vczjk/ls5;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/xf8;

    iget-object v6, v0, Llyiahf/vczjk/ls5;->this$0:Llyiahf/vczjk/ns5;

    iget-object v7, v6, Llyiahf/vczjk/ns5;->OooOOO:Llyiahf/vczjk/ks5;

    iget-object v8, v0, Llyiahf/vczjk/ls5;->this$1:Llyiahf/vczjk/ms5;

    iget-object v7, v7, Llyiahf/vczjk/a88;->OooO00o:[J

    array-length v9, v7

    add-int/lit8 v9, v9, -0x2

    if-ltz v9, :cond_5

    move v10, v4

    :goto_0
    aget-wide v11, v7, v10

    not-long v13, v11

    const/4 v15, 0x7

    shl-long/2addr v13, v15

    and-long/2addr v13, v11

    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v13, v15

    cmp-long v13, v13, v15

    if-eqz v13, :cond_4

    sub-int v13, v10, v9

    not-int v13, v13

    ushr-int/lit8 v13, v13, 0x1f

    rsub-int/lit8 v13, v13, 0x8

    move v14, v10

    move v10, v9

    move v9, v14

    move-object v14, v3

    move v3, v4

    move-wide/from16 v19, v11

    move-object v12, v6

    move-object v11, v7

    move v6, v13

    move-object v13, v8

    move-wide/from16 v7, v19

    :goto_1
    if-ge v3, v6, :cond_3

    const-wide/16 v15, 0xff

    and-long/2addr v15, v7

    const-wide/16 v17, 0x80

    cmp-long v15, v15, v17

    if-gez v15, :cond_2

    shl-int/lit8 v4, v9, 0x3

    add-int/2addr v4, v3

    iput v4, v13, Llyiahf/vczjk/ms5;->OooOOO0:I

    iget-object v5, v12, Llyiahf/vczjk/ns5;->OooOOO:Llyiahf/vczjk/ks5;

    iget-object v5, v5, Llyiahf/vczjk/a88;->OooO0O0:[Ljava/lang/Object;

    aget-object v4, v5, v4

    iput-object v14, v0, Llyiahf/vczjk/ls5;->L$0:Ljava/lang/Object;

    iput-object v13, v0, Llyiahf/vczjk/ls5;->L$1:Ljava/lang/Object;

    iput-object v12, v0, Llyiahf/vczjk/ls5;->L$2:Ljava/lang/Object;

    iput-object v11, v0, Llyiahf/vczjk/ls5;->L$3:Ljava/lang/Object;

    iput v10, v0, Llyiahf/vczjk/ls5;->I$0:I

    iput v9, v0, Llyiahf/vczjk/ls5;->I$1:I

    iput-wide v7, v0, Llyiahf/vczjk/ls5;->J$0:J

    iput v6, v0, Llyiahf/vczjk/ls5;->I$2:I

    iput v3, v0, Llyiahf/vczjk/ls5;->I$3:I

    iput v1, v0, Llyiahf/vczjk/ls5;->label:I

    invoke-virtual {v14, v4, v0}, Llyiahf/vczjk/xf8;->OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)V

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object v2

    :cond_2
    :goto_2
    shr-long/2addr v7, v5

    add-int/2addr v3, v1

    goto :goto_1

    :cond_3
    if-ne v6, v5, :cond_5

    move v3, v10

    move v10, v9

    move v9, v3

    move-object v7, v11

    move-object v6, v12

    move-object v8, v13

    move-object v3, v14

    :cond_4
    if-eq v10, v9, :cond_5

    add-int/2addr v10, v1

    goto :goto_0

    :cond_5
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
