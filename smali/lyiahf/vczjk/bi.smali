.class public final Llyiahf/vczjk/bi;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animation:Llyiahf/vczjk/yk;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/yk;"
        }
    .end annotation
.end field

.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $initialVelocity:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $startTime:J

.field L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/gi;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/gi;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    iput-object p2, p0, Llyiahf/vczjk/bi;->$initialVelocity:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/bi;->$animation:Llyiahf/vczjk/yk;

    iput-wide p4, p0, Llyiahf/vczjk/bi;->$startTime:J

    iput-object p6, p0, Llyiahf/vczjk/bi;->$block:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1, p7}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1}, Llyiahf/vczjk/bi;->create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bi;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bi;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final create(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 8

    new-instance v0, Llyiahf/vczjk/bi;

    iget-object v1, p0, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    iget-object v2, p0, Llyiahf/vczjk/bi;->$initialVelocity:Ljava/lang/Object;

    iget-object v3, p0, Llyiahf/vczjk/bi;->$animation:Llyiahf/vczjk/yk;

    iget-wide v4, p0, Llyiahf/vczjk/bi;->$startTime:J

    iget-object v6, p0, Llyiahf/vczjk/bi;->$block:Llyiahf/vczjk/oe3;

    move-object v7, p1

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/bi;-><init>(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v5, p0

    sget-object v6, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, v5, Llyiahf/vczjk/bi;->label:I

    const/4 v1, 0x1

    if-eqz v0, :cond_1

    if-ne v0, v1, :cond_0

    iget-object v0, v5, Llyiahf/vczjk/bi;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/dl7;

    iget-object v1, v5, Llyiahf/vczjk/bi;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/xl;

    :try_start_0
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0

    goto/16 :goto_0

    :catch_0
    move-exception v0

    goto/16 :goto_2

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iget-object v0, v5, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    iget-object v2, v0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v0, v0, Llyiahf/vczjk/gi;->OooO00o:Llyiahf/vczjk/m1a;

    check-cast v0, Llyiahf/vczjk/n1a;

    iget-object v0, v0, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    iget-object v3, v5, Llyiahf/vczjk/bi;->$initialVelocity:Ljava/lang/Object;

    invoke-interface {v0, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dm;

    iput-object v0, v2, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    iget-object v0, v5, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    iget-object v2, v5, Llyiahf/vczjk/bi;->$animation:Llyiahf/vczjk/yk;

    invoke-interface {v2}, Llyiahf/vczjk/yk;->OooO0oO()Ljava/lang/Object;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/gi;->OooO0o0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, v5, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    iget-object v0, v0, Llyiahf/vczjk/gi;->OooO0Oo:Llyiahf/vczjk/qs5;

    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object v0, v5, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    iget-object v0, v0, Llyiahf/vczjk/gi;->OooO0OO:Llyiahf/vczjk/xl;

    iget-object v2, v0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v2, Llyiahf/vczjk/fw8;

    invoke-virtual {v2}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v9

    iget-object v2, v0, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    invoke-static {v2}, Llyiahf/vczjk/t51;->OooOo0O(Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object v10

    iget-wide v11, v0, Llyiahf/vczjk/xl;->OooOOOo:J

    iget-boolean v15, v0, Llyiahf/vczjk/xl;->OooOOo:Z

    new-instance v7, Llyiahf/vczjk/xl;

    iget-object v8, v0, Llyiahf/vczjk/xl;->OooOOO0:Llyiahf/vczjk/m1a;

    const-wide/high16 v13, -0x8000000000000000L

    invoke-direct/range {v7 .. v15}, Llyiahf/vczjk/xl;-><init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;JJZ)V

    move-object v0, v7

    new-instance v7, Llyiahf/vczjk/dl7;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    iget-object v2, v5, Llyiahf/vczjk/bi;->$animation:Llyiahf/vczjk/yk;

    move-object v4, v2

    iget-wide v2, v5, Llyiahf/vczjk/bi;->$startTime:J

    move-object v8, v4

    new-instance v4, Llyiahf/vczjk/ai;

    iget-object v9, v5, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    iget-object v10, v5, Llyiahf/vczjk/bi;->$block:Llyiahf/vczjk/oe3;

    invoke-direct {v4, v9, v0, v10, v7}, Llyiahf/vczjk/ai;-><init>(Llyiahf/vczjk/gi;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/dl7;)V

    iput-object v0, v5, Llyiahf/vczjk/bi;->L$0:Ljava/lang/Object;

    iput-object v7, v5, Llyiahf/vczjk/bi;->L$1:Ljava/lang/Object;

    iput v1, v5, Llyiahf/vczjk/bi;->label:I

    move-object v1, v8

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/vc6;->OooO(Llyiahf/vczjk/xl;Llyiahf/vczjk/yk;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v6, :cond_2

    return-object v6

    :cond_2
    move-object v1, v0

    move-object v0, v7

    :goto_0
    iget-boolean v0, v0, Llyiahf/vczjk/dl7;->element:Z

    if-eqz v0, :cond_3

    sget-object v0, Llyiahf/vczjk/zk;->OooOOO0:Llyiahf/vczjk/zk;

    goto :goto_1

    :cond_3
    sget-object v0, Llyiahf/vczjk/zk;->OooOOO:Llyiahf/vczjk/zk;

    :goto_1
    iget-object v2, v5, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    invoke-static {v2}, Llyiahf/vczjk/gi;->OooO00o(Llyiahf/vczjk/gi;)V

    new-instance v2, Llyiahf/vczjk/el;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/el;-><init>(Llyiahf/vczjk/xl;Llyiahf/vczjk/zk;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    return-object v2

    :goto_2
    iget-object v1, v5, Llyiahf/vczjk/bi;->this$0:Llyiahf/vczjk/gi;

    invoke-static {v1}, Llyiahf/vczjk/gi;->OooO00o(Llyiahf/vczjk/gi;)V

    throw v0
.end method
