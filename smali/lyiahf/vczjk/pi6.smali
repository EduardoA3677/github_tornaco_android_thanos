.class public final Llyiahf/vczjk/pi6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $remoteMediatorAccessor:Llyiahf/vczjk/bp7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bp7;"
        }
    .end annotation
.end field

.field synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field synthetic Z$0:Z

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/ui6;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ui6;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/pi6;->this$0:Llyiahf/vczjk/ui6;

    const/4 p2, 0x3

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/mi6;

    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/pi6;

    iget-object v1, p0, Llyiahf/vczjk/pi6;->this$0:Llyiahf/vczjk/ui6;

    invoke-direct {v0, p3, v1}, Llyiahf/vczjk/pi6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ui6;)V

    iput-object p1, v0, Llyiahf/vczjk/pi6;->L$0:Ljava/lang/Object;

    iput-boolean p2, v0, Llyiahf/vczjk/pi6;->Z$0:Z

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/pi6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/pi6;->label:I

    const/4 v3, 0x1

    const/4 v4, 0x0

    const/4 v5, 0x2

    if-eqz v2, :cond_2

    if-eq v2, v3, :cond_1

    if-ne v2, v5, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/pi6;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/c46;

    iget-object v2, v0, Llyiahf/vczjk/pi6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/mi6;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v5, p1

    goto :goto_3

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    iget-object v2, v0, Llyiahf/vczjk/pi6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/mi6;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v6, p1

    goto :goto_1

    :cond_2
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/pi6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/mi6;

    iget-object v6, v0, Llyiahf/vczjk/pi6;->this$0:Llyiahf/vczjk/ui6;

    if-eqz v2, :cond_3

    iget-object v7, v2, Llyiahf/vczjk/mi6;->OooO00o:Llyiahf/vczjk/pj6;

    iget-object v7, v7, Llyiahf/vczjk/pj6;->OooO0O0:Llyiahf/vczjk/c46;

    goto :goto_0

    :cond_3
    move-object v7, v4

    :goto_0
    iput-object v2, v0, Llyiahf/vczjk/pi6;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/pi6;->label:I

    invoke-static {v6, v7, v0}, Llyiahf/vczjk/ui6;->OooO00o(Llyiahf/vczjk/ui6;Llyiahf/vczjk/c46;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v6

    if-ne v6, v1, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    check-cast v6, Llyiahf/vczjk/c46;

    if-eqz v2, :cond_6

    iget-object v7, v2, Llyiahf/vczjk/mi6;->OooO00o:Llyiahf/vczjk/pj6;

    iput-object v2, v0, Llyiahf/vczjk/pi6;->L$0:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/pi6;->L$1:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/pi6;->label:I

    invoke-virtual {v7, v0}, Llyiahf/vczjk/pj6;->OooO0o0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    move-object v1, v6

    :goto_3
    check-cast v5, Llyiahf/vczjk/rn6;

    move-object v8, v1

    goto :goto_4

    :cond_6
    move-object v5, v4

    move-object v8, v6

    :goto_4
    if-eqz v5, :cond_7

    iget-object v1, v5, Llyiahf/vczjk/rn6;->OooO00o:Ljava/util/List;

    goto :goto_5

    :cond_7
    move-object v1, v4

    :goto_5
    if-eqz v1, :cond_8

    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_9

    :cond_8
    if-eqz v2, :cond_9

    iget-object v1, v2, Llyiahf/vczjk/mi6;->OooO0O0:Llyiahf/vczjk/rn6;

    if-eqz v1, :cond_9

    iget-object v6, v1, Llyiahf/vczjk/rn6;->OooO00o:Ljava/util/List;

    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    move-result v6

    xor-int/2addr v6, v3

    if-ne v6, v3, :cond_9

    move-object v5, v1

    :cond_9
    if-eqz v5, :cond_a

    iget-object v1, v5, Llyiahf/vczjk/rn6;->OooO0O0:Ljava/lang/Integer;

    goto :goto_6

    :cond_a
    move-object v1, v4

    :goto_6
    if-nez v1, :cond_c

    if-eqz v2, :cond_b

    iget-object v1, v2, Llyiahf/vczjk/mi6;->OooO0O0:Llyiahf/vczjk/rn6;

    if-eqz v1, :cond_b

    iget-object v1, v1, Llyiahf/vczjk/rn6;->OooO0O0:Ljava/lang/Integer;

    goto :goto_7

    :cond_b
    move-object v1, v4

    :goto_7
    if-eqz v1, :cond_c

    iget-object v5, v2, Llyiahf/vczjk/mi6;->OooO0O0:Llyiahf/vczjk/rn6;

    :cond_c
    move-object v11, v5

    if-nez v11, :cond_d

    iget-object v1, v0, Llyiahf/vczjk/pi6;->this$0:Llyiahf/vczjk/ui6;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    goto/16 :goto_b

    :cond_d
    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v11, Llyiahf/vczjk/rn6;->OooO0O0:Ljava/lang/Integer;

    if-eqz v1, :cond_13

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    move-result v1

    iget-object v3, v11, Llyiahf/vczjk/rn6;->OooO00o:Ljava/util/List;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v5

    if-eqz v5, :cond_e

    goto :goto_9

    :cond_e
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v5

    :cond_f
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v6

    if-eqz v6, :cond_12

    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pn6;

    iget-object v6, v6, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-interface {v6}, Ljava/util/List;->isEmpty()Z

    move-result v6

    if-nez v6, :cond_f

    iget v5, v11, Llyiahf/vczjk/rn6;->OooO0Oo:I

    sub-int/2addr v1, v5

    const/4 v5, 0x0

    :goto_8
    invoke-static {v3}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v6

    if-ge v5, v6, :cond_10

    invoke-interface {v3, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pn6;

    iget-object v6, v6, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-static {v6}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v6

    if-le v1, v6, :cond_10

    invoke-interface {v3, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/pn6;

    iget-object v6, v6, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-interface {v6}, Ljava/util/List;->size()I

    move-result v6

    sub-int/2addr v1, v6

    add-int/lit8 v5, v5, 0x1

    goto :goto_8

    :cond_10
    if-gez v1, :cond_11

    invoke-static {v3}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pn6;

    goto :goto_a

    :cond_11
    invoke-interface {v3, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/pn6;

    goto :goto_a

    :cond_12
    :goto_9
    move-object v1, v4

    :cond_13
    :goto_a
    sget-object v1, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v1, :cond_14

    const/4 v1, 0x3

    const-string v3, "Paging"

    invoke-static {v3, v1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v1

    if-eqz v1, :cond_14

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v5, "Refresh key "

    invoke-direct {v1, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v5, " returned from PagingSource "

    invoke-virtual {v1, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    const-string v5, "message"

    invoke-static {v1, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v3, v1, v4}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_14
    :goto_b
    if-eqz v2, :cond_15

    iget-object v1, v2, Llyiahf/vczjk/mi6;->OooO00o:Llyiahf/vczjk/pj6;

    iget-object v1, v1, Llyiahf/vczjk/pj6;->OooO:Llyiahf/vczjk/x74;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_15
    if-eqz v2, :cond_16

    iget-object v1, v2, Llyiahf/vczjk/mi6;->OooO0OO:Llyiahf/vczjk/x74;

    invoke-virtual {v1, v4}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_16
    new-instance v1, Llyiahf/vczjk/mi6;

    iget-object v14, v0, Llyiahf/vczjk/pi6;->this$0:Llyiahf/vczjk/ui6;

    iget-object v9, v14, Llyiahf/vczjk/ui6;->OooO0O0:Llyiahf/vczjk/o55;

    iget-object v2, v14, Llyiahf/vczjk/ui6;->OooO0Oo:Llyiahf/vczjk/n62;

    iget-object v2, v2, Llyiahf/vczjk/n62;->OooOOOO:Ljava/lang/Object;

    move-object v10, v2

    check-cast v10, Llyiahf/vczjk/i00;

    new-instance v12, Llyiahf/vczjk/da;

    const-class v15, Llyiahf/vczjk/ui6;

    const-string v16, "refresh"

    const/4 v13, 0x0

    const-string v17, "refresh()V"

    const/16 v18, 0x0

    const/16 v19, 0x9

    invoke-direct/range {v12 .. v19}, Llyiahf/vczjk/da;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    new-instance v6, Llyiahf/vczjk/pj6;

    const/4 v7, 0x0

    invoke-direct/range {v6 .. v12}, Llyiahf/vczjk/pj6;-><init>(Ljava/lang/Object;Llyiahf/vczjk/c46;Llyiahf/vczjk/o55;Llyiahf/vczjk/i00;Llyiahf/vczjk/rn6;Llyiahf/vczjk/da;)V

    invoke-static {}, Llyiahf/vczjk/zsa;->OooO0oO()Llyiahf/vczjk/x74;

    move-result-object v2

    invoke-direct {v1, v6, v11, v2}, Llyiahf/vczjk/mi6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/rn6;Llyiahf/vczjk/x74;)V

    return-object v1
.end method
