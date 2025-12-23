.class public final Llyiahf/vczjk/pj6;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO:Llyiahf/vczjk/x74;

.field public final OooO00o:Ljava/lang/Object;

.field public final OooO0O0:Llyiahf/vczjk/c46;

.field public final OooO0OO:Llyiahf/vczjk/o55;

.field public final OooO0Oo:Llyiahf/vczjk/i00;

.field public final OooO0o:Ljava/util/concurrent/atomic/AtomicBoolean;

.field public final OooO0o0:Llyiahf/vczjk/vz5;

.field public final OooO0oO:Llyiahf/vczjk/jj0;

.field public final OooO0oo:Llyiahf/vczjk/qj6;

.field public final OooOO0:Llyiahf/vczjk/l53;


# direct methods
.method public constructor <init>(Ljava/lang/Object;Llyiahf/vczjk/c46;Llyiahf/vczjk/o55;Llyiahf/vczjk/i00;Llyiahf/vczjk/rn6;Llyiahf/vczjk/da;)V
    .locals 0

    const-string p5, "pagingSource"

    invoke-static {p2, p5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p5, "retryFlow"

    invoke-static {p4, p5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pj6;->OooO00o:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/pj6;->OooO0O0:Llyiahf/vczjk/c46;

    iput-object p3, p0, Llyiahf/vczjk/pj6;->OooO0OO:Llyiahf/vczjk/o55;

    iput-object p4, p0, Llyiahf/vczjk/pj6;->OooO0Oo:Llyiahf/vczjk/i00;

    new-instance p1, Llyiahf/vczjk/vz5;

    const/16 p2, 0x15

    invoke-direct {p1, p2}, Llyiahf/vczjk/vz5;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    new-instance p1, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 p2, 0x0

    invoke-direct {p1, p2}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    iput-object p1, p0, Llyiahf/vczjk/pj6;->OooO0o:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 p1, -0x2

    const/4 p2, 0x6

    const/4 p4, 0x0

    invoke-static {p1, p2, p4}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/pj6;->OooO0oO:Llyiahf/vczjk/jj0;

    new-instance p1, Llyiahf/vczjk/qj6;

    invoke-direct {p1, p3}, Llyiahf/vczjk/qj6;-><init>(Llyiahf/vczjk/o55;)V

    iput-object p1, p0, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    invoke-static {}, Llyiahf/vczjk/zsa;->OooO0oO()Llyiahf/vczjk/x74;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/pj6;->OooO:Llyiahf/vczjk/x74;

    new-instance p2, Llyiahf/vczjk/lj6;

    invoke-direct {p2, p0, p4}, Llyiahf/vczjk/lj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V

    new-instance p3, Llyiahf/vczjk/sp0;

    invoke-direct {p3, p1, p2, p4}, Llyiahf/vczjk/sp0;-><init>(Llyiahf/vczjk/v74;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)V

    invoke-static {p3}, Llyiahf/vczjk/ll6;->OooOOOo(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/mj6;

    invoke-direct {p2, p0, p4}, Llyiahf/vczjk/mj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V

    new-instance p3, Llyiahf/vczjk/l53;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/l53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    iput-object p3, p0, Llyiahf/vczjk/pj6;->OooOO0:Llyiahf/vczjk/l53;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/pj6;Llyiahf/vczjk/l53;Llyiahf/vczjk/s25;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/wi6;

    const/4 v1, 0x0

    invoke-direct {v0, v1, p0, p2}, Llyiahf/vczjk/wi6;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;)V

    new-instance v2, Llyiahf/vczjk/w43;

    invoke-direct {v2, p1, v0, v1}, Llyiahf/vczjk/w43;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    invoke-static {v2}, Llyiahf/vczjk/ll6;->OooOOOo(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/xi6;

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/xi6;-><init>(Llyiahf/vczjk/s25;Llyiahf/vczjk/yo1;)V

    const-string v2, "<this>"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v2, Llyiahf/vczjk/r43;

    invoke-direct {v2, p1, v0, v1}, Llyiahf/vczjk/r43;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;Llyiahf/vczjk/yo1;)V

    new-instance p1, Llyiahf/vczjk/s48;

    invoke-direct {p1, v2}, Llyiahf/vczjk/s48;-><init>(Llyiahf/vczjk/ze3;)V

    const/4 v0, -0x1

    invoke-static {p1, v0}, Llyiahf/vczjk/rs;->OooOO0(Llyiahf/vczjk/f43;I)Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/tx3;

    const/4 v1, 0x2

    invoke-direct {v0, v1, p0, p2}, Llyiahf/vczjk/tx3;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-interface {p1, v0, p3}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final OooO0O0(Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/xg3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 24

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v2, p3

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v3, v2, Llyiahf/vczjk/cj6;

    if-eqz v3, :cond_0

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/cj6;

    iget v4, v3, Llyiahf/vczjk/cj6;->label:I

    const/high16 v5, -0x80000000

    and-int v6, v4, v5

    if-eqz v6, :cond_0

    sub-int/2addr v4, v5

    iput v4, v3, Llyiahf/vczjk/cj6;->label:I

    goto :goto_0

    :cond_0
    new-instance v3, Llyiahf/vczjk/cj6;

    invoke-direct {v3, v0, v2}, Llyiahf/vczjk/cj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object v2, v3, Llyiahf/vczjk/cj6;->result:Ljava/lang/Object;

    sget-object v4, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v5, v3, Llyiahf/vczjk/cj6;->label:I

    sget-object v6, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    sget-object v7, Llyiahf/vczjk/s25;->OooOOOO:Llyiahf/vczjk/s25;

    sget-object v8, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    const-string v10, "message"

    const-string v11, "Use doInitialLoad for LoadType == REFRESH"

    const-string v14, "Paging"

    packed-switch v5, :pswitch_data_0

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_0
    iget v0, v3, Llyiahf/vczjk/cj6;->I$1:I

    iget v1, v3, Llyiahf/vczjk/cj6;->I$0:I

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/jt5;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/qj6;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/dl7;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/hl7;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/fl7;

    move/from16 p0, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xg3;

    move-object/from16 p1, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s25;

    move-object/from16 p2, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_0
    iget-object v2, v12, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object v12, v0, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    iget-object v12, v12, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/ld9;

    iget-object v12, v12, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/mja;

    invoke-virtual {v2, v12}, Llyiahf/vczjk/tj6;->OooO00o(Llyiahf/vczjk/mja;)Llyiahf/vczjk/rn6;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v2, 0x0

    invoke-interface {v5, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    if-nez v1, :cond_2

    if-nez p0, :cond_1

    move-object/from16 v20, v6

    move-object/from16 v19, v7

    move-object v12, v13

    move-object v1, v15

    move-object/from16 v13, p1

    move-object/from16 v15, p2

    goto/16 :goto_10

    :cond_1
    throw v2

    :cond_2
    throw v2

    :catchall_0
    move-exception v0

    const/4 v2, 0x0

    invoke-interface {v5, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :pswitch_1
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qn6;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/on6;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/dl7;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/hl7;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/fl7;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/xg3;

    move-object/from16 p0, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s25;

    move-object/from16 p1, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    :try_start_1
    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    move-object v2, v12

    move-object v12, v9

    move-object v9, v2

    move-object/from16 v2, p1

    move-object/from16 v20, v6

    move-object/from16 v19, v7

    move-object/from16 v21, v8

    move-object/from16 v22, v10

    const/16 v17, 0x1

    move-object v8, v1

    move-object v1, v0

    move-object/from16 v0, p0

    :goto_1
    const/4 v7, 0x0

    goto/16 :goto_22

    :catchall_1
    move-exception v0

    :goto_2
    const/4 v2, 0x0

    goto/16 :goto_23

    :pswitch_2
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$9:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tj6;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/qn6;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/on6;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/dl7;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/hl7;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/fl7;

    move-object/from16 p0, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xg3;

    move-object/from16 p1, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s25;

    move-object/from16 p2, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    :try_start_2
    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    move-object/from16 v20, v6

    move-object/from16 v19, v7

    move-object/from16 v21, v8

    const/16 v17, 0x1

    move-object/from16 v6, p0

    move-object v8, v1

    move-object/from16 v1, p2

    :goto_3
    move-object/from16 v2, p1

    goto/16 :goto_1d

    :pswitch_3
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$10:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt5;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$9:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qj6;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/s25;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/qn6;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/on6;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/dl7;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/hl7;

    move-object/from16 p0, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/fl7;

    move-object/from16 p1, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xg3;

    move-object/from16 p2, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s25;

    move-object/from16 v19, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v20, v6

    move-object/from16 v21, v8

    move-object v2, v12

    move-object v12, v13

    move-object v13, v15

    const/16 v17, 0x1

    move-object/from16 v8, p0

    move-object v15, v0

    move-object v6, v1

    move-object/from16 v1, v19

    move-object/from16 v0, p2

    move-object/from16 v19, v7

    move-object/from16 v7, p1

    goto/16 :goto_1c

    :pswitch_4
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tj6;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v4, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xg3;

    iget-object v3, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/s25;

    :try_start_3
    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v0, v0, Llyiahf/vczjk/tj6;->OooO:Ljava/util/LinkedHashMap;

    iget-object v2, v4, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    invoke-interface {v0, v3, v2}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    const/4 v2, 0x0

    invoke-interface {v1, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object v6

    :catchall_2
    move-exception v0

    const/4 v2, 0x0

    goto :goto_4

    :pswitch_5
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/qj6;

    iget-object v4, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qn6;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/xg3;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/s25;

    iget-object v3, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/pj6;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_4
    iget-object v0, v0, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    if-nez v4, :cond_3

    const/16 v18, 0x0

    throw v18

    :cond_3
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    :goto_4
    invoke-interface {v1, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :pswitch_6
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$9:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt5;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qj6;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/qn6;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/on6;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/dl7;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/hl7;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/fl7;

    move-object/from16 p0, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xg3;

    move-object/from16 p1, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s25;

    move-object/from16 p2, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v20, v6

    move-object/from16 v19, v7

    move-object v2, v15

    move-object/from16 v7, p0

    move-object v15, v0

    move-object v6, v1

    move-object/from16 v0, p1

    move-object/from16 v1, p2

    goto/16 :goto_15

    :pswitch_7
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/on6;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/dl7;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/hl7;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/fl7;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/xg3;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/s25;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/pj6;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v19, v9

    move-object v9, v0

    move-object v0, v13

    move-object v13, v5

    move-object/from16 v5, v19

    move-object/from16 v20, v6

    move-object/from16 v19, v7

    goto/16 :goto_13

    :pswitch_8
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hl7;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/jt5;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/hl7;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/fl7;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/xg3;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/s25;

    move-object/from16 p0, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    :try_start_5
    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    move-object v2, v1

    move-object/from16 v20, v6

    move-object/from16 v19, v7

    move-object v1, v0

    move-object/from16 v0, p0

    goto/16 :goto_c

    :catchall_3
    move-exception v0

    :goto_5
    const/4 v2, 0x0

    goto/16 :goto_24

    :pswitch_9
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hl7;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/qj6;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/hl7;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/fl7;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/xg3;

    iget-object v15, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/s25;

    move-object/from16 p0, v0

    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v20, v6

    move-object v6, v1

    move-object/from16 v1, p0

    goto/16 :goto_b

    :pswitch_a
    iget-object v0, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt5;

    iget-object v1, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qj6;

    iget-object v5, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/fl7;

    iget-object v9, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/xg3;

    iget-object v12, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/s25;

    iget-object v13, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    check-cast v13, Llyiahf/vczjk/pj6;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v2, v1

    move-object v1, v0

    move-object v0, v13

    const/4 v13, 0x1

    goto :goto_6

    :pswitch_b
    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object v2, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    if-eq v1, v2, :cond_23

    new-instance v5, Llyiahf/vczjk/fl7;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    iget-object v2, v0, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v9, v2, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    move-object/from16 v12, p2

    iput-object v12, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    iput-object v5, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    iput-object v2, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    iput-object v9, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    const/4 v13, 0x1

    iput v13, v3, Llyiahf/vczjk/cj6;->label:I

    invoke-virtual {v9, v3}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v15

    if-ne v15, v4, :cond_4

    goto/16 :goto_21

    :cond_4
    move-object/from16 v23, v12

    move-object v12, v1

    move-object v1, v9

    move-object/from16 v9, v23

    :goto_6
    :try_start_6
    iget-object v2, v2, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    invoke-virtual {v12}, Ljava/lang/Enum;->ordinal()I

    move-result v15

    if-eqz v15, :cond_22

    const/16 v19, 0x14

    if-eq v15, v13, :cond_8

    move/from16 v17, v13

    const/4 v13, 0x2

    if-eq v15, v13, :cond_6

    move-object/from16 v20, v6

    :cond_5
    const/4 v2, 0x0

    goto/16 :goto_a

    :cond_6
    iget v13, v2, Llyiahf/vczjk/tj6;->OooO0Oo:I

    iget-object v15, v9, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    iget v15, v15, Llyiahf/vczjk/oja;->OooO0Oo:I

    add-int/2addr v13, v15

    add-int/lit8 v13, v13, 0x1

    if-gez v13, :cond_7

    iget v15, v5, Llyiahf/vczjk/fl7;->element:I

    move-object/from16 v20, v6

    iget-object v6, v0, Llyiahf/vczjk/pj6;->OooO0OO:Llyiahf/vczjk/o55;

    neg-int v6, v13

    mul-int v19, v19, v6

    add-int v6, v19, v15

    iput v6, v5, Llyiahf/vczjk/fl7;->element:I
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    const/4 v13, 0x0

    goto :goto_7

    :catchall_4
    move-exception v0

    const/4 v2, 0x0

    goto/16 :goto_25

    :cond_7
    move-object/from16 v20, v6

    :goto_7
    iget-object v2, v2, Llyiahf/vczjk/tj6;->OooO0OO:Ljava/util/ArrayList;

    :try_start_7
    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v6

    if-gt v13, v6, :cond_5

    :goto_8
    iget v15, v5, Llyiahf/vczjk/fl7;->element:I

    invoke-virtual {v2, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v19

    move-object/from16 p0, v2

    move-object/from16 v2, v19

    check-cast v2, Llyiahf/vczjk/pn6;

    iget-object v2, v2, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    add-int/2addr v15, v2

    iput v15, v5, Llyiahf/vczjk/fl7;->element:I

    if-eq v13, v6, :cond_5

    add-int/lit8 v13, v13, 0x1

    move-object/from16 v2, p0

    goto :goto_8

    :cond_8
    move-object/from16 v20, v6

    iget v6, v2, Llyiahf/vczjk/tj6;->OooO0Oo:I

    iget-object v13, v9, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    iget v13, v13, Llyiahf/vczjk/oja;->OooO0OO:I
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_4

    add-int/2addr v6, v13

    const/16 v17, 0x1

    add-int/lit8 v6, v6, -0x1

    iget-object v2, v2, Llyiahf/vczjk/tj6;->OooO0OO:Ljava/util/ArrayList;

    :try_start_8
    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v13

    if-le v6, v13, :cond_9

    iget v13, v5, Llyiahf/vczjk/fl7;->element:I

    iget-object v15, v0, Llyiahf/vczjk/pj6;->OooO0OO:Llyiahf/vczjk/o55;

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v15

    sub-int/2addr v6, v15

    mul-int/lit8 v6, v6, 0x14

    add-int/2addr v6, v13

    iput v6, v5, Llyiahf/vczjk/fl7;->element:I

    invoke-static {v2}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v6

    :cond_9
    if-ltz v6, :cond_5

    const/4 v13, 0x0

    :goto_9
    iget v15, v5, Llyiahf/vczjk/fl7;->element:I

    invoke-virtual {v2, v13}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v19

    move-object/from16 p0, v2

    move-object/from16 v2, v19

    check-cast v2, Llyiahf/vczjk/pn6;

    iget-object v2, v2, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-interface {v2}, Ljava/util/List;->size()I

    move-result v2

    add-int/2addr v15, v2

    iput v15, v5, Llyiahf/vczjk/fl7;->element:I
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_4

    if-eq v13, v6, :cond_5

    add-int/lit8 v13, v13, 0x1

    move-object/from16 v2, p0

    goto :goto_9

    :goto_a
    invoke-interface {v1, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    new-instance v1, Llyiahf/vczjk/hl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iget-object v2, v0, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v6, v2, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    iput-object v12, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    iput-object v9, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    iput-object v5, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    iput-object v2, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    iput-object v6, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    const/4 v13, 0x2

    iput v13, v3, Llyiahf/vczjk/cj6;->label:I

    invoke-virtual {v6, v3}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v13

    if-ne v13, v4, :cond_a

    goto/16 :goto_21

    :cond_a
    move-object v13, v9

    move-object v15, v12

    move-object v9, v1

    move-object v12, v5

    move-object v5, v2

    :goto_b
    :try_start_9
    iget-object v2, v5, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget v5, v13, Llyiahf/vczjk/xg3;->OooO00o:I

    move-object/from16 v19, v7

    iget-object v7, v13, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    invoke-virtual {v7, v15}, Llyiahf/vczjk/oja;->OooO00o(Llyiahf/vczjk/s25;)I

    move-result v7

    move/from16 p0, v7

    iget v7, v12, Llyiahf/vczjk/fl7;->element:I

    add-int v7, p0, v7

    invoke-virtual {v0, v2, v15, v5, v7}, Llyiahf/vczjk/pj6;->OooO(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;II)Ljava/lang/Object;

    move-result-object v5

    if-eqz v5, :cond_c

    iput-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    iput-object v15, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    iput-object v13, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    iput-object v12, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    iput-object v9, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    iput-object v6, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    iput-object v5, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    const/4 v7, 0x3

    iput v7, v3, Llyiahf/vczjk/cj6;->label:I

    invoke-virtual {v0, v2, v15, v3}, Llyiahf/vczjk/pj6;->OooOO0(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v2
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_5

    if-ne v2, v4, :cond_b

    goto/16 :goto_21

    :cond_b
    move-object v2, v1

    move-object v1, v0

    move-object v0, v2

    move-object v2, v5

    move-object v5, v6

    :goto_c
    move-object v6, v1

    move-object v1, v0

    move-object v0, v6

    move-object v6, v5

    :goto_d
    const/4 v5, 0x0

    goto :goto_f

    :goto_e
    move-object v5, v6

    goto/16 :goto_5

    :catchall_5
    move-exception v0

    goto :goto_e

    :cond_c
    const/4 v2, 0x0

    goto :goto_d

    :goto_f
    invoke-interface {v6, v5}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    iput-object v2, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    new-instance v1, Llyiahf/vczjk/dl7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    :goto_10
    iget-object v2, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-eqz v2, :cond_21

    invoke-virtual {v0, v15, v2}, Llyiahf/vczjk/pj6;->OooO0oO(Llyiahf/vczjk/s25;Ljava/lang/Object;)Llyiahf/vczjk/on6;

    move-result-object v2

    sget-object v5, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v5, :cond_d

    const/4 v7, 0x3

    invoke-static {v14, v7}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v5

    if-eqz v5, :cond_d

    const/4 v5, 0x1

    goto :goto_11

    :cond_d
    const/4 v5, 0x0

    :goto_11
    iget-object v6, v0, Llyiahf/vczjk/pj6;->OooO0O0:Llyiahf/vczjk/c46;

    if-eqz v5, :cond_e

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v7, "Start "

    invoke-direct {v5, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v7, " with loadKey "

    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v7, v9, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v7, " on "

    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v5

    invoke-static {v5, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v7, 0x0

    invoke-static {v14, v5, v7}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    goto :goto_12

    :cond_e
    const/4 v7, 0x0

    :goto_12
    iput-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    iput-object v15, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    iput-object v13, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    iput-object v12, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    iput-object v9, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    iput-object v2, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    iput-object v7, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    iput-object v7, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    const/4 v5, 0x4

    iput v5, v3, Llyiahf/vczjk/cj6;->label:I

    invoke-virtual {v6, v2, v3}, Llyiahf/vczjk/c46;->OooO0O0(Llyiahf/vczjk/on6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v4, :cond_f

    goto/16 :goto_21

    :cond_f
    move-object/from16 v23, v15

    move-object v15, v0

    move-object/from16 v0, v23

    move-object/from16 v23, v9

    move-object v9, v2

    move-object v2, v5

    move-object v5, v12

    move-object v12, v13

    move-object/from16 v13, v23

    :goto_13
    check-cast v2, Llyiahf/vczjk/qn6;

    instance-of v6, v2, Llyiahf/vczjk/pn6;

    if-eqz v6, :cond_19

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v6

    const/4 v7, 0x1

    if-eq v6, v7, :cond_11

    const/4 v7, 0x2

    if-ne v6, v7, :cond_10

    move-object v6, v2

    check-cast v6, Llyiahf/vczjk/pn6;

    iget-object v6, v6, Llyiahf/vczjk/pn6;->OooOOO:Ljava/lang/Integer;

    goto :goto_14

    :cond_10
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v11}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_11
    move-object v6, v2

    check-cast v6, Llyiahf/vczjk/pn6;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v6, 0x0

    :goto_14
    iget-object v7, v15, Llyiahf/vczjk/pj6;->OooO0O0:Llyiahf/vczjk/c46;

    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v7, v13, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v6

    if-nez v6, :cond_17

    iget-object v6, v15, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v7, v6, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v15, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    iput-object v0, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    iput-object v12, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    iput-object v5, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    iput-object v13, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    iput-object v9, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    iput-object v2, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    iput-object v6, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    iput-object v7, v3, Llyiahf/vczjk/cj6;->L$9:Ljava/lang/Object;

    move-object/from16 p0, v1

    const/4 v1, 0x5

    iput v1, v3, Llyiahf/vczjk/cj6;->label:I

    invoke-virtual {v7, v3}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v4, :cond_12

    goto/16 :goto_21

    :cond_12
    move-object v1, v5

    move-object v5, v2

    move-object v2, v1

    move-object v1, v0

    move-object v0, v12

    move-object/from16 v12, p0

    :goto_15
    :try_start_a
    iget-object v6, v6, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    move-object/from16 p0, v3

    iget v3, v0, Llyiahf/vczjk/xg3;->OooO00o:I

    move-object/from16 p1, v0

    move-object v0, v5

    check-cast v0, Llyiahf/vczjk/pn6;

    invoke-virtual {v6, v3, v1, v0}, Llyiahf/vczjk/tj6;->OooO0O0(ILlyiahf/vczjk/s25;Llyiahf/vczjk/pn6;)Z

    move-result v0
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_6

    const/4 v3, 0x0

    invoke-interface {v7, v3}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    if-nez v0, :cond_13

    sget-object v0, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v0, :cond_21

    const/4 v7, 0x2

    invoke-static {v14, v7}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v0

    if-eqz v0, :cond_21

    iget-object v0, v13, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v0, v3}, Llyiahf/vczjk/pj6;->OooO0oo(Llyiahf/vczjk/s25;Ljava/lang/Object;Llyiahf/vczjk/qn6;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v14, v0, v3}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    return-object v20

    :cond_13
    sget-object v0, Landroid/os/Build;->ID:Ljava/lang/String;

    const/4 v6, 0x3

    if-eqz v0, :cond_14

    invoke-static {v14, v6}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v0

    if-eqz v0, :cond_14

    iget-object v0, v13, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, v0, v5}, Llyiahf/vczjk/pj6;->OooO0oo(Llyiahf/vczjk/s25;Ljava/lang/Object;Llyiahf/vczjk/qn6;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, v10}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v3, 0x0

    invoke-static {v14, v0, v3}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_14
    iget v0, v2, Llyiahf/vczjk/fl7;->element:I

    move-object v3, v5

    check-cast v3, Llyiahf/vczjk/pn6;

    iget-object v7, v3, Llyiahf/vczjk/pn6;->OooOOO0:Ljava/lang/Object;

    invoke-interface {v7}, Ljava/util/List;->size()I

    move-result v7

    add-int/2addr v7, v0

    iput v7, v2, Llyiahf/vczjk/fl7;->element:I

    if-ne v1, v8, :cond_15

    move-object/from16 v0, v19

    :goto_16
    const/4 v3, 0x1

    goto :goto_17

    :cond_15
    move-object/from16 v0, v19

    if-ne v1, v0, :cond_16

    iget-object v3, v3, Llyiahf/vczjk/pn6;->OooOOO:Ljava/lang/Integer;

    if-nez v3, :cond_16

    goto :goto_16

    :goto_17
    iput-boolean v3, v12, Llyiahf/vczjk/dl7;->element:Z

    goto :goto_18

    :cond_16
    const/4 v3, 0x1

    :goto_18
    move-object/from16 v17, v5

    move-object v5, v2

    move-object v2, v9

    move-object/from16 v9, v17

    move-object/from16 v19, v0

    move-object v0, v1

    move/from16 v17, v3

    move-object v1, v12

    move-object/from16 v3, p0

    move-object/from16 v12, p1

    goto :goto_1a

    :catchall_6
    move-exception v0

    const/4 v2, 0x0

    invoke-interface {v7, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :cond_17
    if-ne v0, v8, :cond_18

    const-string v0, "prevKey"

    goto :goto_19

    :cond_18
    const-string v0, "nextKey"

    :goto_19
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "The same value, "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, v13, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, ", was passed as the "

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v0, " in two\n                            | sequential Pages loaded from a PagingSource. Re-using load keys in\n                            | PagingSource is often an error, and must be explicitly enabled by\n                            | overriding PagingSource.keyReuseSupported.\n                            "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/a79;->OooOoO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    new-instance v1, Ljava/lang/IllegalStateException;

    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_19
    move-object/from16 p0, v1

    const/4 v6, 0x3

    const/16 v17, 0x1

    move-object v1, v9

    move-object v9, v2

    move-object v2, v1

    move-object/from16 v1, p0

    :goto_1a
    sget-object v7, Llyiahf/vczjk/vi6;->OooO00o:[I

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v16

    aget v7, v7, v16

    const/4 v6, 0x2

    if-ne v7, v6, :cond_1a

    move-object/from16 v7, v19

    goto :goto_1b

    :cond_1a
    move-object v7, v8

    :goto_1b
    iget-object v6, v15, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    move-object/from16 v21, v8

    iget-object v8, v6, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v15, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    iput-object v0, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    iput-object v12, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    iput-object v5, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    iput-object v13, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    iput-object v2, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    iput-object v9, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    iput-object v7, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    iput-object v6, v3, Llyiahf/vczjk/cj6;->L$9:Ljava/lang/Object;

    iput-object v8, v3, Llyiahf/vczjk/cj6;->L$10:Ljava/lang/Object;

    move-object/from16 p0, v0

    const/16 v0, 0x8

    iput v0, v3, Llyiahf/vczjk/cj6;->label:I

    invoke-virtual {v8, v3}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v4, :cond_1b

    goto/16 :goto_21

    :cond_1b
    move-object v0, v7

    move-object v7, v5

    move-object v5, v0

    move-object v0, v12

    move-object v12, v1

    move-object/from16 v1, p0

    :goto_1c
    :try_start_b
    iget-object v6, v6, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    move-object/from16 p0, v1

    iget-object v1, v0, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object/from16 p1, v0

    const-string v0, "loadType"

    invoke-static {v5, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "hint"

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    move-object/from16 v1, p0

    move-object v5, v9

    move-object v0, v15

    move-object v9, v2

    move-object v15, v7

    goto/16 :goto_3

    :goto_1d
    iget v7, v2, Llyiahf/vczjk/xg3;->OooO00o:I

    move-object/from16 v22, v10

    iget-object v10, v2, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    invoke-virtual {v10, v1}, Llyiahf/vczjk/oja;->OooO00o(Llyiahf/vczjk/s25;)I

    move-result v10

    move/from16 p0, v10

    iget v10, v15, Llyiahf/vczjk/fl7;->element:I

    add-int v10, p0, v10

    invoke-virtual {v0, v6, v1, v7, v10}, Llyiahf/vczjk/pj6;->OooO(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;II)Ljava/lang/Object;

    move-result-object v7
    :try_end_b
    .catchall {:try_start_b .. :try_end_b} :catchall_7

    iget-object v10, v6, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    :try_start_c
    iput-object v7, v13, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-nez v7, :cond_1d

    invoke-virtual {v10, v1}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;

    iget-boolean v7, v12, Llyiahf/vczjk/dl7;->element:Z

    if-eqz v7, :cond_1c

    sget-object v7, Llyiahf/vczjk/p25;->OooO0O0:Llyiahf/vczjk/p25;

    goto :goto_1f

    :goto_1e
    move-object v1, v8

    goto/16 :goto_2

    :cond_1c
    sget-object v7, Llyiahf/vczjk/p25;->OooO0OO:Llyiahf/vczjk/p25;

    :goto_1f
    invoke-virtual {v10, v1, v7}, Llyiahf/vczjk/ed5;->Oooo0oO(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)V

    goto :goto_20

    :catchall_7
    move-exception v0

    goto :goto_1e

    :cond_1d
    :goto_20
    move-object v7, v5

    check-cast v7, Llyiahf/vczjk/pn6;

    invoke-virtual {v6, v7, v1}, Llyiahf/vczjk/tj6;->OooO0OO(Llyiahf/vczjk/pn6;Llyiahf/vczjk/s25;)Llyiahf/vczjk/ii6;

    move-result-object v6

    iget-object v7, v0, Llyiahf/vczjk/pj6;->OooO0oO:Llyiahf/vczjk/jj0;

    iput-object v0, v3, Llyiahf/vczjk/cj6;->L$0:Ljava/lang/Object;

    iput-object v1, v3, Llyiahf/vczjk/cj6;->L$1:Ljava/lang/Object;

    iput-object v2, v3, Llyiahf/vczjk/cj6;->L$2:Ljava/lang/Object;

    iput-object v15, v3, Llyiahf/vczjk/cj6;->L$3:Ljava/lang/Object;

    iput-object v13, v3, Llyiahf/vczjk/cj6;->L$4:Ljava/lang/Object;

    iput-object v12, v3, Llyiahf/vczjk/cj6;->L$5:Ljava/lang/Object;

    iput-object v9, v3, Llyiahf/vczjk/cj6;->L$6:Ljava/lang/Object;

    iput-object v5, v3, Llyiahf/vczjk/cj6;->L$7:Ljava/lang/Object;

    iput-object v8, v3, Llyiahf/vczjk/cj6;->L$8:Ljava/lang/Object;

    const/4 v10, 0x0

    iput-object v10, v3, Llyiahf/vczjk/cj6;->L$9:Ljava/lang/Object;

    iput-object v10, v3, Llyiahf/vczjk/cj6;->L$10:Ljava/lang/Object;

    const/16 v10, 0xa

    iput v10, v3, Llyiahf/vczjk/cj6;->label:I

    invoke-interface {v7, v6, v3}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v6
    :try_end_c
    .catchall {:try_start_c .. :try_end_c} :catchall_7

    if-ne v6, v4, :cond_1e

    :goto_21
    return-object v4

    :cond_1e
    move-object v7, v1

    move-object v1, v0

    move-object v0, v5

    move-object v5, v9

    move-object v9, v13

    move-object v13, v15

    move-object v15, v2

    move-object v2, v7

    goto/16 :goto_1

    :goto_22
    invoke-interface {v8, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    instance-of v6, v5, Llyiahf/vczjk/mn6;

    if-eqz v6, :cond_1f

    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/pn6;

    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    :cond_1f
    instance-of v5, v5, Llyiahf/vczjk/ln6;

    if-eqz v5, :cond_20

    check-cast v0, Llyiahf/vczjk/pn6;

    iget-object v0, v0, Llyiahf/vczjk/pn6;->OooOOO:Ljava/lang/Integer;

    :cond_20
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-object v0, v1

    move-object v1, v12

    move-object v12, v13

    move-object v13, v15

    move-object/from16 v8, v21

    move-object/from16 v10, v22

    move-object v15, v2

    goto/16 :goto_10

    :goto_23
    invoke-interface {v1, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :cond_21
    return-object v20

    :goto_24
    invoke-interface {v5, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :cond_22
    :try_start_d
    new-instance v0, Ljava/lang/IllegalStateException;

    invoke-direct {v0, v11}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_4

    :goto_25
    invoke-interface {v1, v2}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :cond_23
    new-instance v0, Ljava/lang/IllegalArgumentException;

    invoke-direct {v0, v11}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
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

.method public static final OooO0OO(Llyiahf/vczjk/pj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/oja;Llyiahf/vczjk/ij6;)Ljava/lang/Object;
    .locals 3

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/vi6;->OooO00o:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v0, v0, v1

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v2, 0x1

    if-ne v0, v2, :cond_1

    invoke-virtual {p0, p3}, Llyiahf/vczjk/pj6;->OooO0o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    return-object v1

    :cond_1
    if-eqz p2, :cond_4

    iget-object p0, p0, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p3, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    if-eq p1, p3, :cond_3

    sget-object p3, Llyiahf/vczjk/s25;->OooOOOO:Llyiahf/vczjk/s25;

    if-ne p1, p3, :cond_2

    goto :goto_0

    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    const-string p2, "invalid load type for reset: "

    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    new-instance p1, Ljava/lang/IllegalArgumentException;

    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    :goto_0
    new-instance p3, Llyiahf/vczjk/xn3;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/xn3;-><init>(Llyiahf/vczjk/s25;Llyiahf/vczjk/oja;)V

    iget-object p0, p0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/ld9;

    const/4 p1, 0x0

    invoke-virtual {p0, p1, p3}, Llyiahf/vczjk/ld9;->Ooooo00(Llyiahf/vczjk/mja;Llyiahf/vczjk/ze3;)V

    return-object v1

    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Cannot retry APPEND / PREPEND load on PagingSource without ViewportHint"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/pj6;Llyiahf/vczjk/xr1;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/pj6;->OooO0OO:Llyiahf/vczjk/o55;

    new-instance v0, Llyiahf/vczjk/nj6;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/nj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V

    const/4 v2, 0x3

    invoke-static {p1, v1, v1, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    new-instance v0, Llyiahf/vczjk/oj6;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/oj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v1, v1, v0, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public static OooO0oo(Llyiahf/vczjk/s25;Ljava/lang/Object;Llyiahf/vczjk/qn6;)Ljava/lang/String;
    .locals 2

    const-string v0, "End "

    if-nez p2, :cond_0

    new-instance p2, Ljava/lang/StringBuilder;

    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, " with loadkey "

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, ". Load CANCELLED."

    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, " with loadKey "

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p0, ". Returned "

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;II)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    if-eqz v0, :cond_5

    const/4 v1, 0x1

    if-eq v0, v1, :cond_1

    const/4 v1, 0x2

    if-ne v0, v1, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    :goto_0
    const/4 v0, 0x0

    if-eqz p3, :cond_2

    goto :goto_1

    :cond_2
    iget-object p3, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {p3, p2}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;

    const/16 p3, 0x14

    if-lt p4, p3, :cond_3

    :goto_1
    return-object v0

    :cond_3
    sget-object p3, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooO0OO:Ljava/util/ArrayList;

    if-ne p2, p3, :cond_4

    invoke-static {p1}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/pn6;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object v0

    :cond_4
    invoke-static {p1}, Llyiahf/vczjk/d21;->o0Oo0oo(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/pn6;

    iget-object p1, p1, Llyiahf/vczjk/pn6;->OooOOO:Ljava/lang/Integer;

    return-object p1

    :cond_5
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "Cannot get loadId for loadType: REFRESH"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0o(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v1, p0

    move-object/from16 v0, p1

    instance-of v2, v0, Llyiahf/vczjk/bj6;

    if-eqz v2, :cond_0

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/bj6;

    iget v3, v2, Llyiahf/vczjk/bj6;->label:I

    const/high16 v4, -0x80000000

    and-int v5, v3, v4

    if-eqz v5, :cond_0

    sub-int/2addr v3, v4

    iput v3, v2, Llyiahf/vczjk/bj6;->label:I

    goto :goto_0

    :cond_0
    new-instance v2, Llyiahf/vczjk/bj6;

    invoke-direct {v2, v1, v0}, Llyiahf/vczjk/bj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object v0, v2, Llyiahf/vczjk/bj6;->result:Ljava/lang/Object;

    sget-object v3, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v4, v2, Llyiahf/vczjk/bj6;->label:I

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    sget-object v6, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    const/4 v7, 0x0

    const-string v8, "message"

    const/4 v9, 0x0

    const/4 v10, 0x1

    const/4 v11, 0x3

    const/4 v12, 0x2

    const-string v13, "Paging"

    packed-switch v4, :pswitch_data_0

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_0
    iget-object v2, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jt5;

    :try_start_0
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v2, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object v5

    :catchall_0
    move-exception v0

    goto :goto_1

    :pswitch_1
    iget-object v3, v2, Llyiahf/vczjk/bj6;->L$3:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jt5;

    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qj6;

    iget-object v5, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/qn6;

    iget-object v2, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pj6;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iget-object v0, v4, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    if-nez v5, :cond_1

    throw v7

    :catchall_1
    move-exception v0

    move-object v2, v3

    goto :goto_1

    :cond_1
    new-instance v0, Ljava/lang/ClassCastException;

    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    throw v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :goto_1
    invoke-interface {v2, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :pswitch_2
    iget-object v3, v2, Llyiahf/vczjk/bj6;->L$3:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jt5;

    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qj6;

    iget-object v5, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/qn6;

    iget-object v2, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pj6;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_2
    iget-object v0, v4, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object v2, v2, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    iget-object v2, v2, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ld9;

    iget-object v2, v2, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/mja;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/tj6;->OooO00o(Llyiahf/vczjk/mja;)Llyiahf/vczjk/rn6;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    invoke-interface {v3, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    check-cast v5, Llyiahf/vczjk/pn6;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    throw v7

    :catchall_2
    move-exception v0

    invoke-interface {v3, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :pswitch_3
    iget-object v3, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/jt5;

    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/qn6;

    iget-object v2, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pj6;

    :try_start_3
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_3

    goto/16 :goto_a

    :catchall_3
    move-exception v0

    goto/16 :goto_b

    :pswitch_4
    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$3:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/jt5;

    iget-object v8, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/qj6;

    iget-object v9, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/qn6;

    iget-object v10, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/pj6;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v15, v10

    goto/16 :goto_8

    :pswitch_5
    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$3:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/jt5;

    iget-object v10, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    check-cast v10, Llyiahf/vczjk/qj6;

    iget-object v14, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/qn6;

    iget-object v15, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/pj6;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_6

    :pswitch_6
    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/pj6;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v15, v4

    goto/16 :goto_5

    :pswitch_7
    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/jt5;

    iget-object v14, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/pj6;

    :try_start_4
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_4

    goto :goto_3

    :catchall_4
    move-exception v0

    goto/16 :goto_e

    :pswitch_8
    iget-object v4, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/jt5;

    iget-object v14, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/qj6;

    iget-object v15, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    check-cast v15, Llyiahf/vczjk/pj6;

    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :pswitch_9
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v14, v1, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v0, v14, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v1, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    iput-object v14, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    iput-object v0, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    iput v10, v2, Llyiahf/vczjk/bj6;->label:I

    invoke-virtual {v0, v2}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v3, :cond_2

    goto/16 :goto_9

    :cond_2
    move-object v4, v0

    move-object v15, v1

    :goto_2
    :try_start_5
    iget-object v0, v14, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iput-object v15, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    iput-object v4, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    iput-object v7, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    iput v12, v2, Llyiahf/vczjk/bj6;->label:I

    invoke-virtual {v15, v0, v6, v2}, Llyiahf/vczjk/pj6;->OooOO0(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_4

    if-ne v0, v3, :cond_3

    goto/16 :goto_9

    :cond_3
    move-object v14, v15

    :goto_3
    invoke-interface {v4, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    iget-object v0, v14, Llyiahf/vczjk/pj6;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v14, v6, v0}, Llyiahf/vczjk/pj6;->OooO0oO(Llyiahf/vczjk/s25;Ljava/lang/Object;)Llyiahf/vczjk/on6;

    move-result-object v0

    sget-object v4, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v4, :cond_4

    invoke-static {v13, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v4

    if-eqz v4, :cond_4

    goto :goto_4

    :cond_4
    move v10, v9

    :goto_4
    iget-object v4, v14, Llyiahf/vczjk/pj6;->OooO0O0:Llyiahf/vczjk/c46;

    if-eqz v10, :cond_5

    new-instance v10, Ljava/lang/StringBuilder;

    const-string v15, "Start REFRESH with loadKey "

    invoke-direct {v10, v15}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v15, v14, Llyiahf/vczjk/pj6;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v10, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v15, " on "

    invoke-virtual {v10, v15}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v10, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v10}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v10

    invoke-static {v10, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v13, v10, v7}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_5
    iput-object v14, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    iput-object v7, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    iput v11, v2, Llyiahf/vczjk/bj6;->label:I

    invoke-virtual {v4, v0, v2}, Llyiahf/vczjk/c46;->OooO0O0(Llyiahf/vczjk/on6;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v3, :cond_6

    goto/16 :goto_9

    :cond_6
    move-object v15, v14

    :goto_5
    check-cast v0, Llyiahf/vczjk/qn6;

    instance-of v4, v0, Llyiahf/vczjk/pn6;

    if-eqz v4, :cond_e

    iget-object v10, v15, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v4, v10, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v15, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    iput-object v0, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    iput-object v10, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    iput-object v4, v2, Llyiahf/vczjk/bj6;->L$3:Ljava/lang/Object;

    const/4 v14, 0x4

    iput v14, v2, Llyiahf/vczjk/bj6;->label:I

    invoke-virtual {v4, v2}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v14

    if-ne v14, v3, :cond_7

    goto/16 :goto_9

    :cond_7
    move-object v14, v0

    :goto_6
    :try_start_6
    iget-object v0, v10, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    move-object v10, v14

    check-cast v10, Llyiahf/vczjk/pn6;

    invoke-virtual {v0, v9, v6, v10}, Llyiahf/vczjk/tj6;->OooO0O0(ILlyiahf/vczjk/s25;Llyiahf/vczjk/pn6;)Z

    move-result v9
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_5

    iget-object v0, v0, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    :try_start_7
    sget-object v10, Llyiahf/vczjk/p25;->OooO0OO:Llyiahf/vczjk/p25;

    invoke-virtual {v0, v6, v10}, Llyiahf/vczjk/ed5;->Oooo0oO(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)V

    move-object v10, v14

    check-cast v10, Llyiahf/vczjk/pn6;

    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v10, Llyiahf/vczjk/s25;->OooOOO:Llyiahf/vczjk/s25;

    sget-object v12, Llyiahf/vczjk/p25;->OooO0O0:Llyiahf/vczjk/p25;

    invoke-virtual {v0, v10, v12}, Llyiahf/vczjk/ed5;->Oooo0oO(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)V

    move-object v10, v14

    check-cast v10, Llyiahf/vczjk/pn6;

    iget-object v10, v10, Llyiahf/vczjk/pn6;->OooOOO:Ljava/lang/Integer;

    if-nez v10, :cond_8

    sget-object v10, Llyiahf/vczjk/s25;->OooOOOO:Llyiahf/vczjk/s25;

    invoke-virtual {v0, v10, v12}, Llyiahf/vczjk/ed5;->Oooo0oO(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)V
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_5

    goto :goto_7

    :catchall_5
    move-exception v0

    goto/16 :goto_d

    :cond_8
    :goto_7
    invoke-interface {v4, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    if-eqz v9, :cond_c

    sget-object v0, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v0, :cond_9

    invoke-static {v13, v11}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v0

    if-eqz v0, :cond_9

    iget-object v0, v15, Llyiahf/vczjk/pj6;->OooO00o:Ljava/lang/Object;

    invoke-static {v6, v0, v14}, Llyiahf/vczjk/pj6;->OooO0oo(Llyiahf/vczjk/s25;Ljava/lang/Object;Llyiahf/vczjk/qn6;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v13, v0, v7}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_9
    iget-object v8, v15, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object v0, v8, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object v15, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    iput-object v14, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    iput-object v8, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    iput-object v0, v2, Llyiahf/vczjk/bj6;->L$3:Ljava/lang/Object;

    const/4 v4, 0x5

    iput v4, v2, Llyiahf/vczjk/bj6;->label:I

    invoke-virtual {v0, v2}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v3, :cond_a

    goto :goto_9

    :cond_a
    move-object v4, v0

    move-object v9, v14

    :goto_8
    :try_start_8
    iget-object v0, v8, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object v8, v15, Llyiahf/vczjk/pj6;->OooO0oO:Llyiahf/vczjk/jj0;

    move-object v10, v9

    check-cast v10, Llyiahf/vczjk/pn6;

    invoke-virtual {v0, v10, v6}, Llyiahf/vczjk/tj6;->OooO0OO(Llyiahf/vczjk/pn6;Llyiahf/vczjk/s25;)Llyiahf/vczjk/ii6;

    move-result-object v0

    iput-object v15, v2, Llyiahf/vczjk/bj6;->L$0:Ljava/lang/Object;

    iput-object v9, v2, Llyiahf/vczjk/bj6;->L$1:Ljava/lang/Object;

    iput-object v4, v2, Llyiahf/vczjk/bj6;->L$2:Ljava/lang/Object;

    iput-object v7, v2, Llyiahf/vczjk/bj6;->L$3:Ljava/lang/Object;

    const/4 v6, 0x6

    iput v6, v2, Llyiahf/vczjk/bj6;->label:I

    invoke-interface {v8, v0, v2}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_6

    if-ne v0, v3, :cond_b

    :goto_9
    return-object v3

    :cond_b
    move-object v3, v4

    move-object v2, v15

    :goto_a
    invoke-interface {v3, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    move-object v15, v2

    goto :goto_c

    :catchall_6
    move-exception v0

    move-object v3, v4

    :goto_b
    invoke-interface {v3, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :cond_c
    sget-object v0, Landroid/os/Build;->ID:Ljava/lang/String;

    if-eqz v0, :cond_d

    const/4 v0, 0x2

    invoke-static {v13, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result v0

    if-eqz v0, :cond_d

    iget-object v0, v15, Llyiahf/vczjk/pj6;->OooO00o:Ljava/lang/Object;

    invoke-static {v6, v0, v7}, Llyiahf/vczjk/pj6;->OooO0oo(Llyiahf/vczjk/s25;Ljava/lang/Object;Llyiahf/vczjk/qn6;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0, v8}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v13, v0, v7}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_d
    :goto_c
    invoke-virtual {v15}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-object v5

    :goto_d
    invoke-interface {v4, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :cond_e
    return-object v5

    :goto_e
    invoke-interface {v4, v7}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0

    :pswitch_data_0
    .packed-switch 0x0
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

.method public final OooO0o0(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p1, Llyiahf/vczjk/aj6;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/aj6;

    iget v1, v0, Llyiahf/vczjk/aj6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/aj6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/aj6;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/aj6;-><init>(Llyiahf/vczjk/pj6;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/aj6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/aj6;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object v1, v0, Llyiahf/vczjk/aj6;->L$2:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jt5;

    iget-object v2, v0, Llyiahf/vczjk/aj6;->L$1:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/qj6;

    iget-object v0, v0, Llyiahf/vczjk/aj6;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/pj6;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, p0, Llyiahf/vczjk/pj6;->OooO0oo:Llyiahf/vczjk/qj6;

    iget-object p1, v2, Llyiahf/vczjk/qj6;->OooO00o:Llyiahf/vczjk/mt5;

    iput-object p0, v0, Llyiahf/vczjk/aj6;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/aj6;->L$1:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/aj6;->L$2:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/aj6;->label:I

    invoke-virtual {p1, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_3

    return-object v1

    :cond_3
    move-object v0, p0

    move-object v1, p1

    :goto_1
    const/4 p1, 0x0

    :try_start_0
    iget-object v2, v2, Llyiahf/vczjk/qj6;->OooO0O0:Llyiahf/vczjk/tj6;

    iget-object v0, v0, Llyiahf/vczjk/pj6;->OooO0o0:Llyiahf/vczjk/vz5;

    iget-object v0, v0, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mja;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/tj6;->OooO00o(Llyiahf/vczjk/mja;)Llyiahf/vczjk/rn6;

    move-result-object v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-interface {v1, p1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    return-object v0

    :catchall_0
    move-exception v0

    invoke-interface {v1, p1}, Llyiahf/vczjk/jt5;->OooO0Oo(Ljava/lang/Object;)V

    throw v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/s25;Ljava/lang/Object;)Llyiahf/vczjk/on6;
    .locals 2

    sget-object v0, Llyiahf/vczjk/s25;->OooOOO0:Llyiahf/vczjk/s25;

    iget-object v1, p0, Llyiahf/vczjk/pj6;->OooO0OO:Llyiahf/vczjk/o55;

    if-ne p1, v0, :cond_0

    iget v0, v1, Llyiahf/vczjk/o55;->OooOOO0:I

    goto :goto_0

    :cond_0
    const/16 v0, 0x14

    :goto_0
    const-string v1, "loadType"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_5

    const/4 v1, 0x1

    if-eq p1, v1, :cond_3

    const/4 v1, 0x2

    if-ne p1, v1, :cond_2

    if-eqz p2, :cond_1

    new-instance p1, Llyiahf/vczjk/ln6;

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/ln6;-><init>(Ljava/lang/Object;I)V

    return-object p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "key cannot be null for append"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_3
    if-eqz p2, :cond_4

    new-instance p1, Llyiahf/vczjk/mn6;

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/mn6;-><init>(Ljava/lang/Object;I)V

    return-object p1

    :cond_4
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string p2, "key cannot be null for prepend"

    invoke-direct {p1, p2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_5
    new-instance p1, Llyiahf/vczjk/nn6;

    invoke-direct {p1, p2, v0}, Llyiahf/vczjk/nn6;-><init>(Ljava/lang/Object;I)V

    return-object p1
.end method

.method public final OooOO0(Llyiahf/vczjk/tj6;Llyiahf/vczjk/s25;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/ed5;->OooOOo0(Llyiahf/vczjk/s25;)Llyiahf/vczjk/q25;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/o25;->OooO0O0:Llyiahf/vczjk/o25;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-nez v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/tj6;->OooOO0:Llyiahf/vczjk/ed5;

    invoke-virtual {p1, p2, v1}, Llyiahf/vczjk/ed5;->Oooo0oO(Llyiahf/vczjk/s25;Llyiahf/vczjk/q25;)V

    iget-object p2, p0, Llyiahf/vczjk/pj6;->OooO0oO:Llyiahf/vczjk/jj0;

    new-instance v0, Llyiahf/vczjk/ji6;

    invoke-virtual {p1}, Llyiahf/vczjk/ed5;->Oooo0oo()Llyiahf/vczjk/r25;

    move-result-object p1

    const/4 v1, 0x0

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/ji6;-><init>(Llyiahf/vczjk/r25;Llyiahf/vczjk/r25;)V

    invoke-interface {p2, v0, p3}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    return-object v2
.end method
