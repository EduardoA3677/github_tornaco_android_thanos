.class public final Llyiahf/vczjk/p81;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gf3;


# instance fields
.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field synthetic L$2:Ljava/lang/Object;

.field synthetic L$3:Ljava/lang/Object;

.field synthetic L$4:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/t81;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t81;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/p81;->this$0:Llyiahf/vczjk/t81;

    const/4 p1, 0x7

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/io/Serializable;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/h43;

    check-cast p2, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    check-cast p3, Ljava/lang/String;

    check-cast p4, Llyiahf/vczjk/y03;

    check-cast p5, Llyiahf/vczjk/yia;

    check-cast p6, Ljava/lang/Number;

    invoke-virtual {p6}, Ljava/lang/Number;->longValue()J

    check-cast p7, Llyiahf/vczjk/yo1;

    new-instance p6, Llyiahf/vczjk/p81;

    iget-object v0, p0, Llyiahf/vczjk/p81;->this$0:Llyiahf/vczjk/t81;

    invoke-direct {p6, v0, p7}, Llyiahf/vczjk/p81;-><init>(Llyiahf/vczjk/t81;Llyiahf/vczjk/yo1;)V

    iput-object p1, p6, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    iput-object p2, p6, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    iput-object p3, p6, Llyiahf/vczjk/p81;->L$2:Ljava/lang/Object;

    iput-object p4, p6, Llyiahf/vczjk/p81;->L$3:Ljava/lang/Object;

    iput-object p5, p6, Llyiahf/vczjk/p81;->L$4:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p6, p1}, Llyiahf/vczjk/p81;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v1, p0

    sget-object v2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, v1, Llyiahf/vczjk/p81;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x4

    const/4 v5, 0x3

    const/4 v6, 0x2

    const/4 v7, 0x1

    const/4 v8, 0x0

    if-eqz v0, :cond_4

    if-eq v0, v7, :cond_3

    if-eq v0, v6, :cond_2

    if-eq v0, v5, :cond_1

    if-ne v0, v4, :cond_0

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_8

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    iget-object v0, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/h43;

    :try_start_0
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto/16 :goto_3

    :catchall_0
    move-exception v0

    goto/16 :goto_5

    :cond_2
    iget-object v0, v1, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/h43;

    iget-object v6, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/h43;

    :try_start_1
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    move-object v11, v0

    move-object/from16 v0, p1

    goto/16 :goto_2

    :catchall_1
    move-exception v0

    move-object v5, v6

    goto/16 :goto_5

    :cond_3
    iget-object v0, v1, Llyiahf/vczjk/p81;->L$4:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yia;

    iget-object v7, v1, Llyiahf/vczjk/p81;->L$3:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/y03;

    iget-object v9, v1, Llyiahf/vczjk/p81;->L$2:Ljava/lang/Object;

    check-cast v9, Ljava/lang/String;

    iget-object v10, v1, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    check-cast v10, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v11, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/h43;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v16, v0

    move-object/from16 v17, v7

    :goto_0
    move-object/from16 v18, v9

    move-object v15, v10

    goto :goto_1

    :cond_4
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v0, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/h43;

    iget-object v9, v1, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    move-object v10, v9

    check-cast v10, Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    iget-object v9, v1, Llyiahf/vczjk/p81;->L$2:Ljava/lang/Object;

    check-cast v9, Ljava/lang/String;

    iget-object v11, v1, Llyiahf/vczjk/p81;->L$3:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/y03;

    iget-object v12, v1, Llyiahf/vczjk/p81;->L$4:Ljava/lang/Object;

    check-cast v12, Llyiahf/vczjk/yia;

    sget-object v13, Llyiahf/vczjk/q7a;->OooO00o:Llyiahf/vczjk/q7a;

    iput-object v0, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    iput-object v10, v1, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    iput-object v9, v1, Llyiahf/vczjk/p81;->L$2:Ljava/lang/Object;

    iput-object v11, v1, Llyiahf/vczjk/p81;->L$3:Ljava/lang/Object;

    iput-object v12, v1, Llyiahf/vczjk/p81;->L$4:Ljava/lang/Object;

    iput v7, v1, Llyiahf/vczjk/p81;->label:I

    invoke-interface {v0, v13, v1}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v2, :cond_5

    goto/16 :goto_7

    :cond_5
    move-object/from16 v17, v11

    move-object/from16 v16, v12

    move-object v11, v0

    goto :goto_0

    :goto_1
    sget-object v0, Llyiahf/vczjk/dx7;->OooO00o:Ljava/util/concurrent/atomic/AtomicBoolean;

    iget-object v0, v1, Llyiahf/vczjk/p81;->this$0:Llyiahf/vczjk/t81;

    iget-object v0, v0, Llyiahf/vczjk/t81;->OooO0O0:Landroid/content/Context;

    invoke-static {v0}, Llyiahf/vczjk/dx7;->OooO00o(Landroid/content/Context;)V

    iget-object v14, v1, Llyiahf/vczjk/p81;->this$0:Llyiahf/vczjk/t81;

    :try_start_2
    iput-object v11, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    iput-object v11, v1, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$2:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$3:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$4:Ljava/lang/Object;

    iput v6, v1, Llyiahf/vczjk/p81;->label:I

    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v0, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v13, Llyiahf/vczjk/r81;

    const/16 v19, 0x0

    invoke-direct/range {v13 .. v19}, Llyiahf/vczjk/r81;-><init>(Llyiahf/vczjk/t81;Lgithub/tornaco/android/thanos/core/pm/AppInfo;Llyiahf/vczjk/yia;Llyiahf/vczjk/y03;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v13, v1}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    if-ne v0, v2, :cond_6

    goto :goto_7

    :cond_6
    move-object v6, v11

    :goto_2
    :try_start_3
    new-instance v7, Llyiahf/vczjk/p7a;

    invoke-direct {v7, v0}, Llyiahf/vczjk/p7a;-><init>(Ljava/lang/Object;)V

    iput-object v6, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    iput v5, v1, Llyiahf/vczjk/p81;->label:I

    invoke-interface {v11, v7, v1}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    if-ne v0, v2, :cond_7

    goto :goto_7

    :cond_7
    move-object v5, v6

    :goto_3
    move-object v0, v3

    goto :goto_6

    :goto_4
    move-object v5, v11

    goto :goto_5

    :catchall_2
    move-exception v0

    goto :goto_4

    :goto_5
    invoke-static {v0}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v0

    :goto_6
    invoke-static {v0}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v6

    if-eqz v6, :cond_8

    new-instance v7, Llyiahf/vczjk/o7a;

    invoke-direct {v7, v6}, Llyiahf/vczjk/o7a;-><init>(Ljava/lang/Throwable;)V

    iput-object v0, v1, Llyiahf/vczjk/p81;->L$0:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$1:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$2:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$3:Ljava/lang/Object;

    iput-object v8, v1, Llyiahf/vczjk/p81;->L$4:Ljava/lang/Object;

    iput v4, v1, Llyiahf/vczjk/p81;->label:I

    invoke-interface {v5, v7, v1}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v2, :cond_8

    :goto_7
    return-object v2

    :cond_8
    :goto_8
    return-object v3
.end method
