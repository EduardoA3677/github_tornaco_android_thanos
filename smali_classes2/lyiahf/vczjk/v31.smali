.class public final Llyiahf/vczjk/v31;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $arrayFactory:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $flows:[Llyiahf/vczjk/f43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "[",
            "Llyiahf/vczjk/f43;"
        }
    .end annotation
.end field

.field final synthetic $this_combineInternal:Llyiahf/vczjk/h43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h43;"
        }
    .end annotation
.end field

.field final synthetic $transform:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field I$0:I

.field I$1:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/le3;Llyiahf/vczjk/bf3;[Llyiahf/vczjk/f43;)V
    .locals 0

    iput-object p5, p0, Llyiahf/vczjk/v31;->$flows:[Llyiahf/vczjk/f43;

    iput-object p3, p0, Llyiahf/vczjk/v31;->$arrayFactory:Llyiahf/vczjk/le3;

    iput-object p4, p0, Llyiahf/vczjk/v31;->$transform:Llyiahf/vczjk/bf3;

    iput-object p2, p0, Llyiahf/vczjk/v31;->$this_combineInternal:Llyiahf/vczjk/h43;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/v31;

    iget-object v5, p0, Llyiahf/vczjk/v31;->$flows:[Llyiahf/vczjk/f43;

    iget-object v3, p0, Llyiahf/vczjk/v31;->$arrayFactory:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/v31;->$transform:Llyiahf/vczjk/bf3;

    iget-object v2, p0, Llyiahf/vczjk/v31;->$this_combineInternal:Llyiahf/vczjk/h43;

    move-object v1, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/v31;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/le3;Llyiahf/vczjk/bf3;[Llyiahf/vczjk/f43;)V

    iput-object p1, v0, Llyiahf/vczjk/v31;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/v31;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/v31;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/v31;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/v31;->label:I

    sget-object v3, Llyiahf/vczjk/bua;->OooO0o0:Llyiahf/vczjk/h87;

    sget-object v4, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v5, 0x1

    const/4 v6, 0x3

    const/4 v7, 0x0

    const/4 v8, 0x2

    if-eqz v2, :cond_3

    if-eq v2, v5, :cond_2

    if-eq v2, v8, :cond_1

    if-ne v2, v6, :cond_0

    goto :goto_0

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    :goto_0
    iget v2, v0, Llyiahf/vczjk/v31;->I$1:I

    iget v9, v0, Llyiahf/vczjk/v31;->I$0:I

    iget-object v10, v0, Llyiahf/vczjk/v31;->L$2:Ljava/lang/Object;

    check-cast v10, [B

    iget-object v11, v0, Llyiahf/vczjk/v31;->L$1:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/rs0;

    iget-object v12, v0, Llyiahf/vczjk/v31;->L$0:Ljava/lang/Object;

    check-cast v12, [Ljava/lang/Object;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v19, v12

    move v12, v2

    move-object v2, v10

    move-object/from16 v10, v19

    goto :goto_2

    :cond_2
    iget v2, v0, Llyiahf/vczjk/v31;->I$1:I

    iget v9, v0, Llyiahf/vczjk/v31;->I$0:I

    iget-object v10, v0, Llyiahf/vczjk/v31;->L$2:Ljava/lang/Object;

    check-cast v10, [B

    iget-object v11, v0, Llyiahf/vczjk/v31;->L$1:Ljava/lang/Object;

    check-cast v11, Llyiahf/vczjk/rs0;

    iget-object v12, v0, Llyiahf/vczjk/v31;->L$0:Ljava/lang/Object;

    check-cast v12, [Ljava/lang/Object;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v13, p1

    check-cast v13, Llyiahf/vczjk/jt0;

    iget-object v13, v13, Llyiahf/vczjk/jt0;->OooO00o:Ljava/lang/Object;

    move-object/from16 v19, v12

    move v12, v2

    move-object v2, v10

    move-object/from16 v10, v19

    goto :goto_3

    :cond_3
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/v31;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/xr1;

    iget-object v9, v0, Llyiahf/vczjk/v31;->$flows:[Llyiahf/vczjk/f43;

    array-length v9, v9

    if-nez v9, :cond_4

    goto :goto_4

    :cond_4
    new-array v10, v9, [Ljava/lang/Object;

    invoke-static {v10, v3, v7, v9}, Llyiahf/vczjk/sy;->o0ooOoO([Ljava/lang/Object;Llyiahf/vczjk/h87;II)V

    const/4 v11, 0x6

    const/4 v12, 0x0

    invoke-static {v9, v11, v12}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v17

    new-instance v11, Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-direct {v11, v9}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    move v15, v7

    :goto_1
    if-ge v15, v9, :cond_5

    new-instance v13, Llyiahf/vczjk/u31;

    iget-object v14, v0, Llyiahf/vczjk/v31;->$flows:[Llyiahf/vczjk/f43;

    const/16 v18, 0x0

    move-object/from16 v16, v11

    invoke-direct/range {v13 .. v18}, Llyiahf/vczjk/u31;-><init>([Llyiahf/vczjk/f43;ILjava/util/concurrent/atomic/AtomicInteger;Llyiahf/vczjk/rs0;Llyiahf/vczjk/yo1;)V

    invoke-static {v2, v12, v12, v13, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    add-int/lit8 v15, v15, 0x1

    goto :goto_1

    :cond_5
    new-array v2, v9, [B

    move v12, v7

    move-object/from16 v11, v17

    :cond_6
    :goto_2
    add-int/2addr v12, v5

    int-to-byte v12, v12

    iput-object v10, v0, Llyiahf/vczjk/v31;->L$0:Ljava/lang/Object;

    iput-object v11, v0, Llyiahf/vczjk/v31;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/v31;->L$2:Ljava/lang/Object;

    iput v9, v0, Llyiahf/vczjk/v31;->I$0:I

    iput v12, v0, Llyiahf/vczjk/v31;->I$1:I

    iput v5, v0, Llyiahf/vczjk/v31;->label:I

    invoke-interface {v11, v0}, Llyiahf/vczjk/ui7;->OooO(Llyiahf/vczjk/v31;)Ljava/lang/Object;

    move-result-object v13

    if-ne v13, v1, :cond_7

    goto :goto_5

    :cond_7
    :goto_3
    invoke-static {v13}, Llyiahf/vczjk/jt0;->OooO00o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/kx3;

    if-nez v13, :cond_8

    :goto_4
    return-object v4

    :cond_8
    iget v14, v13, Llyiahf/vczjk/kx3;->OooO00o:I

    aget-object v15, v10, v14

    iget-object v13, v13, Llyiahf/vczjk/kx3;->OooO0O0:Ljava/lang/Object;

    aput-object v13, v10, v14

    if-ne v15, v3, :cond_9

    add-int/lit8 v9, v9, -0x1

    :cond_9
    aget-byte v13, v2, v14

    if-eq v13, v12, :cond_a

    int-to-byte v13, v12

    aput-byte v13, v2, v14

    invoke-interface {v11}, Llyiahf/vczjk/ui7;->OooO0OO()Ljava/lang/Object;

    move-result-object v13

    invoke-static {v13}, Llyiahf/vczjk/jt0;->OooO00o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v13

    check-cast v13, Llyiahf/vczjk/kx3;

    if-nez v13, :cond_8

    :cond_a
    if-nez v9, :cond_6

    iget-object v13, v0, Llyiahf/vczjk/v31;->$arrayFactory:Llyiahf/vczjk/le3;

    invoke-interface {v13}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v13

    check-cast v13, [Ljava/lang/Object;

    if-nez v13, :cond_b

    iget-object v13, v0, Llyiahf/vczjk/v31;->$transform:Llyiahf/vczjk/bf3;

    iget-object v14, v0, Llyiahf/vczjk/v31;->$this_combineInternal:Llyiahf/vczjk/h43;

    iput-object v10, v0, Llyiahf/vczjk/v31;->L$0:Ljava/lang/Object;

    iput-object v11, v0, Llyiahf/vczjk/v31;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/v31;->L$2:Ljava/lang/Object;

    iput v9, v0, Llyiahf/vczjk/v31;->I$0:I

    iput v12, v0, Llyiahf/vczjk/v31;->I$1:I

    iput v8, v0, Llyiahf/vczjk/v31;->label:I

    invoke-interface {v13, v14, v10, v0}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v13

    if-ne v13, v1, :cond_6

    goto :goto_5

    :cond_b
    const/16 v14, 0xe

    invoke-static {v7, v7, v10, v14, v13}, Llyiahf/vczjk/sy;->oo000o(II[Ljava/lang/Object;I[Ljava/lang/Object;)V

    iget-object v14, v0, Llyiahf/vczjk/v31;->$transform:Llyiahf/vczjk/bf3;

    iget-object v15, v0, Llyiahf/vczjk/v31;->$this_combineInternal:Llyiahf/vczjk/h43;

    iput-object v10, v0, Llyiahf/vczjk/v31;->L$0:Ljava/lang/Object;

    iput-object v11, v0, Llyiahf/vczjk/v31;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/v31;->L$2:Ljava/lang/Object;

    iput v9, v0, Llyiahf/vczjk/v31;->I$0:I

    iput v12, v0, Llyiahf/vczjk/v31;->I$1:I

    iput v6, v0, Llyiahf/vczjk/v31;->label:I

    invoke-interface {v14, v15, v13, v0}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v13

    if-ne v13, v1, :cond_6

    :goto_5
    return-object v1
.end method
