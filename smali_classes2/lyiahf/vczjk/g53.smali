.class public final Llyiahf/vczjk/g53;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $this_debounceInternal:Llyiahf/vczjk/f43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/f43;"
        }
    .end annotation
.end field

.field final synthetic $timeoutMillisSelector:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field L$2:Ljava/lang/Object;

.field L$3:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/g53;->$timeoutMillisSelector:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/g53;->$this_debounceInternal:Llyiahf/vczjk/f43;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/h43;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/g53;

    iget-object v1, p0, Llyiahf/vczjk/g53;->$timeoutMillisSelector:Llyiahf/vczjk/oe3;

    iget-object v2, p0, Llyiahf/vczjk/g53;->$this_debounceInternal:Llyiahf/vczjk/f43;

    invoke-direct {v0, v1, v2, p3}, Llyiahf/vczjk/g53;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/g53;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/g53;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g53;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/g53;->label:I

    const/4 v3, 0x0

    const/4 v4, 0x2

    const/4 v5, 0x1

    const/4 v6, 0x0

    if-eqz v2, :cond_3

    if-eq v2, v5, :cond_2

    if-ne v2, v4, :cond_1

    iget-object v2, v0, Llyiahf/vczjk/g53;->L$2:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/hl7;

    iget-object v7, v0, Llyiahf/vczjk/g53;->L$1:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/ui7;

    iget-object v8, v0, Llyiahf/vczjk/g53;->L$0:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/h43;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :cond_0
    move-object v9, v8

    move-object v8, v7

    goto :goto_0

    :cond_1
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_2
    iget-object v2, v0, Llyiahf/vczjk/g53;->L$3:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/gl7;

    iget-object v7, v0, Llyiahf/vczjk/g53;->L$2:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/hl7;

    iget-object v8, v0, Llyiahf/vczjk/g53;->L$1:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/ui7;

    iget-object v9, v0, Llyiahf/vczjk/g53;->L$0:Ljava/lang/Object;

    check-cast v9, Llyiahf/vczjk/h43;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_1

    :cond_3
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/g53;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/xr1;

    iget-object v7, v0, Llyiahf/vczjk/g53;->L$1:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/h43;

    new-instance v8, Llyiahf/vczjk/f53;

    iget-object v9, v0, Llyiahf/vczjk/g53;->$this_debounceInternal:Llyiahf/vczjk/f43;

    invoke-direct {v8, v9, v6}, Llyiahf/vczjk/f53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/yo1;)V

    sget-object v9, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    sget-object v10, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    sget-object v11, Llyiahf/vczjk/as1;->OooOOO0:Llyiahf/vczjk/as1;

    const/4 v12, 0x4

    invoke-static {v3, v12, v10}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v10

    invoke-static {v2, v9}, Llyiahf/vczjk/t51;->Oooo(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v2

    new-instance v9, Llyiahf/vczjk/r77;

    invoke-direct {v9, v2, v10}, Llyiahf/vczjk/r77;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/jj0;)V

    invoke-virtual {v9, v11, v9, v8}, Llyiahf/vczjk/o000O000;->Oooooo(Llyiahf/vczjk/as1;Llyiahf/vczjk/o000O000;Llyiahf/vczjk/ze3;)V

    new-instance v2, Llyiahf/vczjk/hl7;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    move-object v8, v9

    move-object v9, v7

    :goto_0
    move-object v7, v2

    iget-object v2, v7, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object v10, Llyiahf/vczjk/bua;->OooO0o:Llyiahf/vczjk/h87;

    if-eq v2, v10, :cond_b

    new-instance v10, Llyiahf/vczjk/gl7;

    invoke-direct {v10}, Ljava/lang/Object;-><init>()V

    if-eqz v2, :cond_7

    iget-object v11, v0, Llyiahf/vczjk/g53;->$timeoutMillisSelector:Llyiahf/vczjk/oe3;

    sget-object v12, Llyiahf/vczjk/bua;->OooO0Oo:Llyiahf/vczjk/h87;

    if-ne v2, v12, :cond_4

    move-object v2, v6

    :cond_4
    invoke-interface {v11, v2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->longValue()J

    move-result-wide v13

    iput-wide v13, v10, Llyiahf/vczjk/gl7;->element:J

    const-wide/16 v15, 0x0

    cmp-long v2, v13, v15

    if-ltz v2, :cond_8

    if-nez v2, :cond_7

    iget-object v2, v7, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-ne v2, v12, :cond_5

    move-object v2, v6

    :cond_5
    iput-object v9, v0, Llyiahf/vczjk/g53;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/g53;->L$1:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/g53;->L$2:Ljava/lang/Object;

    iput-object v10, v0, Llyiahf/vczjk/g53;->L$3:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/g53;->label:I

    invoke-interface {v9, v2, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_6

    goto/16 :goto_4

    :cond_6
    move-object v2, v10

    :goto_1
    iput-object v6, v7, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    move-object v10, v2

    :cond_7
    move-object v2, v7

    move-object v7, v8

    move-object v8, v9

    goto :goto_2

    :cond_8
    new-instance v1, Ljava/lang/IllegalArgumentException;

    const-string v2, "Debounce timeout should not be negative"

    invoke-direct {v1, v2}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v1

    :goto_2
    new-instance v12, Llyiahf/vczjk/gd8;

    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v9

    invoke-direct {v12, v9}, Llyiahf/vczjk/gd8;-><init>(Llyiahf/vczjk/or1;)V

    iget-object v9, v2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-eqz v9, :cond_9

    iget-wide v9, v10, Llyiahf/vczjk/gl7;->element:J

    new-instance v11, Llyiahf/vczjk/b53;

    invoke-direct {v11, v6, v8, v2}, Llyiahf/vczjk/b53;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/hl7;)V

    new-instance v13, Llyiahf/vczjk/gb6;

    invoke-direct {v13, v9, v10}, Llyiahf/vczjk/gb6;-><init>(J)V

    sget-object v14, Llyiahf/vczjk/fb6;->OooOOO:Llyiahf/vczjk/fb6;

    const/4 v9, 0x3

    invoke-static {v9, v14}, Llyiahf/vczjk/l4a;->OooOO0(ILjava/lang/Object;)Ljava/lang/Object;

    sget-object v15, Llyiahf/vczjk/tb1;->Oooo:Llyiahf/vczjk/tb1;

    move-object/from16 v17, v11

    new-instance v11, Llyiahf/vczjk/ed8;

    sget-object v16, Llyiahf/vczjk/c6a;->OooOoo0:Llyiahf/vczjk/h87;

    const/16 v18, 0x0

    invoke-direct/range {v11 .. v18}, Llyiahf/vczjk/ed8;-><init>(Llyiahf/vczjk/gd8;Ljava/lang/Object;Llyiahf/vczjk/bf3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/h87;Llyiahf/vczjk/eb9;Llyiahf/vczjk/dj0;)V

    invoke-virtual {v12, v11, v3}, Llyiahf/vczjk/gd8;->OooO0o(Llyiahf/vczjk/ed8;Z)V

    :cond_9
    invoke-interface {v7}, Llyiahf/vczjk/ui7;->OooO0O0()Llyiahf/vczjk/bh6;

    move-result-object v9

    new-instance v10, Llyiahf/vczjk/c53;

    invoke-direct {v10, v6, v8, v2}, Llyiahf/vczjk/c53;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/hl7;)V

    new-instance v11, Llyiahf/vczjk/ed8;

    iget-object v9, v9, Llyiahf/vczjk/bh6;->OooOOO0:Ljava/lang/Object;

    move-object v13, v9

    check-cast v13, Llyiahf/vczjk/jj0;

    sget-object v14, Llyiahf/vczjk/fj0;->OooOOO:Llyiahf/vczjk/fj0;

    sget-object v15, Llyiahf/vczjk/gj0;->OooOOO:Llyiahf/vczjk/gj0;

    const/16 v16, 0x0

    const/16 v18, 0x0

    move-object/from16 v17, v10

    invoke-direct/range {v11 .. v18}, Llyiahf/vczjk/ed8;-><init>(Llyiahf/vczjk/gd8;Ljava/lang/Object;Llyiahf/vczjk/bf3;Llyiahf/vczjk/bf3;Llyiahf/vczjk/h87;Llyiahf/vczjk/eb9;Llyiahf/vczjk/dj0;)V

    invoke-virtual {v12, v11, v3}, Llyiahf/vczjk/gd8;->OooO0o(Llyiahf/vczjk/ed8;Z)V

    iput-object v8, v0, Llyiahf/vczjk/g53;->L$0:Ljava/lang/Object;

    iput-object v7, v0, Llyiahf/vczjk/g53;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/g53;->L$2:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/g53;->L$3:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/g53;->label:I

    sget-object v9, Llyiahf/vczjk/gd8;->OooOOo:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    invoke-virtual {v9, v12}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v9

    instance-of v9, v9, Llyiahf/vczjk/ed8;

    if-eqz v9, :cond_a

    invoke-virtual {v12, v0}, Llyiahf/vczjk/gd8;->OooO0OO(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v9

    goto :goto_3

    :cond_a
    invoke-virtual {v12, v0}, Llyiahf/vczjk/gd8;->OooO0Oo(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v9

    :goto_3
    if-ne v9, v1, :cond_0

    :goto_4
    return-object v1

    :cond_b
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
