.class public final Llyiahf/vczjk/lv1;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $block$inlined:Llyiahf/vczjk/oe3;

.field final synthetic $db$inlined:Llyiahf/vczjk/ru7;

.field final synthetic $inTransaction$inlined:Z

.field final synthetic $isReadOnly$inlined:Z

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ru7;ZZ)V
    .locals 0

    iput-object p3, p0, Llyiahf/vczjk/lv1;->$db$inlined:Llyiahf/vczjk/ru7;

    iput-boolean p4, p0, Llyiahf/vczjk/lv1;->$isReadOnly$inlined:Z

    iput-boolean p5, p0, Llyiahf/vczjk/lv1;->$inTransaction$inlined:Z

    iput-object p2, p0, Llyiahf/vczjk/lv1;->$block$inlined:Llyiahf/vczjk/oe3;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/lv1;

    iget-object v3, p0, Llyiahf/vczjk/lv1;->$db$inlined:Llyiahf/vczjk/ru7;

    iget-boolean v4, p0, Llyiahf/vczjk/lv1;->$isReadOnly$inlined:Z

    iget-boolean v5, p0, Llyiahf/vczjk/lv1;->$inTransaction$inlined:Z

    iget-object v2, p0, Llyiahf/vczjk/lv1;->$block$inlined:Llyiahf/vczjk/oe3;

    move-object v1, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/lv1;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ru7;ZZ)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/lv1;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/lv1;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/lv1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/lv1;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v6, p0, Llyiahf/vczjk/lv1;->$db$inlined:Llyiahf/vczjk/ru7;

    iget-boolean v8, p0, Llyiahf/vczjk/lv1;->$isReadOnly$inlined:Z

    new-instance v3, Llyiahf/vczjk/ov1;

    iget-boolean v7, p0, Llyiahf/vczjk/lv1;->$inTransaction$inlined:Z

    const/4 v4, 0x0

    iget-object v5, p0, Llyiahf/vczjk/lv1;->$block$inlined:Llyiahf/vczjk/oe3;

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/ov1;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;Llyiahf/vczjk/ru7;ZZ)V

    iput v2, p0, Llyiahf/vczjk/lv1;->label:I

    invoke-virtual {v6, v8, v3, p0}, Llyiahf/vczjk/ru7;->useConnection$room_runtime_release(ZLlyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    return-object v0

    :cond_2
    return-object p1
.end method
