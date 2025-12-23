.class public final Llyiahf/vczjk/a65;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $observer:Llyiahf/vczjk/bi9;

.field final synthetic $this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/a65;->$this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

    iput-object p2, p0, Llyiahf/vczjk/a65;->$observer:Llyiahf/vczjk/bi9;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/a65;

    iget-object v0, p0, Llyiahf/vczjk/a65;->$this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

    iget-object v1, p0, Llyiahf/vczjk/a65;->$observer:Llyiahf/vczjk/bi9;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/a65;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/a65;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/a65;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/a65;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/a65;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/a65;->$this_detectDownAndDragGesturesWithObserver:Llyiahf/vczjk/oy6;

    iget-object v1, p0, Llyiahf/vczjk/a65;->$observer:Llyiahf/vczjk/bi9;

    iput v3, p0, Llyiahf/vczjk/a65;->label:I

    new-instance v3, Llyiahf/vczjk/c65;

    invoke-direct {v3, v1}, Llyiahf/vczjk/c65;-><init>(Llyiahf/vczjk/bi9;)V

    new-instance v4, Llyiahf/vczjk/d65;

    invoke-direct {v4, v1}, Llyiahf/vczjk/d65;-><init>(Llyiahf/vczjk/bi9;)V

    new-instance v11, Llyiahf/vczjk/e65;

    invoke-direct {v11, v1}, Llyiahf/vczjk/e65;-><init>(Llyiahf/vczjk/bi9;)V

    new-instance v10, Llyiahf/vczjk/f65;

    invoke-direct {v10, v1}, Llyiahf/vczjk/f65;-><init>(Llyiahf/vczjk/bi9;)V

    sget v1, Llyiahf/vczjk/ve2;->OooO00o:F

    new-instance v9, Llyiahf/vczjk/re2;

    invoke-direct {v9, v3}, Llyiahf/vczjk/re2;-><init>(Llyiahf/vczjk/c65;)V

    new-instance v12, Llyiahf/vczjk/se2;

    invoke-direct {v12, v4}, Llyiahf/vczjk/se2;-><init>(Llyiahf/vczjk/d65;)V

    sget-object v6, Llyiahf/vczjk/zg1;->Oooo0:Llyiahf/vczjk/zg1;

    new-instance v7, Llyiahf/vczjk/gl7;

    invoke-direct {v7}, Ljava/lang/Object;-><init>()V

    new-instance v5, Llyiahf/vczjk/te2;

    const/4 v13, 0x0

    const/4 v8, 0x0

    invoke-direct/range {v5 .. v13}, Llyiahf/vczjk/te2;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/gl7;Llyiahf/vczjk/nf6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v5, p0}, Llyiahf/vczjk/u34;->OooO0o0(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_4

    goto :goto_2

    :cond_4
    move-object p1, v2

    :goto_2
    if-ne p1, v0, :cond_5

    return-object v0

    :cond_5
    return-object v2
.end method
