.class public final Llyiahf/vczjk/km4;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $activeDialog:Llyiahf/vczjk/zh1;

.field final synthetic $subscribeDialogState:Llyiahf/vczjk/yo9;

.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo9;Llyiahf/vczjk/zh1;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/km4;->$subscribeDialogState:Llyiahf/vczjk/yo9;

    iput-object p2, p0, Llyiahf/vczjk/km4;->$activeDialog:Llyiahf/vczjk/zh1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/km4;

    iget-object v1, p0, Llyiahf/vczjk/km4;->$subscribeDialogState:Llyiahf/vczjk/yo9;

    iget-object v2, p0, Llyiahf/vczjk/km4;->$activeDialog:Llyiahf/vczjk/zh1;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/km4;-><init>(Llyiahf/vczjk/yo9;Llyiahf/vczjk/zh1;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/km4;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/bm4;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/km4;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/km4;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/km4;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/km4;->label:I

    if-nez v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/km4;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/bm4;

    sget-object v0, Llyiahf/vczjk/yl4;->OooO00o:Llyiahf/vczjk/yl4;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x1

    if-eqz v0, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/km4;->$subscribeDialogState:Llyiahf/vczjk/yo9;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    goto :goto_0

    :cond_0
    instance-of v0, p1, Llyiahf/vczjk/am4;

    if-nez v0, :cond_2

    sget-object v0, Llyiahf/vczjk/zl4;->OooO00o:Llyiahf/vczjk/zl4;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/km4;->$activeDialog:Llyiahf/vczjk/zh1;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    goto :goto_0

    :cond_1
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_2
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
