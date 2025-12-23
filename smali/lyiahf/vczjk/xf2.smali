.class public final Llyiahf/vczjk/xf2;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $startedPosition:J

.field private synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/zf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zf2;JLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xf2;->this$0:Llyiahf/vczjk/zf2;

    iput-wide p2, p0, Llyiahf/vczjk/xf2;->$startedPosition:J

    const/4 p1, 0x2

    invoke-direct {p0, p1, p4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/xf2;

    iget-object v1, p0, Llyiahf/vczjk/xf2;->this$0:Llyiahf/vczjk/zf2;

    iget-wide v2, p0, Llyiahf/vczjk/xf2;->$startedPosition:J

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/xf2;-><init>(Llyiahf/vczjk/zf2;JLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/xf2;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/xf2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/xf2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/xf2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/xf2;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/xf2;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object p1, p0, Llyiahf/vczjk/xf2;->this$0:Llyiahf/vczjk/zf2;

    iget-object p1, p1, Llyiahf/vczjk/zf2;->Oooo0oO:Llyiahf/vczjk/rf2;

    iput v3, p0, Llyiahf/vczjk/xf2;->label:I

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p1, Llyiahf/vczjk/rf2;

    const/4 v1, 0x3

    invoke-direct {p1, v1, p0}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {p1, v2}, Llyiahf/vczjk/rf2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    if-ne v2, v0, :cond_2

    return-object v0

    :cond_2
    :goto_0
    return-object v2
.end method
