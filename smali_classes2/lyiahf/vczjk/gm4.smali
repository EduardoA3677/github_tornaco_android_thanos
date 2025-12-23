.class public final Llyiahf/vczjk/gm4;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $reason:Ljava/lang/String;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gm4;->$reason:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/gm4;

    iget-object v1, p0, Llyiahf/vczjk/gm4;->$reason:Ljava/lang/String;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/gm4;-><init>(Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/gm4;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/uc9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/gm4;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/gm4;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/gm4;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    const/4 v0, 0x1

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, p0, Llyiahf/vczjk/gm4;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x2

    if-eqz v2, :cond_2

    if-eq v2, v0, :cond_1

    if-ne v2, v4, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v2, p0, Llyiahf/vczjk/gm4;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/uc9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/gm4;->L$0:Ljava/lang/Object;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/uc9;

    sget-object p1, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    new-instance p1, Llyiahf/vczjk/rt3;

    invoke-direct {p1, v0}, Llyiahf/vczjk/rt3;-><init>(I)V

    iput-object v2, p0, Llyiahf/vczjk/gm4;->L$0:Ljava/lang/Object;

    iput v0, p0, Llyiahf/vczjk/gm4;->label:I

    iget-object v5, v2, Llyiahf/vczjk/uc9;->OooO00o:Llyiahf/vczjk/tl1;

    iget-object v5, v5, Llyiahf/vczjk/tl1;->OooO0OO:Llyiahf/vczjk/zh7;

    new-instance v6, Llyiahf/vczjk/tc9;

    invoke-direct {v6, p1}, Llyiahf/vczjk/tc9;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-virtual {v5, v6, p0}, Llyiahf/vczjk/zh7;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    if-ne v3, v1, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    new-instance p1, Llyiahf/vczjk/am4;

    new-instance v5, Llyiahf/vczjk/cm4;

    const/4 v6, 0x0

    const/4 v7, 0x0

    invoke-direct {v5, v7, v6, v0}, Llyiahf/vczjk/cm4;-><init>(Ljava/lang/String;ZZ)V

    invoke-direct {p1, v5}, Llyiahf/vczjk/am4;-><init>(Llyiahf/vczjk/cm4;)V

    iput-object v7, p0, Llyiahf/vczjk/gm4;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/gm4;->label:I

    invoke-virtual {v2, p1, p0}, Llyiahf/vczjk/uc9;->OooO00o(Llyiahf/vczjk/bm4;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_4

    :goto_1
    return-object v1

    :cond_4
    :goto_2
    return-object v3
.end method
