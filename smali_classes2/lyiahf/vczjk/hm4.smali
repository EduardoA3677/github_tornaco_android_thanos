.class public final Llyiahf/vczjk/hm4;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $token:Ljava/lang/String;

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hm4;->$token:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/hm4;

    iget-object v1, p0, Llyiahf/vczjk/hm4;->$token:Ljava/lang/String;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/hm4;-><init>(Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/hm4;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/uc9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/hm4;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hm4;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/hm4;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/hm4;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v4, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/hm4;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/uc9;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/hm4;->L$0:Ljava/lang/Object;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/uc9;

    sget-object p1, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    iget-object p1, p0, Llyiahf/vczjk/hm4;->$token:Ljava/lang/String;

    new-instance v5, Llyiahf/vczjk/kf0;

    const/4 v6, 0x3

    invoke-direct {v5, p1, v6}, Llyiahf/vczjk/kf0;-><init>(Ljava/lang/String;I)V

    iput-object v1, p0, Llyiahf/vczjk/hm4;->L$0:Ljava/lang/Object;

    iput v4, p0, Llyiahf/vczjk/hm4;->label:I

    iget-object p1, v1, Llyiahf/vczjk/uc9;->OooO00o:Llyiahf/vczjk/tl1;

    iget-object p1, p1, Llyiahf/vczjk/tl1;->OooO0OO:Llyiahf/vczjk/zh7;

    new-instance v6, Llyiahf/vczjk/tc9;

    invoke-direct {v6, v5}, Llyiahf/vczjk/tc9;-><init>(Llyiahf/vczjk/oe3;)V

    invoke-virtual {p1, v6, p0}, Llyiahf/vczjk/zh7;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    if-ne v2, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    new-instance p1, Llyiahf/vczjk/am4;

    new-instance v5, Llyiahf/vczjk/cm4;

    iget-object v6, p0, Llyiahf/vczjk/hm4;->$token:Ljava/lang/String;

    invoke-direct {v5, v6, v4, v4}, Llyiahf/vczjk/cm4;-><init>(Ljava/lang/String;ZZ)V

    invoke-direct {p1, v5}, Llyiahf/vczjk/am4;-><init>(Llyiahf/vczjk/cm4;)V

    const/4 v4, 0x0

    iput-object v4, p0, Llyiahf/vczjk/hm4;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/hm4;->label:I

    invoke-virtual {v1, p1, p0}, Llyiahf/vczjk/uc9;->OooO00o(Llyiahf/vczjk/bm4;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    :goto_2
    return-object v2
.end method
