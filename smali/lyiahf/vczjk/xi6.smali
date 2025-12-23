.class public final Llyiahf/vczjk/xi6;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $loadType:Llyiahf/vczjk/s25;

.field synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/s25;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xi6;->$loadType:Llyiahf/vczjk/s25;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/xg3;

    check-cast p2, Llyiahf/vczjk/xg3;

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/xi6;

    iget-object v1, p0, Llyiahf/vczjk/xi6;->$loadType:Llyiahf/vczjk/s25;

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/xi6;-><init>(Llyiahf/vczjk/s25;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/xi6;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/xi6;->L$1:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xi6;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/xi6;->label:I

    if-nez v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/xi6;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xg3;

    iget-object v0, p0, Llyiahf/vczjk/xi6;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xg3;

    iget-object v1, p0, Llyiahf/vczjk/xi6;->$loadType:Llyiahf/vczjk/s25;

    const-string v2, "<this>"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "previous"

    invoke-static {p1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "loadType"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget v2, v0, Llyiahf/vczjk/xg3;->OooO00o:I

    iget v3, p1, Llyiahf/vczjk/xg3;->OooO00o:I

    if-le v2, v3, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    if-ge v2, v3, :cond_1

    const/4 v1, 0x0

    goto :goto_0

    :cond_1
    iget-object v2, v0, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    iget-object v3, p1, Llyiahf/vczjk/xg3;->OooO0O0:Llyiahf/vczjk/oja;

    invoke-static {v2, v3, v1}, Llyiahf/vczjk/yi4;->o0ooOoO(Llyiahf/vczjk/oja;Llyiahf/vczjk/oja;Llyiahf/vczjk/s25;)Z

    move-result v1

    :goto_0
    if-eqz v1, :cond_2

    return-object v0

    :cond_2
    return-object p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
