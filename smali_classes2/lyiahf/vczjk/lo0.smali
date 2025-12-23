.class public final Llyiahf/vczjk/lo0;
.super Llyiahf/vczjk/vs0;
.source "SourceFile"


# instance fields
.field public final OooOOOo:Llyiahf/vczjk/eb9;

.field public final OooOOo0:Llyiahf/vczjk/eb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V
    .locals 0

    invoke-direct {p0, p2, p3, p4}, Llyiahf/vczjk/vs0;-><init>(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V

    check-cast p1, Llyiahf/vczjk/eb9;

    iput-object p1, p0, Llyiahf/vczjk/lo0;->OooOOOo:Llyiahf/vczjk/eb9;

    iput-object p1, p0, Llyiahf/vczjk/lo0;->OooOOo0:Llyiahf/vczjk/eb9;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/s77;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/ko0;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/ko0;

    iget v1, v0, Llyiahf/vczjk/ko0;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ko0;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ko0;

    check-cast p2, Llyiahf/vczjk/zo1;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/ko0;-><init>(Llyiahf/vczjk/lo0;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/ko0;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ko0;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v4, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/ko0;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/s77;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput-object p1, v0, Llyiahf/vczjk/ko0;->L$0:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/ko0;->label:I

    iget-object p2, p0, Llyiahf/vczjk/lo0;->OooOOOo:Llyiahf/vczjk/eb9;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_3

    goto :goto_1

    :cond_3
    move-object p2, v3

    :goto_1
    if-ne p2, v1, :cond_4

    return-object v1

    :cond_4
    :goto_2
    check-cast p1, Llyiahf/vczjk/r77;

    iget-object p1, p1, Llyiahf/vczjk/r77;->OooOOOo:Llyiahf/vczjk/jj0;

    invoke-virtual {p1}, Llyiahf/vczjk/jj0;->OooOoO0()Z

    move-result p1

    if-eqz p1, :cond_5

    return-object v3

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "\'awaitClose { yourCallbackOrListener.cancel() }\' should be used in the end of callbackFlow block.\nOtherwise, a callback/listener may leak in case of external cancellation.\nSee callbackFlow API documentation for the details."

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/vs0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/lo0;

    iget-object v1, p0, Llyiahf/vczjk/lo0;->OooOOo0:Llyiahf/vczjk/eb9;

    invoke-direct {v0, v1, p1, p2, p3}, Llyiahf/vczjk/lo0;-><init>(Llyiahf/vczjk/ze3;Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "block["

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/lo0;->OooOOOo:Llyiahf/vczjk/eb9;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "] -> "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-super {p0}, Llyiahf/vczjk/vs0;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
