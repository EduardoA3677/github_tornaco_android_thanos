.class public final Llyiahf/vczjk/em4;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/em4;

    const/4 v0, 0x2

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/em4;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/em4;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/em4;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/em4;->label:I

    if-nez v0, :cond_3

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    new-instance v0, Llyiahf/vczjk/gm4;

    const-string v1, "init."

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/gm4;-><init>(Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v0}, Llyiahf/vczjk/dn8;->o0OoOo0(Llyiahf/vczjk/im4;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/v74;

    invoke-static {}, Lcom/tencent/mmkv/MMKV;->OooO0Oo()Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    const-string v1, "39M5DC32-B17D-4370-AB98-A9L809256685"

    invoke-virtual {v0, v1}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-static {v0}, Lcom/tencent/mmkv/MMKV;->OooO(Ljava/lang/String;)Lcom/tencent/mmkv/MMKV;

    move-result-object v0

    invoke-static {}, Llyiahf/vczjk/m6a;->o0000oO()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Lcom/tencent/mmkv/MMKV;->OooO0OO(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    sget v1, Llyiahf/vczjk/xl4;->OooO00o:I

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v1, Llyiahf/vczjk/hm4;

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/hm4;-><init>(Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v1}, Llyiahf/vczjk/dn8;->o0OoOo0(Llyiahf/vczjk/im4;Llyiahf/vczjk/ze3;)Llyiahf/vczjk/v74;

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_2
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Required value was null."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_3
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
