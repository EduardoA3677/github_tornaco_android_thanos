.class public final Llyiahf/vczjk/d00;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field synthetic L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/j00;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/j00;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d00;->this$0:Llyiahf/vczjk/j00;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/d00;

    iget-object v1, p0, Llyiahf/vczjk/d00;->this$0:Llyiahf/vczjk/j00;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/d00;-><init>(Llyiahf/vczjk/j00;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/d00;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kv3;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/d00;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/d00;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/d00;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/d00;->label:I

    const/4 v2, 0x0

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/d00;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j00;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/d00;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kv3;

    iget-object v1, p0, Llyiahf/vczjk/d00;->this$0:Llyiahf/vczjk/j00;

    iget-object v4, v1, Llyiahf/vczjk/j00;->Oooo000:Llyiahf/vczjk/qs5;

    check-cast v4, Llyiahf/vczjk/fw8;

    invoke-virtual {v4}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/fv3;

    iget-object v5, p0, Llyiahf/vczjk/d00;->this$0:Llyiahf/vczjk/j00;

    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/kv3;->OooO00o(Llyiahf/vczjk/kv3;)Llyiahf/vczjk/jv3;

    move-result-object v6

    new-instance v7, Llyiahf/vczjk/vz5;

    const/4 v8, 0x6

    invoke-direct {v7, v5, v8}, Llyiahf/vczjk/vz5;-><init>(Ljava/lang/Object;I)V

    iput-object v7, v6, Llyiahf/vczjk/jv3;->OooO0Oo:Llyiahf/vczjk/eg9;

    invoke-virtual {v6}, Llyiahf/vczjk/jv3;->OooO0O0()V

    iget-object p1, p1, Llyiahf/vczjk/kv3;->OooOoO0:Llyiahf/vczjk/z42;

    iget-object v7, p1, Llyiahf/vczjk/z42;->OooO00o:Llyiahf/vczjk/ar8;

    if-nez v7, :cond_2

    new-instance v7, Llyiahf/vczjk/tg7;

    const/4 v8, 0x4

    invoke-direct {v7, v5, v8}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    iput-object v7, v6, Llyiahf/vczjk/jv3;->OooOO0o:Llyiahf/vczjk/ar8;

    invoke-virtual {v6}, Llyiahf/vczjk/jv3;->OooO0O0()V

    :cond_2
    iget-object v7, p1, Llyiahf/vczjk/z42;->OooO0O0:Llyiahf/vczjk/r78;

    if-nez v7, :cond_5

    iget-object v5, v5, Llyiahf/vczjk/j00;->OooOoOO:Llyiahf/vczjk/en1;

    sget-object v7, Llyiahf/vczjk/uba;->OooO0O0:Llyiahf/vczjk/pi7;

    sget-object v7, Llyiahf/vczjk/dn1;->OooO0O0:Llyiahf/vczjk/op3;

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v7

    if-nez v7, :cond_4

    sget-object v7, Llyiahf/vczjk/dn1;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-static {v5, v7}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v5

    if-eqz v5, :cond_3

    goto :goto_0

    :cond_3
    sget-object v5, Llyiahf/vczjk/r78;->OooOOO0:Llyiahf/vczjk/r78;

    goto :goto_1

    :cond_4
    :goto_0
    sget-object v5, Llyiahf/vczjk/r78;->OooOOO:Llyiahf/vczjk/r78;

    :goto_1
    iput-object v5, v6, Llyiahf/vczjk/jv3;->OooOOO0:Llyiahf/vczjk/r78;

    :cond_5
    sget-object v5, Llyiahf/vczjk/s07;->OooOOO0:Llyiahf/vczjk/s07;

    iget-object p1, p1, Llyiahf/vczjk/z42;->OooO0OO:Llyiahf/vczjk/s07;

    if-eq p1, v5, :cond_6

    sget-object p1, Llyiahf/vczjk/s07;->OooOOO:Llyiahf/vczjk/s07;

    iput-object p1, v6, Llyiahf/vczjk/jv3;->OooO0o0:Llyiahf/vczjk/s07;

    :cond_6
    invoke-virtual {v6}, Llyiahf/vczjk/jv3;->OooO00o()Llyiahf/vczjk/kv3;

    move-result-object p1

    iput-object v1, p0, Llyiahf/vczjk/d00;->L$0:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/d00;->label:I

    check-cast v4, Llyiahf/vczjk/ii7;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v3, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v3, Llyiahf/vczjk/y95;->OooO00o:Llyiahf/vczjk/xl3;

    iget-object v3, v3, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    new-instance v5, Llyiahf/vczjk/ei7;

    invoke-direct {v5, v4, p1, v2}, Llyiahf/vczjk/ei7;-><init>(Llyiahf/vczjk/ii7;Llyiahf/vczjk/kv3;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, v5, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_7

    return-object v0

    :cond_7
    move-object v0, v1

    :goto_2
    check-cast p1, Llyiahf/vczjk/lv3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v1, p1, Llyiahf/vczjk/l99;

    if-eqz v1, :cond_8

    new-instance v1, Llyiahf/vczjk/b00;

    check-cast p1, Llyiahf/vczjk/l99;

    iget-object v2, p1, Llyiahf/vczjk/l99;->OooO00o:Landroid/graphics/drawable/Drawable;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/j00;->OooOO0(Landroid/graphics/drawable/Drawable;)Llyiahf/vczjk/un6;

    move-result-object v0

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/b00;-><init>(Llyiahf/vczjk/un6;Llyiahf/vczjk/l99;)V

    return-object v1

    :cond_8
    instance-of v1, p1, Llyiahf/vczjk/lq2;

    if-eqz v1, :cond_a

    new-instance v1, Llyiahf/vczjk/zz;

    check-cast p1, Llyiahf/vczjk/lq2;

    iget-object v3, p1, Llyiahf/vczjk/lq2;->OooO00o:Landroid/graphics/drawable/Drawable;

    if-eqz v3, :cond_9

    invoke-virtual {v0, v3}, Llyiahf/vczjk/j00;->OooOO0(Landroid/graphics/drawable/Drawable;)Llyiahf/vczjk/un6;

    move-result-object v2

    :cond_9
    invoke-direct {v1, v2, p1}, Llyiahf/vczjk/zz;-><init>(Llyiahf/vczjk/un6;Llyiahf/vczjk/lq2;)V

    return-object v1

    :cond_a
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method
