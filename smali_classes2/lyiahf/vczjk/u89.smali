.class public final Llyiahf/vczjk/u89;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $code:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/v89;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v89;Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    iput-object p2, p0, Llyiahf/vczjk/u89;->$code:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/u89;

    iget-object v0, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    iget-object v1, p0, Llyiahf/vczjk/u89;->$code:Ljava/lang/String;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/u89;-><init>(Llyiahf/vczjk/v89;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/u89;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/u89;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/u89;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/u89;->label:I

    const/4 v2, 0x3

    const/4 v3, 0x0

    packed-switch v1, :pswitch_data_0

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_4

    :pswitch_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :pswitch_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :pswitch_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :pswitch_4
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    iget-object p1, p1, Llyiahf/vczjk/v89;->OooO:Llyiahf/vczjk/jl8;

    sget-object v1, Llyiahf/vczjk/a11;->OooOOO0:Llyiahf/vczjk/a11;

    const/4 v4, 0x1

    iput v4, p0, Llyiahf/vczjk/u89;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_0

    goto/16 :goto_3

    :cond_0
    :goto_0
    const/4 p1, 0x2

    iput p1, p0, Llyiahf/vczjk/u89;->label:I

    const-wide/16 v4, 0x16ca

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/yi4;->Oooo0oo(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_1

    goto :goto_3

    :cond_1
    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    iget-object p1, p1, Llyiahf/vczjk/v89;->OooO0oo:Llyiahf/vczjk/sc9;

    invoke-virtual {p1}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/tq7;

    iget-object v1, p0, Llyiahf/vczjk/u89;->$code:Ljava/lang/String;

    iput v2, p0, Llyiahf/vczjk/u89;->label:I

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/kc2;->OooO00o:Llyiahf/vczjk/q32;

    sget-object v4, Llyiahf/vczjk/m22;->OooOOOO:Llyiahf/vczjk/m22;

    new-instance v5, Llyiahf/vczjk/sq7;

    invoke-direct {v5, v1, p1, v3}, Llyiahf/vczjk/sq7;-><init>(Ljava/lang/String;Llyiahf/vczjk/tq7;Llyiahf/vczjk/yo1;)V

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/os9;->OoooOoO(Llyiahf/vczjk/or1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_3

    :cond_2
    :goto_2
    check-cast p1, Llyiahf/vczjk/uea;

    instance-of v1, p1, Llyiahf/vczjk/rea;

    if-eqz v1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    iget-object p1, p1, Llyiahf/vczjk/v89;->OooO:Llyiahf/vczjk/jl8;

    sget-object v1, Llyiahf/vczjk/a11;->OooOOOO:Llyiahf/vczjk/a11;

    const/4 v2, 0x4

    iput v2, p0, Llyiahf/vczjk/u89;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    goto :goto_3

    :cond_3
    sget-object v1, Llyiahf/vczjk/sea;->OooO00o:Llyiahf/vczjk/sea;

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    iget-object p1, p1, Llyiahf/vczjk/v89;->OooO:Llyiahf/vczjk/jl8;

    sget-object v1, Llyiahf/vczjk/a11;->OooOOOo:Llyiahf/vczjk/a11;

    const/4 v2, 0x5

    iput v2, p0, Llyiahf/vczjk/u89;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    goto :goto_3

    :cond_4
    instance-of v1, p1, Llyiahf/vczjk/qea;

    if-eqz v1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    iget-object p1, p1, Llyiahf/vczjk/v89;->OooO:Llyiahf/vczjk/jl8;

    sget-object v1, Llyiahf/vczjk/a11;->OooOOo0:Llyiahf/vczjk/a11;

    const/4 v2, 0x6

    iput v2, p0, Llyiahf/vczjk/u89;->label:I

    invoke-virtual {p1, v1, p0}, Llyiahf/vczjk/jl8;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    :goto_3
    return-object v0

    :cond_5
    instance-of v0, p1, Llyiahf/vczjk/tea;

    if-eqz v0, :cond_8

    iget-object v0, p0, Llyiahf/vczjk/u89;->$code:Ljava/lang/String;

    check-cast p1, Llyiahf/vczjk/tea;

    iget-object v1, p1, Llyiahf/vczjk/tea;->OooO00o:Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->getK()Ljava/lang/String;

    move-result-object v1

    invoke-static {v0, v1}, Ltornaco/android/sec/net/S;->c(Ljava/lang/String;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/tea;->OooO00o:Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/support/subscribe/CommonApiResWrapper;->getI()Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_7

    iget-object p1, p0, Llyiahf/vczjk/u89;->$code:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/u89;->this$0:Llyiahf/vczjk/v89;

    invoke-static {p1}, Llyiahf/vczjk/xl4;->OooO00o(Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/qqa;->Oooo00O(Llyiahf/vczjk/dha;)Llyiahf/vczjk/k01;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/t89;

    invoke-direct {v1, v0, v3}, Llyiahf/vczjk/t89;-><init>(Llyiahf/vczjk/v89;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v3, v3, v1, v2}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_6
    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_7
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Required value was null."

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_8
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
        :pswitch_0
        :pswitch_0
    .end packed-switch
.end method
