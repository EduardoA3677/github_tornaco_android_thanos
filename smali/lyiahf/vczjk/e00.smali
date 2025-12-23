.class public final synthetic Llyiahf/vczjk/e00;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;
.implements Llyiahf/vczjk/kf3;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/e00;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/e00;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/cf3;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/e00;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v1, Llyiahf/vczjk/wf3;

    const/4 v2, 0x2

    iget-object v0, p0, Llyiahf/vczjk/e00;->OooOOO:Ljava/lang/Object;

    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/uo8;

    const-class v4, Llyiahf/vczjk/uo8;

    const-string v6, "send"

    const-string v7, "send(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    const/4 v3, 0x0

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/vf3;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    return-object v1

    :pswitch_0
    new-instance v2, Llyiahf/vczjk/h1;

    const-string v8, "updateState(Lcoil/compose/AsyncImagePainter$State;)V"

    const/4 v4, 0x4

    const/4 v3, 0x2

    iget-object v0, p0, Llyiahf/vczjk/e00;->OooOOO:Ljava/lang/Object;

    move-object v6, v0

    check-cast v6, Llyiahf/vczjk/j00;

    const-class v5, Llyiahf/vczjk/j00;

    const-string v7, "updateState"

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/h1;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    return-object v2

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 3

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    iget-object v1, p0, Llyiahf/vczjk/e00;->OooOOO:Ljava/lang/Object;

    iget v2, p0, Llyiahf/vczjk/e00;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/xm6;

    check-cast v1, Llyiahf/vczjk/uo8;

    check-cast v1, Llyiahf/vczjk/vo8;

    iget-object v1, v1, Llyiahf/vczjk/vo8;->OooOOO0:Llyiahf/vczjk/if8;

    invoke-interface {v1, p1, p2}, Llyiahf/vczjk/if8;->OooO0o0(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    move-object v0, p1

    :cond_0
    return-object v0

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/c00;

    check-cast v1, Llyiahf/vczjk/j00;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/j00;->OooOO0O(Llyiahf/vczjk/c00;)V

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/e00;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    instance-of v0, p1, Llyiahf/vczjk/h43;

    if-eqz v0, :cond_0

    instance-of v0, p1, Llyiahf/vczjk/kf3;

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/e00;->OooO0O0()Llyiahf/vczjk/cf3;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/kf3;

    invoke-interface {p1}, Llyiahf/vczjk/kf3;->OooO0O0()Llyiahf/vczjk/cf3;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    return p1

    :pswitch_0
    instance-of v0, p1, Llyiahf/vczjk/h43;

    if-eqz v0, :cond_1

    instance-of v0, p1, Llyiahf/vczjk/kf3;

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/e00;->OooO0O0()Llyiahf/vczjk/cf3;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/kf3;

    invoke-interface {p1}, Llyiahf/vczjk/kf3;->OooO0O0()Llyiahf/vczjk/cf3;

    move-result-object p1

    invoke-virtual {v0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p1

    goto :goto_1

    :cond_1
    const/4 p1, 0x0

    :goto_1
    return p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final hashCode()I
    .locals 1

    iget v0, p0, Llyiahf/vczjk/e00;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p0}, Llyiahf/vczjk/e00;->OooO0O0()Llyiahf/vczjk/cf3;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0

    :pswitch_0
    invoke-virtual {p0}, Llyiahf/vczjk/e00;->OooO0O0()Llyiahf/vczjk/cf3;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    move-result v0

    return v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
