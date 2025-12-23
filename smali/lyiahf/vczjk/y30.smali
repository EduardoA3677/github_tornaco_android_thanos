.class public final Llyiahf/vczjk/y30;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/y30;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/y30;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/y30;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/ypa;

    iget-object v1, p0, Llyiahf/vczjk/y30;->OooOOO:Ljava/lang/Object;

    check-cast v1, [Llyiahf/vczjk/f43;

    invoke-direct {v0, v1}, Llyiahf/vczjk/ypa;-><init>([Llyiahf/vczjk/f43;)V

    new-instance v2, Llyiahf/vczjk/zpa;

    const/4 v3, 0x3

    const/4 v4, 0x0

    invoke-direct {v2, v3, v4}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-static {p2, p1, v0, v2, v1}, Llyiahf/vczjk/cp7;->OooOOO(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/le3;Llyiahf/vczjk/bf3;[Llyiahf/vczjk/f43;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/l38;

    invoke-direct {v0, p1}, Llyiahf/vczjk/l38;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/y30;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/a28;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/a28;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/y30;->OooOOO:Ljava/lang/Object;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_2

    goto :goto_2

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_2
    return-object p1

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/j43;

    iget-object v1, p0, Llyiahf/vczjk/y30;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/g53;

    const/4 v2, 0x0

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/j43;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)V

    new-instance p1, Llyiahf/vczjk/i43;

    invoke-interface {p2}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v1

    const/4 v2, 0x0

    invoke-direct {p1, v1, p2, v2}, Llyiahf/vczjk/i43;-><init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/yo1;I)V

    const/4 p2, 0x1

    invoke-static {p1, p2, p1, v0}, Llyiahf/vczjk/vl6;->OooOooO(Llyiahf/vczjk/x88;ZLlyiahf/vczjk/x88;Llyiahf/vczjk/ze3;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_3

    goto :goto_3

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_3
    return-object p1

    :pswitch_3
    new-instance v0, Llyiahf/vczjk/my1;

    invoke-direct {v0, p1}, Llyiahf/vczjk/my1;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/y30;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/w53;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/w53;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_4

    goto :goto_4

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_4
    return-object p1

    :pswitch_4
    new-instance v0, Llyiahf/vczjk/x30;

    invoke-direct {v0, p1}, Llyiahf/vczjk/x30;-><init>(Llyiahf/vczjk/h43;)V

    iget-object p1, p0, Llyiahf/vczjk/y30;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/b40;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/b40;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_5

    goto :goto_5

    :cond_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_5
    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
