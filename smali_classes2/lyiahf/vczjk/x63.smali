.class public final Llyiahf/vczjk/x63;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f43;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/x63;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/x63;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/x63;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 4

    iget v0, p0, Llyiahf/vczjk/x63;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/tf8;

    iget-object v1, p0, Llyiahf/vczjk/x63;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/qf8;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/tf8;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/qf8;)V

    iget-object p1, p0, Llyiahf/vczjk/x63;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/f43;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/dq5;

    iget-object v1, p0, Llyiahf/vczjk/x63;->OooOOOO:Ljava/lang/Object;

    check-cast v1, [Ljava/lang/String;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/dq5;-><init>(Llyiahf/vczjk/h43;[Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/x63;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/jl8;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/jl8;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1

    :pswitch_1
    new-instance v0, Llyiahf/vczjk/bc5;

    iget-object v1, p0, Llyiahf/vczjk/x63;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/cc5;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/bc5;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/cc5;)V

    iget-object p1, p0, Llyiahf/vczjk/x63;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/f43;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    :pswitch_2
    new-instance v0, Llyiahf/vczjk/s93;

    iget-object v1, p0, Llyiahf/vczjk/x63;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/u93;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/s93;-><init>(Llyiahf/vczjk/h43;Llyiahf/vczjk/u93;)V

    iget-object p1, p0, Llyiahf/vczjk/x63;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/f43;

    invoke-interface {p1, v0, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_2

    goto :goto_2

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_2
    return-object p1

    :pswitch_3
    sget-object v0, Llyiahf/vczjk/dk0;->OooOo00:Llyiahf/vczjk/dk0;

    new-instance v1, Llyiahf/vczjk/w63;

    iget-object v2, p0, Llyiahf/vczjk/x63;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/x38;

    const/4 v3, 0x0

    invoke-direct {v1, v3, v2}, Llyiahf/vczjk/w63;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ef3;)V

    iget-object v2, p0, Llyiahf/vczjk/x63;->OooOOO:Ljava/lang/Object;

    check-cast v2, [Llyiahf/vczjk/f43;

    invoke-static {p2, p1, v0, v1, v2}, Llyiahf/vczjk/cp7;->OooOOO(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/le3;Llyiahf/vczjk/bf3;[Llyiahf/vczjk/f43;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_3

    goto :goto_3

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_3
    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
