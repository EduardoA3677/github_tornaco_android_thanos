.class public final Llyiahf/vczjk/dr3;
.super Llyiahf/vczjk/fr3;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0Oo:I

.field public final OooO0o0:Llyiahf/vczjk/yn0;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ir7;Llyiahf/vczjk/vn0;Llyiahf/vczjk/fp1;Llyiahf/vczjk/yn0;I)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/dr3;->OooO0Oo:I

    invoke-direct {p0, p1, p2, p3}, Llyiahf/vczjk/fr3;-><init>(Llyiahf/vczjk/ir7;Llyiahf/vczjk/vn0;Llyiahf/vczjk/fp1;)V

    iput-object p4, p0, Llyiahf/vczjk/dr3;->OooO0o0:Llyiahf/vczjk/yn0;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/c96;[Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/dr3;->OooO0o0:Llyiahf/vczjk/yn0;

    iget v1, p0, Llyiahf/vczjk/dr3;->OooO0Oo:I

    packed-switch v1, :pswitch_data_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/yn0;->OoooOO0(Llyiahf/vczjk/c96;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wn0;

    array-length v0, p2

    const/4 v1, 0x1

    sub-int/2addr v0, v1

    aget-object p2, p2, v0

    check-cast p2, Llyiahf/vczjk/yo1;

    :try_start_0
    new-instance v0, Llyiahf/vczjk/yp0;

    invoke-static {p2}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOoo()V

    new-instance v1, Llyiahf/vczjk/lk4;

    invoke-direct {v1, p1}, Llyiahf/vczjk/lk4;-><init>(Llyiahf/vczjk/wn0;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/yp0;->OooOo0(Llyiahf/vczjk/oe3;)V

    new-instance v1, Llyiahf/vczjk/tg7;

    const/16 v2, 0x12

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/tg7;-><init>(Ljava/lang/Object;I)V

    invoke-interface {p1, v1}, Llyiahf/vczjk/wn0;->OooOOOO(Llyiahf/vczjk/ho0;)V

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_0

    :catch_0
    move-exception p1

    invoke-static {p1, p2}, Llyiahf/vczjk/so8;->OoooO00(Ljava/lang/Throwable;Llyiahf/vczjk/yo1;)V

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    :goto_0
    return-object p1

    :pswitch_0
    invoke-interface {v0, p1}, Llyiahf/vczjk/yn0;->OoooOO0(Llyiahf/vczjk/c96;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
