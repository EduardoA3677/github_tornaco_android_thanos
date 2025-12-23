.class public final Llyiahf/vczjk/bg1;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/hc3;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hc3;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/bg1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/bg1;->OooOOO:Llyiahf/vczjk/hc3;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/bg1;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/hc3;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/bg1;->OooOOO:Llyiahf/vczjk/hc3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/hc3;->equals(Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/ko;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/bg1;->OooOOO:Llyiahf/vczjk/hc3;

    invoke-interface {p1, v0}, Llyiahf/vczjk/ko;->OooO0oO(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/un;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
