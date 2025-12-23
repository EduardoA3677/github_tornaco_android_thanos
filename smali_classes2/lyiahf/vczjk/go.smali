.class public final Llyiahf/vczjk/go;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/hk4;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hk4;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/go;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/go;->OooOOO:Llyiahf/vczjk/hk4;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/go;->OooOOO:Llyiahf/vczjk/hk4;

    iget v1, p0, Llyiahf/vczjk/go;->OooOOO0:I

    packed-switch v1, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/qt5;

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooOO0o()Llyiahf/vczjk/dm5;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/x09;->OooOO0o:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/dm5;->OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/hw4;

    iget-object v0, v0, Llyiahf/vczjk/hw4;->OooOo0O:Llyiahf/vczjk/pw4;

    if-eqz v0, :cond_2

    sget-object v2, Llyiahf/vczjk/h16;->OooOOO0:Llyiahf/vczjk/h16;

    invoke-virtual {v0, p1, v2}, Llyiahf/vczjk/pw4;->OooO0O0(Llyiahf/vczjk/qt5;Llyiahf/vczjk/x65;)Llyiahf/vczjk/gz0;

    move-result-object v0

    if-eqz v0, :cond_1

    instance-of v1, v0, Llyiahf/vczjk/by0;

    if-eqz v1, :cond_0

    check-cast v0, Llyiahf/vczjk/by0;

    return-object v0

    :cond_0
    new-instance v1, Ljava/lang/AssertionError;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Must be a class descriptor "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, ", but was "

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v1

    :cond_1
    new-instance v0, Ljava/lang/AssertionError;

    new-instance v2, Ljava/lang/StringBuilder;

    const-string v3, "Built-in class "

    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/hc3;->OooO00o(Llyiahf/vczjk/qt5;)Llyiahf/vczjk/hc3;

    move-result-object p1

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " is not found"

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    throw v0

    :cond_2
    const/16 p1, 0xb

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p1, 0x0

    throw p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/cm5;

    const-string v1, "module"

    invoke-static {p1, v1}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object p1

    sget-object v1, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooOo0O()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/hk4;->OooO0oo(Llyiahf/vczjk/iaa;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
