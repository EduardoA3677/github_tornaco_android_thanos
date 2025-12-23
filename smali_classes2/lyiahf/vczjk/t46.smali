.class public final Llyiahf/vczjk/t46;
.super Llyiahf/vczjk/ij1;
.source "SourceFile"


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/cm5;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/hk4;->OooOOOO()Llyiahf/vczjk/dp8;

    move-result-object p1

    const/4 v0, 0x1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/dp8;->o0000Ooo(Z)Llyiahf/vczjk/dp8;

    move-result-object p1

    if-eqz p1, :cond_0

    return-object p1

    :cond_0
    const/16 p1, 0x32

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooO00o(I)V

    const/4 p1, 0x0

    throw p1
.end method
