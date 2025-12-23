.class public final Llyiahf/vczjk/eo2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $enter:Llyiahf/vczjk/ep2;

.field final synthetic $exit:Llyiahf/vczjk/ct2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/eo2;->$enter:Llyiahf/vczjk/ep2;

    iput-object p2, p0, Llyiahf/vczjk/eo2;->$exit:Llyiahf/vczjk/ct2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/sy9;

    sget-object v0, Llyiahf/vczjk/co2;->OooOOO0:Llyiahf/vczjk/co2;

    sget-object v1, Llyiahf/vczjk/co2;->OooOOO:Llyiahf/vczjk/co2;

    invoke-interface {p1, v0, v1}, Llyiahf/vczjk/sy9;->OooO0O0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/eo2;->$enter:Llyiahf/vczjk/ep2;

    check-cast p1, Llyiahf/vczjk/fp2;

    iget-object p1, p1, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO00o:Llyiahf/vczjk/iv2;

    if-eqz p1, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/iv2;->OooO00o:Llyiahf/vczjk/p13;

    if-nez p1, :cond_0

    goto :goto_0

    :cond_0
    return-object p1

    :cond_1
    :goto_0
    sget-object p1, Llyiahf/vczjk/uo2;->OooO0O0:Llyiahf/vczjk/wz8;

    return-object p1

    :cond_2
    sget-object v0, Llyiahf/vczjk/co2;->OooOOOO:Llyiahf/vczjk/co2;

    invoke-interface {p1, v1, v0}, Llyiahf/vczjk/sy9;->OooO0O0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/eo2;->$exit:Llyiahf/vczjk/ct2;

    check-cast p1, Llyiahf/vczjk/dt2;

    iget-object p1, p1, Llyiahf/vczjk/dt2;->OooO0OO:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO00o:Llyiahf/vczjk/iv2;

    if-eqz p1, :cond_4

    iget-object p1, p1, Llyiahf/vczjk/iv2;->OooO00o:Llyiahf/vczjk/p13;

    if-nez p1, :cond_3

    goto :goto_1

    :cond_3
    return-object p1

    :cond_4
    :goto_1
    sget-object p1, Llyiahf/vczjk/uo2;->OooO0O0:Llyiahf/vczjk/wz8;

    return-object p1

    :cond_5
    sget-object p1, Llyiahf/vczjk/uo2;->OooO0O0:Llyiahf/vczjk/wz8;

    return-object p1
.end method
