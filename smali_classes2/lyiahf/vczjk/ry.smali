.class public Llyiahf/vczjk/ry;
.super Llyiahf/vczjk/ij1;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Ljava/util/List;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    iput-object p2, p0, Llyiahf/vczjk/ry;->OooO0O0:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/cm5;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/ry;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/uk4;

    invoke-static {p1}, Llyiahf/vczjk/hk4;->OooOoO(Llyiahf/vczjk/uk4;)Z

    move-result v0

    if-nez v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/hk4;->OooOOoo(Llyiahf/vczjk/gz0;)Llyiahf/vczjk/q47;

    move-result-object v0

    if-eqz v0, :cond_0

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/w09;->OoooOOO:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {p1, v0}, Llyiahf/vczjk/hk4;->OooOoo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/w09;->OoooOOo:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {p1, v0}, Llyiahf/vczjk/hk4;->OooOoo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/w09;->OoooOo0:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {p1, v0}, Llyiahf/vczjk/hk4;->OooOoo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    move-result v0

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/w09;->OoooOoO:Llyiahf/vczjk/hc3;

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-static {p1, v0}, Llyiahf/vczjk/hk4;->OooOoo(Llyiahf/vczjk/uk4;Llyiahf/vczjk/ic3;)Z

    :cond_1
    return-object p1
.end method
