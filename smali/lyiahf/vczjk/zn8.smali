.class public final Llyiahf/vczjk/zn8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xr1;

.field public final OooO0O0:Llyiahf/vczjk/gz1;

.field public final OooO0OO:Llyiahf/vczjk/jj0;

.field public final OooO0Oo:Llyiahf/vczjk/oO0OOo0o;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xr1;Llyiahf/vczjk/fz1;Llyiahf/vczjk/gz1;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zn8;->OooO00o:Llyiahf/vczjk/xr1;

    iput-object p3, p0, Llyiahf/vczjk/zn8;->OooO0O0:Llyiahf/vczjk/gz1;

    const/4 p3, 0x6

    const v0, 0x7fffffff

    const/4 v1, 0x0

    invoke-static {v0, p3, v1}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object p3

    iput-object p3, p0, Llyiahf/vczjk/zn8;->OooO0OO:Llyiahf/vczjk/jj0;

    new-instance p3, Llyiahf/vczjk/oO0OOo0o;

    const/4 v0, 0x7

    invoke-direct {p3, v0}, Llyiahf/vczjk/oO0OOo0o;-><init>(I)V

    iput-object p3, p0, Llyiahf/vczjk/zn8;->OooO0Oo:Llyiahf/vczjk/oO0OOo0o;

    invoke-interface {p1}, Llyiahf/vczjk/xr1;->OoooOO0()Llyiahf/vczjk/or1;

    move-result-object p1

    sget-object p3, Llyiahf/vczjk/ws7;->OooOOo0:Llyiahf/vczjk/ws7;

    invoke-interface {p1, p3}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/v74;

    if-eqz p1, :cond_0

    new-instance p3, Llyiahf/vczjk/xn8;

    invoke-direct {p3, p2, p0}, Llyiahf/vczjk/xn8;-><init>(Llyiahf/vczjk/fz1;Llyiahf/vczjk/zn8;)V

    invoke-interface {p1, p3}, Llyiahf/vczjk/v74;->OoooO00(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/sc2;

    :cond_0
    return-void
.end method
