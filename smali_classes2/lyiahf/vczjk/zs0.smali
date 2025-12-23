.class public final Llyiahf/vczjk/zs0;
.super Llyiahf/vczjk/ys0;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/qr1;ILlyiahf/vczjk/aj0;I)V
    .locals 1

    and-int/lit8 v0, p5, 0x2

    if-eqz v0, :cond_0

    sget-object p2, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    :cond_0
    and-int/lit8 v0, p5, 0x4

    if-eqz v0, :cond_1

    const/4 p3, -0x3

    :cond_1
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_2

    sget-object p4, Llyiahf/vczjk/aj0;->OooOOO0:Llyiahf/vczjk/aj0;

    :cond_2
    invoke-direct {p0, p3, p4, p2, p1}, Llyiahf/vczjk/ys0;-><init>(ILlyiahf/vczjk/aj0;Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;)V

    return-void
.end method


# virtual methods
.method public final OooO0o()Llyiahf/vczjk/f43;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ys0;->OooOOOo:Llyiahf/vczjk/f43;

    return-object v0
.end method

.method public final OooO0o0(Llyiahf/vczjk/or1;ILlyiahf/vczjk/aj0;)Llyiahf/vczjk/vs0;
    .locals 2

    new-instance v0, Llyiahf/vczjk/zs0;

    iget-object v1, p0, Llyiahf/vczjk/ys0;->OooOOOo:Llyiahf/vczjk/f43;

    invoke-direct {v0, p2, p3, p1, v1}, Llyiahf/vczjk/ys0;-><init>(ILlyiahf/vczjk/aj0;Llyiahf/vczjk/or1;Llyiahf/vczjk/f43;)V

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ys0;->OooOOOo:Llyiahf/vczjk/f43;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
