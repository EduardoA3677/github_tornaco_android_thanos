.class public final Llyiahf/vczjk/bj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $specOnEnter:Llyiahf/vczjk/fn1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fn1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bj;->$specOnEnter:Llyiahf/vczjk/fn1;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    iget-wide v0, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v0, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v1, Llyiahf/vczjk/aj;

    iget-object v2, p0, Llyiahf/vczjk/bj;->$specOnEnter:Llyiahf/vczjk/fn1;

    invoke-direct {v1, p2, v2}, Llyiahf/vczjk/aj;-><init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/fn1;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, v0, p2, v1}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
