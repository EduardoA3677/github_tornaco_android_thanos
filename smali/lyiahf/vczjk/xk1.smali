.class public final Llyiahf/vczjk/xk1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ar8;
.implements Llyiahf/vczjk/eo4;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/s29;


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-wide v0, Llyiahf/vczjk/uba;->OooO00o:J

    new-instance v2, Llyiahf/vczjk/rk1;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/rk1;-><init>(J)V

    invoke-static {v2}, Llyiahf/vczjk/r02;->OooO0Oo(Ljava/lang/Object;)Llyiahf/vczjk/s29;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xk1;->OooOOO0:Llyiahf/vczjk/s29;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;
    .locals 3

    new-instance v0, Llyiahf/vczjk/rk1;

    invoke-direct {v0, p3, p4}, Llyiahf/vczjk/rk1;-><init>(J)V

    iget-object v1, p0, Llyiahf/vczjk/xk1;->OooOOO0:Llyiahf/vczjk/s29;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v2, 0x0

    invoke-virtual {v1, v2, v0}, Llyiahf/vczjk/s29;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;)Z

    invoke-interface {p2, p3, p4}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget p4, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    new-instance v0, Llyiahf/vczjk/j50;

    const/4 v1, 0x1

    invoke-direct {v0, p2, v1}, Llyiahf/vczjk/j50;-><init>(Llyiahf/vczjk/ow6;I)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, p4, p2, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooOO0(Llyiahf/vczjk/fi7;)Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/i00;

    iget-object v1, p0, Llyiahf/vczjk/xk1;->OooOOO0:Llyiahf/vczjk/s29;

    const/4 v2, 0x2

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/i00;-><init>(Llyiahf/vczjk/s29;I)V

    invoke-static {v0, p1}, Llyiahf/vczjk/rs;->OooOoO(Llyiahf/vczjk/f43;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
