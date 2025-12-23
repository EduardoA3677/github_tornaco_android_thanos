.class public final Llyiahf/vczjk/da7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $padding:F


# direct methods
.method public constructor <init>(F)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/da7;->$padding:F

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    iget-wide v0, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    iget p3, p0, Llyiahf/vczjk/da7;->$padding:F

    invoke-interface {p1, p3}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p3

    mul-int/lit8 v2, p3, 0x2

    const/4 v3, 0x0

    invoke-static {v3, v2, v0, v1}, Llyiahf/vczjk/uk1;->OooO(IIJ)J

    move-result-wide v0

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    iget v0, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int/2addr v0, v2

    iget v1, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    new-instance v2, Llyiahf/vczjk/ca7;

    invoke-direct {v2, p2, p3}, Llyiahf/vczjk/ca7;-><init>(Llyiahf/vczjk/ow6;I)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, v1, v0, p2, v2}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
