.class public final Llyiahf/vczjk/tk;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $transition:Llyiahf/vczjk/bz9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bz9;"
        }
    .end annotation
.end field

.field final synthetic $visible:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/bz9;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/tk;->$visible:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/tk;->$transition:Llyiahf/vczjk/bz9;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Llyiahf/vczjk/nf5;

    check-cast p2, Llyiahf/vczjk/ef5;

    check-cast p3, Llyiahf/vczjk/rk1;

    iget-wide v0, p3, Llyiahf/vczjk/rk1;->OooO00o:J

    invoke-interface {p2, v0, v1}, Llyiahf/vczjk/ef5;->OooOoOO(J)Llyiahf/vczjk/ow6;

    move-result-object p2

    invoke-interface {p1}, Llyiahf/vczjk/o34;->OoooOo0()Z

    move-result p3

    const-wide v0, 0xffffffffL

    const/16 v2, 0x20

    if-eqz p3, :cond_0

    iget-object p3, p0, Llyiahf/vczjk/tk;->$visible:Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/tk;->$transition:Llyiahf/vczjk/bz9;

    iget-object v3, v3, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-interface {p3, v3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/Boolean;

    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p3

    if-nez p3, :cond_0

    const-wide/16 v3, 0x0

    goto :goto_0

    :cond_0
    iget p3, p2, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v3, p2, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v4, p3

    shl-long/2addr v4, v2

    int-to-long v6, v3

    and-long/2addr v6, v0

    or-long v3, v4, v6

    :goto_0
    shr-long v5, v3, v2

    long-to-int p3, v5

    and-long/2addr v0, v3

    long-to-int v0, v0

    new-instance v1, Llyiahf/vczjk/sk;

    invoke-direct {v1, p2}, Llyiahf/vczjk/sk;-><init>(Llyiahf/vczjk/ow6;)V

    sget-object p2, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    invoke-interface {p1, p3, v0, p2, v1}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
