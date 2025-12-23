.class public final Llyiahf/vczjk/vy4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/jy4;

.field public OooO0O0:Llyiahf/vczjk/sy4;


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 3

    invoke-virtual {p2}, Llyiahf/vczjk/iy4;->OooO00o()Llyiahf/vczjk/jy4;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/vy4;->OooO00o:Llyiahf/vczjk/jy4;

    const-string v2, "state1"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {v0, v1}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v2

    if-gez v2, :cond_0

    move-object v1, v0

    :cond_0
    iput-object v1, p0, Llyiahf/vczjk/vy4;->OooO00o:Llyiahf/vczjk/jy4;

    iget-object v1, p0, Llyiahf/vczjk/vy4;->OooO0O0:Llyiahf/vczjk/sy4;

    invoke-interface {v1, p1, p2}, Llyiahf/vczjk/sy4;->OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V

    iput-object v0, p0, Llyiahf/vczjk/vy4;->OooO00o:Llyiahf/vczjk/jy4;

    return-void
.end method
