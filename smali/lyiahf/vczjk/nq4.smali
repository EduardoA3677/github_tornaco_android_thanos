.class public final Llyiahf/vczjk/nq4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $measuredItemProvider:Llyiahf/vczjk/qq4;

.field final synthetic $measuredLineProvider:Llyiahf/vczjk/sq4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/iq4;Llyiahf/vczjk/hq4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nq4;->$measuredLineProvider:Llyiahf/vczjk/sq4;

    iput-object p2, p0, Llyiahf/vczjk/nq4;->$measuredItemProvider:Llyiahf/vczjk/qq4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result v1

    iget-object p1, p0, Llyiahf/vczjk/nq4;->$measuredLineProvider:Llyiahf/vczjk/sq4;

    iget-object p1, p1, Llyiahf/vczjk/sq4;->OooO0o:Llyiahf/vczjk/yq4;

    iget v0, p1, Llyiahf/vczjk/yq4;->OooO:I

    invoke-virtual {p1, v1}, Llyiahf/vczjk/yq4;->OooO0o0(I)I

    move-result v5

    iget-object p1, p0, Llyiahf/vczjk/nq4;->$measuredLineProvider:Llyiahf/vczjk/sq4;

    const/4 v0, 0x0

    invoke-virtual {p1, v0, v5}, Llyiahf/vczjk/sq4;->OooO00o(II)J

    move-result-wide v2

    iget-object v0, p0, Llyiahf/vczjk/nq4;->$measuredItemProvider:Llyiahf/vczjk/qq4;

    iget v6, v0, Llyiahf/vczjk/qq4;->OooO0OO:I

    const/4 v4, 0x0

    invoke-virtual/range {v0 .. v6}, Llyiahf/vczjk/qq4;->OooO0O0(IJIII)Llyiahf/vczjk/pq4;

    move-result-object p1

    return-object p1
.end method
