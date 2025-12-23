.class public final Llyiahf/vczjk/csa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic $this_measure:Llyiahf/vczjk/nf5;

.field final synthetic $wrapperHeight:I

.field final synthetic $wrapperWidth:I

.field final synthetic this$0:Llyiahf/vczjk/dsa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dsa;ILlyiahf/vczjk/ow6;ILlyiahf/vczjk/nf5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/csa;->this$0:Llyiahf/vczjk/dsa;

    iput p2, p0, Llyiahf/vczjk/csa;->$wrapperWidth:I

    iput-object p3, p0, Llyiahf/vczjk/csa;->$placeable:Llyiahf/vczjk/ow6;

    iput p4, p0, Llyiahf/vczjk/csa;->$wrapperHeight:I

    iput-object p5, p0, Llyiahf/vczjk/csa;->$this_measure:Llyiahf/vczjk/nf5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/csa;->this$0:Llyiahf/vczjk/dsa;

    iget-object v0, v0, Llyiahf/vczjk/dsa;->OooOoo0:Llyiahf/vczjk/rm4;

    iget v1, p0, Llyiahf/vczjk/csa;->$wrapperWidth:I

    iget-object v2, p0, Llyiahf/vczjk/csa;->$placeable:Llyiahf/vczjk/ow6;

    iget v3, v2, Llyiahf/vczjk/ow6;->OooOOO0:I

    sub-int/2addr v1, v3

    iget v3, p0, Llyiahf/vczjk/csa;->$wrapperHeight:I

    iget v2, v2, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int/2addr v3, v2

    int-to-long v1, v1

    const/16 v4, 0x20

    shl-long/2addr v1, v4

    int-to-long v3, v3

    const-wide v5, 0xffffffffL

    and-long/2addr v3, v5

    or-long/2addr v1, v3

    new-instance v3, Llyiahf/vczjk/b24;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/b24;-><init>(J)V

    iget-object v1, p0, Llyiahf/vczjk/csa;->$this_measure:Llyiahf/vczjk/nf5;

    invoke-interface {v1}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v1

    invoke-interface {v0, v3, v1}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/u14;

    iget-wide v0, v0, Llyiahf/vczjk/u14;->OooO00o:J

    iget-object v2, p0, Llyiahf/vczjk/csa;->$placeable:Llyiahf/vczjk/ow6;

    invoke-static {p1, v2, v0, v1}, Llyiahf/vczjk/nw6;->OooO0oO(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
