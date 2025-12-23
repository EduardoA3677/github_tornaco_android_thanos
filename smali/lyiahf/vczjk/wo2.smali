.class public final Llyiahf/vczjk/wo2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $layerBlock:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $offset:J

.field final synthetic $offsetDelta:J

.field final synthetic $placeable:Llyiahf/vczjk/ow6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ow6;JJLlyiahf/vczjk/go2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wo2;->$placeable:Llyiahf/vczjk/ow6;

    iput-wide p2, p0, Llyiahf/vczjk/wo2;->$offset:J

    iput-wide p4, p0, Llyiahf/vczjk/wo2;->$offsetDelta:J

    iput-object p6, p0, Llyiahf/vczjk/wo2;->$layerBlock:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/wo2;->$placeable:Llyiahf/vczjk/ow6;

    iget-wide v1, p0, Llyiahf/vczjk/wo2;->$offset:J

    const/16 v3, 0x20

    shr-long v4, v1, v3

    long-to-int v4, v4

    iget-wide v5, p0, Llyiahf/vczjk/wo2;->$offsetDelta:J

    shr-long v7, v5, v3

    long-to-int v7, v7

    add-int/2addr v4, v7

    const-wide v7, 0xffffffffL

    and-long/2addr v1, v7

    long-to-int v1, v1

    and-long/2addr v5, v7

    long-to-int v2, v5

    add-int/2addr v1, v2

    iget-object v2, p0, Llyiahf/vczjk/wo2;->$layerBlock:Llyiahf/vczjk/oe3;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    int-to-long v4, v4

    shl-long v3, v4, v3

    int-to-long v5, v1

    and-long/2addr v5, v7

    or-long/2addr v3, v5

    invoke-static {p1, v0}, Llyiahf/vczjk/nw6;->OooO00o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;)V

    iget-wide v5, v0, Llyiahf/vczjk/ow6;->OooOOo0:J

    invoke-static {v3, v4, v5, v6}, Llyiahf/vczjk/u14;->OooO0Oo(JJ)J

    move-result-wide v3

    const/4 p1, 0x0

    invoke-virtual {v0, v3, v4, p1, v2}, Llyiahf/vczjk/ow6;->o0OoOo0(JFLlyiahf/vczjk/oe3;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
