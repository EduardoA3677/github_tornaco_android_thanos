.class public final Llyiahf/vczjk/mj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $measuredSize:J

.field final synthetic $placeable:Llyiahf/vczjk/ow6;

.field final synthetic this$0:Llyiahf/vczjk/pj;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/pj;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/pj;Llyiahf/vczjk/ow6;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mj;->this$0:Llyiahf/vczjk/pj;

    iput-object p2, p0, Llyiahf/vczjk/mj;->$placeable:Llyiahf/vczjk/ow6;

    iput-wide p3, p0, Llyiahf/vczjk/mj;->$measuredSize:J

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/mj;->this$0:Llyiahf/vczjk/pj;

    iget-object v0, v0, Llyiahf/vczjk/pj;->OooOoo:Llyiahf/vczjk/uj;

    iget-object v1, v0, Llyiahf/vczjk/uj;->OooO0O0:Llyiahf/vczjk/o4;

    iget-object v0, p0, Llyiahf/vczjk/mj;->$placeable:Llyiahf/vczjk/ow6;

    iget v2, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v0, v0, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v2, v2

    const/16 v4, 0x20

    shl-long/2addr v2, v4

    int-to-long v4, v0

    const-wide v6, 0xffffffffL

    and-long/2addr v4, v6

    or-long/2addr v2, v4

    iget-wide v4, p0, Llyiahf/vczjk/mj;->$measuredSize:J

    sget-object v6, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/o4;->OooO00o(JJLlyiahf/vczjk/yn4;)J

    move-result-wide v0

    iget-object v2, p0, Llyiahf/vczjk/mj;->$placeable:Llyiahf/vczjk/ow6;

    invoke-static {p1, v2, v0, v1}, Llyiahf/vczjk/nw6;->OooO0oO(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
