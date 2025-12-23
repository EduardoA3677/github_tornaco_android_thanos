.class public final Llyiahf/vczjk/no2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $initialHeight:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/no2;->$initialHeight:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v0, p1, Llyiahf/vczjk/b24;->OooO00o:J

    const/16 p1, 0x20

    shr-long v2, v0, p1

    long-to-int v2, v2

    iget-object v3, p0, Llyiahf/vczjk/no2;->$initialHeight:Llyiahf/vczjk/oe3;

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-interface {v3, v0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    int-to-long v1, v2

    shl-long/2addr v1, p1

    int-to-long v6, v0

    and-long v3, v6, v4

    or-long v0, v1, v3

    new-instance p1, Llyiahf/vczjk/b24;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    return-object p1
.end method
