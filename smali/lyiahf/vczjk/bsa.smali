.class public final Llyiahf/vczjk/bsa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $align:Llyiahf/vczjk/m4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sb0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bsa;->$align:Llyiahf/vczjk/m4;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v0, p1, Llyiahf/vczjk/b24;->OooO00o:J

    check-cast p2, Llyiahf/vczjk/yn4;

    iget-object p1, p0, Llyiahf/vczjk/bsa;->$align:Llyiahf/vczjk/m4;

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    const/4 v1, 0x0

    invoke-interface {p1, v1, v0, p2}, Llyiahf/vczjk/m4;->OooO00o(IILlyiahf/vczjk/yn4;)I

    move-result p1

    int-to-long p1, p1

    shl-long/2addr p1, v2

    int-to-long v0, v1

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    or-long/2addr p1, v0

    new-instance v0, Llyiahf/vczjk/u14;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/u14;-><init>(J)V

    return-object v0
.end method
