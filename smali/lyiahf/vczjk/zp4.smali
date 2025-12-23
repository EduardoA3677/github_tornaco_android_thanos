.class public final Llyiahf/vczjk/zp4;
.super Landroidx/compose/foundation/lazy/layout/OooO0O0;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/yq4;

.field public final OooO0O0:Llyiahf/vczjk/yw;

.field public OooO0OO:Z

.field public OooO0Oo:Llyiahf/vczjk/nr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/yq4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/yq4;-><init>(Llyiahf/vczjk/zp4;)V

    iput-object v0, p0, Llyiahf/vczjk/zp4;->OooO00o:Llyiahf/vczjk/yq4;

    new-instance v0, Llyiahf/vczjk/yw;

    const/4 v1, 0x5

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/yw;-><init>(IB)V

    iput-object v0, p0, Llyiahf/vczjk/zp4;->OooO0O0:Llyiahf/vczjk/yw;

    invoke-interface {p1, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public static synthetic OooO0oO(Llyiahf/vczjk/zp4;Llyiahf/vczjk/rt3;Llyiahf/vczjk/a91;I)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p1, 0x0

    :cond_0
    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/zp4;->OooO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    return-void
.end method


# virtual methods
.method public final OooO0O0()Llyiahf/vczjk/yw;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/zp4;->OooO0O0:Llyiahf/vczjk/yw;

    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V
    .locals 5

    if-eqz p1, :cond_0

    new-instance v0, Llyiahf/vczjk/vp4;

    invoke-direct {v0, p1}, Llyiahf/vczjk/vp4;-><init>(Llyiahf/vczjk/oe3;)V

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/ye1;->OooOo0:Llyiahf/vczjk/ye1;

    :goto_0
    new-instance v1, Llyiahf/vczjk/wp4;

    invoke-direct {v1}, Llyiahf/vczjk/wp4;-><init>()V

    new-instance v2, Llyiahf/vczjk/xp4;

    invoke-direct {v2, p2}, Llyiahf/vczjk/xp4;-><init>(Llyiahf/vczjk/a91;)V

    new-instance p2, Llyiahf/vczjk/a91;

    const v3, -0x21013f8

    const/4 v4, 0x1

    invoke-direct {p2, v3, v2, v4}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    new-instance v2, Llyiahf/vczjk/up4;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0, v1, p2}, Llyiahf/vczjk/up4;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    iget-object p2, p0, Llyiahf/vczjk/zp4;->OooO0O0:Llyiahf/vczjk/yw;

    invoke-virtual {p2, v4, v2}, Llyiahf/vczjk/yw;->OooO0OO(ILlyiahf/vczjk/ps4;)V

    if-eqz p1, :cond_1

    iput-boolean v4, p0, Llyiahf/vczjk/zp4;->OooO0OO:Z

    :cond_1
    return-void
.end method

.method public final OooO0oo(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/up4;

    sget-object v1, Llyiahf/vczjk/ye1;->OooOo0:Llyiahf/vczjk/ye1;

    invoke-direct {v0, p2, v1, p3, p4}, Llyiahf/vczjk/up4;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/a91;)V

    iget-object p2, p0, Llyiahf/vczjk/zp4;->OooO0O0:Llyiahf/vczjk/yw;

    invoke-virtual {p2, p1, v0}, Llyiahf/vczjk/yw;->OooO0OO(ILlyiahf/vczjk/ps4;)V

    return-void
.end method
