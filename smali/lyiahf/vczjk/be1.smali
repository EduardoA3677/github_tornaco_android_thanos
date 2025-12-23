.class public final Llyiahf/vczjk/be1;
.super Llyiahf/vczjk/ak1;
.source "SourceFile"


# instance fields
.field public OooO:Llyiahf/vczjk/oe3;

.field public final OooO0oO:Llyiahf/vczjk/ae1;

.field public final OooO0oo:Llyiahf/vczjk/a91;

.field public OooOO0:Llyiahf/vczjk/oe3;

.field public OooOO0O:Llyiahf/vczjk/oe3;

.field public OooOO0o:Llyiahf/vczjk/oe3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ae1;Ljava/lang/String;Llyiahf/vczjk/a91;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/ak1;-><init>(Llyiahf/vczjk/sy5;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/be1;->OooO0oO:Llyiahf/vczjk/ae1;

    iput-object p3, p0, Llyiahf/vczjk/be1;->OooO0oo:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final OooO0OO()Llyiahf/vczjk/av5;
    .locals 2

    invoke-super {p0}, Llyiahf/vczjk/ak1;->OooO0OO()Llyiahf/vczjk/av5;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/zd1;

    iget-object v1, p0, Llyiahf/vczjk/be1;->OooO:Llyiahf/vczjk/oe3;

    iput-object v1, v0, Llyiahf/vczjk/zd1;->OooOOoo:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/be1;->OooOO0:Llyiahf/vczjk/oe3;

    iput-object v1, v0, Llyiahf/vczjk/zd1;->OooOo00:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/be1;->OooOO0O:Llyiahf/vczjk/oe3;

    iput-object v1, v0, Llyiahf/vczjk/zd1;->OooOo0:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/be1;->OooOO0o:Llyiahf/vczjk/oe3;

    iput-object v1, v0, Llyiahf/vczjk/zd1;->OooOo0O:Llyiahf/vczjk/oe3;

    return-object v0
.end method

.method public final OooO0o()Llyiahf/vczjk/av5;
    .locals 3

    new-instance v0, Llyiahf/vczjk/zd1;

    iget-object v1, p0, Llyiahf/vczjk/be1;->OooO0oO:Llyiahf/vczjk/ae1;

    iget-object v2, p0, Llyiahf/vczjk/be1;->OooO0oo:Llyiahf/vczjk/a91;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/zd1;-><init>(Llyiahf/vczjk/ae1;Llyiahf/vczjk/a91;)V

    return-object v0
.end method
