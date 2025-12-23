.class public final Llyiahf/vczjk/ju8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo0:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;JJ)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ju8;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/ju8;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/ju8;->OooOOOO:Llyiahf/vczjk/a91;

    iput-wide p4, p0, Llyiahf/vczjk/ju8;->OooOOOo:J

    iput-wide p6, p0, Llyiahf/vczjk/ju8;->OooOOo0:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    and-int/2addr p2, v2

    check-cast p1, Llyiahf/vczjk/zf1;

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p2

    if-eqz p2, :cond_1

    sget-object p2, Llyiahf/vczjk/pu8;->OooO0oo:Llyiahf/vczjk/p6a;

    invoke-static {p2, p1}, Llyiahf/vczjk/q6a;->OooO00o(Llyiahf/vczjk/p6a;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/rn9;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/pu8;->OooO0O0:Llyiahf/vczjk/p6a;

    invoke-static {v0, p1}, Llyiahf/vczjk/q6a;->OooO00o(Llyiahf/vczjk/p6a;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/rn9;

    move-result-object v5

    sget-object v0, Llyiahf/vczjk/gm9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/jh1;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p2

    new-instance v1, Llyiahf/vczjk/iu8;

    iget-object v3, p0, Llyiahf/vczjk/ju8;->OooOOO:Llyiahf/vczjk/a91;

    iget-wide v6, p0, Llyiahf/vczjk/ju8;->OooOOOo:J

    iget-wide v8, p0, Llyiahf/vczjk/ju8;->OooOOo0:J

    iget-object v2, p0, Llyiahf/vczjk/ju8;->OooOOO0:Llyiahf/vczjk/a91;

    iget-object v4, p0, Llyiahf/vczjk/ju8;->OooOOOO:Llyiahf/vczjk/a91;

    invoke-direct/range {v1 .. v9}, Llyiahf/vczjk/iu8;-><init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJ)V

    const v0, 0x39cbc4b1

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/16 v1, 0x38

    invoke-static {p2, v0, p1, v1}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    goto :goto_1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
