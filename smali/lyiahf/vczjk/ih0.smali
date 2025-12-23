.class public final Llyiahf/vczjk/ih0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $measurePolicy:Llyiahf/vczjk/lf5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lf5;Llyiahf/vczjk/bf3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ih0;->$measurePolicy:Llyiahf/vczjk/lf5;

    iput-object p2, p0, Llyiahf/vczjk/ih0;->$content:Llyiahf/vczjk/bf3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/e89;

    check-cast p2, Llyiahf/vczjk/rk1;

    iget-wide v0, p2, Llyiahf/vczjk/rk1;->OooO00o:J

    new-instance p2, Llyiahf/vczjk/lh0;

    invoke-direct {p2, p1, v0, v1}, Llyiahf/vczjk/lh0;-><init>(Llyiahf/vczjk/e89;J)V

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    new-instance v3, Llyiahf/vczjk/hh0;

    iget-object v4, p0, Llyiahf/vczjk/ih0;->$content:Llyiahf/vczjk/bf3;

    invoke-direct {v3, v4, p2}, Llyiahf/vczjk/hh0;-><init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/lh0;)V

    new-instance p2, Llyiahf/vczjk/a91;

    const v4, -0x73eea2c7

    const/4 v5, 0x1

    invoke-direct {p2, v4, v3, v5}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-interface {p1, v2, p2}, Llyiahf/vczjk/e89;->OooO(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/util/List;

    move-result-object p2

    iget-object v2, p0, Llyiahf/vczjk/ih0;->$measurePolicy:Llyiahf/vczjk/lf5;

    invoke-interface {v2, p1, p2, v0, v1}, Llyiahf/vczjk/lf5;->OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
