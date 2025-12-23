.class public final Llyiahf/vczjk/pt4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $itemContentFactory:Llyiahf/vczjk/kt4;

.field final synthetic $measurePolicy:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kt4;Llyiahf/vczjk/ze3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/pt4;->$itemContentFactory:Llyiahf/vczjk/kt4;

    iput-object p2, p0, Llyiahf/vczjk/pt4;->$measurePolicy:Llyiahf/vczjk/ze3;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/e89;

    check-cast p2, Llyiahf/vczjk/rk1;

    iget-wide v0, p2, Llyiahf/vczjk/rk1;->OooO00o:J

    new-instance p2, Llyiahf/vczjk/tt4;

    iget-object v2, p0, Llyiahf/vczjk/pt4;->$itemContentFactory:Llyiahf/vczjk/kt4;

    invoke-direct {p2, v2, p1}, Llyiahf/vczjk/tt4;-><init>(Llyiahf/vczjk/kt4;Llyiahf/vczjk/e89;)V

    iget-object p1, p0, Llyiahf/vczjk/pt4;->$measurePolicy:Llyiahf/vczjk/ze3;

    new-instance v2, Llyiahf/vczjk/rk1;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/rk1;-><init>(J)V

    invoke-interface {p1, p2, v2}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/mf5;

    return-object p1
.end method
