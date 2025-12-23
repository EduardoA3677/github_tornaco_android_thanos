.class public final Llyiahf/vczjk/oj8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $shadowNodesWithLayoutInfo:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Llyiahf/vczjk/bo4;",
            "Ljava/util/List<",
            "Llyiahf/vczjk/xn6;",
            ">;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/LinkedHashMap;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oj8;->$shadowNodesWithLayoutInfo:Ljava/util/Map;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/nj8;

    iget-object v0, p0, Llyiahf/vczjk/oj8;->$shadowNodesWithLayoutInfo:Ljava/util/Map;

    iget-object p1, p1, Llyiahf/vczjk/nj8;->OooO0O0:Llyiahf/vczjk/rga;

    iget-object p1, p1, Llyiahf/vczjk/rga;->OooO0o:Llyiahf/vczjk/bo4;

    const/4 v1, 0x0

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    move-object p1, v1

    :goto_0
    if-eqz p1, :cond_1

    check-cast p1, Llyiahf/vczjk/ro4;

    invoke-virtual {p1}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v1

    :cond_1
    invoke-interface {v0, v1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/util/List;

    if-nez p1, :cond_2

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :cond_2
    return-object p1
.end method
