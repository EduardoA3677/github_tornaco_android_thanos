.class public final Llyiahf/vczjk/lk6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $consumeFlingNestedScrollConnection:Llyiahf/vczjk/ll1;

.field final synthetic $content:Llyiahf/vczjk/df3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/df3;"
        }
    .end annotation
.end field

.field final synthetic $count:I

.field final synthetic $key:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $pagerScope:Llyiahf/vczjk/pl6;


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/oe3;Llyiahf/vczjk/ll1;Llyiahf/vczjk/df3;Llyiahf/vczjk/pl6;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/lk6;->$count:I

    iput-object p2, p0, Llyiahf/vczjk/lk6;->$key:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/lk6;->$consumeFlingNestedScrollConnection:Llyiahf/vczjk/ll1;

    iput-object p4, p0, Llyiahf/vczjk/lk6;->$content:Llyiahf/vczjk/df3;

    iput-object p5, p0, Llyiahf/vczjk/lk6;->$pagerScope:Llyiahf/vczjk/pl6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/fv4;

    const-string v0, "$this$LazyRow"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget v0, p0, Llyiahf/vczjk/lk6;->$count:I

    iget-object v1, p0, Llyiahf/vczjk/lk6;->$key:Llyiahf/vczjk/oe3;

    new-instance v2, Llyiahf/vczjk/kk6;

    iget-object v3, p0, Llyiahf/vczjk/lk6;->$consumeFlingNestedScrollConnection:Llyiahf/vczjk/ll1;

    iget-object v4, p0, Llyiahf/vczjk/lk6;->$content:Llyiahf/vczjk/df3;

    iget-object v5, p0, Llyiahf/vczjk/lk6;->$pagerScope:Llyiahf/vczjk/pl6;

    invoke-direct {v2, v3, v4, v5}, Llyiahf/vczjk/kk6;-><init>(Llyiahf/vczjk/ll1;Llyiahf/vczjk/df3;Llyiahf/vczjk/pl6;)V

    new-instance v3, Llyiahf/vczjk/a91;

    const v4, -0x434ab74

    const/4 v5, 0x1

    invoke-direct {v3, v4, v2, v5}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    const/4 v2, 0x4

    invoke-static {p1, v0, v1, v3, v2}, Llyiahf/vczjk/fv4;->OooO(Llyiahf/vczjk/fv4;ILlyiahf/vczjk/oe3;Llyiahf/vczjk/a91;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
