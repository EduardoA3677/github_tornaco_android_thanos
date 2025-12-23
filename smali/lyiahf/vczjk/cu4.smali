.class public final Llyiahf/vczjk/cu4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $latestContent:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $latestKey:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $pageCount:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/qs5;Llyiahf/vczjk/le3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cu4;->$latestContent:Llyiahf/vczjk/p29;

    iput-object p2, p0, Llyiahf/vczjk/cu4;->$latestKey:Llyiahf/vczjk/p29;

    iput-object p3, p0, Llyiahf/vczjk/cu4;->$pageCount:Llyiahf/vczjk/le3;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    new-instance v0, Llyiahf/vczjk/el6;

    iget-object v1, p0, Llyiahf/vczjk/cu4;->$latestContent:Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/df3;

    iget-object v2, p0, Llyiahf/vczjk/cu4;->$latestKey:Llyiahf/vczjk/p29;

    invoke-interface {v2}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/cu4;->$pageCount:Llyiahf/vczjk/le3;

    invoke-interface {v3}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    move-result v3

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/el6;-><init>(Llyiahf/vczjk/df3;Llyiahf/vczjk/oe3;I)V

    return-object v0
.end method
