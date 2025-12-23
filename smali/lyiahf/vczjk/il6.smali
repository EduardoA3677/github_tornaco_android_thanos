.class public final Llyiahf/vczjk/il6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $placementScopeInvalidator:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $positionedPages:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/of5;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Ljava/util/ArrayList;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/il6;->$placementScopeInvalidator:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/il6;->$positionedPages:Ljava/util/List;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/nw6;

    new-instance v0, Llyiahf/vczjk/hl6;

    iget-object v1, p0, Llyiahf/vczjk/il6;->$positionedPages:Ljava/util/List;

    invoke-direct {v0, v1}, Llyiahf/vczjk/hl6;-><init>(Ljava/util/List;)V

    const/4 v1, 0x1

    iput-boolean v1, p1, Llyiahf/vczjk/nw6;->OooO00o:Z

    invoke-virtual {v0, p1}, Llyiahf/vczjk/hl6;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v0, 0x0

    iput-boolean v0, p1, Llyiahf/vczjk/nw6;->OooO00o:Z

    iget-object p1, p0, Llyiahf/vczjk/il6;->$placementScopeInvalidator:Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
