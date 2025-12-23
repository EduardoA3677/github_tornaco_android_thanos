.class public final Llyiahf/vczjk/ot4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $executor:Llyiahf/vczjk/i37;

.field final synthetic $itemContentFactory:Llyiahf/vczjk/kt4;

.field final synthetic $prefetchState:Llyiahf/vczjk/ku4;

.field final synthetic $subcomposeLayoutState:Llyiahf/vczjk/d89;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ku4;Llyiahf/vczjk/kt4;Llyiahf/vczjk/d89;Llyiahf/vczjk/i37;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ot4;->$prefetchState:Llyiahf/vczjk/ku4;

    iput-object p2, p0, Llyiahf/vczjk/ot4;->$itemContentFactory:Llyiahf/vczjk/kt4;

    iput-object p3, p0, Llyiahf/vczjk/ot4;->$subcomposeLayoutState:Llyiahf/vczjk/d89;

    iput-object p4, p0, Llyiahf/vczjk/ot4;->$executor:Llyiahf/vczjk/i37;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/ot4;->$prefetchState:Llyiahf/vczjk/ku4;

    new-instance v0, Llyiahf/vczjk/ed5;

    iget-object v1, p0, Llyiahf/vczjk/ot4;->$itemContentFactory:Llyiahf/vczjk/kt4;

    iget-object v2, p0, Llyiahf/vczjk/ot4;->$subcomposeLayoutState:Llyiahf/vczjk/d89;

    iget-object v3, p0, Llyiahf/vczjk/ot4;->$executor:Llyiahf/vczjk/i37;

    const/16 v4, 0xc

    invoke-direct {v0, v1, v2, v4, v3}, Llyiahf/vczjk/ed5;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    iput-object v0, p1, Llyiahf/vczjk/ku4;->OooO0OO:Llyiahf/vczjk/ed5;

    new-instance v0, Llyiahf/vczjk/x;

    const/4 v1, 0x7

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/x;-><init>(Ljava/lang/Object;I)V

    return-object v0
.end method
