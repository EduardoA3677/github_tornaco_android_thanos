.class public final Llyiahf/vczjk/du4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $intervalContentState:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $state:Llyiahf/vczjk/lm6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w62;Llyiahf/vczjk/lm6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/du4;->$intervalContentState:Llyiahf/vczjk/p29;

    iput-object p2, p0, Llyiahf/vczjk/du4;->$state:Llyiahf/vczjk/lm6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/du4;->$intervalContentState:Llyiahf/vczjk/p29;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/el6;

    new-instance v1, Llyiahf/vczjk/uy5;

    iget-object v2, p0, Llyiahf/vczjk/du4;->$state:Llyiahf/vczjk/lm6;

    iget-object v2, v2, Llyiahf/vczjk/lm6;->OooO0Oo:Llyiahf/vczjk/oO00O0o;

    iget-object v2, v2, Llyiahf/vczjk/oO00O0o;->OooO0o0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/wt4;

    invoke-virtual {v2}, Llyiahf/vczjk/wt4;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/x14;

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/uy5;-><init>(Llyiahf/vczjk/x14;Landroidx/compose/foundation/lazy/layout/OooO0O0;)V

    new-instance v2, Llyiahf/vczjk/gl6;

    iget-object v3, p0, Llyiahf/vczjk/du4;->$state:Llyiahf/vczjk/lm6;

    invoke-direct {v2, v3, v0, v1}, Llyiahf/vczjk/gl6;-><init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/el6;Llyiahf/vczjk/uy5;)V

    return-object v2
.end method
