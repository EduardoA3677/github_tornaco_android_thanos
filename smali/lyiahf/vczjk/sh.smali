.class public final Llyiahf/vczjk/sh;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $compositeKeyHash:I

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $factory:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $ownerView:Landroid/view/View;

.field final synthetic $parentReference:Llyiahf/vczjk/lg1;

.field final synthetic $stateRegistry:Llyiahf/vczjk/t58;


# direct methods
.method public constructor <init>(Landroid/content/Context;Llyiahf/vczjk/oe3;Landroidx/compose/runtime/OooO00o;Llyiahf/vczjk/t58;ILandroid/view/View;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sh;->$context:Landroid/content/Context;

    iput-object p2, p0, Llyiahf/vczjk/sh;->$factory:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/sh;->$parentReference:Llyiahf/vczjk/lg1;

    iput-object p4, p0, Llyiahf/vczjk/sh;->$stateRegistry:Llyiahf/vczjk/t58;

    iput p5, p0, Llyiahf/vczjk/sh;->$compositeKeyHash:I

    iput-object p6, p0, Llyiahf/vczjk/sh;->$ownerView:Landroid/view/View;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    new-instance v0, Llyiahf/vczjk/nga;

    iget-object v1, p0, Llyiahf/vczjk/sh;->$context:Landroid/content/Context;

    iget-object v2, p0, Llyiahf/vczjk/sh;->$factory:Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/sh;->$parentReference:Llyiahf/vczjk/lg1;

    iget-object v4, p0, Llyiahf/vczjk/sh;->$stateRegistry:Llyiahf/vczjk/t58;

    iget v5, p0, Llyiahf/vczjk/sh;->$compositeKeyHash:I

    iget-object v6, p0, Llyiahf/vczjk/sh;->$ownerView:Landroid/view/View;

    const-string v7, "null cannot be cast to non-null type androidx.compose.ui.node.Owner"

    invoke-static {v6, v7}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v6, Llyiahf/vczjk/tg6;

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/nga;-><init>(Landroid/content/Context;Llyiahf/vczjk/oe3;Llyiahf/vczjk/lg1;Llyiahf/vczjk/t58;ILlyiahf/vczjk/tg6;)V

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getLayoutNode()Llyiahf/vczjk/ro4;

    move-result-object v0

    return-object v0
.end method
