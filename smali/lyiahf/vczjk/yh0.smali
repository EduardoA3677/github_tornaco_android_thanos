.class public final synthetic Llyiahf/vczjk/yh0;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $boundsProvider:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $childCoordinates:Llyiahf/vczjk/xn4;

.field final synthetic this$0:Llyiahf/vczjk/di0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;)V
    .locals 6

    iput-object p1, p0, Llyiahf/vczjk/yh0;->this$0:Llyiahf/vczjk/di0;

    iput-object p2, p0, Llyiahf/vczjk/yh0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iput-object p3, p0, Llyiahf/vczjk/yh0;->$boundsProvider:Llyiahf/vczjk/le3;

    const-class v2, Llyiahf/vczjk/u34;

    const-string v3, "localRect"

    const/4 v1, 0x0

    const-string v4, "bringIntoView$localRect(Landroidx/compose/foundation/relocation/BringIntoViewResponderNode;Landroidx/compose/ui/layout/LayoutCoordinates;Lkotlin/jvm/functions/Function0;)Landroidx/compose/ui/geometry/Rect;"

    const/4 v5, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/yh0;->this$0:Llyiahf/vczjk/di0;

    iget-object v1, p0, Llyiahf/vczjk/yh0;->$childCoordinates:Llyiahf/vczjk/xn4;

    iget-object v2, p0, Llyiahf/vczjk/yh0;->$boundsProvider:Llyiahf/vczjk/le3;

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/di0;->o00000OO(Llyiahf/vczjk/di0;Llyiahf/vczjk/xn4;Llyiahf/vczjk/le3;)Llyiahf/vczjk/wj7;

    move-result-object v0

    return-object v0
.end method
