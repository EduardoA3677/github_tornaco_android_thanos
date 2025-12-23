.class public final Llyiahf/vczjk/oa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $view:Llyiahf/vczjk/nh;

.field final synthetic this$0:Llyiahf/vczjk/xa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xa;Llyiahf/vczjk/nh;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oa;->this$0:Llyiahf/vczjk/xa;

    iput-object p2, p0, Llyiahf/vczjk/oa;->$view:Llyiahf/vczjk/nh;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/oa;->this$0:Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getAndroidViewsHandler$ui_release()Llyiahf/vczjk/th;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/oa;->$view:Llyiahf/vczjk/nh;

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->removeViewInLayout(Landroid/view/View;)V

    iget-object v0, p0, Llyiahf/vczjk/oa;->this$0:Llyiahf/vczjk/xa;

    invoke-virtual {v0}, Llyiahf/vczjk/xa;->getAndroidViewsHandler$ui_release()Llyiahf/vczjk/th;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/th;->getLayoutNodeToHolder()Ljava/util/HashMap;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/oa;->this$0:Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getAndroidViewsHandler$ui_release()Llyiahf/vczjk/th;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/th;->getHolderToLayoutNode()Ljava/util/HashMap;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/oa;->$view:Llyiahf/vczjk/nh;

    invoke-virtual {v1, v2}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/oa;->$view:Llyiahf/vczjk/nh;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/view/View;->setImportantForAccessibility(I)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
