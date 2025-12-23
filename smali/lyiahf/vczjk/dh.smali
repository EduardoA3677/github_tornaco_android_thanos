.class public final Llyiahf/vczjk/dh;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $layoutNode:Llyiahf/vczjk/ro4;

.field final synthetic $this_run:Llyiahf/vczjk/nh;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/dh;->$this_run:Llyiahf/vczjk/nh;

    iput-object p2, p0, Llyiahf/vczjk/dh;->$layoutNode:Llyiahf/vczjk/ro4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/tg6;

    instance-of v0, p1, Llyiahf/vczjk/xa;

    if-eqz v0, :cond_0

    check-cast p1, Llyiahf/vczjk/xa;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/dh;->$this_run:Llyiahf/vczjk/nh;

    iget-object v1, p0, Llyiahf/vczjk/dh;->$layoutNode:Llyiahf/vczjk/ro4;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getAndroidViewsHandler$ui_release()Llyiahf/vczjk/th;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/th;->getHolderToLayoutNode()Ljava/util/HashMap;

    move-result-object v2

    invoke-interface {v2, v0, v1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getAndroidViewsHandler$ui_release()Llyiahf/vczjk/th;

    move-result-object v2

    invoke-virtual {v2, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    invoke-virtual {p1}, Llyiahf/vczjk/xa;->getAndroidViewsHandler$ui_release()Llyiahf/vczjk/th;

    move-result-object v2

    invoke-virtual {v2}, Llyiahf/vczjk/th;->getLayoutNodeToHolder()Ljava/util/HashMap;

    move-result-object v2

    invoke-interface {v2, v1, v0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v2, 0x1

    invoke-virtual {v0, v2}, Landroid/view/View;->setImportantForAccessibility(I)V

    new-instance v2, Llyiahf/vczjk/ca;

    invoke-direct {v2, p1, v1, p1}, Llyiahf/vczjk/ca;-><init>(Llyiahf/vczjk/xa;Llyiahf/vczjk/ro4;Llyiahf/vczjk/xa;)V

    invoke-static {v0, v2}, Llyiahf/vczjk/xfa;->OooOOOO(Landroid/view/View;Llyiahf/vczjk/o0oO0Ooo;)V

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/dh;->$this_run:Llyiahf/vczjk/nh;

    invoke-virtual {p1}, Llyiahf/vczjk/nh;->getView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/dh;->$this_run:Llyiahf/vczjk/nh;

    if-eq p1, v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getView()Landroid/view/View;

    move-result-object p1

    invoke-virtual {v0, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
