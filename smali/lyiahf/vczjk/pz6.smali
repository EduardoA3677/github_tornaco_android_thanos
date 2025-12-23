.class public abstract Llyiahf/vczjk/pz6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:I

.field public static final OooO0O0:I


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget v0, Landroidx/customview/poolingcontainer/R$id;->pooling_container_listener_holder_tag:I

    sput v0, Llyiahf/vczjk/pz6;->OooO00o:I

    sget v0, Landroidx/customview/poolingcontainer/R$id;->is_pooling_container_tag:I

    sput v0, Llyiahf/vczjk/pz6;->OooO0O0:I

    return-void
.end method

.method public static final OooO00o(Landroid/view/View;)V
    .locals 3

    const-string v0, "<this>"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/uga;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/uga;-><init>(Landroid/view/View;Llyiahf/vczjk/yo1;)V

    invoke-static {v0}, Llyiahf/vczjk/vl6;->OooOo0(Llyiahf/vczjk/ze3;)Llyiahf/vczjk/xf8;

    move-result-object p0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/xf8;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/xf8;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/view/View;

    invoke-static {v0}, Llyiahf/vczjk/pz6;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/rz6;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/rz6;->OooO00o:Ljava/util/ArrayList;

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo0oo(Ljava/util/List;)I

    move-result v1

    :goto_0
    const/4 v2, -0x1

    if-ge v2, v1, :cond_0

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/qz6;

    check-cast v2, Llyiahf/vczjk/yfa;

    iget-object v2, v2, Llyiahf/vczjk/yfa;->OooO00o:Landroidx/compose/ui/platform/AbstractComposeView;

    invoke-virtual {v2}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0Oo()V

    add-int/lit8 v1, v1, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public static final OooO0O0(Landroid/view/View;)Llyiahf/vczjk/rz6;
    .locals 2

    sget v0, Llyiahf/vczjk/pz6;->OooO00o:I

    invoke-virtual {p0, v0}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/rz6;

    if-nez v1, :cond_0

    new-instance v1, Llyiahf/vczjk/rz6;

    invoke-direct {v1}, Llyiahf/vczjk/rz6;-><init>()V

    invoke-virtual {p0, v0, v1}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    :cond_0
    return-object v1
.end method
