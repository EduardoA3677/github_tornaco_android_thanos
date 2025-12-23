.class public final Llyiahf/vczjk/zfa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $listener:Llyiahf/vczjk/aga;

.field final synthetic $poolingContainerListener:Llyiahf/vczjk/qz6;

.field final synthetic $view:Landroidx/compose/ui/platform/AbstractComposeView;


# direct methods
.method public constructor <init>(Landroidx/compose/ui/platform/AbstractComposeView;Llyiahf/vczjk/aga;Llyiahf/vczjk/yfa;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/zfa;->$view:Landroidx/compose/ui/platform/AbstractComposeView;

    iput-object p2, p0, Llyiahf/vczjk/zfa;->$listener:Llyiahf/vczjk/aga;

    iput-object p3, p0, Llyiahf/vczjk/zfa;->$poolingContainerListener:Llyiahf/vczjk/qz6;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/zfa;->$view:Landroidx/compose/ui/platform/AbstractComposeView;

    iget-object v1, p0, Llyiahf/vczjk/zfa;->$listener:Llyiahf/vczjk/aga;

    invoke-virtual {v0, v1}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    iget-object v0, p0, Llyiahf/vczjk/zfa;->$view:Landroidx/compose/ui/platform/AbstractComposeView;

    iget-object v1, p0, Llyiahf/vczjk/zfa;->$poolingContainerListener:Llyiahf/vczjk/qz6;

    sget v2, Llyiahf/vczjk/pz6;->OooO00o:I

    const-string v2, "<this>"

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v2, "listener"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v0}, Llyiahf/vczjk/pz6;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/rz6;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/rz6;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
