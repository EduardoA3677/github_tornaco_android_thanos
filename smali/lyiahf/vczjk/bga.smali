.class public final Llyiahf/vczjk/bga;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $listener:Llyiahf/vczjk/dga;

.field final synthetic $view:Landroidx/compose/ui/platform/AbstractComposeView;


# direct methods
.method public constructor <init>(Landroidx/compose/ui/platform/AbstractComposeView;Llyiahf/vczjk/dga;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bga;->$view:Landroidx/compose/ui/platform/AbstractComposeView;

    iput-object p2, p0, Llyiahf/vczjk/bga;->$listener:Llyiahf/vczjk/dga;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bga;->$view:Landroidx/compose/ui/platform/AbstractComposeView;

    iget-object v1, p0, Llyiahf/vczjk/bga;->$listener:Llyiahf/vczjk/dga;

    invoke-virtual {v0, v1}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
