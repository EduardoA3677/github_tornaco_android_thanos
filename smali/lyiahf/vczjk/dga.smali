.class public final Llyiahf/vczjk/dga;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl7;

.field public final synthetic OooOOO0:Landroidx/compose/ui/platform/AbstractComposeView;


# direct methods
.method public constructor <init>(Landroidx/compose/ui/platform/AbstractComposeView;Llyiahf/vczjk/hl7;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/dga;->OooOOO0:Landroidx/compose/ui/platform/AbstractComposeView;

    iput-object p2, p0, Llyiahf/vczjk/dga;->OooOOO:Llyiahf/vczjk/hl7;

    return-void
.end method


# virtual methods
.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 2

    iget-object p1, p0, Llyiahf/vczjk/dga;->OooOOO0:Landroidx/compose/ui/platform/AbstractComposeView;

    invoke-static {p1}, Llyiahf/vczjk/dr6;->OooOOO(Landroid/view/View;)Llyiahf/vczjk/uy4;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/rl6;->OooO0o(Landroidx/compose/ui/platform/AbstractComposeView;Llyiahf/vczjk/ky4;)Llyiahf/vczjk/fga;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/dga;->OooOOO:Llyiahf/vczjk/hl7;

    iput-object v0, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    return-void

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "View tree for "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " has no ViewTreeLifecycleOwner"

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/pz3;->OooO0OO(Ljava/lang/String;)Ljava/lang/Void;

    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 0

    return-void
.end method
