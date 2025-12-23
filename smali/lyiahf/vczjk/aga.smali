.class public final Llyiahf/vczjk/aga;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnAttachStateChangeListener;


# instance fields
.field public final synthetic OooOOO0:Landroidx/compose/ui/platform/AbstractComposeView;


# direct methods
.method public constructor <init>(Landroidx/compose/ui/platform/AbstractComposeView;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/aga;->OooOOO0:Landroidx/compose/ui/platform/AbstractComposeView;

    return-void
.end method


# virtual methods
.method public final onViewAttachedToWindow(Landroid/view/View;)V
    .locals 0

    return-void
.end method

.method public final onViewDetachedFromWindow(Landroid/view/View;)V
    .locals 4

    sget p1, Llyiahf/vczjk/pz6;->OooO00o:I

    iget-object p1, p0, Llyiahf/vczjk/aga;->OooOOO0:Landroidx/compose/ui/platform/AbstractComposeView;

    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/vga;->OooOOO:Llyiahf/vczjk/vga;

    invoke-static {v0, v1}, Llyiahf/vczjk/ag8;->Oooo0OO(Ljava/lang/Object;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/wf8;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    const/4 v2, 0x0

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroid/view/ViewParent;

    instance-of v3, v1, Landroid/view/View;

    if-eqz v3, :cond_0

    check-cast v1, Landroid/view/View;

    const-string v3, "<this>"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget v3, Llyiahf/vczjk/pz6;->OooO0O0:I

    invoke-virtual {v1, v3}, Landroid/view/View;->getTag(I)Ljava/lang/Object;

    move-result-object v1

    instance-of v3, v1, Ljava/lang/Boolean;

    if-eqz v3, :cond_1

    check-cast v1, Ljava/lang/Boolean;

    goto :goto_0

    :cond_1
    const/4 v1, 0x0

    :goto_0
    if-eqz v1, :cond_2

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v2

    :cond_2
    if-eqz v2, :cond_0

    const/4 v2, 0x1

    :cond_3
    if-nez v2, :cond_4

    invoke-virtual {p1}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0Oo()V

    :cond_4
    return-void
.end method
