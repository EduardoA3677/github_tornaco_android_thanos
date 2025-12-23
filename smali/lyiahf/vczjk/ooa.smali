.class public final Llyiahf/vczjk/ooa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $insets:Llyiahf/vczjk/poa;

.field final synthetic $view:Landroid/view/View;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/poa;Landroid/view/View;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ooa;->$insets:Llyiahf/vczjk/poa;

    iput-object p2, p0, Llyiahf/vczjk/ooa;->$view:Landroid/view/View;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/qc2;

    iget-object p1, p0, Llyiahf/vczjk/ooa;->$insets:Llyiahf/vczjk/poa;

    iget-object v0, p0, Llyiahf/vczjk/ooa;->$view:Landroid/view/View;

    iget v1, p1, Llyiahf/vczjk/poa;->OooOo00:I

    if-nez v1, :cond_1

    sget-object v1, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    iget-object v1, p1, Llyiahf/vczjk/poa;->OooOo0:Llyiahf/vczjk/a14;

    invoke-static {v0, v1}, Llyiahf/vczjk/ofa;->OooOOO0(Landroid/view/View;Llyiahf/vczjk/u96;)V

    invoke-virtual {v0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-virtual {v0}, Landroid/view/View;->requestApplyInsets()V

    :cond_0
    invoke-virtual {v0, v1}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    invoke-static {v0, v1}, Llyiahf/vczjk/xfa;->OooOOo0(Landroid/view/View;Llyiahf/vczjk/i11;)V

    :cond_1
    iget v0, p1, Llyiahf/vczjk/poa;->OooOo00:I

    add-int/lit8 v0, v0, 0x1

    iput v0, p1, Llyiahf/vczjk/poa;->OooOo00:I

    iget-object p1, p0, Llyiahf/vczjk/ooa;->$insets:Llyiahf/vczjk/poa;

    iget-object v0, p0, Llyiahf/vczjk/ooa;->$view:Landroid/view/View;

    new-instance v1, Llyiahf/vczjk/xb;

    const/16 v2, 0xd

    invoke-direct {v1, v2, p1, v0}, Llyiahf/vczjk/xb;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    return-object v1
.end method
