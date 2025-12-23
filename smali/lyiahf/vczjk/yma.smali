.class public final Llyiahf/vczjk/yma;
.super Llyiahf/vczjk/tp6;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/ana;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ana;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/yma;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/yma;->OooO0O0:Llyiahf/vczjk/ana;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0O0(Landroid/view/View;)V
    .locals 3

    iget-object p1, p0, Llyiahf/vczjk/yma;->OooO0O0:Llyiahf/vczjk/ana;

    const/4 v0, 0x0

    iget v1, p0, Llyiahf/vczjk/yma;->OooO00o:I

    packed-switch v1, :pswitch_data_0

    iput-object v0, p1, Llyiahf/vczjk/ana;->OoooOo0:Llyiahf/vczjk/gia;

    iget-object p1, p1, Llyiahf/vczjk/ana;->Oooo0O0:Landroidx/appcompat/widget/ActionBarContainer;

    invoke-virtual {p1}, Landroid/view/View;->requestLayout()V

    return-void

    :pswitch_0
    iget-boolean v1, p1, Llyiahf/vczjk/ana;->OoooOO0:Z

    if-eqz v1, :cond_0

    iget-object v1, p1, Llyiahf/vczjk/ana;->Oooo0o:Landroid/view/View;

    if-eqz v1, :cond_0

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/view/View;->setTranslationY(F)V

    iget-object v1, p1, Llyiahf/vczjk/ana;->Oooo0O0:Landroidx/appcompat/widget/ActionBarContainer;

    invoke-virtual {v1, v2}, Landroid/view/View;->setTranslationY(F)V

    :cond_0
    iget-object v1, p1, Llyiahf/vczjk/ana;->Oooo0O0:Landroidx/appcompat/widget/ActionBarContainer;

    const/16 v2, 0x8

    invoke-virtual {v1, v2}, Landroidx/appcompat/widget/ActionBarContainer;->setVisibility(I)V

    iget-object v1, p1, Llyiahf/vczjk/ana;->Oooo0O0:Landroidx/appcompat/widget/ActionBarContainer;

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroidx/appcompat/widget/ActionBarContainer;->setTransitioning(Z)V

    iput-object v0, p1, Llyiahf/vczjk/ana;->OoooOo0:Llyiahf/vczjk/gia;

    iget-object v1, p1, Llyiahf/vczjk/ana;->OoooO00:Llyiahf/vczjk/a27;

    if-eqz v1, :cond_1

    iget-object v2, p1, Llyiahf/vczjk/ana;->Oooo:Llyiahf/vczjk/zma;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/a27;->OooOO0O(Llyiahf/vczjk/oO0Oo0oo;)V

    iput-object v0, p1, Llyiahf/vczjk/ana;->Oooo:Llyiahf/vczjk/zma;

    iput-object v0, p1, Llyiahf/vczjk/ana;->OoooO00:Llyiahf/vczjk/a27;

    :cond_1
    iget-object p1, p1, Llyiahf/vczjk/ana;->Oooo0:Landroidx/appcompat/widget/ActionBarOverlayLayout;

    if-eqz p1, :cond_2

    sget-object v0, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    invoke-static {p1}, Llyiahf/vczjk/mfa;->OooO0OO(Landroid/view/View;)V

    :cond_2
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
