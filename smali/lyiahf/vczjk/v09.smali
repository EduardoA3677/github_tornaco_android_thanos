.class public final Llyiahf/vczjk/v09;
.super Llyiahf/vczjk/uh5;
.source "SourceFile"

# interfaces
.implements Landroid/widget/PopupWindow$OnDismissListener;
.implements Landroid/view/View$OnKeyListener;


# static fields
.field public static final Oooo00o:I


# instance fields
.field public final OooOOO:Landroid/content/Context;

.field public final OooOOOO:Llyiahf/vczjk/sg5;

.field public final OooOOOo:Llyiahf/vczjk/pg5;

.field public final OooOOo:I

.field public final OooOOo0:Z

.field public final OooOOoo:I

.field public OooOo:Llyiahf/vczjk/vh5;

.field public final OooOo0:Landroidx/appcompat/widget/OooO0o;

.field public final OooOo00:I

.field public final OooOo0O:Llyiahf/vczjk/oOo000o0;

.field public final OooOo0o:Llyiahf/vczjk/ab;

.field public OooOoO:Landroid/view/View;

.field public OooOoO0:Landroid/view/View;

.field public OooOoOO:Llyiahf/vczjk/ci5;

.field public OooOoo:Z

.field public OooOoo0:Landroid/view/ViewTreeObserver;

.field public OooOooO:Z

.field public OooOooo:I

.field public Oooo000:I

.field public Oooo00O:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget v0, Landroidx/appcompat/R$layout;->abc_popup_menu_item_layout:I

    sput v0, Llyiahf/vczjk/v09;->Oooo00o:I

    return-void
.end method

.method public constructor <init>(IILandroid/content/Context;Landroid/view/View;Llyiahf/vczjk/sg5;Z)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/oOo000o0;

    const/4 v1, 0x5

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/oOo000o0;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/v09;->OooOo0O:Llyiahf/vczjk/oOo000o0;

    new-instance v0, Llyiahf/vczjk/ab;

    const/16 v1, 0x8

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/ab;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/v09;->OooOo0o:Llyiahf/vczjk/ab;

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/v09;->Oooo000:I

    iput-object p3, p0, Llyiahf/vczjk/v09;->OooOOO:Landroid/content/Context;

    iput-object p5, p0, Llyiahf/vczjk/v09;->OooOOOO:Llyiahf/vczjk/sg5;

    iput-boolean p6, p0, Llyiahf/vczjk/v09;->OooOOo0:Z

    invoke-static {p3}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/pg5;

    sget v2, Llyiahf/vczjk/v09;->Oooo00o:I

    invoke-direct {v1, p5, v0, p6, v2}, Llyiahf/vczjk/pg5;-><init>(Llyiahf/vczjk/sg5;Landroid/view/LayoutInflater;ZI)V

    iput-object v1, p0, Llyiahf/vczjk/v09;->OooOOOo:Llyiahf/vczjk/pg5;

    iput p1, p0, Llyiahf/vczjk/v09;->OooOOoo:I

    iput p2, p0, Llyiahf/vczjk/v09;->OooOo00:I

    invoke-virtual {p3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p6

    invoke-virtual {p6}, Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;

    move-result-object v0

    iget v0, v0, Landroid/util/DisplayMetrics;->widthPixels:I

    div-int/lit8 v0, v0, 0x2

    sget v1, Landroidx/appcompat/R$dimen;->abc_config_prefDialogWidth:I

    invoke-virtual {p6, v1}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    move-result p6

    invoke-static {v0, p6}, Ljava/lang/Math;->max(II)I

    move-result p6

    iput p6, p0, Llyiahf/vczjk/v09;->OooOOo:I

    iput-object p4, p0, Llyiahf/vczjk/v09;->OooOoO0:Landroid/view/View;

    new-instance p4, Landroidx/appcompat/widget/OooO0o;

    const/4 p6, 0x0

    invoke-direct {p4, p3, p6, p1, p2}, Landroidx/appcompat/widget/ListPopupWindow;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    iput-object p4, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    invoke-virtual {p5, p0, p3}, Llyiahf/vczjk/sg5;->OooO0O0(Llyiahf/vczjk/di5;Landroid/content/Context;)V

    return-void
.end method


# virtual methods
.method public final OooO(Landroid/os/Parcelable;)V
    .locals 0

    return-void
.end method

.method public final OooO00o()Z
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/v09;->OooOoo:Z

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    iget-object v0, v0, Landroidx/appcompat/widget/ListPopupWindow;->Oooo0o0:Landroid/widget/PopupWindow;

    invoke-virtual {v0}, Landroid/widget/PopupWindow;->isShowing()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0O0(Llyiahf/vczjk/ci5;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v09;->OooOoOO:Llyiahf/vczjk/ci5;

    return-void
.end method

.method public final OooO0OO(Z)V
    .locals 0

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/v09;->OooOooO:Z

    iget-object p1, p0, Llyiahf/vczjk/v09;->OooOOOo:Llyiahf/vczjk/pg5;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/pg5;->notifyDataSetChanged()V

    :cond_0
    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/u79;)Z
    .locals 9

    invoke-virtual {p1}, Llyiahf/vczjk/sg5;->hasVisibleItems()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_5

    new-instance v2, Llyiahf/vczjk/wh5;

    iget-object v6, p0, Llyiahf/vczjk/v09;->OooOoO:Landroid/view/View;

    iget-object v5, p0, Llyiahf/vczjk/v09;->OooOOO:Landroid/content/Context;

    iget-boolean v8, p0, Llyiahf/vczjk/v09;->OooOOo0:Z

    iget v3, p0, Llyiahf/vczjk/v09;->OooOOoo:I

    iget v4, p0, Llyiahf/vczjk/v09;->OooOo00:I

    move-object v7, p1

    invoke-direct/range {v2 .. v8}, Llyiahf/vczjk/wh5;-><init>(IILandroid/content/Context;Landroid/view/View;Llyiahf/vczjk/sg5;Z)V

    iget-object p1, p0, Llyiahf/vczjk/v09;->OooOoOO:Llyiahf/vczjk/ci5;

    iput-object p1, v2, Llyiahf/vczjk/wh5;->OooO:Llyiahf/vczjk/ci5;

    iget-object v0, v2, Llyiahf/vczjk/wh5;->OooOO0:Llyiahf/vczjk/uh5;

    if-eqz v0, :cond_0

    invoke-interface {v0, p1}, Llyiahf/vczjk/di5;->OooO0O0(Llyiahf/vczjk/ci5;)V

    :cond_0
    invoke-static {v7}, Llyiahf/vczjk/uh5;->OooOo0o(Llyiahf/vczjk/sg5;)Z

    move-result p1

    invoke-virtual {v2, p1}, Llyiahf/vczjk/wh5;->OooO0Oo(Z)V

    iget-object p1, p0, Llyiahf/vczjk/v09;->OooOo:Llyiahf/vczjk/vh5;

    iput-object p1, v2, Llyiahf/vczjk/wh5;->OooOO0O:Landroid/widget/PopupWindow$OnDismissListener;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/v09;->OooOo:Llyiahf/vczjk/vh5;

    iget-object p1, p0, Llyiahf/vczjk/v09;->OooOOOO:Llyiahf/vczjk/sg5;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/sg5;->OooO0OO(Z)V

    iget-object p1, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    iget v0, p1, Landroidx/appcompat/widget/ListPopupWindow;->OooOOo:I

    invoke-virtual {p1}, Landroidx/appcompat/widget/ListPopupWindow;->OooOOOO()I

    move-result p1

    iget v3, p0, Llyiahf/vczjk/v09;->Oooo000:I

    iget-object v4, p0, Llyiahf/vczjk/v09;->OooOoO0:Landroid/view/View;

    invoke-virtual {v4}, Landroid/view/View;->getLayoutDirection()I

    move-result v4

    invoke-static {v3, v4}, Landroid/view/Gravity;->getAbsoluteGravity(II)I

    move-result v3

    and-int/lit8 v3, v3, 0x7

    const/4 v4, 0x5

    if-ne v3, v4, :cond_1

    iget-object v3, p0, Llyiahf/vczjk/v09;->OooOoO0:Landroid/view/View;

    invoke-virtual {v3}, Landroid/view/View;->getWidth()I

    move-result v3

    add-int/2addr v0, v3

    :cond_1
    invoke-virtual {v2}, Llyiahf/vczjk/wh5;->OooO0O0()Z

    move-result v3

    const/4 v4, 0x1

    if-eqz v3, :cond_2

    goto :goto_0

    :cond_2
    iget-object v3, v2, Llyiahf/vczjk/wh5;->OooO0o:Landroid/view/View;

    if-nez v3, :cond_3

    goto :goto_1

    :cond_3
    invoke-virtual {v2, v0, p1, v4, v4}, Llyiahf/vczjk/wh5;->OooO0o(IIZZ)V

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/v09;->OooOoOO:Llyiahf/vczjk/ci5;

    if-eqz p1, :cond_4

    invoke-interface {p1, v7}, Llyiahf/vczjk/ci5;->OoooO0(Llyiahf/vczjk/sg5;)Z

    :cond_4
    return v4

    :cond_5
    :goto_1
    return v1
.end method

.method public final OooO0o0(Llyiahf/vczjk/sg5;Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOOOO:Llyiahf/vczjk/sg5;

    if-eq p1, v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/v09;->dismiss()V

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOoOO:Llyiahf/vczjk/ci5;

    if-eqz v0, :cond_1

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/ci5;->OooO0o0(Llyiahf/vczjk/sg5;Z)V

    :cond_1
    :goto_0
    return-void
.end method

.method public final OooO0oO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0oo()V
    .locals 8

    invoke-virtual {p0}, Llyiahf/vczjk/v09;->OooO00o()Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/v09;->OooOoo:Z

    if-nez v0, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOoO0:Landroid/view/View;

    if-eqz v0, :cond_7

    iput-object v0, p0, Llyiahf/vczjk/v09;->OooOoO:Landroid/view/View;

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    iget-object v1, v0, Landroidx/appcompat/widget/ListPopupWindow;->Oooo0o0:Landroid/widget/PopupWindow;

    invoke-virtual {v1, p0}, Landroid/widget/PopupWindow;->setOnDismissListener(Landroid/widget/PopupWindow$OnDismissListener;)V

    iput-object p0, v0, Landroidx/appcompat/widget/ListPopupWindow;->OooOoo0:Landroid/widget/AdapterView$OnItemClickListener;

    const/4 v1, 0x1

    iput-boolean v1, v0, Landroidx/appcompat/widget/ListPopupWindow;->Oooo0OO:Z

    iget-object v2, v0, Landroidx/appcompat/widget/ListPopupWindow;->Oooo0o0:Landroid/widget/PopupWindow;

    invoke-virtual {v2, v1}, Landroid/widget/PopupWindow;->setFocusable(Z)V

    iget-object v2, p0, Llyiahf/vczjk/v09;->OooOoO:Landroid/view/View;

    iget-object v3, p0, Llyiahf/vczjk/v09;->OooOoo0:Landroid/view/ViewTreeObserver;

    const/4 v4, 0x0

    if-nez v3, :cond_1

    move v3, v1

    goto :goto_0

    :cond_1
    move v3, v4

    :goto_0
    invoke-virtual {v2}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v5

    iput-object v5, p0, Llyiahf/vczjk/v09;->OooOoo0:Landroid/view/ViewTreeObserver;

    if-eqz v3, :cond_2

    iget-object v3, p0, Llyiahf/vczjk/v09;->OooOo0O:Llyiahf/vczjk/oOo000o0;

    invoke-virtual {v5, v3}, Landroid/view/ViewTreeObserver;->addOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    :cond_2
    iget-object v3, p0, Llyiahf/vczjk/v09;->OooOo0o:Llyiahf/vczjk/ab;

    invoke-virtual {v2, v3}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    iput-object v2, v0, Landroidx/appcompat/widget/ListPopupWindow;->OooOoOO:Landroid/view/View;

    iget v2, p0, Llyiahf/vczjk/v09;->Oooo000:I

    iput v2, v0, Landroidx/appcompat/widget/ListPopupWindow;->OooOo:I

    iget-boolean v2, p0, Llyiahf/vczjk/v09;->OooOooO:Z

    iget-object v3, p0, Llyiahf/vczjk/v09;->OooOOO:Landroid/content/Context;

    iget-object v5, p0, Llyiahf/vczjk/v09;->OooOOOo:Llyiahf/vczjk/pg5;

    if-nez v2, :cond_3

    iget v2, p0, Llyiahf/vczjk/v09;->OooOOo:I

    invoke-static {v5, v3, v2}, Llyiahf/vczjk/uh5;->OooOOOO(Landroid/widget/ListAdapter;Landroid/content/Context;I)I

    move-result v2

    iput v2, p0, Llyiahf/vczjk/v09;->OooOooo:I

    iput-boolean v1, p0, Llyiahf/vczjk/v09;->OooOooO:Z

    :cond_3
    iget v1, p0, Llyiahf/vczjk/v09;->OooOooo:I

    invoke-virtual {v0, v1}, Landroidx/appcompat/widget/ListPopupWindow;->OooOOo(I)V

    iget-object v1, v0, Landroidx/appcompat/widget/ListPopupWindow;->Oooo0o0:Landroid/widget/PopupWindow;

    const/4 v2, 0x2

    invoke-virtual {v1, v2}, Landroid/widget/PopupWindow;->setInputMethodMode(I)V

    iget-object v1, p0, Llyiahf/vczjk/uh5;->OooOOO0:Landroid/graphics/Rect;

    const/4 v2, 0x0

    if-eqz v1, :cond_4

    new-instance v6, Landroid/graphics/Rect;

    invoke-direct {v6, v1}, Landroid/graphics/Rect;-><init>(Landroid/graphics/Rect;)V

    goto :goto_1

    :cond_4
    move-object v6, v2

    :goto_1
    iput-object v6, v0, Landroidx/appcompat/widget/ListPopupWindow;->Oooo0O0:Landroid/graphics/Rect;

    invoke-virtual {v0}, Landroidx/appcompat/widget/ListPopupWindow;->OooO0oo()V

    iget-object v1, v0, Landroidx/appcompat/widget/ListPopupWindow;->OooOOOO:Llyiahf/vczjk/xi2;

    invoke-virtual {v1, p0}, Landroid/view/View;->setOnKeyListener(Landroid/view/View$OnKeyListener;)V

    iget-boolean v6, p0, Llyiahf/vczjk/v09;->Oooo00O:Z

    if-eqz v6, :cond_6

    iget-object v6, p0, Llyiahf/vczjk/v09;->OooOOOO:Llyiahf/vczjk/sg5;

    iget-object v7, v6, Llyiahf/vczjk/sg5;->OooOOO0:Ljava/lang/CharSequence;

    if-eqz v7, :cond_6

    invoke-static {v3}, Landroid/view/LayoutInflater;->from(Landroid/content/Context;)Landroid/view/LayoutInflater;

    move-result-object v3

    sget v7, Landroidx/appcompat/R$layout;->abc_popup_menu_header_item_layout:I

    invoke-virtual {v3, v7, v1, v4}, Landroid/view/LayoutInflater;->inflate(ILandroid/view/ViewGroup;Z)Landroid/view/View;

    move-result-object v3

    check-cast v3, Landroid/widget/FrameLayout;

    const v7, 0x1020016

    invoke-virtual {v3, v7}, Landroid/view/View;->findViewById(I)Landroid/view/View;

    move-result-object v7

    check-cast v7, Landroid/widget/TextView;

    if-eqz v7, :cond_5

    iget-object v6, v6, Llyiahf/vczjk/sg5;->OooOOO0:Ljava/lang/CharSequence;

    invoke-virtual {v7, v6}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    :cond_5
    invoke-virtual {v3, v4}, Landroid/view/View;->setEnabled(Z)V

    invoke-virtual {v1, v3, v2, v4}, Landroid/widget/ListView;->addHeaderView(Landroid/view/View;Ljava/lang/Object;Z)V

    :cond_6
    invoke-virtual {v0, v5}, Landroidx/appcompat/widget/ListPopupWindow;->OooOOOo(Landroid/widget/ListAdapter;)V

    invoke-virtual {v0}, Landroidx/appcompat/widget/ListPopupWindow;->OooO0oo()V

    return-void

    :cond_7
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "StandardMenuPopup cannot be used without an anchor"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooOO0O()Llyiahf/vczjk/xi2;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    iget-object v0, v0, Landroidx/appcompat/widget/ListPopupWindow;->OooOOOO:Llyiahf/vczjk/xi2;

    return-object v0
.end method

.method public final OooOO0o()Landroid/os/Parcelable;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOOO(Llyiahf/vczjk/sg5;)V
    .locals 0

    return-void
.end method

.method public final OooOOOo(Landroid/view/View;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v09;->OooOoO0:Landroid/view/View;

    return-void
.end method

.method public final OooOOo(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/v09;->Oooo000:I

    return-void
.end method

.method public final OooOOo0(Z)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOOOo:Llyiahf/vczjk/pg5;

    iput-boolean p1, v0, Llyiahf/vczjk/pg5;->OooOOOO:Z

    return-void
.end method

.method public final OooOOoo(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    iput p1, v0, Landroidx/appcompat/widget/ListPopupWindow;->OooOOo:I

    return-void
.end method

.method public final OooOo0(Z)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/v09;->Oooo00O:Z

    return-void
.end method

.method public final OooOo00(Landroid/widget/PopupWindow$OnDismissListener;)V
    .locals 0

    check-cast p1, Llyiahf/vczjk/vh5;

    iput-object p1, p0, Llyiahf/vczjk/v09;->OooOo:Llyiahf/vczjk/vh5;

    return-void
.end method

.method public final OooOo0O(I)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    invoke-virtual {v0, p1}, Landroidx/appcompat/widget/ListPopupWindow;->OooOO0(I)V

    return-void
.end method

.method public final dismiss()V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/v09;->OooO00o()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOo0:Landroidx/appcompat/widget/OooO0o;

    invoke-virtual {v0}, Landroidx/appcompat/widget/ListPopupWindow;->dismiss()V

    :cond_0
    return-void
.end method

.method public final onDismiss()V
    .locals 2

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/v09;->OooOoo:Z

    iget-object v1, p0, Llyiahf/vczjk/v09;->OooOOOO:Llyiahf/vczjk/sg5;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/sg5;->OooO0OO(Z)V

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOoo0:Landroid/view/ViewTreeObserver;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroid/view/ViewTreeObserver;->isAlive()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOoO:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/v09;->OooOoo0:Landroid/view/ViewTreeObserver;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOoo0:Landroid/view/ViewTreeObserver;

    iget-object v1, p0, Llyiahf/vczjk/v09;->OooOo0O:Llyiahf/vczjk/oOo000o0;

    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeGlobalOnLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/v09;->OooOoo0:Landroid/view/ViewTreeObserver;

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOoO:Landroid/view/View;

    iget-object v1, p0, Llyiahf/vczjk/v09;->OooOo0o:Llyiahf/vczjk/ab;

    invoke-virtual {v0, v1}, Landroid/view/View;->removeOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    iget-object v0, p0, Llyiahf/vczjk/v09;->OooOo:Llyiahf/vczjk/vh5;

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/vh5;->onDismiss()V

    :cond_2
    return-void
.end method

.method public final onKey(Landroid/view/View;ILandroid/view/KeyEvent;)Z
    .locals 0

    invoke-virtual {p3}, Landroid/view/KeyEvent;->getAction()I

    move-result p1

    const/4 p3, 0x1

    if-ne p1, p3, :cond_0

    const/16 p1, 0x52

    if-ne p2, p1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/v09;->dismiss()V

    return p3

    :cond_0
    const/4 p1, 0x0

    return p1
.end method
