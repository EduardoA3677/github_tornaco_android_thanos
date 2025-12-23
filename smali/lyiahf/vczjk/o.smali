.class public final Llyiahf/vczjk/o;
.super Landroid/animation/AnimatorListenerAdapter;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/uz5;Landroid/view/View;)V
    .locals 0

    const/4 p2, 0x2

    iput p2, p0, Llyiahf/vczjk/o;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    return-void
.end method

.method private final OooO00o(Landroid/animation/Animator;)V
    .locals 0

    return-void
.end method


# virtual methods
.method public onAnimationCancel(Landroid/animation/Animator;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/o;->OooO00o:I

    sparse-switch v0, :sswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationCancel(Landroid/animation/Animator;)V

    return-void

    :sswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationCancel(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Lcom/simplecityapps/recyclerview_fastscroll/views/FastScroller;

    const/4 v0, 0x0

    iput-boolean v0, p1, Lcom/simplecityapps/recyclerview_fastscroll/views/FastScroller;->OooOOOo:Z

    return-void

    :sswitch_1
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/l80;

    invoke-virtual {p1}, Llyiahf/vczjk/l80;->OooO0Oo()V

    return-void

    :sswitch_2
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uz5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void

    :sswitch_3
    const/4 p1, 0x0

    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    iput-object p1, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->Oooo0:Landroid/view/ViewPropertyAnimator;

    const/4 p1, 0x0

    iput-boolean p1, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->OooOo0O:Z

    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x0 -> :sswitch_3
        0x2 -> :sswitch_2
        0x6 -> :sswitch_1
        0x7 -> :sswitch_0
    .end sparse-switch
.end method

.method public onAnimationEnd(Landroid/animation/Animator;)V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/o;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    :pswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Landroidx/transition/Transition;

    invoke-virtual {v0}, Landroidx/transition/Transition;->OooOOO()V

    invoke-virtual {p1, p0}, Landroid/animation/Animator;->removeListener(Landroid/animation/Animator$AnimatorListener;)V

    return-void

    :pswitch_2
    const/4 p1, 0x5

    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    invoke-virtual {v0, p1}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->OooOo(I)V

    iget-object p1, v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->OooOoo0:Ljava/lang/ref/WeakReference;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_0

    iget-object p1, v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->OooOoo0:Ljava/lang/ref/WeakReference;

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->requestLayout()V

    :cond_0
    return-void

    :pswitch_3
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Landroid/view/View;

    if-eqz p1, :cond_1

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    :cond_1
    return-void

    :pswitch_4
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/rd5;

    iget-object v0, p1, Llyiahf/vczjk/md5;->OooO0O0:Landroid/view/View;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/view/View;->setTranslationY(F)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/rd5;->OooO0OO(F)V

    return-void

    :pswitch_5
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;

    const/4 v0, 0x0

    iput-object v0, p1, Lcom/google/android/material/behavior/HideViewOnScrollBehavior;->OooOo:Landroid/view/ViewPropertyAnimator;

    return-void

    :pswitch_6
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;

    const/4 v0, 0x0

    iput-object v0, p1, Lcom/google/android/material/behavior/HideBottomViewOnScrollBehavior;->OooOo:Landroid/view/ViewPropertyAnimator;

    return-void

    :pswitch_7
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationEnd(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Lcom/simplecityapps/recyclerview_fastscroll/views/FastScroller;

    const/4 v0, 0x0

    iput-boolean v0, p1, Lcom/simplecityapps/recyclerview_fastscroll/views/FastScroller;->OooOOOo:Z

    return-void

    :pswitch_8
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/l80;

    invoke-virtual {p1}, Llyiahf/vczjk/l80;->OooO0o0()V

    return-void

    :pswitch_9
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Lcom/google/android/material/transformation/ExpandableTransformationBehavior;

    const/4 v0, 0x0

    iput-object v0, p1, Lcom/google/android/material/transformation/ExpandableTransformationBehavior;->OooOOO:Landroid/animation/AnimatorSet;

    return-void

    :pswitch_a
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/lj2;

    invoke-virtual {p1}, Llyiahf/vczjk/on2;->OooOOo0()V

    iget-object p1, p1, Llyiahf/vczjk/lj2;->OooOOo:Landroid/animation/ValueAnimator;

    invoke-virtual {p1}, Landroid/animation/ValueAnimator;->start()V

    return-void

    :pswitch_b
    const/4 p1, 0x5

    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    invoke-virtual {v0, p1}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->Oooo0O0(I)V

    iget-object p1, v0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OoooooO:Ljava/lang/ref/WeakReference;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    if-eqz p1, :cond_2

    iget-object p1, v0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->OoooooO:Ljava/lang/ref/WeakReference;

    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/view/View;

    invoke-virtual {p1}, Landroid/view/View;->requestLayout()V

    :cond_2
    return-void

    :pswitch_c
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uz5;

    iget-object p1, p1, Llyiahf/vczjk/uz5;->OooOOO:Ljava/lang/Object;

    check-cast p1, Lcom/miguelcatalan/materialsearchview/MaterialSearchView;

    iget-object p1, p1, Lcom/miguelcatalan/materialsearchview/MaterialSearchView;->OooOoO:Llyiahf/vczjk/ie5;

    if-eqz p1, :cond_3

    invoke-interface {p1}, Llyiahf/vczjk/ie5;->OooO0Oo()V

    :cond_3
    return-void

    :pswitch_d
    new-instance p1, Ljava/util/ArrayList;

    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jk;

    iget-object v1, v0, Llyiahf/vczjk/jk;->OooOOo0:Ljava/util/ArrayList;

    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_4

    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/fi;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/fi;->OooO00o(Landroid/graphics/drawable/Drawable;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_4
    return-void

    :pswitch_e
    const/4 p1, 0x0

    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;

    iput-object p1, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->Oooo0:Landroid/view/ViewPropertyAnimator;

    const/4 p1, 0x0

    iput-boolean p1, v0, Landroidx/appcompat/widget/ActionBarOverlayLayout;->OooOo0O:Z

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public onAnimationRepeat(Landroid/animation/Animator;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/o;->OooO00o:I

    sparse-switch v0, :sswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationRepeat(Landroid/animation/Animator;)V

    return-void

    :sswitch_0
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationRepeat(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/z25;

    iget-object v0, p1, Llyiahf/vczjk/z25;->OooO0o0:Llyiahf/vczjk/rz8;

    iget v1, p1, Llyiahf/vczjk/z25;->OooO00o:I

    add-int/lit8 v1, v1, 0x1

    iput v1, p1, Llyiahf/vczjk/z25;->OooO00o:I

    int-to-float p1, v1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/rz8;->OooO00o(F)V

    return-void

    :sswitch_1
    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationRepeat(Landroid/animation/Animator;)V

    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/sz4;

    iget v0, p1, Llyiahf/vczjk/sz4;->OooO0o:I

    const/4 v1, 0x1

    add-int/2addr v0, v1

    iget-object v2, p1, Llyiahf/vczjk/sz4;->OooO0o0:Lcom/google/android/material/progressindicator/LinearProgressIndicatorSpec;

    iget-object v2, v2, Llyiahf/vczjk/q80;->OooO0o0:[I

    array-length v2, v2

    rem-int/2addr v0, v2

    iput v0, p1, Llyiahf/vczjk/sz4;->OooO0o:I

    iput-boolean v1, p1, Llyiahf/vczjk/sz4;->OooO0oO:Z

    :sswitch_2
    return-void

    nop

    :sswitch_data_0
    .sparse-switch
        0x2 -> :sswitch_2
        0xa -> :sswitch_1
        0xb -> :sswitch_0
    .end sparse-switch
.end method

.method public onAnimationStart(Landroid/animation/Animator;)V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/o;->OooO00o:I

    sparse-switch v0, :sswitch_data_0

    invoke-super {p0, p1}, Landroid/animation/AnimatorListenerAdapter;->onAnimationStart(Landroid/animation/Animator;)V

    return-void

    :sswitch_0
    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/l80;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/l80;->OooO0o(Landroid/animation/Animator;)V

    return-void

    :sswitch_1
    iget-object p1, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/uz5;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void

    :sswitch_2
    new-instance p1, Ljava/util/ArrayList;

    iget-object v0, p0, Llyiahf/vczjk/o;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jk;

    iget-object v1, v0, Llyiahf/vczjk/jk;->OooOOo0:Ljava/util/ArrayList;

    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    move-result v1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    invoke-virtual {p1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/fi;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/fi;->OooO0O0(Landroid/graphics/drawable/Drawable;)V

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    return-void

    :sswitch_data_0
    .sparse-switch
        0x1 -> :sswitch_2
        0x2 -> :sswitch_1
        0x6 -> :sswitch_0
    .end sparse-switch
.end method
