.class public abstract Landroidx/compose/ui/platform/AbstractComposeView;
.super Landroid/view/ViewGroup;
.source "SourceFile"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000J\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u000b\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\n\n\u0002\u0018\u0002\n\u0002\u0008\u0011\u0008\'\u0018\u00002\u00020\u0001B\'\u0008\u0007\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\n\u0008\u0002\u0010\u0005\u001a\u0004\u0018\u00010\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0017\u0010\r\u001a\u00020\u000c2\u0008\u0010\u000b\u001a\u0004\u0018\u00010\n\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0015\u0010\u0011\u001a\u00020\u000c2\u0006\u0010\u0010\u001a\u00020\u000f\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\u0017\u0010\u0015\u001a\u00020\u000c2\u0006\u0010\u0014\u001a\u00020\u0013H\u0016\u00a2\u0006\u0004\u0008\u0015\u0010\u0016R(\u0010\u001d\u001a\u0004\u0018\u00010\u00172\u0008\u0010\u0018\u001a\u0004\u0018\u00010\u00178\u0002@BX\u0082\u000e\u00a2\u0006\u000c\n\u0004\u0008\u0019\u0010\u001a\"\u0004\u0008\u001b\u0010\u001cR(\u0010!\u001a\u0004\u0018\u00010\n2\u0008\u0010\u0018\u001a\u0004\u0018\u00010\n8\u0002@BX\u0082\u000e\u00a2\u0006\u000c\n\u0004\u0008\u001e\u0010\u001f\"\u0004\u0008 \u0010\u000eR$\u0010\'\u001a\n\u0012\u0004\u0012\u00020\u000c\u0018\u00010\"8\u0002@\u0002X\u0082\u000e\u00a2\u0006\u000c\n\u0004\u0008#\u0010$\u0012\u0004\u0008%\u0010&R0\u0010.\u001a\u00020\u00132\u0006\u0010\u0018\u001a\u00020\u00138F@FX\u0087\u000e\u00a2\u0006\u0018\n\u0004\u0008(\u0010)\u0012\u0004\u0008-\u0010&\u001a\u0004\u0008*\u0010+\"\u0004\u0008,\u0010\u0016R\u0014\u00100\u001a\u00020\u00138TX\u0094\u0004\u00a2\u0006\u0006\u001a\u0004\u0008/\u0010+R\u0011\u00102\u001a\u00020\u00138F\u00a2\u0006\u0006\u001a\u0004\u00081\u0010+\u00a8\u00063"
    }
    d2 = {
        "Landroidx/compose/ui/platform/AbstractComposeView;",
        "Landroid/view/ViewGroup;",
        "Landroid/content/Context;",
        "context",
        "Landroid/util/AttributeSet;",
        "attrs",
        "",
        "defStyleAttr",
        "<init>",
        "(Landroid/content/Context;Landroid/util/AttributeSet;I)V",
        "Llyiahf/vczjk/lg1;",
        "parent",
        "Llyiahf/vczjk/z8a;",
        "setParentCompositionContext",
        "(Llyiahf/vczjk/lg1;)V",
        "Llyiahf/vczjk/ega;",
        "strategy",
        "setViewCompositionStrategy",
        "(Llyiahf/vczjk/ega;)V",
        "",
        "isTransitionGroup",
        "setTransitionGroup",
        "(Z)V",
        "Landroid/os/IBinder;",
        "value",
        "OooOOO",
        "Landroid/os/IBinder;",
        "setPreviousAttachedWindowToken",
        "(Landroid/os/IBinder;)V",
        "previousAttachedWindowToken",
        "OooOOOo",
        "Llyiahf/vczjk/lg1;",
        "setParentContext",
        "parentContext",
        "Lkotlin/Function0;",
        "OooOOo0",
        "Llyiahf/vczjk/le3;",
        "getDisposeViewCompositionStrategy$annotations",
        "()V",
        "disposeViewCompositionStrategy",
        "OooOOo",
        "Z",
        "getShowLayoutBounds",
        "()Z",
        "setShowLayoutBounds",
        "getShowLayoutBounds$annotations",
        "showLayoutBounds",
        "getShouldCreateCompositionOnAttachedToWindow",
        "shouldCreateCompositionOnAttachedToWindow",
        "getHasComposition",
        "hasComposition",
        "ui_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public OooOOO:Landroid/os/IBinder;

.field public OooOOO0:Ljava/lang/ref/WeakReference;

.field public OooOOOO:Llyiahf/vczjk/jsa;

.field public OooOOOo:Llyiahf/vczjk/lg1;

.field public OooOOo:Z

.field public OooOOo0:Llyiahf/vczjk/le3;

.field public OooOOoo:Z

.field public OooOo00:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 2

    const/4 v0, 0x4

    const/4 v1, 0x0

    invoke-direct {p0, p1, p2, v0, v1}, Landroidx/compose/ui/platform/AbstractComposeView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->setClipToPadding(Z)V

    const/4 p1, 0x1

    invoke-virtual {p0, p1}, Landroid/view/View;->setImportantForAccessibility(I)V

    new-instance p1, Llyiahf/vczjk/aga;

    invoke-direct {p1, p0}, Llyiahf/vczjk/aga;-><init>(Landroidx/compose/ui/platform/AbstractComposeView;)V

    invoke-virtual {p0, p1}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    new-instance p2, Llyiahf/vczjk/yfa;

    invoke-direct {p2, p0}, Llyiahf/vczjk/yfa;-><init>(Landroidx/compose/ui/platform/AbstractComposeView;)V

    invoke-static {p0}, Llyiahf/vczjk/pz6;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/rz6;

    move-result-object p3

    iget-object p3, p3, Llyiahf/vczjk/rz6;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {p3, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance p3, Llyiahf/vczjk/zfa;

    invoke-direct {p3, p0, p1, p2}, Llyiahf/vczjk/zfa;-><init>(Landroidx/compose/ui/platform/AbstractComposeView;Llyiahf/vczjk/aga;Llyiahf/vczjk/yfa;)V

    iput-object p3, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOo0:Llyiahf/vczjk/le3;

    return-void
.end method

.method public synthetic constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    :cond_0
    const/4 p3, 0x0

    invoke-direct {p0, p1, p2, p3}, Landroidx/compose/ui/platform/AbstractComposeView;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    return-void
.end method

.method private static synthetic getDisposeViewCompositionStrategy$annotations()V
    .locals 0

    return-void
.end method

.method public static synthetic getShowLayoutBounds$annotations()V
    .locals 0

    return-void
.end method

.method private final setParentContext(Llyiahf/vczjk/lg1;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOo:Llyiahf/vczjk/lg1;

    if-eq v0, p1, :cond_1

    iput-object p1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOo:Llyiahf/vczjk/lg1;

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    iput-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOO0:Ljava/lang/ref/WeakReference;

    :cond_0
    iget-object p1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOO:Llyiahf/vczjk/jsa;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/jsa;->OooO00o()V

    iput-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOO:Llyiahf/vczjk/jsa;

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result p1

    if-eqz p1, :cond_1

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0o0()V

    :cond_1
    return-void
.end method

.method private final setPreviousAttachedWindowToken(Landroid/os/IBinder;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOO:Landroid/os/IBinder;

    if-eq v0, p1, :cond_0

    iput-object p1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOO:Landroid/os/IBinder;

    const/4 p1, 0x0

    iput-object p1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOO0:Ljava/lang/ref/WeakReference;

    :cond_0
    return-void
.end method


# virtual methods
.method public abstract OooO00o(ILlyiahf/vczjk/rf1;)V
.end method

.method public final OooO0O0()V
    .locals 3

    iget-boolean v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOoo:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Cannot add views to "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "; only Compose content is supported"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final OooO0OO()V
    .locals 2

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOo:Llyiahf/vczjk/lg1;

    if-nez v0, :cond_1

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "createComposition requires either a parent reference or the View to be attachedto a window. Attach the View or call setParentCompositionReference."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_1
    :goto_0
    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0o0()V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 1

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOO:Llyiahf/vczjk/jsa;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/jsa;->OooO00o()V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOO:Llyiahf/vczjk/jsa;

    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    return-void
.end method

.method public OooO0o(ZIIII)V
    .locals 2

    const/4 p1, 0x0

    invoke-virtual {p0, p1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object p1

    if-eqz p1, :cond_0

    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    move-result v0

    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    move-result v1

    sub-int/2addr p4, p2

    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    move-result p2

    sub-int/2addr p4, p2

    sub-int/2addr p5, p3

    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    move-result p2

    sub-int/2addr p5, p2

    invoke-virtual {p1, v0, v1, p4, p5}, Landroid/view/View;->layout(IIII)V

    :cond_0
    return-void
.end method

.method public final OooO0o0()V
    .locals 6

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOO:Llyiahf/vczjk/jsa;

    if-nez v0, :cond_0

    const/4 v0, 0x0

    const/4 v1, 0x1

    :try_start_0
    iput-boolean v1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOoo:Z

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0oo()Llyiahf/vczjk/lg1;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/o0000OO0;

    invoke-direct {v3, p0}, Llyiahf/vczjk/o0000OO0;-><init>(Landroidx/compose/ui/platform/AbstractComposeView;)V

    new-instance v4, Llyiahf/vczjk/a91;

    const v5, -0x271bffc0

    invoke-direct {v4, v5, v3, v1}, Llyiahf/vczjk/a91;-><init>(ILjava/lang/Object;Z)V

    invoke-static {p0, v2, v4}, Llyiahf/vczjk/osa;->OooO00o(Landroidx/compose/ui/platform/AbstractComposeView;Llyiahf/vczjk/lg1;Llyiahf/vczjk/a91;)Llyiahf/vczjk/jsa;

    move-result-object v1

    iput-object v1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOO:Llyiahf/vczjk/jsa;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iput-boolean v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOoo:Z

    return-void

    :catchall_0
    move-exception v1

    iput-boolean v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOoo:Z

    throw v1

    :cond_0
    return-void
.end method

.method public OooO0oO(II)V
    .locals 5

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v1

    if-nez v1, :cond_0

    invoke-super {p0, p1, p2}, Landroid/view/View;->onMeasure(II)V

    return-void

    :cond_0
    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getSize(I)I

    move-result v2

    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    move-result v3

    sub-int/2addr v2, v3

    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    move-result v3

    sub-int/2addr v2, v3

    invoke-static {v0, v2}, Ljava/lang/Math;->max(II)I

    move-result v2

    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getSize(I)I

    move-result v3

    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    move-result v4

    sub-int/2addr v3, v4

    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    move-result v4

    sub-int/2addr v3, v4

    invoke-static {v0, v3}, Ljava/lang/Math;->max(II)I

    move-result v0

    invoke-static {p1}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result p1

    invoke-static {v2, p1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p1

    invoke-static {p2}, Landroid/view/View$MeasureSpec;->getMode(I)I

    move-result p2

    invoke-static {v0, p2}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p2

    invoke-virtual {v1, p1, p2}, Landroid/view/View;->measure(II)V

    invoke-virtual {v1}, Landroid/view/View;->getMeasuredWidth()I

    move-result p1

    invoke-virtual {p0}, Landroid/view/View;->getPaddingLeft()I

    move-result p2

    add-int/2addr p2, p1

    invoke-virtual {p0}, Landroid/view/View;->getPaddingRight()I

    move-result p1

    add-int/2addr p1, p2

    invoke-virtual {v1}, Landroid/view/View;->getMeasuredHeight()I

    move-result p2

    invoke-virtual {p0}, Landroid/view/View;->getPaddingTop()I

    move-result v0

    add-int/2addr v0, p2

    invoke-virtual {p0}, Landroid/view/View;->getPaddingBottom()I

    move-result p2

    add-int/2addr p2, v0

    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setMeasuredDimension(II)V

    return-void
.end method

.method public final OooO0oo()Llyiahf/vczjk/lg1;
    .locals 9

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOo:Llyiahf/vczjk/lg1;

    if-nez v0, :cond_16

    invoke-static {p0}, Llyiahf/vczjk/kpa;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/lg1;

    move-result-object v0

    if-eqz v0, :cond_0

    goto :goto_1

    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v1

    :goto_0
    if-nez v0, :cond_1

    instance-of v2, v1, Landroid/view/View;

    if-eqz v2, :cond_1

    move-object v0, v1

    check-cast v0, Landroid/view/View;

    invoke-static {v0}, Llyiahf/vczjk/kpa;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/lg1;

    move-result-object v0

    invoke-interface {v1}, Landroid/view/ViewParent;->getParent()Landroid/view/ViewParent;

    move-result-object v1

    goto :goto_0

    :cond_1
    :goto_1
    const/4 v1, 0x0

    if-eqz v0, :cond_4

    instance-of v2, v0, Llyiahf/vczjk/oj7;

    if-eqz v2, :cond_3

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/oj7;

    iget-object v2, v2, Llyiahf/vczjk/oj7;->OooOo00:Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/bj7;

    sget-object v3, Llyiahf/vczjk/bj7;->OooOOO:Llyiahf/vczjk/bj7;

    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v2

    if-lez v2, :cond_2

    goto :goto_2

    :cond_2
    move-object v2, v1

    goto :goto_3

    :cond_3
    :goto_2
    move-object v2, v0

    :goto_3
    if-eqz v2, :cond_5

    new-instance v3, Ljava/lang/ref/WeakReference;

    invoke-direct {v3, v2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v3, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOO0:Ljava/lang/ref/WeakReference;

    goto :goto_4

    :cond_4
    move-object v0, v1

    :cond_5
    :goto_4
    if-nez v0, :cond_16

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOO0:Ljava/lang/ref/WeakReference;

    if-eqz v0, :cond_6

    invoke-virtual {v0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/lg1;

    if-eqz v0, :cond_6

    instance-of v2, v0, Llyiahf/vczjk/oj7;

    if-eqz v2, :cond_7

    move-object v2, v0

    check-cast v2, Llyiahf/vczjk/oj7;

    iget-object v2, v2, Llyiahf/vczjk/oj7;->OooOo00:Llyiahf/vczjk/s29;

    invoke-virtual {v2}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/bj7;

    sget-object v3, Llyiahf/vczjk/bj7;->OooOOO:Llyiahf/vczjk/bj7;

    invoke-virtual {v2, v3}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v2

    if-lez v2, :cond_6

    goto :goto_5

    :cond_6
    move-object v0, v1

    :cond_7
    :goto_5
    if-nez v0, :cond_16

    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v0

    if-nez v0, :cond_8

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Cannot locate windowRecomposer; View "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v2, " is not attached to a window"

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :cond_8
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v0

    move-object v7, p0

    :goto_6
    instance-of v2, v0, Landroid/view/View;

    if-eqz v2, :cond_a

    check-cast v0, Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getId()I

    move-result v2

    const v3, 0x1020002

    if-ne v2, v3, :cond_9

    goto :goto_7

    :cond_9
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v2

    move-object v7, v0

    move-object v0, v2

    goto :goto_6

    :cond_a
    :goto_7
    invoke-static {v7}, Llyiahf/vczjk/kpa;->OooO0O0(Landroid/view/View;)Llyiahf/vczjk/lg1;

    move-result-object v0

    if-nez v0, :cond_12

    sget-object v0, Llyiahf/vczjk/dpa;->OooO00o:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/bpa;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    sget-object v2, Llyiahf/vczjk/sg;->OooOoO0:Llyiahf/vczjk/sc9;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v2

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v3

    if-ne v2, v3, :cond_b

    sget-object v2, Llyiahf/vczjk/sg;->OooOoO0:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/or1;

    goto :goto_8

    :cond_b
    sget-object v2, Llyiahf/vczjk/sg;->OooOoO:Llyiahf/vczjk/qg;

    invoke-virtual {v2}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/or1;

    if-eqz v2, :cond_11

    :goto_8
    invoke-interface {v2, v0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v2

    sget-object v3, Llyiahf/vczjk/up3;->OooOOo:Llyiahf/vczjk/up3;

    invoke-interface {v2, v3}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/xn5;

    const/4 v8, 0x0

    if-eqz v3, :cond_c

    new-instance v4, Llyiahf/vczjk/as6;

    invoke-direct {v4, v3}, Llyiahf/vczjk/as6;-><init>(Llyiahf/vczjk/xn5;)V

    iget-object v3, v4, Llyiahf/vczjk/as6;->OooOOO:Llyiahf/vczjk/cn4;

    iget-object v5, v3, Llyiahf/vczjk/cn4;->OooO00o:Ljava/lang/Object;

    monitor-enter v5

    :try_start_0
    iput-boolean v8, v3, Llyiahf/vczjk/cn4;->OooO0Oo:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v5

    goto :goto_9

    :catchall_0
    move-exception v0

    monitor-exit v5

    throw v0

    :cond_c
    move-object v4, v1

    :goto_9
    new-instance v6, Llyiahf/vczjk/hl7;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    sget-object v3, Llyiahf/vczjk/vp3;->OooOOo:Llyiahf/vczjk/vp3;

    invoke-interface {v2, v3}, Llyiahf/vczjk/or1;->OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/fo5;

    if-nez v3, :cond_d

    new-instance v3, Llyiahf/vczjk/go5;

    invoke-direct {v3}, Llyiahf/vczjk/go5;-><init>()V

    iput-object v3, v6, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    :cond_d
    if-eqz v4, :cond_e

    move-object v0, v4

    :cond_e
    invoke-interface {v2, v0}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-interface {v0, v3}, Llyiahf/vczjk/or1;->OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object v0

    new-instance v5, Llyiahf/vczjk/oj7;

    invoke-direct {v5, v0}, Llyiahf/vczjk/oj7;-><init>(Llyiahf/vczjk/or1;)V

    iget-object v2, v5, Llyiahf/vczjk/oj7;->OooO0O0:Ljava/lang/Object;

    monitor-enter v2

    const/4 v3, 0x1

    :try_start_1
    iput-boolean v3, v5, Llyiahf/vczjk/oj7;->OooOOoo:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    monitor-exit v2

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooO0oO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/to1;

    move-result-object v3

    invoke-static {v7}, Llyiahf/vczjk/dr6;->OooOOO(Landroid/view/View;)Llyiahf/vczjk/uy4;

    move-result-object v0

    if-eqz v0, :cond_f

    invoke-interface {v0}, Llyiahf/vczjk/uy4;->getLifecycle()Llyiahf/vczjk/ky4;

    move-result-object v0

    goto :goto_a

    :cond_f
    move-object v0, v1

    :goto_a
    if-eqz v0, :cond_10

    new-instance v2, Llyiahf/vczjk/sn8;

    invoke-direct {v2, v7, v5}, Llyiahf/vczjk/sn8;-><init>(Landroid/view/View;Llyiahf/vczjk/oj7;)V

    invoke-virtual {v7, v2}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    new-instance v2, Llyiahf/vczjk/hpa;

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/hpa;-><init>(Llyiahf/vczjk/to1;Llyiahf/vczjk/as6;Llyiahf/vczjk/oj7;Llyiahf/vczjk/hl7;Landroid/view/View;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/ky4;->OooO00o(Llyiahf/vczjk/ty4;)V

    sget v0, Landroidx/compose/ui/R$id;->androidx_compose_ui_view_composition_context:I

    invoke-virtual {v7, v0, v5}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/ii3;->OooOOO0:Llyiahf/vczjk/ii3;

    invoke-virtual {v7}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    move-result-object v2

    const-string v3, "windowRecomposer cleanup"

    sget v4, Llyiahf/vczjk/yl3;->OooO00o:I

    new-instance v4, Llyiahf/vczjk/xl3;

    invoke-direct {v4, v2, v3, v8}, Llyiahf/vczjk/xl3;-><init>(Landroid/os/Handler;Ljava/lang/String;Z)V

    iget-object v2, v4, Llyiahf/vczjk/xl3;->OooOOo:Llyiahf/vczjk/xl3;

    new-instance v3, Llyiahf/vczjk/cpa;

    invoke-direct {v3, v5, v7, v1}, Llyiahf/vczjk/cpa;-><init>(Llyiahf/vczjk/oj7;Landroid/view/View;Llyiahf/vczjk/yo1;)V

    const/4 v4, 0x2

    invoke-static {v0, v2, v1, v3, v4}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/ab;

    const/16 v3, 0x9

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/ab;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v7, v2}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    goto :goto_b

    :cond_10
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "ViewTreeLifecycleOwner not found from "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0OO(Ljava/lang/String;)Ljava/lang/Void;

    new-instance v0, Llyiahf/vczjk/k61;

    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    throw v0

    :catchall_1
    move-exception v0

    monitor-exit v2

    throw v0

    :cond_11
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "no AndroidUiDispatcher for this thread"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_12
    instance-of v2, v0, Llyiahf/vczjk/oj7;

    if-eqz v2, :cond_15

    move-object v5, v0

    check-cast v5, Llyiahf/vczjk/oj7;

    :goto_b
    iget-object v0, v5, Llyiahf/vczjk/oj7;->OooOo00:Llyiahf/vczjk/s29;

    invoke-virtual {v0}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/bj7;

    sget-object v2, Llyiahf/vczjk/bj7;->OooOOO:Llyiahf/vczjk/bj7;

    invoke-virtual {v0, v2}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    move-result v0

    if-lez v0, :cond_13

    move-object v1, v5

    :cond_13
    if-eqz v1, :cond_14

    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, v1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOO0:Ljava/lang/ref/WeakReference;

    :cond_14
    return-object v5

    :cond_15
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "root viewTreeParentCompositionContext is not a Recomposer"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_16
    return-object v0
.end method

.method public final addView(Landroid/view/View;)V
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0O0()V

    invoke-super {p0, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    return-void
.end method

.method public final addView(Landroid/view/View;I)V
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0O0()V

    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;I)V

    return-void
.end method

.method public final addView(Landroid/view/View;II)V
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0O0()V

    invoke-super {p0, p1, p2, p3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;II)V

    return-void
.end method

.method public final addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0O0()V

    invoke-super {p0, p1, p2, p3}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public final addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0O0()V

    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    return-void
.end method

.method public final addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)Z
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0O0()V

    invoke-super {p0, p1, p2, p3}, Landroid/view/ViewGroup;->addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)Z

    move-result p1

    return p1
.end method

.method public final addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;Z)Z
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0O0()V

    invoke-super {p0, p1, p2, p3, p4}, Landroid/view/ViewGroup;->addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;Z)Z

    move-result p1

    return p1
.end method

.method public final getHasComposition()Z
    .locals 1

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOOO:Llyiahf/vczjk/jsa;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public getShouldCreateCompositionOnAttachedToWindow()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final getShowLayoutBounds()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOo:Z

    return v0
.end method

.method public final isTransitionGroup()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOo00:Z

    if-eqz v0, :cond_1

    invoke-super {p0}, Landroid/view/ViewGroup;->isTransitionGroup()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public onAttachedToWindow()V
    .locals 1

    invoke-super {p0}, Landroid/view/ViewGroup;->onAttachedToWindow()V

    invoke-virtual {p0}, Landroid/view/View;->getWindowToken()Landroid/os/IBinder;

    move-result-object v0

    invoke-direct {p0, v0}, Landroidx/compose/ui/platform/AbstractComposeView;->setPreviousAttachedWindowToken(Landroid/os/IBinder;)V

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->getShouldCreateCompositionOnAttachedToWindow()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0o0()V

    :cond_0
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    invoke-virtual/range {p0 .. p5}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0o(ZIIII)V

    return-void
.end method

.method public final onMeasure(II)V
    .locals 0

    invoke-virtual {p0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0o0()V

    invoke-virtual {p0, p1, p2}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0oO(II)V

    return-void
.end method

.method public final onRtlPropertiesChanged(I)V
    .locals 1

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    if-nez v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {v0, p1}, Landroid/view/View;->setLayoutDirection(I)V

    return-void
.end method

.method public final setParentCompositionContext(Llyiahf/vczjk/lg1;)V
    .locals 0

    invoke-direct {p0, p1}, Landroidx/compose/ui/platform/AbstractComposeView;->setParentContext(Llyiahf/vczjk/lg1;)V

    return-void
.end method

.method public final setShowLayoutBounds(Z)V
    .locals 1

    iput-boolean p1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOo:Z

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/tg6;

    check-cast v0, Llyiahf/vczjk/xa;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/xa;->setShowLayoutBounds(Z)V

    :cond_0
    return-void
.end method

.method public setTransitionGroup(Z)V
    .locals 0

    invoke-super {p0, p1}, Landroid/view/ViewGroup;->setTransitionGroup(Z)V

    const/4 p1, 0x1

    iput-boolean p1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOo00:Z

    return-void
.end method

.method public final setViewCompositionStrategy(Llyiahf/vczjk/ega;)V
    .locals 1

    iget-object v0, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOo0:Llyiahf/vczjk/le3;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    invoke-interface {p1, p0}, Llyiahf/vczjk/ega;->OooO0oo(Landroidx/compose/ui/platform/AbstractComposeView;)Llyiahf/vczjk/le3;

    move-result-object p1

    iput-object p1, p0, Landroidx/compose/ui/platform/AbstractComposeView;->OooOOo0:Llyiahf/vczjk/le3;

    return-void
.end method

.method public final shouldDelayChildPressedState()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method
