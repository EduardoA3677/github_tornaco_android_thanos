.class public final Llyiahf/vczjk/bp8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tp8;
.implements Llyiahf/vczjk/a5a;
.implements Llyiahf/vczjk/u96;


# instance fields
.field public OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I

.field public final OooOOOO:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Llyiahf/vczjk/bp8;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/lang/Object;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/bp8;->OooOOO0:I

    iput-object p2, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/view/WindowInsetsAnimation$Bounds;)V
    .locals 1

    const/4 v0, 0x6

    iput v0, p0, Llyiahf/vczjk/bp8;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-static {p1}, Llyiahf/vczjk/o0O0OOO0;->OooO0o(Landroid/view/WindowInsetsAnimation$Bounds;)Landroid/graphics/Insets;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    invoke-static {p1}, Llyiahf/vczjk/ona;->OooO0o0(Landroid/view/WindowInsetsAnimation$Bounds;)Landroid/graphics/Insets;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/x04;->OooO0Oo(Landroid/graphics/Insets;)Llyiahf/vczjk/x04;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/viewpager/widget/ViewPager;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, Llyiahf/vczjk/bp8;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    new-instance p1, Landroid/graphics/Rect;

    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/n77;Llyiahf/vczjk/rqa;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, Llyiahf/vczjk/bp8;->OooOOO0:I

    const-string v0, "processor"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "workTaskExecutor"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/np8;Llyiahf/vczjk/tp8;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/bp8;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public OooO(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;
    .locals 2

    instance-of v0, p1, Ljava/lang/Class;

    iget-object v1, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/a4a;

    if-eqz v0, :cond_0

    invoke-virtual {v1, p1}, Llyiahf/vczjk/a4a;->OooOO0O(Ljava/lang/reflect/Type;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/i3a;

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/a4a;->OooOO0o(Ljava/lang/reflect/Type;Llyiahf/vczjk/i3a;)Llyiahf/vczjk/x64;

    move-result-object p1

    return-object p1
.end method

.method public OooO00o(Llyiahf/vczjk/g29;I)V
    .locals 3

    const-string v0, "workSpecId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/ye0;

    iget-object v1, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/n77;

    const/4 v2, 0x0

    invoke-direct {v0, v1, p1, v2, p2}, Llyiahf/vczjk/ye0;-><init>(Llyiahf/vczjk/n77;Llyiahf/vczjk/g29;ZI)V

    iget-object p1, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/rqa;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/rqa;->OooO00o(Ljava/lang/Runnable;)V

    return-void
.end method

.method public OooO0O0(Llyiahf/vczjk/nc2;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0O0(Llyiahf/vczjk/nc2;)V

    return-void
.end method

.method public OooO0OO(Ljava/lang/Throwable;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/np8;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v0, Llyiahf/vczjk/np8;->OooOo:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/tp8;

    if-nez v0, :cond_0

    new-instance v0, Ljava/lang/NullPointerException;

    const-string v2, "Value supplied was null"

    invoke-direct {v0, v2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/Throwable;->initCause(Ljava/lang/Throwable;)Ljava/lang/Throwable;

    invoke-interface {v1, v0}, Llyiahf/vczjk/tp8;->OooO0OO(Ljava/lang/Throwable;)V

    return-void

    :cond_0
    invoke-interface {v1, v0}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    return-void
.end method

.method public OooO0o0(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/tp8;

    invoke-interface {v0, p1}, Llyiahf/vczjk/tp8;->OooO0o0(Ljava/lang/Object;)V

    return-void
.end method

.method public Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 6

    invoke-static {p1, p2}, Llyiahf/vczjk/xfa;->OooOO0(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;

    move-result-object p1

    iget-object p2, p1, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {p2}, Llyiahf/vczjk/foa;->OooOOOO()Z

    move-result p2

    if-eqz p2, :cond_0

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO0O0()I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroid/graphics/Rect;

    iput p2, v0, Landroid/graphics/Rect;->left:I

    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO0Oo()I

    move-result p2

    iput p2, v0, Landroid/graphics/Rect;->top:I

    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO0OO()I

    move-result p2

    iput p2, v0, Landroid/graphics/Rect;->right:I

    invoke-virtual {p1}, Llyiahf/vczjk/ioa;->OooO00o()I

    move-result p2

    iput p2, v0, Landroid/graphics/Rect;->bottom:I

    iget-object p2, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Landroidx/viewpager/widget/ViewPager;

    invoke-virtual {p2}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v1

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_1

    invoke-virtual {p2, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v3

    invoke-static {v3, p1}, Llyiahf/vczjk/xfa;->OooO0O0(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;

    move-result-object v3

    invoke-virtual {v3}, Llyiahf/vczjk/ioa;->OooO0O0()I

    move-result v4

    iget v5, v0, Landroid/graphics/Rect;->left:I

    invoke-static {v4, v5}, Ljava/lang/Math;->min(II)I

    move-result v4

    iput v4, v0, Landroid/graphics/Rect;->left:I

    invoke-virtual {v3}, Llyiahf/vczjk/ioa;->OooO0Oo()I

    move-result v4

    iget v5, v0, Landroid/graphics/Rect;->top:I

    invoke-static {v4, v5}, Ljava/lang/Math;->min(II)I

    move-result v4

    iput v4, v0, Landroid/graphics/Rect;->top:I

    invoke-virtual {v3}, Llyiahf/vczjk/ioa;->OooO0OO()I

    move-result v4

    iget v5, v0, Landroid/graphics/Rect;->right:I

    invoke-static {v4, v5}, Ljava/lang/Math;->min(II)I

    move-result v4

    iput v4, v0, Landroid/graphics/Rect;->right:I

    invoke-virtual {v3}, Llyiahf/vczjk/ioa;->OooO00o()I

    move-result v3

    iget v4, v0, Landroid/graphics/Rect;->bottom:I

    invoke-static {v3, v4}, Ljava/lang/Math;->min(II)I

    move-result v3

    iput v3, v0, Landroid/graphics/Rect;->bottom:I

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    iget p2, v0, Landroid/graphics/Rect;->left:I

    iget v1, v0, Landroid/graphics/Rect;->top:I

    iget v2, v0, Landroid/graphics/Rect;->right:I

    iget v0, v0, Landroid/graphics/Rect;->bottom:I

    invoke-virtual {p1, p2, v1, v2, v0}, Llyiahf/vczjk/ioa;->OooO0o(IIII)Llyiahf/vczjk/ioa;

    move-result-object p1

    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/bp8;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    :pswitch_0
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_1
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Bounds{lower="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/x04;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " upper="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/x04;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, "}"

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/bp8;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/uj2;

    iget-object v1, p0, Llyiahf/vczjk/bp8;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/HashMap;

    filled-new-array {v0, v1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "VersionTagsTuple<%s, %s>"

    invoke-static {v1, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_2
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method
