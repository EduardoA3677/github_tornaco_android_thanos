.class public final Llyiahf/vczjk/yj5;
.super Llyiahf/vczjk/a71;
.source "SourceFile"


# instance fields
.field public OooOOOo:Llyiahf/vczjk/le3;

.field public OooOOo:J

.field public OooOOo0:Llyiahf/vczjk/vk5;

.field public final OooOOoo:Landroid/view/View;

.field public final OooOo00:Llyiahf/vczjk/tj5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/vk5;JLandroid/view/View;Llyiahf/vczjk/yn4;Llyiahf/vczjk/f62;Ljava/util/UUID;Llyiahf/vczjk/gi;Llyiahf/vczjk/xr1;)V
    .locals 8

    new-instance v0, Landroid/view/ContextThemeWrapper;

    invoke-virtual {p5}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v1

    sget v2, Landroidx/compose/material3/R$style;->EdgeToEdgeFloatingDialogWindowTheme:I

    invoke-direct {v0, v1, v2}, Landroid/view/ContextThemeWrapper;-><init>(Landroid/content/Context;I)V

    const/4 v1, 0x0

    invoke-direct {p0, v0, v1}, Llyiahf/vczjk/a71;-><init>(Landroid/content/Context;I)V

    iput-object p1, p0, Llyiahf/vczjk/yj5;->OooOOOo:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/yj5;->OooOOo0:Llyiahf/vczjk/vk5;

    iput-wide p3, p0, Llyiahf/vczjk/yj5;->OooOOo:J

    iput-object p5, p0, Llyiahf/vczjk/yj5;->OooOOoo:Landroid/view/View;

    const/16 p2, 0x8

    int-to-float p2, p2

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object p3

    if-eqz p3, :cond_5

    const/4 p4, 0x1

    invoke-virtual {p3, p4}, Landroid/view/Window;->requestFeature(I)Z

    const v0, 0x106000d

    invoke-virtual {p3, v0}, Landroid/view/Window;->setBackgroundDrawableResource(I)V

    invoke-static {p3, v1}, Llyiahf/vczjk/dl6;->OooOO0O(Landroid/view/Window;Z)V

    new-instance v0, Llyiahf/vczjk/tj5;

    invoke-virtual {p0}, Landroid/app/Dialog;->getContext()Landroid/content/Context;

    move-result-object v2

    invoke-direct {v0, v2}, Llyiahf/vczjk/tj5;-><init>(Landroid/content/Context;)V

    sget v2, Landroidx/compose/ui/R$id;->compose_view_saveable_id_tag:I

    new-instance v3, Ljava/lang/StringBuilder;

    const-string v4, "Dialog:"

    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    move-object/from16 v4, p8

    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v0, v2, v3}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    invoke-virtual {v0, v1}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    invoke-interface {p7, p2}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result p2

    invoke-virtual {v0, p2}, Landroid/view/View;->setElevation(F)V

    new-instance p2, Llyiahf/vczjk/cb2;

    const/4 v2, 0x1

    invoke-direct {p2, v2}, Llyiahf/vczjk/cb2;-><init>(I)V

    invoke-virtual {v0, p2}, Landroid/view/View;->setOutlineProvider(Landroid/view/ViewOutlineProvider;)V

    iput-object v0, p0, Llyiahf/vczjk/yj5;->OooOo00:Llyiahf/vczjk/tj5;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/a71;->setContentView(Landroid/view/View;)V

    invoke-static {p5}, Llyiahf/vczjk/dr6;->OooOOO(Landroid/view/View;)Llyiahf/vczjk/uy4;

    move-result-object p2

    invoke-static {v0, p2}, Llyiahf/vczjk/dr6;->OooOo0(Landroid/view/View;Llyiahf/vczjk/uy4;)V

    invoke-static {p5}, Llyiahf/vczjk/xr6;->OooOO0O(Landroid/view/View;)Llyiahf/vczjk/lha;

    move-result-object p2

    invoke-static {v0, p2}, Llyiahf/vczjk/xr6;->OooOo00(Landroid/view/View;Llyiahf/vczjk/lha;)V

    invoke-static {p5}, Llyiahf/vczjk/wr6;->OooOO0o(Landroid/view/View;)Llyiahf/vczjk/h68;

    move-result-object p1

    invoke-static {v0, p1}, Llyiahf/vczjk/wr6;->OooOo0o(Landroid/view/View;Llyiahf/vczjk/h68;)V

    iget-object v3, p0, Llyiahf/vczjk/yj5;->OooOOOo:Llyiahf/vczjk/le3;

    iget-object v4, p0, Llyiahf/vczjk/yj5;->OooOOo0:Llyiahf/vczjk/vk5;

    iget-wide v5, p0, Llyiahf/vczjk/yj5;->OooOOo:J

    move-object v2, p0

    move-object v7, p6

    invoke-virtual/range {v2 .. v7}, Llyiahf/vczjk/yj5;->OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/vk5;JLlyiahf/vczjk/yn4;)V

    invoke-virtual {p3}, Landroid/view/Window;->getDecorView()Landroid/view/View;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/wg7;

    invoke-direct {p2, p1}, Llyiahf/vczjk/wg7;-><init>(Landroid/view/View;)V

    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x23

    if-lt p1, v0, :cond_0

    new-instance p1, Llyiahf/vczjk/moa;

    invoke-direct {p1, p3, p2}, Llyiahf/vczjk/loa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    goto :goto_0

    :cond_0
    const/16 v0, 0x1e

    if-lt p1, v0, :cond_1

    new-instance p1, Llyiahf/vczjk/loa;

    invoke-direct {p1, p3, p2}, Llyiahf/vczjk/loa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    goto :goto_0

    :cond_1
    const/16 v0, 0x1a

    if-lt p1, v0, :cond_2

    new-instance p1, Llyiahf/vczjk/koa;

    invoke-direct {p1, p3, p2}, Llyiahf/vczjk/joa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    goto :goto_0

    :cond_2
    new-instance p1, Llyiahf/vczjk/joa;

    invoke-direct {p1, p3, p2}, Llyiahf/vczjk/joa;-><init>(Landroid/view/Window;Llyiahf/vczjk/wg7;)V

    :goto_0
    iget-object p2, p0, Llyiahf/vczjk/yj5;->OooOOo0:Llyiahf/vczjk/vk5;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-wide p2, p0, Llyiahf/vczjk/yj5;->OooOOo:J

    sget-wide v3, Llyiahf/vczjk/n21;->OooO:J

    invoke-static {p2, p3, v3, v4}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v0

    const-wide/high16 v5, 0x3fe0000000000000L    # 0.5

    if-nez v0, :cond_3

    invoke-static {p2, p3}, Llyiahf/vczjk/v34;->OooooOO(J)F

    move-result p2

    float-to-double p2, p2

    cmpg-double p2, p2, v5

    if-gtz p2, :cond_3

    move p2, p4

    goto :goto_1

    :cond_3
    move p2, v1

    :goto_1
    invoke-virtual {p1, p2}, Llyiahf/vczjk/rl6;->OooOoO(Z)V

    iget-object p2, p0, Llyiahf/vczjk/yj5;->OooOOo0:Llyiahf/vczjk/vk5;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-wide p2, p0, Llyiahf/vczjk/yj5;->OooOOo:J

    invoke-static {p2, p3, v3, v4}, Llyiahf/vczjk/n21;->OooO0OO(JJ)Z

    move-result v0

    if-nez v0, :cond_4

    invoke-static {p2, p3}, Llyiahf/vczjk/v34;->OooooOO(J)F

    move-result p2

    float-to-double p2, p2

    cmpg-double p2, p2, v5

    if-gtz p2, :cond_4

    move v1, p4

    :cond_4
    invoke-virtual {p1, v1}, Llyiahf/vczjk/rl6;->OooOoO0(Z)V

    iget-object p1, p0, Llyiahf/vczjk/a71;->OooOOOO:Llyiahf/vczjk/ha6;

    new-instance p2, Llyiahf/vczjk/xj5;

    iget-object p3, p0, Llyiahf/vczjk/yj5;->OooOOo0:Llyiahf/vczjk/vk5;

    iget-boolean p3, p3, Llyiahf/vczjk/vk5;->OooO0O0:Z

    new-instance p4, Llyiahf/vczjk/fz3;

    const/16 v0, 0x9

    invoke-direct {p4, p0, v0}, Llyiahf/vczjk/fz3;-><init>(Ljava/lang/Object;I)V

    move-object/from16 v0, p9

    move-object/from16 v1, p10

    invoke-direct {p2, p3, v1, v0, p4}, Llyiahf/vczjk/xj5;-><init>(ZLlyiahf/vczjk/xr1;Llyiahf/vczjk/gi;Llyiahf/vczjk/fz3;)V

    invoke-virtual {p1, p0, p2}, Llyiahf/vczjk/ha6;->OooO00o(Llyiahf/vczjk/uy4;Llyiahf/vczjk/y96;)V

    return-void

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "Dialog has no window"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/le3;Llyiahf/vczjk/vk5;JLlyiahf/vczjk/yn4;)V
    .locals 1

    iput-object p1, p0, Llyiahf/vczjk/yj5;->OooOOOo:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/yj5;->OooOOo0:Llyiahf/vczjk/vk5;

    iput-wide p3, p0, Llyiahf/vczjk/yj5;->OooOOo:J

    iget-object p1, p2, Llyiahf/vczjk/vk5;->OooO00o:Llyiahf/vczjk/ic8;

    iget-object p2, p0, Llyiahf/vczjk/yj5;->OooOOoo:Landroid/view/View;

    invoke-virtual {p2}, Landroid/view/View;->getRootView()Landroid/view/View;

    move-result-object p2

    invoke-virtual {p2}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p2

    instance-of p3, p2, Landroid/view/WindowManager$LayoutParams;

    if-eqz p3, :cond_0

    check-cast p2, Landroid/view/WindowManager$LayoutParams;

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    const/4 p3, 0x0

    const/4 p4, 0x1

    const/16 v0, 0x2000

    if-eqz p2, :cond_1

    iget p2, p2, Landroid/view/WindowManager$LayoutParams;->flags:I

    and-int/2addr p2, v0

    if-eqz p2, :cond_1

    move p2, p4

    goto :goto_1

    :cond_1
    move p2, p3

    :goto_1
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_4

    if-eq p1, p4, :cond_3

    const/4 p2, 0x2

    if-ne p1, p2, :cond_2

    move p2, p3

    goto :goto_2

    :cond_2
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_3
    move p2, p4

    :cond_4
    :goto_2
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    if-eqz p2, :cond_5

    move p2, v0

    goto :goto_3

    :cond_5
    const/16 p2, -0x2001

    :goto_3
    invoke-virtual {p1, p2, v0}, Landroid/view/Window;->setFlags(II)V

    invoke-virtual {p5}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    if-eqz p1, :cond_7

    if-ne p1, p4, :cond_6

    move p3, p4

    goto :goto_4

    :cond_6
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_7
    :goto_4
    iget-object p1, p0, Llyiahf/vczjk/yj5;->OooOo00:Llyiahf/vczjk/tj5;

    invoke-virtual {p1, p3}, Landroid/view/View;->setLayoutDirection(I)V

    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object p1

    if-eqz p1, :cond_8

    const/4 p2, -0x1

    invoke-virtual {p1, p2, p2}, Landroid/view/Window;->setLayout(II)V

    :cond_8
    invoke-virtual {p0}, Landroid/app/Dialog;->getWindow()Landroid/view/Window;

    move-result-object p1

    if-eqz p1, :cond_a

    sget p2, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 p3, 0x1e

    if-lt p2, p3, :cond_9

    const/16 p2, 0x30

    goto :goto_5

    :cond_9
    const/16 p2, 0x10

    :goto_5
    invoke-virtual {p1, p2}, Landroid/view/Window;->setSoftInputMode(I)V

    :cond_a
    return-void
.end method

.method public final cancel()V
    .locals 0

    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 1

    invoke-super {p0, p1}, Landroid/app/Dialog;->onTouchEvent(Landroid/view/MotionEvent;)Z

    move-result p1

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/yj5;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    return p1
.end method
