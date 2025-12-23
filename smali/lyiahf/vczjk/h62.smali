.class public final Llyiahf/vczjk/h62;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/g62;
.implements Llyiahf/vczjk/apa;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/h62;

.field public static final OooOOO0:Llyiahf/vczjk/h62;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/h62;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/h62;->OooOOO0:Llyiahf/vczjk/h62;

    new-instance v0, Llyiahf/vczjk/h62;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/h62;->OooOOO:Llyiahf/vczjk/h62;

    return-void
.end method


# virtual methods
.method public OooO00o(Landroid/content/Context;)F
    .locals 1

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-class v0, Landroid/view/WindowManager;

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/view/WindowManager;

    invoke-interface {p1}, Landroid/view/WindowManager;->getCurrentWindowMetrics()Landroid/view/WindowMetrics;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/WindowMetrics;->getDensity()F

    move-result p1

    return p1
.end method

.method public OooOO0o(Landroid/content/Context;Llyiahf/vczjk/g62;)Llyiahf/vczjk/zoa;
    .locals 2

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "densityCompatHelper"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-class p2, Landroid/view/WindowManager;

    invoke-virtual {p1, p2}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/view/WindowManager;

    new-instance p2, Llyiahf/vczjk/zoa;

    invoke-interface {p1}, Landroid/view/WindowManager;->getCurrentWindowMetrics()Landroid/view/WindowMetrics;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/WindowMetrics;->getBounds()Landroid/graphics/Rect;

    move-result-object v0

    const-string v1, "getBounds(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Landroid/view/WindowManager;->getCurrentWindowMetrics()Landroid/view/WindowMetrics;

    move-result-object p1

    invoke-virtual {p1}, Landroid/view/WindowMetrics;->getDensity()F

    move-result p1

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/zoa;-><init>(Landroid/graphics/Rect;F)V

    return-object p2
.end method

.method public OooOOOO(Landroid/app/Activity;Llyiahf/vczjk/g62;)Llyiahf/vczjk/zoa;
    .locals 3

    const-string v0, "activity"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "densityCompatHelper"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/zoa;

    new-instance v1, Llyiahf/vczjk/ug0;

    sget-object v2, Llyiahf/vczjk/wg0;->OooO0O0:Llyiahf/vczjk/vg0;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Llyiahf/vczjk/vg0;->OooO00o()Llyiahf/vczjk/wg0;

    move-result-object v2

    invoke-interface {v2, p1}, Llyiahf/vczjk/wg0;->OooO00o(Landroid/app/Activity;)Landroid/graphics/Rect;

    move-result-object v2

    invoke-direct {v1, v2}, Llyiahf/vczjk/ug0;-><init>(Landroid/graphics/Rect;)V

    invoke-interface {p2, p1}, Llyiahf/vczjk/g62;->OooO00o(Landroid/content/Context;)F

    move-result p1

    invoke-direct {v0, v1, p1}, Llyiahf/vczjk/zoa;-><init>(Llyiahf/vczjk/ug0;F)V

    return-object v0
.end method
