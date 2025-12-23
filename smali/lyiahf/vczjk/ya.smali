.class public final synthetic Llyiahf/vczjk/ya;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/accessibility/AccessibilityManager$AccessibilityStateChangeListener;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/hb;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hb;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ya;->OooOOO0:Llyiahf/vczjk/hb;

    return-void
.end method


# virtual methods
.method public final onAccessibilityStateChanged(Z)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/ya;->OooOOO0:Llyiahf/vczjk/hb;

    if-eqz p1, :cond_0

    iget-object p1, v0, Llyiahf/vczjk/hb;->OooO0oO:Landroid/view/accessibility/AccessibilityManager;

    const/4 v1, -0x1

    invoke-virtual {p1, v1}, Landroid/view/accessibility/AccessibilityManager;->getEnabledAccessibilityServiceList(I)Ljava/util/List;

    move-result-object p1

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    :goto_0
    iput-object p1, v0, Llyiahf/vczjk/hb;->OooOO0O:Ljava/util/List;

    return-void
.end method
