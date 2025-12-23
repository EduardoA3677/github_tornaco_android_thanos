.class public final Llyiahf/vczjk/cy5;
.super Llyiahf/vczjk/o0oO0Ooo;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0Oo:I

.field public final synthetic OooO0o:Llyiahf/vczjk/dy5;

.field public final synthetic OooO0o0:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dy5;IZ)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cy5;->OooO0o:Llyiahf/vczjk/dy5;

    iput p2, p0, Llyiahf/vczjk/cy5;->OooO0Oo:I

    iput-boolean p3, p0, Llyiahf/vczjk/cy5;->OooO0o0:Z

    invoke-direct {p0}, Llyiahf/vczjk/o0oO0Ooo;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Landroid/view/View;Llyiahf/vczjk/o0O0oo00;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/o0oO0Ooo;->OooO00o:Landroid/view/View$AccessibilityDelegate;

    iget-object v1, p2, Llyiahf/vczjk/o0O0oo00;->OooO00o:Landroid/view/accessibility/AccessibilityNodeInfo;

    invoke-virtual {v0, p1, v1}, Landroid/view/View$AccessibilityDelegate;->onInitializeAccessibilityNodeInfo(Landroid/view/View;Landroid/view/accessibility/AccessibilityNodeInfo;)V

    iget v0, p0, Llyiahf/vczjk/cy5;->OooO0Oo:I

    const/4 v1, 0x0

    move v2, v0

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/cy5;->OooO0o:Llyiahf/vczjk/dy5;

    if-ge v1, v0, :cond_2

    iget-object v3, v3, Llyiahf/vczjk/dy5;->OooO0oO:Llyiahf/vczjk/ly5;

    iget-object v4, v3, Llyiahf/vczjk/ly5;->OooOOo0:Llyiahf/vczjk/dy5;

    invoke-virtual {v4, v1}, Llyiahf/vczjk/dy5;->OooO0o0(I)I

    move-result v4

    const/4 v5, 0x2

    if-eq v4, v5, :cond_0

    iget-object v3, v3, Llyiahf/vczjk/ly5;->OooOOo0:Llyiahf/vczjk/dy5;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/dy5;->OooO0o0(I)I

    move-result v3

    const/4 v4, 0x3

    if-ne v3, v4, :cond_1

    :cond_0
    add-int/lit8 v2, v2, -0x1

    :cond_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p1}, Landroid/view/View;->isSelected()Z

    move-result v7

    const/4 v4, 0x1

    const/4 v5, 0x1

    const/4 v3, 0x1

    iget-boolean v6, p0, Llyiahf/vczjk/cy5;->OooO0o0:Z

    invoke-static/range {v2 .. v7}, Llyiahf/vczjk/tqa;->OooO0OO(IIIIZZ)Llyiahf/vczjk/tqa;

    move-result-object p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/o0O0oo00;->OooOOO0(Llyiahf/vczjk/tqa;)V

    return-void
.end method
