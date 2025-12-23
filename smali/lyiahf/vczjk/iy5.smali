.class public final Llyiahf/vczjk/iy5;
.super Llyiahf/vczjk/cl7;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0o:Llyiahf/vczjk/ly5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ly5;Lcom/google/android/material/internal/NavigationMenuView;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/iy5;->OooO0o:Llyiahf/vczjk/ly5;

    invoke-direct {p0, p2}, Llyiahf/vczjk/cl7;-><init>(Landroidx/recyclerview/widget/RecyclerView;)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Landroid/view/View;Llyiahf/vczjk/o0O0oo00;)V
    .locals 6

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/cl7;->OooO0Oo(Landroid/view/View;Llyiahf/vczjk/o0O0oo00;)V

    iget-object p1, p0, Llyiahf/vczjk/iy5;->OooO0o:Llyiahf/vczjk/ly5;

    iget-object p1, p1, Llyiahf/vczjk/ly5;->OooOOo0:Llyiahf/vczjk/dy5;

    const/4 v0, 0x0

    move v1, v0

    move v2, v1

    :goto_0
    iget-object v3, p1, Llyiahf/vczjk/dy5;->OooO0oO:Llyiahf/vczjk/ly5;

    iget-object v4, v3, Llyiahf/vczjk/ly5;->OooOOo0:Llyiahf/vczjk/dy5;

    iget-object v4, v4, Llyiahf/vczjk/dy5;->OooO0Oo:Ljava/util/ArrayList;

    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v4

    const/4 v5, 0x1

    if-ge v1, v4, :cond_2

    iget-object v3, v3, Llyiahf/vczjk/ly5;->OooOOo0:Llyiahf/vczjk/dy5;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/dy5;->OooO0o0(I)I

    move-result v3

    if-eqz v3, :cond_0

    if-ne v3, v5, :cond_1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    :cond_1
    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_2
    invoke-static {v2, v5, v0}, Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;->obtain(IIZ)Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;

    move-result-object p1

    iget-object p2, p2, Llyiahf/vczjk/o0O0oo00;->OooO00o:Landroid/view/accessibility/AccessibilityNodeInfo;

    invoke-virtual {p2, p1}, Landroid/view/accessibility/AccessibilityNodeInfo;->setCollectionInfo(Landroid/view/accessibility/AccessibilityNodeInfo$CollectionInfo;)V

    return-void
.end method
