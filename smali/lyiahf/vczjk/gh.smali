.class public final Llyiahf/vczjk/gh;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/lf5;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/nga;

.field public final synthetic OooO0O0:Llyiahf/vczjk/ro4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gh;->OooO00o:Llyiahf/vczjk/nga;

    iput-object p2, p0, Llyiahf/vczjk/gh;->OooO0O0:Llyiahf/vczjk/ro4;

    return-void
.end method


# virtual methods
.method public final OooO(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/gh;->OooO00o:Llyiahf/vczjk/nga;

    invoke-virtual {p1}, Llyiahf/vczjk/nh;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget p2, p2, Landroid/view/ViewGroup$LayoutParams;->width:I

    const/4 v0, 0x0

    invoke-static {p1, v0, p3, p2}, Llyiahf/vczjk/nh;->OooOO0O(Llyiahf/vczjk/nga;III)I

    move-result p2

    invoke-static {v0, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p3

    invoke-virtual {p1, p2, p3}, Landroid/view/View;->measure(II)V

    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    move-result p1

    return p1
.end method

.method public final OooO0OO(Llyiahf/vczjk/nf5;Ljava/util/List;J)Llyiahf/vczjk/mf5;
    .locals 4

    iget-object p2, p0, Llyiahf/vczjk/gh;->OooO00o:Llyiahf/vczjk/nga;

    invoke-virtual {p2}, Landroid/view/ViewGroup;->getChildCount()I

    move-result v0

    sget-object v1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    if-nez v0, :cond_0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result p2

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result p3

    sget-object p4, Llyiahf/vczjk/o6;->OooOo:Llyiahf/vczjk/o6;

    invoke-interface {p1, p2, p3, v1, p4}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v0

    const/4 v2, 0x0

    if-eqz v0, :cond_1

    invoke-virtual {p2, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v3

    invoke-virtual {v0, v3}, Landroid/view/View;->setMinimumWidth(I)V

    :cond_1
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p2, v2}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    move-result-object v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v2

    invoke-virtual {v0, v2}, Landroid/view/View;->setMinimumHeight(I)V

    :cond_2
    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooOO0(J)I

    move-result v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oo(J)I

    move-result v2

    invoke-virtual {p2}, Llyiahf/vczjk/nh;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v3

    invoke-static {v3}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget v3, v3, Landroid/view/ViewGroup$LayoutParams;->width:I

    invoke-static {p2, v0, v2, v3}, Llyiahf/vczjk/nh;->OooOO0O(Llyiahf/vczjk/nga;III)I

    move-result v0

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO(J)I

    move-result v2

    invoke-static {p3, p4}, Llyiahf/vczjk/rk1;->OooO0oO(J)I

    move-result p3

    invoke-virtual {p2}, Llyiahf/vczjk/nh;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p4

    invoke-static {p4}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget p4, p4, Landroid/view/ViewGroup$LayoutParams;->height:I

    invoke-static {p2, v2, p3, p4}, Llyiahf/vczjk/nh;->OooOO0O(Llyiahf/vczjk/nga;III)I

    move-result p3

    invoke-virtual {p2, v0, p3}, Landroid/view/View;->measure(II)V

    invoke-virtual {p2}, Landroid/view/View;->getMeasuredWidth()I

    move-result p3

    invoke-virtual {p2}, Landroid/view/View;->getMeasuredHeight()I

    move-result p4

    new-instance v0, Llyiahf/vczjk/fh;

    iget-object v2, p0, Llyiahf/vczjk/gh;->OooO0O0:Llyiahf/vczjk/ro4;

    invoke-direct {v0, p2, v2}, Llyiahf/vczjk/fh;-><init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;)V

    invoke-interface {p1, p3, p4, v1, v0}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 2

    const/4 p1, 0x0

    invoke-static {p1, p1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/gh;->OooO00o:Llyiahf/vczjk/nga;

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget v1, v1, Landroid/view/ViewGroup$LayoutParams;->height:I

    invoke-static {v0, p1, p3, v1}, Llyiahf/vczjk/nh;->OooOO0O(Llyiahf/vczjk/nga;III)I

    move-result p1

    invoke-virtual {v0, p2, p1}, Landroid/view/View;->measure(II)V

    invoke-virtual {v0}, Landroid/view/View;->getMeasuredWidth()I

    move-result p1

    return p1
.end method

.method public final OooO0o(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 2

    const/4 p1, 0x0

    invoke-static {p1, p1}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/gh;->OooO00o:Llyiahf/vczjk/nga;

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget v1, v1, Landroid/view/ViewGroup$LayoutParams;->height:I

    invoke-static {v0, p1, p3, v1}, Llyiahf/vczjk/nh;->OooOO0O(Llyiahf/vczjk/nga;III)I

    move-result p1

    invoke-virtual {v0, p2, p1}, Landroid/view/View;->measure(II)V

    invoke-virtual {v0}, Landroid/view/View;->getMeasuredWidth()I

    move-result p1

    return p1
.end method

.method public final OooOO0(Llyiahf/vczjk/o34;Ljava/util/List;I)I
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/gh;->OooO00o:Llyiahf/vczjk/nga;

    invoke-virtual {p1}, Llyiahf/vczjk/nh;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object p2

    invoke-static {p2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget p2, p2, Landroid/view/ViewGroup$LayoutParams;->width:I

    const/4 v0, 0x0

    invoke-static {p1, v0, p3, p2}, Llyiahf/vczjk/nh;->OooOO0O(Llyiahf/vczjk/nga;III)I

    move-result p2

    invoke-static {v0, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    move-result p3

    invoke-virtual {p1, p2, p3}, Landroid/view/View;->measure(II)V

    invoke-virtual {p1}, Landroid/view/View;->getMeasuredHeight()I

    move-result p1

    return p1
.end method
