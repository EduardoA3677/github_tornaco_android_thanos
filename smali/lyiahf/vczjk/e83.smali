.class public final Llyiahf/vczjk/e83;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/f83;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f83;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/e83;->this$0:Llyiahf/vczjk/f83;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    check-cast p1, Llyiahf/vczjk/op0;

    iget-object v0, p0, Llyiahf/vczjk/e83;->this$0:Llyiahf/vczjk/f83;

    invoke-static {v0}, Llyiahf/vczjk/c6a;->OooOoO0(Llyiahf/vczjk/jl5;)Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->hasFocus()Z

    move-result v1

    if-eqz v1, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/e83;->this$0:Llyiahf/vczjk/f83;

    invoke-static {v1}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/e83;->this$0:Llyiahf/vczjk/f83;

    invoke-static {v2}, Llyiahf/vczjk/ye5;->OooOooO(Llyiahf/vczjk/l52;)Landroid/view/View;

    move-result-object v2

    instance-of v3, v0, Landroid/view/ViewGroup;

    const-string v4, "host view did not take focus"

    if-nez v3, :cond_1

    invoke-virtual {v2}, Landroid/view/View;->requestFocus()Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {v1, v2, v0}, Llyiahf/vczjk/c6a;->OooOo(Llyiahf/vczjk/m83;Landroid/view/View;Landroid/view/View;)Landroid/graphics/Rect;

    move-result-object v1

    iget v3, p1, Llyiahf/vczjk/op0;->OooO00o:I

    invoke-static {v3}, Llyiahf/vczjk/nqa;->Oooo0oO(I)Ljava/lang/Integer;

    move-result-object v3

    if-eqz v3, :cond_2

    invoke-virtual {v3}, Ljava/lang/Integer;->intValue()I

    move-result v3

    goto :goto_0

    :cond_2
    const/16 v3, 0x82

    :goto_0
    invoke-static {}, Landroid/view/FocusFinder;->getInstance()Landroid/view/FocusFinder;

    move-result-object v5

    iget-object v6, p0, Llyiahf/vczjk/e83;->this$0:Llyiahf/vczjk/f83;

    iget-object v6, v6, Llyiahf/vczjk/f83;->OooOoOO:Landroid/view/View;

    if-eqz v6, :cond_3

    move-object v7, v2

    check-cast v7, Landroid/view/ViewGroup;

    invoke-virtual {v5, v7, v6, v3}, Landroid/view/FocusFinder;->findNextFocus(Landroid/view/ViewGroup;Landroid/view/View;I)Landroid/view/View;

    move-result-object v5

    goto :goto_1

    :cond_3
    move-object v6, v2

    check-cast v6, Landroid/view/ViewGroup;

    invoke-virtual {v5, v6, v1, v3}, Landroid/view/FocusFinder;->findNextFocusFromRect(Landroid/view/ViewGroup;Landroid/graphics/Rect;I)Landroid/view/View;

    move-result-object v5

    :goto_1
    if-eqz v5, :cond_4

    invoke-static {v0, v5}, Llyiahf/vczjk/c6a;->OooOo0o(Landroid/view/View;Landroid/view/View;)Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-virtual {v5, v3, v1}, Landroid/view/View;->requestFocus(ILandroid/graphics/Rect;)Z

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/op0;->OooO0O0:Z

    goto :goto_2

    :cond_4
    invoke-virtual {v2}, Landroid/view/View;->requestFocus()Z

    move-result p1

    if-eqz p1, :cond_5

    goto :goto_2

    :cond_5
    new-instance p1, Ljava/lang/IllegalStateException;

    invoke-direct {p1, v4}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_6
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
