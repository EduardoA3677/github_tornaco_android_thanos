.class public final Llyiahf/vczjk/d83;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/f83;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/f83;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d83;->this$0:Llyiahf/vczjk/f83;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/op0;

    iget-object v0, p0, Llyiahf/vczjk/d83;->this$0:Llyiahf/vczjk/f83;

    invoke-static {v0}, Llyiahf/vczjk/c6a;->OooOoO0(Llyiahf/vczjk/jl5;)Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->isFocused()Z

    move-result v1

    if-nez v1, :cond_0

    invoke-virtual {v0}, Landroid/view/View;->hasFocus()Z

    move-result v1

    if-nez v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/d83;->this$0:Llyiahf/vczjk/f83;

    invoke-static {v1}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getFocusOwner()Llyiahf/vczjk/m83;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/d83;->this$0:Llyiahf/vczjk/f83;

    invoke-static {v2}, Llyiahf/vczjk/ye5;->OooOooO(Llyiahf/vczjk/l52;)Landroid/view/View;

    move-result-object v2

    iget v3, p1, Llyiahf/vczjk/op0;->OooO00o:I

    invoke-static {v3}, Llyiahf/vczjk/nqa;->Oooo0oO(I)Ljava/lang/Integer;

    move-result-object v3

    invoke-static {v1, v2, v0}, Llyiahf/vczjk/c6a;->OooOo(Llyiahf/vczjk/m83;Landroid/view/View;Landroid/view/View;)Landroid/graphics/Rect;

    move-result-object v1

    invoke-static {v0, v3, v1}, Llyiahf/vczjk/nqa;->Oooo0OO(Landroid/view/View;Ljava/lang/Integer;Landroid/graphics/Rect;)Z

    move-result v0

    if-nez v0, :cond_0

    const/4 v0, 0x1

    iput-boolean v0, p1, Llyiahf/vczjk/op0;->OooO0O0:Z

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
