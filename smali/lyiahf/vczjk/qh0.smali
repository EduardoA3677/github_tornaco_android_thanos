.class public final Llyiahf/vczjk/qh0;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oh0;


# instance fields
.field public OooOoOO:Landroid/view/ViewGroup;


# virtual methods
.method public final OooooOO(Llyiahf/vczjk/v16;Llyiahf/vczjk/ph0;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 2

    const-wide/16 v0, 0x0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/v16;->OoooOO0(J)J

    move-result-wide v0

    invoke-virtual {p2}, Llyiahf/vczjk/ph0;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wj7;

    if-eqz p1, :cond_0

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/wj7;->OooO(J)Llyiahf/vczjk/wj7;

    move-result-object p1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/qh0;->OooOoOO:Landroid/view/ViewGroup;

    invoke-static {p1}, Llyiahf/vczjk/dl6;->OooOOO(Llyiahf/vczjk/wj7;)Landroid/graphics/Rect;

    move-result-object p1

    const/4 p3, 0x0

    invoke-virtual {p2, p1, p3}, Landroid/view/View;->requestRectangleOnScreen(Landroid/graphics/Rect;Z)Z

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
