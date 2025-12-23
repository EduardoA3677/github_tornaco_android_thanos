.class public abstract Llyiahf/vczjk/dr;
.super Ljava/lang/Object;
.source "SourceFile"


# direct methods
.method public static OooO00o(Landroid/app/Activity;)Landroid/window/OnBackInvokedDispatcher;
    .locals 0

    invoke-static {p0}, Llyiahf/vczjk/oo0OOoo;->OooOOO(Landroid/app/Activity;)Landroid/window/OnBackInvokedDispatcher;

    move-result-object p0

    return-object p0
.end method

.method public static OooO0O0(Ljava/lang/Object;Llyiahf/vczjk/jr;)Landroid/window/OnBackInvokedCallback;
    .locals 2

    invoke-static {p1}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/zo;

    const/4 v1, 0x1

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/zo;-><init>(Ljava/lang/Object;I)V

    invoke-static {p0}, Llyiahf/vczjk/oo0OOoo;->OooOOOo(Ljava/lang/Object;)Landroid/window/OnBackInvokedDispatcher;

    move-result-object p0

    invoke-static {p0, v0}, Llyiahf/vczjk/oo0OOoo;->OooOo0O(Landroid/window/OnBackInvokedDispatcher;Llyiahf/vczjk/zo;)V

    return-object v0
.end method

.method public static OooO0OO(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/oo0OOoo;->OooOOO0(Ljava/lang/Object;)Landroid/window/OnBackInvokedCallback;

    move-result-object p1

    invoke-static {p0}, Llyiahf/vczjk/oo0OOoo;->OooOOOo(Ljava/lang/Object;)Landroid/window/OnBackInvokedDispatcher;

    move-result-object p0

    invoke-static {p0, p1}, Llyiahf/vczjk/oo0OOoo;->OooOo0(Landroid/window/OnBackInvokedDispatcher;Landroid/window/OnBackInvokedCallback;)V

    return-void
.end method
