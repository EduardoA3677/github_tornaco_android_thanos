.class public final Llyiahf/vczjk/xz6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/zz6;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/zz6;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xz6;->this$0:Llyiahf/vczjk/zz6;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/le3;

    iget-object v0, p0, Llyiahf/vczjk/xz6;->this$0:Llyiahf/vczjk/zz6;

    invoke-virtual {v0}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    move-result-object v0

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Landroid/os/Handler;->getLooper()Landroid/os/Looper;

    move-result-object v0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v1

    if-ne v0, v1, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    goto :goto_1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/xz6;->this$0:Llyiahf/vczjk/zz6;

    invoke-virtual {v0}, Landroid/view/View;->getHandler()Landroid/os/Handler;

    move-result-object v0

    if-eqz v0, :cond_2

    new-instance v1, Llyiahf/vczjk/sa;

    const/4 v2, 0x1

    invoke-direct {v1, v2, p1}, Llyiahf/vczjk/sa;-><init>(ILlyiahf/vczjk/le3;)V

    invoke-virtual {v0, v1}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    :cond_2
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
