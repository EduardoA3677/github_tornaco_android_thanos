.class public final Llyiahf/vczjk/hh;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $layoutNode:Llyiahf/vczjk/ro4;

.field final synthetic $this_run:Llyiahf/vczjk/nh;

.field final synthetic this$0:Llyiahf/vczjk/nh;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;Llyiahf/vczjk/ro4;Llyiahf/vczjk/nga;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hh;->$this_run:Llyiahf/vczjk/nh;

    iput-object p2, p0, Llyiahf/vczjk/hh;->$layoutNode:Llyiahf/vczjk/ro4;

    iput-object p3, p0, Llyiahf/vczjk/hh;->this$0:Llyiahf/vczjk/nh;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/hg2;

    iget-object v0, p0, Llyiahf/vczjk/hh;->$this_run:Llyiahf/vczjk/nh;

    iget-object v1, p0, Llyiahf/vczjk/hh;->$layoutNode:Llyiahf/vczjk/ro4;

    iget-object v2, p0, Llyiahf/vczjk/hh;->this$0:Llyiahf/vczjk/nh;

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object p1

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getView()Landroid/view/View;

    move-result-object v3

    invoke-virtual {v3}, Landroid/view/View;->getVisibility()I

    move-result v3

    const/16 v4, 0x8

    if-eq v3, v4, :cond_2

    const/4 v3, 0x1

    iput-boolean v3, v0, Llyiahf/vczjk/nh;->Oooo0O0:Z

    iget-object v1, v1, Llyiahf/vczjk/ro4;->OooOoO:Llyiahf/vczjk/xa;

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    :goto_0
    if-eqz v1, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/t9;->OooO00o(Llyiahf/vczjk/eq0;)Landroid/graphics/Canvas;

    move-result-object p1

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getAndroidViewsHandler$ui_release()Llyiahf/vczjk/th;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2, p1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    :cond_1
    const/4 p1, 0x0

    iput-boolean p1, v0, Llyiahf/vczjk/nh;->Oooo0O0:Z

    :cond_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
