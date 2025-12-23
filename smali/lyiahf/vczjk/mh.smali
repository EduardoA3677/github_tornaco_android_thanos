.class public final Llyiahf/vczjk/mh;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/nh;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nga;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mh;->this$0:Llyiahf/vczjk/nh;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/mh;->this$0:Llyiahf/vczjk/nh;

    iget-boolean v1, v0, Llyiahf/vczjk/nh;->OooOOo0:Z

    if-eqz v1, :cond_0

    invoke-virtual {v0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/mh;->this$0:Llyiahf/vczjk/nh;

    invoke-virtual {v0}, Llyiahf/vczjk/nh;->getView()Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/mh;->this$0:Llyiahf/vczjk/nh;

    if-ne v0, v1, :cond_0

    invoke-static {v1}, Llyiahf/vczjk/nh;->OooOO0(Llyiahf/vczjk/nh;)Llyiahf/vczjk/vg6;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/mh;->this$0:Llyiahf/vczjk/nh;

    sget-object v2, Llyiahf/vczjk/o6;->OooOo0o:Llyiahf/vczjk/o6;

    invoke-virtual {v1}, Llyiahf/vczjk/nh;->getUpdate()Llyiahf/vczjk/le3;

    move-result-object v3

    invoke-virtual {v0, v1, v2, v3}, Llyiahf/vczjk/vg6;->OooO00o(Llyiahf/vczjk/ug6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;)V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
