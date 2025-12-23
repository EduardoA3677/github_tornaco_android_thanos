.class public final Llyiahf/vczjk/x;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/pc2;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/x;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()V
    .locals 2

    iget v0, p0, Llyiahf/vczjk/x;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/d17;

    invoke-virtual {v0}, Llyiahf/vczjk/y96;->OooO0o0()V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yj5;

    invoke-virtual {v0}, Landroid/app/Dialog;->dismiss()V

    iget-object v0, v0, Llyiahf/vczjk/yj5;->OooOo00:Llyiahf/vczjk/tj5;

    invoke-virtual {v0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0Oo()V

    return-void

    :pswitch_1
    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/eu4;

    iput-boolean v0, v1, Llyiahf/vczjk/eu4;->OooO0o:Z

    return-void

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ku4;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/ku4;->OooO0OO:Llyiahf/vczjk/ed5;

    return-void

    :pswitch_3
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/jt4;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/jt4;->OooO0Oo:Llyiahf/vczjk/a91;

    return-void

    :pswitch_4
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/mk9;

    invoke-virtual {v0}, Llyiahf/vczjk/mk9;->OooOOO()V

    return-void

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/r40;

    invoke-virtual {v0}, Llyiahf/vczjk/y96;->OooO0o0()V

    return-void

    :pswitch_6
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/zz6;

    invoke-virtual {v0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0Oo()V

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-static {v0, v1}, Llyiahf/vczjk/dr6;->OooOo0(Landroid/view/View;Llyiahf/vczjk/uy4;)V

    iget-object v1, v0, Llyiahf/vczjk/zz6;->OooOoO:Landroid/view/WindowManager;

    invoke-interface {v1, v0}, Landroid/view/WindowManager;->removeViewImmediate(Landroid/view/View;)V

    return-void

    :pswitch_7
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/eb2;

    invoke-virtual {v0}, Landroid/app/Dialog;->dismiss()V

    iget-object v0, v0, Llyiahf/vczjk/eb2;->OooOOoo:Llyiahf/vczjk/xa2;

    invoke-virtual {v0}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0Oo()V

    return-void

    :pswitch_8
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vc2;

    iget-object v0, v0, Llyiahf/vczjk/vc2;->OooO00o:Llyiahf/vczjk/wc2;

    invoke-virtual {v0}, Llyiahf/vczjk/wc2;->OooO00o()Ljava/lang/Object;

    return-void

    :pswitch_9
    iget-object v0, p0, Llyiahf/vczjk/x;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/q;

    iget-object v0, v0, Llyiahf/vczjk/q;->OooO00o:Llyiahf/vczjk/v;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/v;->OooO0O0()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    return-void

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Launcher has not been initialized"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
