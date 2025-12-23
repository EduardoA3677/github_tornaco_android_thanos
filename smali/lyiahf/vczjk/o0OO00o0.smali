.class public final synthetic Llyiahf/vczjk/o0OO00o0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final synthetic OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 2

    iget p1, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    sget-object p1, Llyiahf/vczjk/iy4;->ON_DESTROY:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO:Ljava/lang/Object;

    check-cast p1, Landroidx/compose/ui/platform/AbstractComposeView;

    invoke-virtual {p1}, Landroidx/compose/ui/platform/AbstractComposeView;->OooO0Oo()V

    :cond_0
    return-void

    :pswitch_0
    sget-object p1, Llyiahf/vczjk/iy4;->ON_START:Llyiahf/vczjk/iy4;

    iget-object v0, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/g68;

    if-ne p2, p1, :cond_1

    const/4 p1, 0x1

    iput-boolean p1, v0, Llyiahf/vczjk/g68;->OooO0oo:Z

    goto :goto_0

    :cond_1
    sget-object p1, Llyiahf/vczjk/iy4;->ON_STOP:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_2

    const/4 p1, 0x0

    iput-boolean p1, v0, Llyiahf/vczjk/g68;->OooO0oo:Z

    :cond_2
    :goto_0
    return-void

    :pswitch_1
    sget-object p1, Llyiahf/vczjk/iy4;->ON_RESUME:Llyiahf/vczjk/iy4;

    if-ne p2, p1, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/qs5;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_3
    return-void

    :pswitch_2
    invoke-virtual {p2}, Llyiahf/vczjk/iy4;->OooO00o()Llyiahf/vczjk/jy4;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/su5;

    iput-object p1, v0, Llyiahf/vczjk/su5;->OooOOo0:Llyiahf/vczjk/jy4;

    iget-object p1, v0, Llyiahf/vczjk/su5;->OooO0OO:Llyiahf/vczjk/dv5;

    if-eqz p1, :cond_4

    iget-object p1, v0, Llyiahf/vczjk/su5;->OooO0o:Llyiahf/vczjk/xx;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o0000OO0(Ljava/util/Collection;)Ljava/util/ArrayList;

    move-result-object p1

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ku5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, v0, Llyiahf/vczjk/ku5;->OooOo00:Llyiahf/vczjk/mu5;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p2}, Llyiahf/vczjk/iy4;->OooO00o()Llyiahf/vczjk/jy4;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/mu5;->OooO0Oo:Llyiahf/vczjk/jy4;

    invoke-virtual {v0}, Llyiahf/vczjk/mu5;->OooO0O0()V

    goto :goto_1

    :cond_4
    return-void

    :pswitch_3
    iget-object p1, p0, Llyiahf/vczjk/o0OO00o0;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/oe3;

    invoke-interface {p1, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
