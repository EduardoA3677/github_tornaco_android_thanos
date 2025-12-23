.class public final Llyiahf/vczjk/zc;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnDragListener;
.implements Llyiahf/vczjk/ee2;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ie2;

.field public final OooO0O0:Llyiahf/vczjk/ny;

.field public final OooO0OO:Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ie2;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    const-wide/16 v1, 0x0

    iput-wide v1, v0, Llyiahf/vczjk/ie2;->OooOoo:J

    iput-object v0, p0, Llyiahf/vczjk/zc;->OooO00o:Llyiahf/vczjk/ie2;

    new-instance v0, Llyiahf/vczjk/ny;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ny;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/zc;->OooO0O0:Llyiahf/vczjk/ny;

    new-instance v0, Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;

    invoke-direct {v0, p0}, Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;-><init>(Llyiahf/vczjk/zc;)V

    iput-object v0, p0, Llyiahf/vczjk/zc;->OooO0OO:Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;

    return-void
.end method


# virtual methods
.method public final onDrag(Landroid/view/View;Landroid/view/DragEvent;)Z
    .locals 5

    new-instance p1, Llyiahf/vczjk/de2;

    invoke-direct {p1, p2}, Llyiahf/vczjk/de2;-><init>(Landroid/view/DragEvent;)V

    invoke-virtual {p2}, Landroid/view/DragEvent;->getAction()I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/zc;->OooO00o:Llyiahf/vczjk/ie2;

    iget-object v1, p0, Llyiahf/vczjk/zc;->OooO0O0:Llyiahf/vczjk/ny;

    const/4 v2, 0x0

    packed-switch p2, :pswitch_data_0

    return v2

    :pswitch_0
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000o0(Llyiahf/vczjk/de2;)V

    return v2

    :pswitch_1
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000Oo(Llyiahf/vczjk/de2;)V

    return v2

    :pswitch_2
    new-instance p2, Llyiahf/vczjk/ge2;

    invoke-direct {p2, p1}, Llyiahf/vczjk/ge2;-><init>(Llyiahf/vczjk/de2;)V

    invoke-virtual {p2, v0}, Llyiahf/vczjk/ge2;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    sget-object v3, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    if-eq p1, v3, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {v0, p2}, Llyiahf/vczjk/er8;->OooOo(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    :goto_0
    invoke-virtual {v1}, Llyiahf/vczjk/ny;->clear()V

    return v2

    :pswitch_3
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o00000OO(Llyiahf/vczjk/de2;)Z

    move-result p1

    return p1

    :pswitch_4
    invoke-virtual {v0, p1}, Llyiahf/vczjk/ie2;->o0000Ooo(Llyiahf/vczjk/de2;)V

    return v2

    :pswitch_5
    new-instance p2, Llyiahf/vczjk/dl7;

    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    new-instance v2, Llyiahf/vczjk/fe2;

    invoke-direct {v2, p1, v0, p2}, Llyiahf/vczjk/fe2;-><init>(Llyiahf/vczjk/de2;Llyiahf/vczjk/ie2;Llyiahf/vczjk/dl7;)V

    invoke-virtual {v2, v0}, Llyiahf/vczjk/fe2;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    sget-object v4, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    if-eq v3, v4, :cond_1

    goto :goto_1

    :cond_1
    invoke-static {v0, v2}, Llyiahf/vczjk/er8;->OooOo(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    :goto_1
    iget-boolean p2, p2, Llyiahf/vczjk/dl7;->element:Z

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v0, Llyiahf/vczjk/cy;

    invoke-direct {v0, v1}, Llyiahf/vczjk/cy;-><init>(Llyiahf/vczjk/ny;)V

    :goto_2
    invoke-virtual {v0}, Llyiahf/vczjk/cy;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/cy;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/ie2;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/ie2;->o00000oO(Llyiahf/vczjk/de2;)V

    goto :goto_2

    :cond_2
    return p2

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
