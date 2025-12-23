.class public final Llyiahf/vczjk/yw9;
.super Llyiahf/vczjk/tp6;
.source "SourceFile"


# instance fields
.field public final synthetic OooO00o:I

.field public OooO0O0:Z

.field public OooO0OO:I

.field public final synthetic OooO0Oo:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/appcompat/widget/Oooo000;I)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/yw9;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yw9;->OooO0Oo:Ljava/lang/Object;

    iput p2, p0, Llyiahf/vczjk/yw9;->OooO0OO:I

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/yw9;->OooO0O0:Z

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/gia;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/yw9;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yw9;->OooO0Oo:Ljava/lang/Object;

    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/yw9;->OooO0O0:Z

    iput p1, p0, Llyiahf/vczjk/yw9;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public OooO00o()V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/yw9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    return-void

    :pswitch_0
    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/yw9;->OooO0O0:Z

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0O0(Landroid/view/View;)V
    .locals 2

    iget p1, p0, Llyiahf/vczjk/yw9;->OooO00o:I

    packed-switch p1, :pswitch_data_0

    iget p1, p0, Llyiahf/vczjk/yw9;->OooO0OO:I

    add-int/lit8 p1, p1, 0x1

    iput p1, p0, Llyiahf/vczjk/yw9;->OooO0OO:I

    iget-object v0, p0, Llyiahf/vczjk/yw9;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/gia;

    iget-object v1, v0, Llyiahf/vczjk/gia;->OooO00o:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ne p1, v1, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/gia;->OooO0Oo:Llyiahf/vczjk/tp6;

    if-eqz p1, :cond_0

    const/4 v1, 0x0

    invoke-interface {p1, v1}, Llyiahf/vczjk/hia;->OooO0O0(Landroid/view/View;)V

    :cond_0
    const/4 p1, 0x0

    iput p1, p0, Llyiahf/vczjk/yw9;->OooO0OO:I

    iput-boolean p1, p0, Llyiahf/vczjk/yw9;->OooO0O0:Z

    iput-boolean p1, v0, Llyiahf/vczjk/gia;->OooO0o0:Z

    :cond_1
    return-void

    :pswitch_0
    iget-boolean p1, p0, Llyiahf/vczjk/yw9;->OooO0O0:Z

    if-nez p1, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/yw9;->OooO0Oo:Ljava/lang/Object;

    check-cast p1, Landroidx/appcompat/widget/Oooo000;

    iget-object p1, p1, Landroidx/appcompat/widget/Oooo000;->OooO00o:Landroidx/appcompat/widget/Toolbar;

    iget v0, p0, Llyiahf/vczjk/yw9;->OooO0OO:I

    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    :cond_2
    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final OooO0OO(Landroid/view/View;)V
    .locals 1

    iget p1, p0, Llyiahf/vczjk/yw9;->OooO00o:I

    packed-switch p1, :pswitch_data_0

    iget-boolean p1, p0, Llyiahf/vczjk/yw9;->OooO0O0:Z

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/yw9;->OooO0O0:Z

    iget-object p1, p0, Llyiahf/vczjk/yw9;->OooO0Oo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/gia;

    iget-object p1, p1, Llyiahf/vczjk/gia;->OooO0Oo:Llyiahf/vczjk/tp6;

    if-eqz p1, :cond_1

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Llyiahf/vczjk/hia;->OooO0OO(Landroid/view/View;)V

    :cond_1
    :goto_0
    return-void

    :pswitch_0
    iget-object p1, p0, Llyiahf/vczjk/yw9;->OooO0Oo:Ljava/lang/Object;

    check-cast p1, Landroidx/appcompat/widget/Oooo000;

    iget-object p1, p1, Landroidx/appcompat/widget/Oooo000;->OooO00o:Landroidx/appcompat/widget/Toolbar;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Landroid/view/View;->setVisibility(I)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
