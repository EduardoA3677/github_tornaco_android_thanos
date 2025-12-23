.class public final Llyiahf/vczjk/fr8;
.super Llyiahf/vczjk/eo6;
.source "SourceFile"


# instance fields
.field public final synthetic OooO0OO:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/fr8;->OooO0OO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Landroid/view/ViewGroup;Landroid/view/View;)F
    .locals 1

    iget v0, p0, Llyiahf/vczjk/fr8;->OooO0OO:I

    packed-switch v0, :pswitch_data_0

    invoke-virtual {p2}, Landroid/view/View;->getTranslationY()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    move-result p1

    int-to-float p1, p1

    add-float/2addr p2, p1

    return p2

    :pswitch_0
    invoke-virtual {p2}, Landroid/view/View;->getTranslationY()F

    move-result p2

    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    move-result p1

    int-to-float p1, p1

    sub-float/2addr p2, p1

    return p2

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
