.class public final Llyiahf/vczjk/i43;
.super Llyiahf/vczjk/x88;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/or1;Llyiahf/vczjk/yo1;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/i43;->OooOOo0:I

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/x88;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/or1;)V

    return-void
.end method


# virtual methods
.method public final OooOo0O(Ljava/lang/Throwable;)Z
    .locals 1

    iget v0, p0, Llyiahf/vczjk/i43;->OooOOo0:I

    packed-switch v0, :pswitch_data_0

    const/4 p1, 0x0

    return p1

    :pswitch_0
    instance-of v0, p1, Llyiahf/vczjk/mv0;

    if-eqz v0, :cond_0

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/k84;->OooOOo(Ljava/lang/Object;)Z

    move-result p1

    :goto_0
    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
