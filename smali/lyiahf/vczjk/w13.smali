.class public final Llyiahf/vczjk/w13;
.super Llyiahf/vczjk/ow6;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOo:I


# direct methods
.method public constructor <init>(III)V
    .locals 4

    iput p3, p0, Llyiahf/vczjk/w13;->OooOOo:I

    packed-switch p3, :pswitch_data_0

    invoke-direct {p0}, Llyiahf/vczjk/ow6;-><init>()V

    int-to-long v0, p1

    const/16 p1, 0x20

    shl-long/2addr v0, p1

    int-to-long p1, p2

    const-wide v2, 0xffffffffL

    and-long/2addr p1, v2

    or-long/2addr p1, v0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ow6;->o00O0O(J)V

    return-void

    :pswitch_0
    invoke-direct {p0}, Llyiahf/vczjk/ow6;-><init>()V

    int-to-long v0, p1

    const/16 p1, 0x20

    shl-long/2addr v0, p1

    int-to-long p1, p2

    const-wide v2, 0xffffffffL

    and-long/2addr p1, v2

    or-long/2addr p1, v0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ow6;->o00O0O(J)V

    return-void

    :pswitch_1
    invoke-direct {p0}, Llyiahf/vczjk/ow6;-><init>()V

    int-to-long v0, p1

    const/16 p1, 0x20

    shl-long/2addr v0, p1

    int-to-long p1, p2

    const-wide v2, 0xffffffffL

    and-long/2addr p1, v2

    or-long/2addr p1, v0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ow6;->o00O0O(J)V

    return-void

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method private final o00oO0O(JFLlyiahf/vczjk/oe3;)V
    .locals 0

    return-void
.end method

.method private final o0OOO0o(JFLlyiahf/vczjk/oe3;)V
    .locals 0

    return-void
.end method

.method private final o0ooOoO(JFLlyiahf/vczjk/oe3;)V
    .locals 0

    return-void
.end method


# virtual methods
.method public final OooooOO(Llyiahf/vczjk/p4;)I
    .locals 0

    iget p1, p0, Llyiahf/vczjk/w13;->OooOOo:I

    packed-switch p1, :pswitch_data_0

    const/high16 p1, -0x80000000

    return p1

    :pswitch_0
    const/high16 p1, -0x80000000

    return p1

    :pswitch_1
    const/high16 p1, -0x80000000

    return p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final o0OoOo0(JFLlyiahf/vczjk/oe3;)V
    .locals 0

    iget p1, p0, Llyiahf/vczjk/w13;->OooOOo:I

    return-void
.end method
