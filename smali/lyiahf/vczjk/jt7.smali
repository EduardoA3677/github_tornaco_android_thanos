.class public final synthetic Llyiahf/vczjk/jt7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sd2;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/ot7;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ot7;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/jt7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/jt7;->OooOOO:Llyiahf/vczjk/ot7;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0oo(D)D
    .locals 9

    iget v0, p0, Llyiahf/vczjk/jt7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/jt7;->OooOOO:Llyiahf/vczjk/ot7;

    iget-object v1, v0, Llyiahf/vczjk/ot7;->OooOOO:Llyiahf/vczjk/sd2;

    iget v2, v0, Llyiahf/vczjk/ot7;->OooO0o0:F

    float-to-double v5, v2

    iget v0, v0, Llyiahf/vczjk/ot7;->OooO0o:F

    float-to-double v7, v0

    move-wide v3, p1

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/vt6;->OooOOOo(DDD)D

    move-result-wide p1

    invoke-interface {v1, p1, p2}, Llyiahf/vczjk/sd2;->OooO0oo(D)D

    move-result-wide p1

    return-wide p1

    :pswitch_0
    move-wide v3, p1

    iget-object p1, p0, Llyiahf/vczjk/jt7;->OooOOO:Llyiahf/vczjk/ot7;

    iget-object p2, p1, Llyiahf/vczjk/ot7;->OooOO0O:Llyiahf/vczjk/sd2;

    invoke-interface {p2, v3, v4}, Llyiahf/vczjk/sd2;->OooO0oo(D)D

    move-result-wide v0

    iget p2, p1, Llyiahf/vczjk/ot7;->OooO0o0:F

    float-to-double v2, p2

    iget p1, p1, Llyiahf/vczjk/ot7;->OooO0o:F

    float-to-double v4, p1

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/vt6;->OooOOOo(DDD)D

    move-result-wide p1

    return-wide p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
