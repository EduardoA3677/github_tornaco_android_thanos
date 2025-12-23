.class public final Llyiahf/vczjk/a66;
.super Llyiahf/vczjk/z56;
.source "SourceFile"


# instance fields
.field public final synthetic OooOOOO:I


# direct methods
.method public constructor <init>(ILjava/lang/Class;)V
    .locals 1

    iput p1, p0, Llyiahf/vczjk/a66;->OooOOOO:I

    packed-switch p1, :pswitch_data_0

    sget-object p1, Llyiahf/vczjk/db4;->OooOOo0:Llyiahf/vczjk/db4;

    const-string v0, "number"

    invoke-direct {p0, p2, p1, v0}, Llyiahf/vczjk/z56;-><init>(Ljava/lang/Class;Llyiahf/vczjk/db4;Ljava/lang/String;)V

    return-void

    :pswitch_0
    sget-object p1, Llyiahf/vczjk/db4;->OooOOO:Llyiahf/vczjk/db4;

    const-string v0, "number"

    invoke-direct {p0, p2, p1, v0}, Llyiahf/vczjk/z56;-><init>(Ljava/lang/Class;Llyiahf/vczjk/db4;Ljava/lang/String;)V

    return-void

    :pswitch_1
    sget-object p1, Llyiahf/vczjk/db4;->OooOOO0:Llyiahf/vczjk/db4;

    const-string v0, "integer"

    invoke-direct {p0, p2, p1, v0}, Llyiahf/vczjk/z56;-><init>(Ljava/lang/Class;Llyiahf/vczjk/db4;Ljava/lang/String;)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V
    .locals 2

    iget p3, p0, Llyiahf/vczjk/a66;->OooOOOO:I

    packed-switch p3, :pswitch_data_0

    check-cast p1, Ljava/lang/Long;

    invoke-virtual {p1}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/u94;->o0000oO(J)V

    return-void

    :pswitch_0
    check-cast p1, Ljava/lang/Integer;

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    invoke-virtual {p2, p1}, Llyiahf/vczjk/u94;->o0000oo(I)V

    return-void

    :pswitch_1
    check-cast p1, Ljava/lang/Double;

    invoke-virtual {p1}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v0

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/u94;->o0000(D)V

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/a66;->OooOOOO:I

    packed-switch v0, :pswitch_data_0

    invoke-super {p0, p1, p2, p3, p4}, Llyiahf/vczjk/wt9;->OooO0oO(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;Llyiahf/vczjk/d5a;)V

    return-void

    :pswitch_0
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/a66;->OooO0o(Ljava/lang/Object;Llyiahf/vczjk/u94;Llyiahf/vczjk/tg8;)V

    return-void

    :pswitch_1
    move-object p3, p1

    check-cast p3, Ljava/lang/Double;

    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v0

    invoke-static {v0, v1}, Ljava/lang/Double;->isNaN(D)Z

    move-result v2

    if-nez v2, :cond_1

    invoke-static {v0, v1}, Ljava/lang/Double;->isInfinite(D)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    move-result-wide p3

    invoke-virtual {p2, p3, p4}, Llyiahf/vczjk/u94;->o0000(D)V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOo0O:Llyiahf/vczjk/gc4;

    invoke-virtual {p4, p1, v0}, Llyiahf/vczjk/d5a;->OooO0Oo(Ljava/lang/Object;Llyiahf/vczjk/gc4;)Llyiahf/vczjk/rsa;

    move-result-object p1

    invoke-virtual {p4, p2, p1}, Llyiahf/vczjk/d5a;->OooO0o0(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    move-result-object p1

    invoke-virtual {p3}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v0

    invoke-virtual {p2, v0, v1}, Llyiahf/vczjk/u94;->o0000(D)V

    invoke-virtual {p4, p2, p1}, Llyiahf/vczjk/d5a;->OooO0o(Llyiahf/vczjk/u94;Llyiahf/vczjk/rsa;)Llyiahf/vczjk/rsa;

    :goto_1
    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
