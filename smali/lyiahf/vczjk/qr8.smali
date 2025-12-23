.class public final synthetic Llyiahf/vczjk/qr8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/cs8;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/cs8;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/qr8;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/qr8;->OooOOO:Llyiahf/vczjk/cs8;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    iget v0, p0, Llyiahf/vczjk/qr8;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/p86;

    iget-object p1, p0, Llyiahf/vczjk/qr8;->OooOOO:Llyiahf/vczjk/cs8;

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/cs8;->OooO0O0(F)V

    iget-object p1, p1, Llyiahf/vczjk/cs8;->OooOOO:Llyiahf/vczjk/ku7;

    invoke-virtual {p1}, Llyiahf/vczjk/ku7;->OooO00o()Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/b24;

    iget-wide v0, p1, Llyiahf/vczjk/b24;->OooO00o:J

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    iget-object v1, p0, Llyiahf/vczjk/qr8;->OooOOO:Llyiahf/vczjk/cs8;

    iget-object v2, v1, Llyiahf/vczjk/cs8;->OooOO0:Llyiahf/vczjk/qr5;

    check-cast v2, Llyiahf/vczjk/bw8;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    const-wide v2, 0xffffffffL

    iget-wide v4, p1, Llyiahf/vczjk/b24;->OooO00o:J

    and-long/2addr v2, v4

    long-to-int p1, v2

    iget-object v0, v1, Llyiahf/vczjk/cs8;->OooOO0O:Llyiahf/vczjk/qr5;

    check-cast v0, Llyiahf/vczjk/bw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/bw8;->OooOo00(I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/qr8;->OooOOO:Llyiahf/vczjk/cs8;

    iget-object v1, v0, Llyiahf/vczjk/cs8;->OooO0O0:Llyiahf/vczjk/m01;

    iget v2, v1, Llyiahf/vczjk/m01;->OooO00o:F

    iget v3, v1, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-static {p1, v2, v3}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    const/4 v2, 0x1

    const/4 v3, 0x0

    iget v4, v0, Llyiahf/vczjk/cs8;->OooO00o:I

    if-lez v4, :cond_2

    add-int/2addr v4, v2

    if-ltz v4, :cond_2

    move v6, p1

    move v7, v6

    move v5, v3

    :goto_0
    int-to-float v8, v5

    int-to-float v9, v4

    div-float/2addr v8, v9

    iget v9, v1, Llyiahf/vczjk/m01;->OooO00o:F

    iget v10, v1, Llyiahf/vczjk/m01;->OooO0O0:F

    invoke-static {v9, v10, v8}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result v8

    sub-float v9, v8, p1

    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v10

    cmpg-float v10, v10, v6

    if-gtz v10, :cond_0

    invoke-static {v9}, Ljava/lang/Math;->abs(F)F

    move-result v6

    move v7, v8

    :cond_0
    if-eq v5, v4, :cond_1

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_1
    move p1, v7

    :cond_2
    invoke-virtual {v0}, Llyiahf/vczjk/cs8;->OooO0Oo()F

    move-result v1

    cmpg-float v1, p1, v1

    if-nez v1, :cond_3

    move v2, v3

    goto :goto_1

    :cond_3
    invoke-virtual {v0}, Llyiahf/vczjk/cs8;->OooO0Oo()F

    move-result v1

    cmpg-float v1, p1, v1

    if-nez v1, :cond_4

    goto :goto_1

    :cond_4
    iget-object v1, v0, Llyiahf/vczjk/cs8;->OooO0Oo:Llyiahf/vczjk/oe3;

    if-eqz v1, :cond_5

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :cond_5
    invoke-virtual {v0, p1}, Llyiahf/vczjk/cs8;->OooO0o0(F)V

    :goto_1
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
