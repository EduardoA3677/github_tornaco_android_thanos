.class public final synthetic Llyiahf/vczjk/sp7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/fq7;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/fq7;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/sp7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/sp7;->OooOOO:Llyiahf/vczjk/fq7;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/sp7;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/ft7;

    packed-switch v0, :pswitch_data_0

    const-string v0, "$this$graphicsLayer"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/sp7;->OooOOO:Llyiahf/vczjk/fq7;

    invoke-virtual {v0}, Llyiahf/vczjk/fq7;->OooOOOo()Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_0

    iget-object v1, v0, Llyiahf/vczjk/fq7;->OooO0Oo:Llyiahf/vczjk/tz8;

    iget-object v1, v1, Llyiahf/vczjk/tz8;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v1}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/p86;

    iget-wide v3, v1, Llyiahf/vczjk/p86;->OooO00o:J

    const/16 v1, 0x20

    shr-long/2addr v3, v1

    long-to-int v1, v3

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    goto :goto_0

    :cond_0
    move v1, v2

    :goto_0
    invoke-virtual {p1, v1}, Llyiahf/vczjk/ft7;->OooOo00(F)V

    invoke-virtual {v0}, Llyiahf/vczjk/fq7;->OooOOOo()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/fq7;->OooO0Oo:Llyiahf/vczjk/tz8;

    iget-object v0, v0, Llyiahf/vczjk/tz8;->OooO00o:Llyiahf/vczjk/gi;

    invoke-virtual {v0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p86;

    iget-wide v0, v0, Llyiahf/vczjk/p86;->OooO00o:J

    const-wide v2, 0xffffffffL

    and-long/2addr v0, v2

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v2

    :cond_1
    invoke-virtual {p1, v2}, Llyiahf/vczjk/ft7;->OooOo0(F)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const-string v0, "$this$graphicsLayer"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/sp7;->OooOOO:Llyiahf/vczjk/fq7;

    invoke-virtual {v0}, Llyiahf/vczjk/fq7;->OooOOOo()Z

    move-result v1

    const/4 v2, 0x0

    if-nez v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/fq7;->OooO0oO()F

    move-result v1

    goto :goto_1

    :cond_2
    move v1, v2

    :goto_1
    invoke-virtual {p1, v1}, Llyiahf/vczjk/ft7;->OooOo00(F)V

    invoke-virtual {v0}, Llyiahf/vczjk/fq7;->OooOOOo()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/fq7;->OooO0oo()F

    move-result v2

    :cond_3
    invoke-virtual {p1, v2}, Llyiahf/vczjk/ft7;->OooOo0(F)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
