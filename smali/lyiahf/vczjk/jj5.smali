.class public final synthetic Llyiahf/vczjk/jj5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOo:I


# direct methods
.method public synthetic constructor <init>(ILlyiahf/vczjk/ow6;I)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/jj5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/jj5;->OooOOO:I

    iput-object p2, p0, Llyiahf/vczjk/jj5;->OooOOOO:Llyiahf/vczjk/ow6;

    iput p3, p0, Llyiahf/vczjk/jj5;->OooOOOo:I

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;II)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/jj5;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jj5;->OooOOOO:Llyiahf/vczjk/ow6;

    iput p2, p0, Llyiahf/vczjk/jj5;->OooOOO:I

    iput p3, p0, Llyiahf/vczjk/jj5;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/jj5;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/nw6;

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/jj5;->OooOOOO:Llyiahf/vczjk/ow6;

    iget v1, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v2, p0, Llyiahf/vczjk/jj5;->OooOOO:I

    sub-int/2addr v2, v1

    int-to-float v1, v2

    const/high16 v2, 0x40000000    # 2.0f

    div-float/2addr v1, v2

    invoke-static {v1}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v1

    iget v3, v0, Llyiahf/vczjk/ow6;->OooOOO:I

    iget v4, p0, Llyiahf/vczjk/jj5;->OooOOOo:I

    sub-int/2addr v4, v3

    int-to-float v3, v4

    div-float/2addr v3, v2

    invoke-static {v3}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v2

    invoke-static {p1, v0, v1, v2}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/jj5;->OooOOOO:Llyiahf/vczjk/ow6;

    iget v1, v0, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget v2, p0, Llyiahf/vczjk/jj5;->OooOOO:I

    sub-int/2addr v2, v1

    div-int/lit8 v2, v2, 0x2

    iget v1, v0, Llyiahf/vczjk/ow6;->OooOOO:I

    iget v3, p0, Llyiahf/vczjk/jj5;->OooOOOo:I

    sub-int/2addr v3, v1

    div-int/lit8 v3, v3, 0x2

    invoke-static {p1, v0, v2, v3}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
