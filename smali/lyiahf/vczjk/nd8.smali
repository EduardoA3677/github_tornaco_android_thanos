.class public final Llyiahf/vczjk/nd8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $currentRawLine$delegate:Llyiahf/vczjk/kp4;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/kp4;"
        }
    .end annotation
.end field

.field final synthetic $currentRawOffset:I

.field final synthetic $info:Llyiahf/vczjk/id8;

.field final synthetic $otherRawOffset:I

.field final synthetic $this_updateSelectionBoundary:Llyiahf/vczjk/ae8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/id8;IILlyiahf/vczjk/hl1;Llyiahf/vczjk/kp4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/nd8;->$info:Llyiahf/vczjk/id8;

    iput p2, p0, Llyiahf/vczjk/nd8;->$currentRawOffset:I

    iput p3, p0, Llyiahf/vczjk/nd8;->$otherRawOffset:I

    iput-object p4, p0, Llyiahf/vczjk/nd8;->$this_updateSelectionBoundary:Llyiahf/vczjk/ae8;

    iput-object p5, p0, Llyiahf/vczjk/nd8;->$currentRawLine$delegate:Llyiahf/vczjk/kp4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 15

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/nd8;->$info:Llyiahf/vczjk/id8;

    iget-object v2, p0, Llyiahf/vczjk/nd8;->$currentRawLine$delegate:Llyiahf/vczjk/kp4;

    invoke-interface {v2}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    iget v3, p0, Llyiahf/vczjk/nd8;->$currentRawOffset:I

    iget v4, p0, Llyiahf/vczjk/nd8;->$otherRawOffset:I

    iget-object v5, p0, Llyiahf/vczjk/nd8;->$this_updateSelectionBoundary:Llyiahf/vczjk/ae8;

    check-cast v5, Llyiahf/vczjk/hl1;

    iget-boolean v6, v5, Llyiahf/vczjk/hl1;->OooOOO:Z

    invoke-virtual {v5}, Llyiahf/vczjk/hl1;->OooO0o()Llyiahf/vczjk/vs1;

    move-result-object v5

    sget-object v7, Llyiahf/vczjk/vs1;->OooOOO0:Llyiahf/vczjk/vs1;

    const/4 v8, 0x0

    if-ne v5, v7, :cond_0

    move v5, v0

    goto :goto_0

    :cond_0
    move v5, v8

    :goto_0
    iget-object v7, v1, Llyiahf/vczjk/id8;->OooO0Oo:Llyiahf/vczjk/mm9;

    invoke-virtual {v7, v3}, Llyiahf/vczjk/mm9;->OooO(I)J

    move-result-wide v9

    sget v7, Llyiahf/vczjk/gn9;->OooO0OO:I

    const/16 v7, 0x20

    shr-long v11, v9, v7

    long-to-int v7, v11

    iget-object v11, v1, Llyiahf/vczjk/id8;->OooO0Oo:Llyiahf/vczjk/mm9;

    iget-object v12, v11, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    invoke-virtual {v12, v7}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v12

    iget-object v13, v11, Llyiahf/vczjk/mm9;->OooO0O0:Llyiahf/vczjk/lq5;

    iget v14, v13, Llyiahf/vczjk/lq5;->OooO0o:I

    if-ne v12, v2, :cond_1

    goto :goto_1

    :cond_1
    if-lt v2, v14, :cond_2

    add-int/lit8 v7, v14, -0x1

    invoke-virtual {v11, v7}, Llyiahf/vczjk/mm9;->OooO0o(I)I

    move-result v7

    goto :goto_1

    :cond_2
    invoke-virtual {v11, v2}, Llyiahf/vczjk/mm9;->OooO0o(I)I

    move-result v7

    :goto_1
    const-wide v11, 0xffffffffL

    and-long/2addr v9, v11

    long-to-int v9, v9

    invoke-virtual {v13, v9}, Llyiahf/vczjk/lq5;->OooO0Oo(I)I

    move-result v10

    if-ne v10, v2, :cond_3

    goto :goto_2

    :cond_3
    if-lt v2, v14, :cond_4

    sub-int/2addr v14, v0

    invoke-virtual {v13, v14, v8}, Llyiahf/vczjk/lq5;->OooO0OO(IZ)I

    move-result v9

    goto :goto_2

    :cond_4
    invoke-virtual {v13, v2, v8}, Llyiahf/vczjk/lq5;->OooO0OO(IZ)I

    move-result v9

    :goto_2
    if-ne v7, v4, :cond_5

    invoke-virtual {v1, v9}, Llyiahf/vczjk/id8;->OooO00o(I)Llyiahf/vczjk/kd8;

    move-result-object v0

    return-object v0

    :cond_5
    if-ne v9, v4, :cond_6

    invoke-virtual {v1, v7}, Llyiahf/vczjk/id8;->OooO00o(I)Llyiahf/vczjk/kd8;

    move-result-object v0

    return-object v0

    :cond_6
    xor-int v0, v6, v5

    if-eqz v0, :cond_7

    if-gt v3, v9, :cond_8

    goto :goto_3

    :cond_7
    if-lt v3, v7, :cond_9

    :cond_8
    move v7, v9

    :cond_9
    :goto_3
    invoke-virtual {v1, v7}, Llyiahf/vczjk/id8;->OooO00o(I)Llyiahf/vczjk/kd8;

    move-result-object v0

    return-object v0
.end method
