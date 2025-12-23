.class public final Llyiahf/vczjk/gw7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $beforeCrossAxisAlignmentLine:I

.field final synthetic $crossAxisLayoutSize:I

.field final synthetic $mainAxisPositions:[I

.field final synthetic $placeables:[Llyiahf/vczjk/ow6;

.field final synthetic this$0:Llyiahf/vczjk/hw7;


# direct methods
.method public constructor <init>([Llyiahf/vczjk/ow6;Llyiahf/vczjk/hw7;II[I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/gw7;->$placeables:[Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/gw7;->this$0:Llyiahf/vczjk/hw7;

    iput p3, p0, Llyiahf/vczjk/gw7;->$crossAxisLayoutSize:I

    iput p4, p0, Llyiahf/vczjk/gw7;->$beforeCrossAxisAlignmentLine:I

    iput-object p5, p0, Llyiahf/vczjk/gw7;->$mainAxisPositions:[I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/gw7;->$placeables:[Llyiahf/vczjk/ow6;

    iget-object v1, p0, Llyiahf/vczjk/gw7;->this$0:Llyiahf/vczjk/hw7;

    iget v2, p0, Llyiahf/vczjk/gw7;->$crossAxisLayoutSize:I

    iget v3, p0, Llyiahf/vczjk/gw7;->$beforeCrossAxisAlignmentLine:I

    iget-object v4, p0, Llyiahf/vczjk/gw7;->$mainAxisPositions:[I

    array-length v5, v0

    const/4 v6, 0x0

    move v7, v6

    move v8, v7

    :goto_0
    if-ge v7, v5, :cond_3

    aget-object v9, v0, v7

    add-int/lit8 v10, v8, 0x1

    invoke-static {v9}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v9}, Llyiahf/vczjk/ow6;->OooOoo()Ljava/lang/Object;

    move-result-object v11

    instance-of v12, v11, Llyiahf/vczjk/ew7;

    const/4 v13, 0x0

    if-eqz v12, :cond_0

    check-cast v11, Llyiahf/vczjk/ew7;

    goto :goto_1

    :cond_0
    move-object v11, v13

    :goto_1
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    if-eqz v11, :cond_1

    iget-object v13, v11, Llyiahf/vczjk/ew7;->OooO0OO:Llyiahf/vczjk/mc4;

    :cond_1
    if-eqz v13, :cond_2

    iget v11, v9, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int v11, v2, v11

    sget-object v12, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    invoke-virtual {v13, v11, v12, v9, v3}, Llyiahf/vczjk/mc4;->OooOOOO(ILlyiahf/vczjk/yn4;Llyiahf/vczjk/ow6;I)I

    move-result v11

    goto :goto_2

    :cond_2
    iget v11, v9, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int v11, v2, v11

    iget-object v12, v1, Llyiahf/vczjk/hw7;->OooO0O0:Llyiahf/vczjk/tb0;

    invoke-virtual {v12, v6, v11}, Llyiahf/vczjk/tb0;->OooO00o(II)I

    move-result v11

    :goto_2
    aget v8, v4, v8

    invoke-static {p1, v9, v8, v11}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    add-int/lit8 v7, v7, 0x1

    move v8, v10

    goto :goto_0

    :cond_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
