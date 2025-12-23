.class public final Llyiahf/vczjk/n73;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $beforeCrossAxisAlignmentLine:I

.field final synthetic $crossAxisLayoutSize:I

.field final synthetic $crossAxisOffset:[I

.field final synthetic $currentLineIndex:I

.field final synthetic $endIndex:I

.field final synthetic $layoutDirection:Llyiahf/vczjk/yn4;

.field final synthetic $mainAxisPositions:[I

.field final synthetic $placeables:[Llyiahf/vczjk/ow6;

.field final synthetic $startIndex:I

.field final synthetic this$0:Llyiahf/vczjk/o73;


# direct methods
.method public constructor <init>([IIII[Llyiahf/vczjk/ow6;Llyiahf/vczjk/o73;ILlyiahf/vczjk/yn4;I[I)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/n73;->$crossAxisOffset:[I

    iput p2, p0, Llyiahf/vczjk/n73;->$currentLineIndex:I

    iput p3, p0, Llyiahf/vczjk/n73;->$startIndex:I

    iput p4, p0, Llyiahf/vczjk/n73;->$endIndex:I

    iput-object p5, p0, Llyiahf/vczjk/n73;->$placeables:[Llyiahf/vczjk/ow6;

    iput-object p6, p0, Llyiahf/vczjk/n73;->this$0:Llyiahf/vczjk/o73;

    iput p7, p0, Llyiahf/vczjk/n73;->$crossAxisLayoutSize:I

    iput-object p8, p0, Llyiahf/vczjk/n73;->$layoutDirection:Llyiahf/vczjk/yn4;

    iput p9, p0, Llyiahf/vczjk/n73;->$beforeCrossAxisAlignmentLine:I

    iput-object p10, p0, Llyiahf/vczjk/n73;->$mainAxisPositions:[I

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/n73;->$crossAxisOffset:[I

    if-eqz v0, :cond_0

    iget v1, p0, Llyiahf/vczjk/n73;->$currentLineIndex:I

    aget v0, v0, v1

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iget v1, p0, Llyiahf/vczjk/n73;->$startIndex:I

    :goto_1
    iget v2, p0, Llyiahf/vczjk/n73;->$endIndex:I

    if-ge v1, v2, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/n73;->$placeables:[Llyiahf/vczjk/ow6;

    aget-object v2, v2, v1

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v3, p0, Llyiahf/vczjk/n73;->this$0:Llyiahf/vczjk/o73;

    iget v4, p0, Llyiahf/vczjk/n73;->$crossAxisLayoutSize:I

    iget-object v5, p0, Llyiahf/vczjk/n73;->$layoutDirection:Llyiahf/vczjk/yn4;

    iget v6, p0, Llyiahf/vczjk/n73;->$beforeCrossAxisAlignmentLine:I

    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/ow6;->OooOoo()Ljava/lang/Object;

    move-result-object v7

    instance-of v8, v7, Llyiahf/vczjk/ew7;

    if-eqz v8, :cond_1

    check-cast v7, Llyiahf/vczjk/ew7;

    goto :goto_2

    :cond_1
    const/4 v7, 0x0

    :goto_2
    if-eqz v7, :cond_2

    iget-object v7, v7, Llyiahf/vczjk/ew7;->OooO0OO:Llyiahf/vczjk/mc4;

    if-nez v7, :cond_3

    :cond_2
    check-cast v3, Llyiahf/vczjk/s73;

    iget-object v7, v3, Llyiahf/vczjk/s73;->OooO0Oo:Llyiahf/vczjk/us1;

    :cond_3
    invoke-virtual {v2}, Llyiahf/vczjk/ow6;->OooooOo()I

    move-result v3

    sub-int/2addr v4, v3

    invoke-virtual {v7, v4, v5, v2, v6}, Llyiahf/vczjk/mc4;->OooOOOO(ILlyiahf/vczjk/yn4;Llyiahf/vczjk/ow6;I)I

    move-result v3

    add-int/2addr v3, v0

    iget-object v4, p0, Llyiahf/vczjk/n73;->this$0:Llyiahf/vczjk/o73;

    check-cast v4, Llyiahf/vczjk/s73;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v4, p0, Llyiahf/vczjk/n73;->$mainAxisPositions:[I

    iget v5, p0, Llyiahf/vczjk/n73;->$startIndex:I

    sub-int v5, v1, v5

    aget v4, v4, v5

    invoke-static {p1, v2, v4, v3}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :cond_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
