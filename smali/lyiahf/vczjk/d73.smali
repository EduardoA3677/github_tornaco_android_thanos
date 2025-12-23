.class public final Llyiahf/vczjk/d73;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $horizontalArrangement:Llyiahf/vczjk/nx;

.field final synthetic $itemVerticalAlignment:Llyiahf/vczjk/n4;

.field final synthetic $maxItemsInEachRow:I

.field final synthetic $maxLines:I

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $overflow:Llyiahf/vczjk/v73;

.field final synthetic $verticalArrangement:Llyiahf/vczjk/px;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kl5;Llyiahf/vczjk/nx;Llyiahf/vczjk/px;Llyiahf/vczjk/n4;IILlyiahf/vczjk/v73;Llyiahf/vczjk/bf3;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/d73;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p2, p0, Llyiahf/vczjk/d73;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iput-object p3, p0, Llyiahf/vczjk/d73;->$verticalArrangement:Llyiahf/vczjk/px;

    iput-object p4, p0, Llyiahf/vczjk/d73;->$itemVerticalAlignment:Llyiahf/vczjk/n4;

    iput p5, p0, Llyiahf/vczjk/d73;->$maxItemsInEachRow:I

    iput p6, p0, Llyiahf/vczjk/d73;->$maxLines:I

    iput-object p7, p0, Llyiahf/vczjk/d73;->$overflow:Llyiahf/vczjk/v73;

    iput-object p8, p0, Llyiahf/vczjk/d73;->$content:Llyiahf/vczjk/bf3;

    iput p9, p0, Llyiahf/vczjk/d73;->$$changed:I

    iput p10, p0, Llyiahf/vczjk/d73;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/d73;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v1, p0, Llyiahf/vczjk/d73;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iget-object v2, p0, Llyiahf/vczjk/d73;->$verticalArrangement:Llyiahf/vczjk/px;

    iget-object v3, p0, Llyiahf/vczjk/d73;->$itemVerticalAlignment:Llyiahf/vczjk/n4;

    iget v4, p0, Llyiahf/vczjk/d73;->$maxItemsInEachRow:I

    iget v5, p0, Llyiahf/vczjk/d73;->$maxLines:I

    iget-object v6, p0, Llyiahf/vczjk/d73;->$overflow:Llyiahf/vczjk/v73;

    iget-object v7, p0, Llyiahf/vczjk/d73;->$content:Llyiahf/vczjk/bf3;

    iget p1, p0, Llyiahf/vczjk/d73;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget v10, p0, Llyiahf/vczjk/d73;->$$default:I

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/os9;->OooO0o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/nx;Llyiahf/vczjk/px;Llyiahf/vczjk/n4;IILlyiahf/vczjk/v73;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
