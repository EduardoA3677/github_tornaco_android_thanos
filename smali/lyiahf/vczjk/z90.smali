.class public final Llyiahf/vczjk/z90;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $autoSize:Llyiahf/vczjk/rh9;

.field final synthetic $color:Llyiahf/vczjk/w21;

.field final synthetic $inlineContent:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $maxLines:I

.field final synthetic $minLines:I

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onTextLayout:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $overflow:I

.field final synthetic $softWrap:Z

.field final synthetic $style:Llyiahf/vczjk/rn9;

.field final synthetic $text:Llyiahf/vczjk/an;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/an;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rn9;Llyiahf/vczjk/oe3;IZIILjava/util/Map;Llyiahf/vczjk/w21;III)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/z90;->$text:Llyiahf/vczjk/an;

    iput-object p2, p0, Llyiahf/vczjk/z90;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/z90;->$style:Llyiahf/vczjk/rn9;

    iput-object p4, p0, Llyiahf/vczjk/z90;->$onTextLayout:Llyiahf/vczjk/oe3;

    iput p5, p0, Llyiahf/vczjk/z90;->$overflow:I

    iput-boolean p6, p0, Llyiahf/vczjk/z90;->$softWrap:Z

    iput p7, p0, Llyiahf/vczjk/z90;->$maxLines:I

    iput p8, p0, Llyiahf/vczjk/z90;->$minLines:I

    iput-object p9, p0, Llyiahf/vczjk/z90;->$inlineContent:Ljava/util/Map;

    iput-object p10, p0, Llyiahf/vczjk/z90;->$color:Llyiahf/vczjk/w21;

    iput p11, p0, Llyiahf/vczjk/z90;->$$changed:I

    iput p12, p0, Llyiahf/vczjk/z90;->$$changed1:I

    iput p13, p0, Llyiahf/vczjk/z90;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    move-object/from16 p1, p2

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/z90;->$text:Llyiahf/vczjk/an;

    iget-object v1, p0, Llyiahf/vczjk/z90;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/z90;->$style:Llyiahf/vczjk/rn9;

    iget-object v3, p0, Llyiahf/vczjk/z90;->$onTextLayout:Llyiahf/vczjk/oe3;

    iget v4, p0, Llyiahf/vczjk/z90;->$overflow:I

    iget-boolean v5, p0, Llyiahf/vczjk/z90;->$softWrap:Z

    iget v6, p0, Llyiahf/vczjk/z90;->$maxLines:I

    iget v7, p0, Llyiahf/vczjk/z90;->$minLines:I

    iget-object v8, p0, Llyiahf/vczjk/z90;->$inlineContent:Ljava/util/Map;

    iget-object v9, p0, Llyiahf/vczjk/z90;->$color:Llyiahf/vczjk/w21;

    iget p1, p0, Llyiahf/vczjk/z90;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    iget p1, p0, Llyiahf/vczjk/z90;->$$changed1:I

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v12

    iget v13, p0, Llyiahf/vczjk/z90;->$$default:I

    invoke-static/range {v0 .. v13}, Llyiahf/vczjk/sb;->OooO00o(Llyiahf/vczjk/an;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rn9;Llyiahf/vczjk/oe3;IZIILjava/util/Map;Llyiahf/vczjk/w21;Llyiahf/vczjk/rf1;III)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
