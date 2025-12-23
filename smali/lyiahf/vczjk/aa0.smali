.class public final Llyiahf/vczjk/aa0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $color:Llyiahf/vczjk/w21;

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

.field final synthetic $text:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rn9;Llyiahf/vczjk/oe3;IZIILlyiahf/vczjk/w21;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/aa0;->$text:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/aa0;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/aa0;->$style:Llyiahf/vczjk/rn9;

    iput-object p4, p0, Llyiahf/vczjk/aa0;->$onTextLayout:Llyiahf/vczjk/oe3;

    iput p5, p0, Llyiahf/vczjk/aa0;->$overflow:I

    iput-boolean p6, p0, Llyiahf/vczjk/aa0;->$softWrap:Z

    iput p7, p0, Llyiahf/vczjk/aa0;->$maxLines:I

    iput p8, p0, Llyiahf/vczjk/aa0;->$minLines:I

    iput-object p9, p0, Llyiahf/vczjk/aa0;->$color:Llyiahf/vczjk/w21;

    iput p10, p0, Llyiahf/vczjk/aa0;->$$changed:I

    iput p11, p0, Llyiahf/vczjk/aa0;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/aa0;->$text:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/aa0;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v2, p0, Llyiahf/vczjk/aa0;->$style:Llyiahf/vczjk/rn9;

    iget-object v3, p0, Llyiahf/vczjk/aa0;->$onTextLayout:Llyiahf/vczjk/oe3;

    iget v4, p0, Llyiahf/vczjk/aa0;->$overflow:I

    iget-boolean v5, p0, Llyiahf/vczjk/aa0;->$softWrap:Z

    iget v6, p0, Llyiahf/vczjk/aa0;->$maxLines:I

    iget v7, p0, Llyiahf/vczjk/aa0;->$minLines:I

    iget-object v8, p0, Llyiahf/vczjk/aa0;->$color:Llyiahf/vczjk/w21;

    iget p1, p0, Llyiahf/vczjk/aa0;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v10

    iget v11, p0, Llyiahf/vczjk/aa0;->$$default:I

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/sb;->OooO0OO(Ljava/lang/String;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rn9;Llyiahf/vczjk/oe3;IZIILlyiahf/vczjk/w21;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
