.class public final Llyiahf/vczjk/yp1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $cursorBrush:Llyiahf/vczjk/ri0;

.field final synthetic $decorationBox:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $enabled:Z

.field final synthetic $imeOptions:Llyiahf/vczjk/wv3;

.field final synthetic $interactionSource:Llyiahf/vczjk/rr5;

.field final synthetic $keyboardActions:Llyiahf/vczjk/mj4;

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

.field final synthetic $onValueChange:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $readOnly:Z

.field final synthetic $softWrap:Z

.field final synthetic $textScrollerPosition:Llyiahf/vczjk/vj9;

.field final synthetic $textStyle:Llyiahf/vczjk/rn9;

.field final synthetic $value:Llyiahf/vczjk/gl9;

.field final synthetic $visualTransformation:Llyiahf/vczjk/jka;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gl9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rn9;Llyiahf/vczjk/jka;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/ri0;ZIILlyiahf/vczjk/wv3;Llyiahf/vczjk/mj4;ZZLlyiahf/vczjk/bf3;Llyiahf/vczjk/vj9;III)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/yp1;->$value:Llyiahf/vczjk/gl9;

    iput-object p2, p0, Llyiahf/vczjk/yp1;->$onValueChange:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/yp1;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p4, p0, Llyiahf/vczjk/yp1;->$textStyle:Llyiahf/vczjk/rn9;

    iput-object p5, p0, Llyiahf/vczjk/yp1;->$visualTransformation:Llyiahf/vczjk/jka;

    iput-object p6, p0, Llyiahf/vczjk/yp1;->$onTextLayout:Llyiahf/vczjk/oe3;

    iput-object p7, p0, Llyiahf/vczjk/yp1;->$interactionSource:Llyiahf/vczjk/rr5;

    iput-object p8, p0, Llyiahf/vczjk/yp1;->$cursorBrush:Llyiahf/vczjk/ri0;

    iput-boolean p9, p0, Llyiahf/vczjk/yp1;->$softWrap:Z

    iput p10, p0, Llyiahf/vczjk/yp1;->$maxLines:I

    iput p11, p0, Llyiahf/vczjk/yp1;->$minLines:I

    iput-object p12, p0, Llyiahf/vczjk/yp1;->$imeOptions:Llyiahf/vczjk/wv3;

    iput-object p13, p0, Llyiahf/vczjk/yp1;->$keyboardActions:Llyiahf/vczjk/mj4;

    iput-boolean p14, p0, Llyiahf/vczjk/yp1;->$enabled:Z

    iput-boolean p15, p0, Llyiahf/vczjk/yp1;->$readOnly:Z

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/yp1;->$decorationBox:Llyiahf/vczjk/bf3;

    move-object/from16 p1, p17

    iput-object p1, p0, Llyiahf/vczjk/yp1;->$textScrollerPosition:Llyiahf/vczjk/vj9;

    move/from16 p1, p18

    iput p1, p0, Llyiahf/vczjk/yp1;->$$changed:I

    move/from16 p1, p19

    iput p1, p0, Llyiahf/vczjk/yp1;->$$changed1:I

    move/from16 p1, p20

    iput p1, p0, Llyiahf/vczjk/yp1;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v0, p0

    move-object/from16 v18, p1

    check-cast v18, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/yp1;->$value:Llyiahf/vczjk/gl9;

    iget-object v2, v0, Llyiahf/vczjk/yp1;->$onValueChange:Llyiahf/vczjk/oe3;

    iget-object v3, v0, Llyiahf/vczjk/yp1;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v4, v0, Llyiahf/vczjk/yp1;->$textStyle:Llyiahf/vczjk/rn9;

    iget-object v5, v0, Llyiahf/vczjk/yp1;->$visualTransformation:Llyiahf/vczjk/jka;

    iget-object v6, v0, Llyiahf/vczjk/yp1;->$onTextLayout:Llyiahf/vczjk/oe3;

    iget-object v7, v0, Llyiahf/vczjk/yp1;->$interactionSource:Llyiahf/vczjk/rr5;

    iget-object v8, v0, Llyiahf/vczjk/yp1;->$cursorBrush:Llyiahf/vczjk/ri0;

    iget-boolean v9, v0, Llyiahf/vczjk/yp1;->$softWrap:Z

    iget v10, v0, Llyiahf/vczjk/yp1;->$maxLines:I

    iget v11, v0, Llyiahf/vczjk/yp1;->$minLines:I

    iget-object v12, v0, Llyiahf/vczjk/yp1;->$imeOptions:Llyiahf/vczjk/wv3;

    iget-object v13, v0, Llyiahf/vczjk/yp1;->$keyboardActions:Llyiahf/vczjk/mj4;

    iget-boolean v14, v0, Llyiahf/vczjk/yp1;->$enabled:Z

    iget-boolean v15, v0, Llyiahf/vczjk/yp1;->$readOnly:Z

    move-object/from16 v16, v1

    iget-object v1, v0, Llyiahf/vczjk/yp1;->$decorationBox:Llyiahf/vczjk/bf3;

    move-object/from16 v17, v1

    iget-object v1, v0, Llyiahf/vczjk/yp1;->$textScrollerPosition:Llyiahf/vczjk/vj9;

    move-object/from16 v19, v1

    iget v1, v0, Llyiahf/vczjk/yp1;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/yp1;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v20

    iget v1, v0, Llyiahf/vczjk/yp1;->$$default:I

    move/from16 v21, v1

    move-object/from16 v1, v16

    move-object/from16 v16, v17

    move-object/from16 v17, v19

    move/from16 v19, p1

    invoke-static/range {v1 .. v21}, Llyiahf/vczjk/sb;->OooO0Oo(Llyiahf/vczjk/gl9;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/rn9;Llyiahf/vczjk/jka;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/ri0;ZIILlyiahf/vczjk/wv3;Llyiahf/vczjk/mj4;ZZLlyiahf/vczjk/bf3;Llyiahf/vczjk/vj9;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
