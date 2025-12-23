.class public final Llyiahf/vczjk/v90;
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

.field final synthetic $interactionSource:Llyiahf/vczjk/rr5;

.field final synthetic $keyboardActions:Llyiahf/vczjk/mj4;

.field final synthetic $keyboardOptions:Llyiahf/vczjk/nj4;

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

.field final synthetic $singleLine:Z

.field final synthetic $textStyle:Llyiahf/vczjk/rn9;

.field final synthetic $value:Ljava/lang/String;

.field final synthetic $visualTransformation:Llyiahf/vczjk/jka;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/rn9;Llyiahf/vczjk/nj4;Llyiahf/vczjk/mj4;ZIILlyiahf/vczjk/jka;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/ri0;Llyiahf/vczjk/bf3;III)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v90;->$value:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/v90;->$onValueChange:Llyiahf/vczjk/oe3;

    iput-object p3, p0, Llyiahf/vczjk/v90;->$modifier:Llyiahf/vczjk/kl5;

    iput-boolean p4, p0, Llyiahf/vczjk/v90;->$enabled:Z

    iput-boolean p5, p0, Llyiahf/vczjk/v90;->$readOnly:Z

    iput-object p6, p0, Llyiahf/vczjk/v90;->$textStyle:Llyiahf/vczjk/rn9;

    iput-object p7, p0, Llyiahf/vczjk/v90;->$keyboardOptions:Llyiahf/vczjk/nj4;

    iput-object p8, p0, Llyiahf/vczjk/v90;->$keyboardActions:Llyiahf/vczjk/mj4;

    iput-boolean p9, p0, Llyiahf/vczjk/v90;->$singleLine:Z

    iput p10, p0, Llyiahf/vczjk/v90;->$maxLines:I

    iput p11, p0, Llyiahf/vczjk/v90;->$minLines:I

    iput-object p12, p0, Llyiahf/vczjk/v90;->$visualTransformation:Llyiahf/vczjk/jka;

    iput-object p13, p0, Llyiahf/vczjk/v90;->$onTextLayout:Llyiahf/vczjk/oe3;

    iput-object p14, p0, Llyiahf/vczjk/v90;->$interactionSource:Llyiahf/vczjk/rr5;

    iput-object p15, p0, Llyiahf/vczjk/v90;->$cursorBrush:Llyiahf/vczjk/ri0;

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/v90;->$decorationBox:Llyiahf/vczjk/bf3;

    move/from16 p1, p17

    iput p1, p0, Llyiahf/vczjk/v90;->$$changed:I

    move/from16 p1, p18

    iput p1, p0, Llyiahf/vczjk/v90;->$$changed1:I

    move/from16 p1, p19

    iput p1, p0, Llyiahf/vczjk/v90;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    move-object/from16 v0, p0

    move-object/from16 v17, p1

    check-cast v17, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/v90;->$value:Ljava/lang/String;

    iget-object v2, v0, Llyiahf/vczjk/v90;->$onValueChange:Llyiahf/vczjk/oe3;

    iget-object v3, v0, Llyiahf/vczjk/v90;->$modifier:Llyiahf/vczjk/kl5;

    iget-boolean v4, v0, Llyiahf/vczjk/v90;->$enabled:Z

    iget-boolean v5, v0, Llyiahf/vczjk/v90;->$readOnly:Z

    iget-object v6, v0, Llyiahf/vczjk/v90;->$textStyle:Llyiahf/vczjk/rn9;

    iget-object v7, v0, Llyiahf/vczjk/v90;->$keyboardOptions:Llyiahf/vczjk/nj4;

    iget-object v8, v0, Llyiahf/vczjk/v90;->$keyboardActions:Llyiahf/vczjk/mj4;

    iget-boolean v9, v0, Llyiahf/vczjk/v90;->$singleLine:Z

    iget v10, v0, Llyiahf/vczjk/v90;->$maxLines:I

    iget v11, v0, Llyiahf/vczjk/v90;->$minLines:I

    iget-object v12, v0, Llyiahf/vczjk/v90;->$visualTransformation:Llyiahf/vczjk/jka;

    iget-object v13, v0, Llyiahf/vczjk/v90;->$onTextLayout:Llyiahf/vczjk/oe3;

    iget-object v14, v0, Llyiahf/vczjk/v90;->$interactionSource:Llyiahf/vczjk/rr5;

    iget-object v15, v0, Llyiahf/vczjk/v90;->$cursorBrush:Llyiahf/vczjk/ri0;

    move-object/from16 v16, v1

    iget-object v1, v0, Llyiahf/vczjk/v90;->$decorationBox:Llyiahf/vczjk/bf3;

    move-object/from16 v18, v1

    iget v1, v0, Llyiahf/vczjk/v90;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/v90;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v19

    iget v1, v0, Llyiahf/vczjk/v90;->$$default:I

    move/from16 v20, v1

    move-object/from16 v1, v16

    move-object/from16 v16, v18

    move/from16 v18, p1

    invoke-static/range {v1 .. v20}, Llyiahf/vczjk/w90;->OooO00o(Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/kl5;ZZLlyiahf/vczjk/rn9;Llyiahf/vczjk/nj4;Llyiahf/vczjk/mj4;ZIILlyiahf/vczjk/jka;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/ri0;Llyiahf/vczjk/bf3;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
