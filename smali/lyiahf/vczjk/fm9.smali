.class public final Llyiahf/vczjk/fm9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $color:J

.field final synthetic $fontFamily:Llyiahf/vczjk/ba3;

.field final synthetic $fontSize:J

.field final synthetic $fontStyle:Llyiahf/vczjk/cb3;

.field final synthetic $fontWeight:Llyiahf/vczjk/ib3;

.field final synthetic $letterSpacing:J

.field final synthetic $lineHeight:J

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

.field final synthetic $textAlign:Llyiahf/vczjk/ch9;

.field final synthetic $textDecoration:Llyiahf/vczjk/vh9;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/cb3;Llyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;III)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fm9;->$text:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/fm9;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p3, p0, Llyiahf/vczjk/fm9;->$color:J

    iput-wide p5, p0, Llyiahf/vczjk/fm9;->$fontSize:J

    iput-object p7, p0, Llyiahf/vczjk/fm9;->$fontStyle:Llyiahf/vczjk/cb3;

    iput-object p8, p0, Llyiahf/vczjk/fm9;->$fontWeight:Llyiahf/vczjk/ib3;

    iput-object p9, p0, Llyiahf/vczjk/fm9;->$fontFamily:Llyiahf/vczjk/ba3;

    iput-wide p10, p0, Llyiahf/vczjk/fm9;->$letterSpacing:J

    iput-object p12, p0, Llyiahf/vczjk/fm9;->$textDecoration:Llyiahf/vczjk/vh9;

    iput-object p13, p0, Llyiahf/vczjk/fm9;->$textAlign:Llyiahf/vczjk/ch9;

    iput-wide p14, p0, Llyiahf/vczjk/fm9;->$lineHeight:J

    move/from16 p1, p16

    iput p1, p0, Llyiahf/vczjk/fm9;->$overflow:I

    move/from16 p1, p17

    iput-boolean p1, p0, Llyiahf/vczjk/fm9;->$softWrap:Z

    move/from16 p1, p18

    iput p1, p0, Llyiahf/vczjk/fm9;->$maxLines:I

    move/from16 p1, p19

    iput p1, p0, Llyiahf/vczjk/fm9;->$minLines:I

    move-object/from16 p1, p20

    iput-object p1, p0, Llyiahf/vczjk/fm9;->$onTextLayout:Llyiahf/vczjk/oe3;

    move-object/from16 p1, p21

    iput-object p1, p0, Llyiahf/vczjk/fm9;->$style:Llyiahf/vczjk/rn9;

    move/from16 p1, p22

    iput p1, p0, Llyiahf/vczjk/fm9;->$$changed:I

    move/from16 p1, p23

    iput p1, p0, Llyiahf/vczjk/fm9;->$$changed1:I

    move/from16 p1, p24

    iput p1, p0, Llyiahf/vczjk/fm9;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    move-object/from16 v0, p0

    move-object/from16 v22, p1

    check-cast v22, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/fm9;->$text:Ljava/lang/String;

    iget-object v2, v0, Llyiahf/vczjk/fm9;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v3, v0, Llyiahf/vczjk/fm9;->$color:J

    iget-wide v5, v0, Llyiahf/vczjk/fm9;->$fontSize:J

    iget-object v7, v0, Llyiahf/vczjk/fm9;->$fontStyle:Llyiahf/vczjk/cb3;

    iget-object v8, v0, Llyiahf/vczjk/fm9;->$fontWeight:Llyiahf/vczjk/ib3;

    iget-object v9, v0, Llyiahf/vczjk/fm9;->$fontFamily:Llyiahf/vczjk/ba3;

    iget-wide v10, v0, Llyiahf/vczjk/fm9;->$letterSpacing:J

    iget-object v12, v0, Llyiahf/vczjk/fm9;->$textDecoration:Llyiahf/vczjk/vh9;

    iget-object v13, v0, Llyiahf/vczjk/fm9;->$textAlign:Llyiahf/vczjk/ch9;

    iget-wide v14, v0, Llyiahf/vczjk/fm9;->$lineHeight:J

    move-object/from16 v16, v1

    iget v1, v0, Llyiahf/vczjk/fm9;->$overflow:I

    move/from16 v17, v1

    iget-boolean v1, v0, Llyiahf/vczjk/fm9;->$softWrap:Z

    move/from16 v18, v1

    iget v1, v0, Llyiahf/vczjk/fm9;->$maxLines:I

    move/from16 v19, v1

    iget v1, v0, Llyiahf/vczjk/fm9;->$minLines:I

    move/from16 v20, v1

    iget-object v1, v0, Llyiahf/vczjk/fm9;->$onTextLayout:Llyiahf/vczjk/oe3;

    move-object/from16 v21, v1

    iget-object v1, v0, Llyiahf/vczjk/fm9;->$style:Llyiahf/vczjk/rn9;

    move-object/from16 v23, v1

    iget v1, v0, Llyiahf/vczjk/fm9;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/fm9;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v24

    iget v1, v0, Llyiahf/vczjk/fm9;->$$default:I

    move/from16 v25, v1

    move-object/from16 v1, v16

    move/from16 v16, v17

    move/from16 v17, v18

    move/from16 v18, v19

    move/from16 v19, v20

    move-object/from16 v20, v21

    move-object/from16 v21, v23

    move/from16 v23, p1

    invoke-static/range {v1 .. v25}, Llyiahf/vczjk/hm9;->OooO0O0(Ljava/lang/String;Llyiahf/vczjk/kl5;JJLlyiahf/vczjk/cb3;Llyiahf/vczjk/ib3;Llyiahf/vczjk/ba3;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ch9;JIZIILlyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
