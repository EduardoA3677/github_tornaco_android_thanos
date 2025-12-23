.class public final Llyiahf/vczjk/qc5;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$changed2:I

.field final synthetic $$default:I

.field final synthetic $afterSetMarkdown:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $autoSizeConfig:Llyiahf/vczjk/w10;

.field final synthetic $beforeSetMarkdown:Llyiahf/vczjk/ze3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ze3;"
        }
    .end annotation
.end field

.field final synthetic $disableLinkMovementMethod:Z

.field final synthetic $enableSoftBreakAddsNewLine:Z

.field final synthetic $fontResource:Ljava/lang/Integer;

.field final synthetic $headingBreakColor:J

.field final synthetic $imageLoader:Llyiahf/vczjk/fv3;

.field final synthetic $isTextSelectable:Z

.field final synthetic $linkColor:J

.field final synthetic $linkifyMask:I

.field final synthetic $markdown:Ljava/lang/String;

.field final synthetic $maxLines:I

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $onClick:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $onLinkClicked:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $onTextLayout:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $style:Llyiahf/vczjk/rn9;

.field final synthetic $syntaxHighlightColor:J

.field final synthetic $truncateOnTextOverflow:Z

.field final synthetic $viewId:Ljava/lang/Integer;


# direct methods
.method public constructor <init>(Ljava/lang/String;Llyiahf/vczjk/kl5;JZIZLjava/lang/Integer;Llyiahf/vczjk/rn9;Ljava/lang/Integer;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/fv3;IZJJLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;IIII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qc5;->$markdown:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/qc5;->$modifier:Llyiahf/vczjk/kl5;

    iput-wide p3, p0, Llyiahf/vczjk/qc5;->$linkColor:J

    iput-boolean p5, p0, Llyiahf/vczjk/qc5;->$truncateOnTextOverflow:Z

    iput p6, p0, Llyiahf/vczjk/qc5;->$maxLines:I

    iput-boolean p7, p0, Llyiahf/vczjk/qc5;->$isTextSelectable:Z

    iput-object p8, p0, Llyiahf/vczjk/qc5;->$fontResource:Ljava/lang/Integer;

    iput-object p9, p0, Llyiahf/vczjk/qc5;->$style:Llyiahf/vczjk/rn9;

    iput-object p10, p0, Llyiahf/vczjk/qc5;->$viewId:Ljava/lang/Integer;

    iput-object p11, p0, Llyiahf/vczjk/qc5;->$onClick:Llyiahf/vczjk/le3;

    iput-boolean p12, p0, Llyiahf/vczjk/qc5;->$disableLinkMovementMethod:Z

    iput-object p13, p0, Llyiahf/vczjk/qc5;->$imageLoader:Llyiahf/vczjk/fv3;

    iput p14, p0, Llyiahf/vczjk/qc5;->$linkifyMask:I

    iput-boolean p15, p0, Llyiahf/vczjk/qc5;->$enableSoftBreakAddsNewLine:Z

    move-wide/from16 p1, p16

    iput-wide p1, p0, Llyiahf/vczjk/qc5;->$syntaxHighlightColor:J

    move-wide/from16 p1, p18

    iput-wide p1, p0, Llyiahf/vczjk/qc5;->$headingBreakColor:J

    move-object/from16 p1, p20

    iput-object p1, p0, Llyiahf/vczjk/qc5;->$beforeSetMarkdown:Llyiahf/vczjk/ze3;

    move-object/from16 p1, p21

    iput-object p1, p0, Llyiahf/vczjk/qc5;->$afterSetMarkdown:Llyiahf/vczjk/oe3;

    move-object/from16 p1, p22

    iput-object p1, p0, Llyiahf/vczjk/qc5;->$onLinkClicked:Llyiahf/vczjk/oe3;

    move-object/from16 p1, p23

    iput-object p1, p0, Llyiahf/vczjk/qc5;->$onTextLayout:Llyiahf/vczjk/oe3;

    move/from16 p1, p24

    iput p1, p0, Llyiahf/vczjk/qc5;->$$changed:I

    move/from16 p1, p25

    iput p1, p0, Llyiahf/vczjk/qc5;->$$changed1:I

    move/from16 p1, p26

    iput p1, p0, Llyiahf/vczjk/qc5;->$$changed2:I

    move/from16 p1, p27

    iput p1, p0, Llyiahf/vczjk/qc5;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 32

    move-object/from16 v0, p0

    move-object/from16 v24, p1

    check-cast v24, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/qc5;->$markdown:Ljava/lang/String;

    iget-object v2, v0, Llyiahf/vczjk/qc5;->$modifier:Llyiahf/vczjk/kl5;

    iget-wide v3, v0, Llyiahf/vczjk/qc5;->$linkColor:J

    iget-boolean v5, v0, Llyiahf/vczjk/qc5;->$truncateOnTextOverflow:Z

    iget v6, v0, Llyiahf/vczjk/qc5;->$maxLines:I

    iget-boolean v7, v0, Llyiahf/vczjk/qc5;->$isTextSelectable:Z

    iget-object v8, v0, Llyiahf/vczjk/qc5;->$fontResource:Ljava/lang/Integer;

    iget-object v9, v0, Llyiahf/vczjk/qc5;->$style:Llyiahf/vczjk/rn9;

    iget-object v10, v0, Llyiahf/vczjk/qc5;->$viewId:Ljava/lang/Integer;

    iget-object v11, v0, Llyiahf/vczjk/qc5;->$onClick:Llyiahf/vczjk/le3;

    iget-boolean v12, v0, Llyiahf/vczjk/qc5;->$disableLinkMovementMethod:Z

    iget-object v13, v0, Llyiahf/vczjk/qc5;->$imageLoader:Llyiahf/vczjk/fv3;

    iget v14, v0, Llyiahf/vczjk/qc5;->$linkifyMask:I

    iget-boolean v15, v0, Llyiahf/vczjk/qc5;->$enableSoftBreakAddsNewLine:Z

    move-object/from16 v16, v1

    move-object/from16 v17, v2

    iget-wide v1, v0, Llyiahf/vczjk/qc5;->$syntaxHighlightColor:J

    move-wide/from16 v18, v1

    iget-wide v1, v0, Llyiahf/vczjk/qc5;->$headingBreakColor:J

    move-wide/from16 v20, v1

    iget-object v1, v0, Llyiahf/vczjk/qc5;->$beforeSetMarkdown:Llyiahf/vczjk/ze3;

    iget-object v2, v0, Llyiahf/vczjk/qc5;->$afterSetMarkdown:Llyiahf/vczjk/oe3;

    move-object/from16 v22, v1

    iget-object v1, v0, Llyiahf/vczjk/qc5;->$onLinkClicked:Llyiahf/vczjk/oe3;

    move-object/from16 v23, v1

    iget-object v1, v0, Llyiahf/vczjk/qc5;->$onTextLayout:Llyiahf/vczjk/oe3;

    move-object/from16 v25, v1

    iget v1, v0, Llyiahf/vczjk/qc5;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/qc5;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v26

    iget v1, v0, Llyiahf/vczjk/qc5;->$$changed2:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v27

    iget v1, v0, Llyiahf/vczjk/qc5;->$$default:I

    move/from16 v28, v1

    move-object/from16 v1, v16

    move-object/from16 v29, v25

    move/from16 v25, p1

    move-wide/from16 v30, v20

    move-object/from16 v21, v2

    move-object/from16 v2, v17

    move-wide/from16 v16, v18

    move-wide/from16 v18, v30

    move-object/from16 v20, v22

    move-object/from16 v22, v23

    move-object/from16 v23, v29

    invoke-static/range {v1 .. v28}, Llyiahf/vczjk/mc4;->OooO0oo(Ljava/lang/String;Llyiahf/vczjk/kl5;JZIZLjava/lang/Integer;Llyiahf/vczjk/rn9;Ljava/lang/Integer;Llyiahf/vczjk/le3;ZLlyiahf/vczjk/fv3;IZJJLlyiahf/vczjk/ze3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;IIII)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
