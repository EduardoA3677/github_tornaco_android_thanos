.class public final Llyiahf/vczjk/xp1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $bringIntoViewRequester:Llyiahf/vczjk/th0;

.field final synthetic $cursorModifier:Llyiahf/vczjk/kl5;

.field final synthetic $decorationBox:Llyiahf/vczjk/bf3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/bf3;"
        }
    .end annotation
.end field

.field final synthetic $density:Llyiahf/vczjk/f62;

.field final synthetic $drawModifier:Llyiahf/vczjk/kl5;

.field final synthetic $magnifierModifier:Llyiahf/vczjk/kl5;

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $maxLines:I

.field final synthetic $minLines:I

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $onPositionedModifier:Llyiahf/vczjk/kl5;

.field final synthetic $onTextLayout:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $readOnly:Z

.field final synthetic $scrollerPosition:Llyiahf/vczjk/vj9;

.field final synthetic $showHandleAndMagnifier:Z

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $textStyle:Llyiahf/vczjk/rn9;

.field final synthetic $value:Llyiahf/vczjk/gl9;

.field final synthetic $visualTransformation:Llyiahf/vczjk/jka;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bf3;Llyiahf/vczjk/lx4;Llyiahf/vczjk/rn9;IILlyiahf/vczjk/vj9;Llyiahf/vczjk/gl9;Llyiahf/vczjk/jka;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/th0;Llyiahf/vczjk/mk9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/s86;Llyiahf/vczjk/f62;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/xp1;->$decorationBox:Llyiahf/vczjk/bf3;

    iput-object p2, p0, Llyiahf/vczjk/xp1;->$state:Llyiahf/vczjk/lx4;

    iput-object p3, p0, Llyiahf/vczjk/xp1;->$textStyle:Llyiahf/vczjk/rn9;

    iput p4, p0, Llyiahf/vczjk/xp1;->$minLines:I

    iput p5, p0, Llyiahf/vczjk/xp1;->$maxLines:I

    iput-object p6, p0, Llyiahf/vczjk/xp1;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iput-object p7, p0, Llyiahf/vczjk/xp1;->$value:Llyiahf/vczjk/gl9;

    iput-object p8, p0, Llyiahf/vczjk/xp1;->$visualTransformation:Llyiahf/vczjk/jka;

    iput-object p9, p0, Llyiahf/vczjk/xp1;->$cursorModifier:Llyiahf/vczjk/kl5;

    iput-object p10, p0, Llyiahf/vczjk/xp1;->$drawModifier:Llyiahf/vczjk/kl5;

    iput-object p11, p0, Llyiahf/vczjk/xp1;->$onPositionedModifier:Llyiahf/vczjk/kl5;

    iput-object p12, p0, Llyiahf/vczjk/xp1;->$magnifierModifier:Llyiahf/vczjk/kl5;

    iput-object p13, p0, Llyiahf/vczjk/xp1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    iput-object p14, p0, Llyiahf/vczjk/xp1;->$manager:Llyiahf/vczjk/mk9;

    iput-boolean p15, p0, Llyiahf/vczjk/xp1;->$showHandleAndMagnifier:Z

    move/from16 p1, p16

    iput-boolean p1, p0, Llyiahf/vczjk/xp1;->$readOnly:Z

    move-object/from16 p1, p17

    iput-object p1, p0, Llyiahf/vczjk/xp1;->$onTextLayout:Llyiahf/vczjk/oe3;

    move-object/from16 p1, p18

    iput-object p1, p0, Llyiahf/vczjk/xp1;->$offsetMapping:Llyiahf/vczjk/s86;

    move-object/from16 p1, p19

    iput-object p1, p0, Llyiahf/vczjk/xp1;->$density:Llyiahf/vczjk/f62;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eq v3, v4, :cond_0

    move v3, v5

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    and-int/2addr v2, v5

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_1

    iget-object v2, v0, Llyiahf/vczjk/xp1;->$decorationBox:Llyiahf/vczjk/bf3;

    new-instance v3, Llyiahf/vczjk/wp1;

    iget-object v4, v0, Llyiahf/vczjk/xp1;->$state:Llyiahf/vczjk/lx4;

    iget-object v5, v0, Llyiahf/vczjk/xp1;->$textStyle:Llyiahf/vczjk/rn9;

    iget v6, v0, Llyiahf/vczjk/xp1;->$minLines:I

    iget v7, v0, Llyiahf/vczjk/xp1;->$maxLines:I

    iget-object v8, v0, Llyiahf/vczjk/xp1;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iget-object v9, v0, Llyiahf/vczjk/xp1;->$value:Llyiahf/vczjk/gl9;

    iget-object v10, v0, Llyiahf/vczjk/xp1;->$visualTransformation:Llyiahf/vczjk/jka;

    iget-object v11, v0, Llyiahf/vczjk/xp1;->$cursorModifier:Llyiahf/vczjk/kl5;

    iget-object v12, v0, Llyiahf/vczjk/xp1;->$drawModifier:Llyiahf/vczjk/kl5;

    iget-object v13, v0, Llyiahf/vczjk/xp1;->$onPositionedModifier:Llyiahf/vczjk/kl5;

    iget-object v14, v0, Llyiahf/vczjk/xp1;->$magnifierModifier:Llyiahf/vczjk/kl5;

    iget-object v15, v0, Llyiahf/vczjk/xp1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    move-object/from16 p1, v3

    iget-object v3, v0, Llyiahf/vczjk/xp1;->$manager:Llyiahf/vczjk/mk9;

    move-object/from16 v16, v3

    iget-boolean v3, v0, Llyiahf/vczjk/xp1;->$showHandleAndMagnifier:Z

    move/from16 v17, v3

    iget-boolean v3, v0, Llyiahf/vczjk/xp1;->$readOnly:Z

    move/from16 v18, v3

    iget-object v3, v0, Llyiahf/vczjk/xp1;->$onTextLayout:Llyiahf/vczjk/oe3;

    move-object/from16 v19, v3

    iget-object v3, v0, Llyiahf/vczjk/xp1;->$offsetMapping:Llyiahf/vczjk/s86;

    move-object/from16 v20, v3

    iget-object v3, v0, Llyiahf/vczjk/xp1;->$density:Llyiahf/vczjk/f62;

    move-object/from16 v21, v3

    move-object/from16 v3, p1

    invoke-direct/range {v3 .. v21}, Llyiahf/vczjk/wp1;-><init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/rn9;IILlyiahf/vczjk/vj9;Llyiahf/vczjk/gl9;Llyiahf/vczjk/jka;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/th0;Llyiahf/vczjk/mk9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/s86;Llyiahf/vczjk/f62;)V

    const v4, -0x6d69c381

    invoke-static {v4, v3, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v3

    const/4 v4, 0x6

    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-interface {v2, v3, v1, v4}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_1

    :cond_1
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_1
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
