.class public final Llyiahf/vczjk/wp1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $bringIntoViewRequester:Llyiahf/vczjk/th0;

.field final synthetic $cursorModifier:Llyiahf/vczjk/kl5;

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
.method public constructor <init>(Llyiahf/vczjk/lx4;Llyiahf/vczjk/rn9;IILlyiahf/vczjk/vj9;Llyiahf/vczjk/gl9;Llyiahf/vczjk/jka;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/kl5;Llyiahf/vczjk/th0;Llyiahf/vczjk/mk9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/s86;Llyiahf/vczjk/f62;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wp1;->$state:Llyiahf/vczjk/lx4;

    iput-object p2, p0, Llyiahf/vczjk/wp1;->$textStyle:Llyiahf/vczjk/rn9;

    iput p3, p0, Llyiahf/vczjk/wp1;->$minLines:I

    iput p4, p0, Llyiahf/vczjk/wp1;->$maxLines:I

    iput-object p5, p0, Llyiahf/vczjk/wp1;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iput-object p6, p0, Llyiahf/vczjk/wp1;->$value:Llyiahf/vczjk/gl9;

    iput-object p7, p0, Llyiahf/vczjk/wp1;->$visualTransformation:Llyiahf/vczjk/jka;

    iput-object p8, p0, Llyiahf/vczjk/wp1;->$cursorModifier:Llyiahf/vczjk/kl5;

    iput-object p9, p0, Llyiahf/vczjk/wp1;->$drawModifier:Llyiahf/vczjk/kl5;

    iput-object p10, p0, Llyiahf/vczjk/wp1;->$onPositionedModifier:Llyiahf/vczjk/kl5;

    iput-object p11, p0, Llyiahf/vczjk/wp1;->$magnifierModifier:Llyiahf/vczjk/kl5;

    iput-object p12, p0, Llyiahf/vczjk/wp1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    iput-object p13, p0, Llyiahf/vczjk/wp1;->$manager:Llyiahf/vczjk/mk9;

    iput-boolean p14, p0, Llyiahf/vczjk/wp1;->$showHandleAndMagnifier:Z

    iput-boolean p15, p0, Llyiahf/vczjk/wp1;->$readOnly:Z

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/wp1;->$onTextLayout:Llyiahf/vczjk/oe3;

    move-object/from16 p1, p17

    iput-object p1, p0, Llyiahf/vczjk/wp1;->$offsetMapping:Llyiahf/vczjk/s86;

    move-object/from16 p1, p18

    iput-object p1, p0, Llyiahf/vczjk/wp1;->$density:Llyiahf/vczjk/f62;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/rf1;

    move-object/from16 v2, p2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    move-result v2

    and-int/lit8 v3, v2, 0x3

    const/4 v5, 0x1

    const/4 v6, 0x2

    if-eq v3, v6, :cond_0

    move v3, v5

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    and-int/2addr v2, v5

    check-cast v1, Llyiahf/vczjk/zf1;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v2

    if-eqz v2, :cond_7

    sget-object v2, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$state:Llyiahf/vczjk/lx4;

    iget-object v3, v3, Llyiahf/vczjk/lx4;->OooO0oO:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/wd2;

    iget v3, v3, Llyiahf/vczjk/wd2;->OooOOO0:F

    const/4 v7, 0x0

    invoke-static {v2, v3, v7, v6}, Landroidx/compose/foundation/layout/OooO0OO;->OooO0oO(Llyiahf/vczjk/kl5;FFI)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$textStyle:Llyiahf/vczjk/rn9;

    iget v6, v0, Llyiahf/vczjk/wp1;->$minLines:I

    iget v7, v0, Llyiahf/vczjk/wp1;->$maxLines:I

    new-instance v8, Llyiahf/vczjk/zm3;

    invoke-direct {v8, v6, v7, v3}, Llyiahf/vczjk/zm3;-><init>(IILlyiahf/vczjk/rn9;)V

    invoke-static {v2, v8}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$scrollerPosition:Llyiahf/vczjk/vj9;

    iget-object v6, v0, Llyiahf/vczjk/wp1;->$value:Llyiahf/vczjk/gl9;

    iget-object v7, v0, Llyiahf/vczjk/wp1;->$visualTransformation:Llyiahf/vczjk/jka;

    iget-object v8, v0, Llyiahf/vczjk/wp1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v1, v8}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v8

    iget-object v9, v0, Llyiahf/vczjk/wp1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v10

    if-nez v8, :cond_1

    sget-object v8, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v10, v8, :cond_2

    :cond_1
    new-instance v10, Llyiahf/vczjk/vp1;

    invoke-direct {v10, v9}, Llyiahf/vczjk/vp1;-><init>(Llyiahf/vczjk/lx4;)V

    invoke-virtual {v1, v10}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_2
    check-cast v10, Llyiahf/vczjk/le3;

    iget-object v8, v3, Llyiahf/vczjk/vj9;->OooO0o:Llyiahf/vczjk/qs5;

    check-cast v8, Llyiahf/vczjk/fw8;

    invoke-virtual {v8}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Llyiahf/vczjk/nf6;

    iget-wide v11, v6, Llyiahf/vczjk/gl9;->OooO0O0:J

    sget v9, Llyiahf/vczjk/gn9;->OooO0OO:I

    const/16 v9, 0x20

    shr-long v13, v11, v9

    long-to-int v13, v13

    iget-wide v14, v3, Llyiahf/vczjk/vj9;->OooO0o0:J

    shr-long v4, v14, v9

    long-to-int v4, v4

    if-eq v13, v4, :cond_3

    goto :goto_1

    :cond_3
    const-wide v16, 0xffffffffL

    and-long v4, v11, v16

    long-to-int v13, v4

    and-long v4, v14, v16

    long-to-int v4, v4

    if-eq v13, v4, :cond_4

    goto :goto_1

    :cond_4
    invoke-static {v11, v12}, Llyiahf/vczjk/gn9;->OooO0o0(J)I

    move-result v13

    :goto_1
    iget-wide v4, v6, Llyiahf/vczjk/gl9;->OooO0O0:J

    iput-wide v4, v3, Llyiahf/vczjk/vj9;->OooO0o0:J

    iget-object v4, v6, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    invoke-static {v7, v4}, Llyiahf/vczjk/nqa;->OooOo0o(Llyiahf/vczjk/jka;Llyiahf/vczjk/an;)Llyiahf/vczjk/gy9;

    move-result-object v4

    invoke-virtual {v8}, Ljava/lang/Enum;->ordinal()I

    move-result v5

    if-eqz v5, :cond_6

    const/4 v6, 0x1

    if-ne v5, v6, :cond_5

    new-instance v5, Llyiahf/vczjk/po3;

    invoke-direct {v5, v3, v13, v4, v10}, Llyiahf/vczjk/po3;-><init>(Llyiahf/vczjk/vj9;ILlyiahf/vczjk/gy9;Llyiahf/vczjk/le3;)V

    goto :goto_2

    :cond_5
    new-instance v1, Llyiahf/vczjk/k61;

    invoke-direct {v1}, Ljava/lang/RuntimeException;-><init>()V

    throw v1

    :cond_6
    new-instance v5, Llyiahf/vczjk/ffa;

    invoke-direct {v5, v3, v13, v4, v10}, Llyiahf/vczjk/ffa;-><init>(Llyiahf/vczjk/vj9;ILlyiahf/vczjk/gy9;Llyiahf/vczjk/le3;)V

    :goto_2
    invoke-static {v2}, Llyiahf/vczjk/zsa;->Oooo000(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    invoke-interface {v2, v5}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$cursorModifier:Llyiahf/vczjk/kl5;

    invoke-interface {v2, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$drawModifier:Llyiahf/vczjk/kl5;

    invoke-interface {v2, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$textStyle:Llyiahf/vczjk/rn9;

    new-instance v4, Llyiahf/vczjk/el9;

    invoke-direct {v4, v3}, Llyiahf/vczjk/el9;-><init>(Llyiahf/vczjk/rn9;)V

    invoke-static {v2, v4}, Llyiahf/vczjk/ng0;->OooOOoo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/bf3;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$onPositionedModifier:Llyiahf/vczjk/kl5;

    invoke-interface {v2, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$magnifierModifier:Llyiahf/vczjk/kl5;

    invoke-interface {v2, v3}, Llyiahf/vczjk/kl5;->OooO0oO(Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v2

    iget-object v3, v0, Llyiahf/vczjk/wp1;->$bringIntoViewRequester:Llyiahf/vczjk/th0;

    invoke-static {v2, v3}, Landroidx/compose/foundation/relocation/OooO00o;->OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/th0;)Llyiahf/vczjk/kl5;

    move-result-object v2

    new-instance v3, Llyiahf/vczjk/up1;

    iget-object v4, v0, Llyiahf/vczjk/wp1;->$manager:Llyiahf/vczjk/mk9;

    iget-object v5, v0, Llyiahf/vczjk/wp1;->$state:Llyiahf/vczjk/lx4;

    iget-boolean v6, v0, Llyiahf/vczjk/wp1;->$showHandleAndMagnifier:Z

    iget-boolean v7, v0, Llyiahf/vczjk/wp1;->$readOnly:Z

    iget-object v8, v0, Llyiahf/vczjk/wp1;->$onTextLayout:Llyiahf/vczjk/oe3;

    iget-object v9, v0, Llyiahf/vczjk/wp1;->$value:Llyiahf/vczjk/gl9;

    iget-object v10, v0, Llyiahf/vczjk/wp1;->$offsetMapping:Llyiahf/vczjk/s86;

    iget-object v11, v0, Llyiahf/vczjk/wp1;->$density:Llyiahf/vczjk/f62;

    iget v12, v0, Llyiahf/vczjk/wp1;->$maxLines:I

    invoke-direct/range {v3 .. v12}, Llyiahf/vczjk/up1;-><init>(Llyiahf/vczjk/mk9;Llyiahf/vczjk/lx4;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;Llyiahf/vczjk/f62;I)V

    const v4, -0x45e26f0b

    invoke-static {v4, v3, v1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v3

    const/16 v4, 0x30

    const/4 v5, 0x0

    invoke-static {v2, v3, v1, v4, v5}, Llyiahf/vczjk/rl6;->OooO0Oo(Llyiahf/vczjk/kl5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;II)V

    goto :goto_3

    :cond_7
    invoke-virtual {v1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_3
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
