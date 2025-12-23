.class public final Llyiahf/vczjk/mk6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $content:Llyiahf/vczjk/df3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/df3;"
        }
    .end annotation
.end field

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $count:I

.field final synthetic $flingBehavior:Llyiahf/vczjk/o23;

.field final synthetic $horizontalAlignment:Llyiahf/vczjk/m4;

.field final synthetic $isVertical:Z

.field final synthetic $itemSpacing:F

.field final synthetic $key:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $reverseLayout:Z

.field final synthetic $state:Llyiahf/vczjk/km6;

.field final synthetic $userScrollEnabled:Z

.field final synthetic $verticalAlignment:Llyiahf/vczjk/n4;


# direct methods
.method public constructor <init>(ILlyiahf/vczjk/kl5;Llyiahf/vczjk/km6;ZFZLlyiahf/vczjk/o23;Llyiahf/vczjk/oe3;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/n4;Llyiahf/vczjk/m4;Llyiahf/vczjk/df3;III)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/mk6;->$count:I

    iput-object p2, p0, Llyiahf/vczjk/mk6;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/mk6;->$state:Llyiahf/vczjk/km6;

    iput-boolean p4, p0, Llyiahf/vczjk/mk6;->$reverseLayout:Z

    iput p5, p0, Llyiahf/vczjk/mk6;->$itemSpacing:F

    iput-boolean p6, p0, Llyiahf/vczjk/mk6;->$isVertical:Z

    iput-object p7, p0, Llyiahf/vczjk/mk6;->$flingBehavior:Llyiahf/vczjk/o23;

    iput-object p8, p0, Llyiahf/vczjk/mk6;->$key:Llyiahf/vczjk/oe3;

    iput-object p9, p0, Llyiahf/vczjk/mk6;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-boolean p10, p0, Llyiahf/vczjk/mk6;->$userScrollEnabled:Z

    iput-object p11, p0, Llyiahf/vczjk/mk6;->$verticalAlignment:Llyiahf/vczjk/n4;

    iput-object p12, p0, Llyiahf/vczjk/mk6;->$horizontalAlignment:Llyiahf/vczjk/m4;

    iput-object p13, p0, Llyiahf/vczjk/mk6;->$content:Llyiahf/vczjk/df3;

    iput p14, p0, Llyiahf/vczjk/mk6;->$$changed:I

    iput p15, p0, Llyiahf/vczjk/mk6;->$$changed1:I

    move/from16 p1, p16

    iput p1, p0, Llyiahf/vczjk/mk6;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v14, p1

    check-cast v14, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget v1, v0, Llyiahf/vczjk/mk6;->$count:I

    iget-object v2, v0, Llyiahf/vczjk/mk6;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, v0, Llyiahf/vczjk/mk6;->$state:Llyiahf/vczjk/km6;

    iget-boolean v4, v0, Llyiahf/vczjk/mk6;->$reverseLayout:Z

    iget v5, v0, Llyiahf/vczjk/mk6;->$itemSpacing:F

    iget-boolean v6, v0, Llyiahf/vczjk/mk6;->$isVertical:Z

    iget-object v7, v0, Llyiahf/vczjk/mk6;->$flingBehavior:Llyiahf/vczjk/o23;

    iget-object v8, v0, Llyiahf/vczjk/mk6;->$key:Llyiahf/vczjk/oe3;

    iget-object v9, v0, Llyiahf/vczjk/mk6;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-boolean v10, v0, Llyiahf/vczjk/mk6;->$userScrollEnabled:Z

    iget-object v11, v0, Llyiahf/vczjk/mk6;->$verticalAlignment:Llyiahf/vczjk/n4;

    iget-object v12, v0, Llyiahf/vczjk/mk6;->$horizontalAlignment:Llyiahf/vczjk/m4;

    iget-object v13, v0, Llyiahf/vczjk/mk6;->$content:Llyiahf/vczjk/df3;

    iget v15, v0, Llyiahf/vczjk/mk6;->$$changed:I

    or-int/lit8 v15, v15, 0x1

    invoke-static {v15}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v15

    move/from16 v16, v1

    iget v1, v0, Llyiahf/vczjk/mk6;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/mk6;->$$default:I

    move/from16 v17, v1

    move/from16 v1, v16

    move/from16 v16, p1

    invoke-static/range {v1 .. v17}, Llyiahf/vczjk/ok6;->OooO0oO(ILlyiahf/vczjk/kl5;Llyiahf/vczjk/km6;ZFZLlyiahf/vczjk/o23;Llyiahf/vczjk/oe3;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/n4;Llyiahf/vczjk/m4;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
