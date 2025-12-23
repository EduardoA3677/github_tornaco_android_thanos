.class public final Llyiahf/vczjk/sp4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $columns:Llyiahf/vczjk/ak3;

.field final synthetic $content:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $flingBehavior:Llyiahf/vczjk/o23;

.field final synthetic $horizontalArrangement:Llyiahf/vczjk/nx;

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $overscrollEffect:Llyiahf/vczjk/qg6;

.field final synthetic $reverseLayout:Z

.field final synthetic $state:Llyiahf/vczjk/er4;

.field final synthetic $userScrollEnabled:Z

.field final synthetic $verticalArrangement:Llyiahf/vczjk/px;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ak3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;III)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sp4;->$columns:Llyiahf/vczjk/ak3;

    iput-object p2, p0, Llyiahf/vczjk/sp4;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/sp4;->$state:Llyiahf/vczjk/er4;

    iput-object p4, p0, Llyiahf/vczjk/sp4;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-boolean p5, p0, Llyiahf/vczjk/sp4;->$reverseLayout:Z

    iput-object p6, p0, Llyiahf/vczjk/sp4;->$verticalArrangement:Llyiahf/vczjk/px;

    iput-object p7, p0, Llyiahf/vczjk/sp4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iput-object p8, p0, Llyiahf/vczjk/sp4;->$flingBehavior:Llyiahf/vczjk/o23;

    iput-boolean p9, p0, Llyiahf/vczjk/sp4;->$userScrollEnabled:Z

    iput-object p10, p0, Llyiahf/vczjk/sp4;->$overscrollEffect:Llyiahf/vczjk/qg6;

    iput-object p11, p0, Llyiahf/vczjk/sp4;->$content:Llyiahf/vczjk/oe3;

    iput p12, p0, Llyiahf/vczjk/sp4;->$$changed:I

    iput p13, p0, Llyiahf/vczjk/sp4;->$$changed1:I

    iput p14, p0, Llyiahf/vczjk/sp4;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v12, p1

    check-cast v12, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/sp4;->$columns:Llyiahf/vczjk/ak3;

    iget-object v2, v0, Llyiahf/vczjk/sp4;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, v0, Llyiahf/vczjk/sp4;->$state:Llyiahf/vczjk/er4;

    iget-object v4, v0, Llyiahf/vczjk/sp4;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-boolean v5, v0, Llyiahf/vczjk/sp4;->$reverseLayout:Z

    iget-object v6, v0, Llyiahf/vczjk/sp4;->$verticalArrangement:Llyiahf/vczjk/px;

    iget-object v7, v0, Llyiahf/vczjk/sp4;->$horizontalArrangement:Llyiahf/vczjk/nx;

    iget-object v8, v0, Llyiahf/vczjk/sp4;->$flingBehavior:Llyiahf/vczjk/o23;

    iget-boolean v9, v0, Llyiahf/vczjk/sp4;->$userScrollEnabled:Z

    iget-object v10, v0, Llyiahf/vczjk/sp4;->$overscrollEffect:Llyiahf/vczjk/qg6;

    iget-object v11, v0, Llyiahf/vczjk/sp4;->$content:Llyiahf/vczjk/oe3;

    iget v13, v0, Llyiahf/vczjk/sp4;->$$changed:I

    or-int/lit8 v13, v13, 0x1

    invoke-static {v13}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v13

    iget v14, v0, Llyiahf/vczjk/sp4;->$$changed1:I

    invoke-static {v14}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v14

    iget v15, v0, Llyiahf/vczjk/sp4;->$$default:I

    invoke-static/range {v1 .. v15}, Llyiahf/vczjk/yi4;->OooOOO0(Llyiahf/vczjk/ak3;Llyiahf/vczjk/kl5;Llyiahf/vczjk/er4;Llyiahf/vczjk/bi6;ZLlyiahf/vczjk/px;Llyiahf/vczjk/nx;Llyiahf/vczjk/o23;ZLlyiahf/vczjk/qg6;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
