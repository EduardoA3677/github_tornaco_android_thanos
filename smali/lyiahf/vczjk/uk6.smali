.class public final Llyiahf/vczjk/uk6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $beyondViewportPageCount:I

.field final synthetic $contentPadding:Llyiahf/vczjk/bi6;

.field final synthetic $flingBehavior:Llyiahf/vczjk/hg9;

.field final synthetic $key:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $overscrollEffect:Llyiahf/vczjk/qg6;

.field final synthetic $pageContent:Llyiahf/vczjk/df3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/df3;"
        }
    .end annotation
.end field

.field final synthetic $pageNestedScrollConnection:Llyiahf/vczjk/bz5;

.field final synthetic $pageSize:Llyiahf/vczjk/uj6;

.field final synthetic $pageSpacing:F

.field final synthetic $reverseLayout:Z

.field final synthetic $snapPosition:Llyiahf/vczjk/dv8;

.field final synthetic $state:Llyiahf/vczjk/lm6;

.field final synthetic $userScrollEnabled:Z

.field final synthetic $verticalAlignment:Llyiahf/vczjk/n4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lm6;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;Llyiahf/vczjk/uj6;IFLlyiahf/vczjk/n4;Llyiahf/vczjk/hg9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/bz5;Llyiahf/vczjk/dv8;Llyiahf/vczjk/qg6;Llyiahf/vczjk/df3;III)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/uk6;->$state:Llyiahf/vczjk/lm6;

    iput-object p2, p0, Llyiahf/vczjk/uk6;->$modifier:Llyiahf/vczjk/kl5;

    iput-object p3, p0, Llyiahf/vczjk/uk6;->$contentPadding:Llyiahf/vczjk/bi6;

    iput-object p4, p0, Llyiahf/vczjk/uk6;->$pageSize:Llyiahf/vczjk/uj6;

    iput p5, p0, Llyiahf/vczjk/uk6;->$beyondViewportPageCount:I

    iput p6, p0, Llyiahf/vczjk/uk6;->$pageSpacing:F

    iput-object p7, p0, Llyiahf/vczjk/uk6;->$verticalAlignment:Llyiahf/vczjk/n4;

    iput-object p8, p0, Llyiahf/vczjk/uk6;->$flingBehavior:Llyiahf/vczjk/hg9;

    iput-boolean p9, p0, Llyiahf/vczjk/uk6;->$userScrollEnabled:Z

    iput-boolean p10, p0, Llyiahf/vczjk/uk6;->$reverseLayout:Z

    iput-object p11, p0, Llyiahf/vczjk/uk6;->$key:Llyiahf/vczjk/oe3;

    iput-object p12, p0, Llyiahf/vczjk/uk6;->$pageNestedScrollConnection:Llyiahf/vczjk/bz5;

    iput-object p13, p0, Llyiahf/vczjk/uk6;->$snapPosition:Llyiahf/vczjk/dv8;

    iput-object p14, p0, Llyiahf/vczjk/uk6;->$overscrollEffect:Llyiahf/vczjk/qg6;

    iput-object p15, p0, Llyiahf/vczjk/uk6;->$pageContent:Llyiahf/vczjk/df3;

    move/from16 p1, p16

    iput p1, p0, Llyiahf/vczjk/uk6;->$$changed:I

    move/from16 p1, p17

    iput p1, p0, Llyiahf/vczjk/uk6;->$$changed1:I

    move/from16 p1, p18

    iput p1, p0, Llyiahf/vczjk/uk6;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    move-object/from16 v16, p1

    check-cast v16, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/uk6;->$state:Llyiahf/vczjk/lm6;

    iget-object v2, v0, Llyiahf/vczjk/uk6;->$modifier:Llyiahf/vczjk/kl5;

    iget-object v3, v0, Llyiahf/vczjk/uk6;->$contentPadding:Llyiahf/vczjk/bi6;

    iget-object v4, v0, Llyiahf/vczjk/uk6;->$pageSize:Llyiahf/vczjk/uj6;

    iget v5, v0, Llyiahf/vczjk/uk6;->$beyondViewportPageCount:I

    iget v6, v0, Llyiahf/vczjk/uk6;->$pageSpacing:F

    iget-object v7, v0, Llyiahf/vczjk/uk6;->$verticalAlignment:Llyiahf/vczjk/n4;

    iget-object v8, v0, Llyiahf/vczjk/uk6;->$flingBehavior:Llyiahf/vczjk/hg9;

    iget-boolean v9, v0, Llyiahf/vczjk/uk6;->$userScrollEnabled:Z

    iget-boolean v10, v0, Llyiahf/vczjk/uk6;->$reverseLayout:Z

    iget-object v11, v0, Llyiahf/vczjk/uk6;->$key:Llyiahf/vczjk/oe3;

    iget-object v12, v0, Llyiahf/vczjk/uk6;->$pageNestedScrollConnection:Llyiahf/vczjk/bz5;

    iget-object v13, v0, Llyiahf/vczjk/uk6;->$snapPosition:Llyiahf/vczjk/dv8;

    iget-object v14, v0, Llyiahf/vczjk/uk6;->$overscrollEffect:Llyiahf/vczjk/qg6;

    iget-object v15, v0, Llyiahf/vczjk/uk6;->$pageContent:Llyiahf/vczjk/df3;

    move-object/from16 v17, v1

    iget v1, v0, Llyiahf/vczjk/uk6;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/uk6;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v18

    iget v1, v0, Llyiahf/vczjk/uk6;->$$default:I

    move/from16 v19, v1

    move-object/from16 v1, v17

    move/from16 v17, p1

    invoke-static/range {v1 .. v19}, Llyiahf/vczjk/cl6;->OooO0OO(Llyiahf/vczjk/lm6;Llyiahf/vczjk/kl5;Llyiahf/vczjk/bi6;Llyiahf/vczjk/uj6;IFLlyiahf/vczjk/n4;Llyiahf/vczjk/hg9;ZZLlyiahf/vczjk/oe3;Llyiahf/vczjk/bz5;Llyiahf/vczjk/dv8;Llyiahf/vczjk/qg6;Llyiahf/vczjk/df3;Llyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
