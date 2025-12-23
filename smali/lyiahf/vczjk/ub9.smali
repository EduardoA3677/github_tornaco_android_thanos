.class public final Llyiahf/vczjk/ub9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$changed1:I

.field final synthetic $$default:I

.field final synthetic $arrowEnabled:Z

.field final synthetic $backgroundColor:J

.field final synthetic $contentColor:J

.field final synthetic $elevation:F

.field final synthetic $fade:Z

.field final synthetic $largeIndication:Z

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $refreshTriggerDistance:F

.field final synthetic $refreshingOffset:F

.field final synthetic $scale:Z

.field final synthetic $shape:Llyiahf/vczjk/qj8;

.field final synthetic $state:Llyiahf/vczjk/jc9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jc9;FLlyiahf/vczjk/kl5;ZZZJJLlyiahf/vczjk/qj8;FZFIII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ub9;->$state:Llyiahf/vczjk/jc9;

    iput p2, p0, Llyiahf/vczjk/ub9;->$refreshTriggerDistance:F

    iput-object p3, p0, Llyiahf/vczjk/ub9;->$modifier:Llyiahf/vczjk/kl5;

    iput-boolean p4, p0, Llyiahf/vczjk/ub9;->$fade:Z

    iput-boolean p5, p0, Llyiahf/vczjk/ub9;->$scale:Z

    iput-boolean p6, p0, Llyiahf/vczjk/ub9;->$arrowEnabled:Z

    iput-wide p7, p0, Llyiahf/vczjk/ub9;->$backgroundColor:J

    iput-wide p9, p0, Llyiahf/vczjk/ub9;->$contentColor:J

    iput-object p11, p0, Llyiahf/vczjk/ub9;->$shape:Llyiahf/vczjk/qj8;

    iput p12, p0, Llyiahf/vczjk/ub9;->$refreshingOffset:F

    iput-boolean p13, p0, Llyiahf/vczjk/ub9;->$largeIndication:Z

    iput p14, p0, Llyiahf/vczjk/ub9;->$elevation:F

    iput p15, p0, Llyiahf/vczjk/ub9;->$$changed:I

    move/from16 p1, p16

    iput p1, p0, Llyiahf/vczjk/ub9;->$$changed1:I

    move/from16 p1, p17

    iput p1, p0, Llyiahf/vczjk/ub9;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    move-object/from16 v0, p0

    move-object/from16 v15, p1

    check-cast v15, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->intValue()I

    iget-object v1, v0, Llyiahf/vczjk/ub9;->$state:Llyiahf/vczjk/jc9;

    iget v2, v0, Llyiahf/vczjk/ub9;->$refreshTriggerDistance:F

    iget-object v3, v0, Llyiahf/vczjk/ub9;->$modifier:Llyiahf/vczjk/kl5;

    iget-boolean v4, v0, Llyiahf/vczjk/ub9;->$fade:Z

    iget-boolean v5, v0, Llyiahf/vczjk/ub9;->$scale:Z

    iget-boolean v6, v0, Llyiahf/vczjk/ub9;->$arrowEnabled:Z

    iget-wide v7, v0, Llyiahf/vczjk/ub9;->$backgroundColor:J

    iget-wide v9, v0, Llyiahf/vczjk/ub9;->$contentColor:J

    iget-object v11, v0, Llyiahf/vczjk/ub9;->$shape:Llyiahf/vczjk/qj8;

    iget v12, v0, Llyiahf/vczjk/ub9;->$refreshingOffset:F

    iget-boolean v13, v0, Llyiahf/vczjk/ub9;->$largeIndication:Z

    iget v14, v0, Llyiahf/vczjk/ub9;->$elevation:F

    move-object/from16 v16, v1

    iget v1, v0, Llyiahf/vczjk/ub9;->$$changed:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v1

    move/from16 p1, v1

    iget v1, v0, Llyiahf/vczjk/ub9;->$$changed1:I

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v17

    iget v1, v0, Llyiahf/vczjk/ub9;->$$default:I

    move/from16 v18, v1

    move-object/from16 v1, v16

    move/from16 v16, p1

    invoke-static/range {v1 .. v18}, Llyiahf/vczjk/vb9;->OooO00o(Llyiahf/vczjk/jc9;FLlyiahf/vczjk/kl5;ZZZJJLlyiahf/vczjk/qj8;FZFLlyiahf/vczjk/rf1;III)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
