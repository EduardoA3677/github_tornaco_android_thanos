.class public final Llyiahf/vczjk/s16;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $distanceFromEdge:F

.field final synthetic $hitTestResult:Llyiahf/vczjk/eo3;

.field final synthetic $hitTestSource:Llyiahf/vczjk/o16;

.field final synthetic $isHitInMinimumTouchTargetBetter:Z

.field final synthetic $isInLayer:Z

.field final synthetic $pointerPosition:J

.field final synthetic $pointerType:I

.field final synthetic $this_outOfBoundsHit:Llyiahf/vczjk/jl5;

.field final synthetic this$0:Llyiahf/vczjk/v16;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v16;Llyiahf/vczjk/jl5;Llyiahf/vczjk/o16;JLlyiahf/vczjk/eo3;IZFZ)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s16;->this$0:Llyiahf/vczjk/v16;

    iput-object p2, p0, Llyiahf/vczjk/s16;->$this_outOfBoundsHit:Llyiahf/vczjk/jl5;

    iput-object p3, p0, Llyiahf/vczjk/s16;->$hitTestSource:Llyiahf/vczjk/o16;

    iput-wide p4, p0, Llyiahf/vczjk/s16;->$pointerPosition:J

    iput-object p6, p0, Llyiahf/vczjk/s16;->$hitTestResult:Llyiahf/vczjk/eo3;

    iput p7, p0, Llyiahf/vczjk/s16;->$pointerType:I

    iput-boolean p8, p0, Llyiahf/vczjk/s16;->$isInLayer:Z

    iput p9, p0, Llyiahf/vczjk/s16;->$distanceFromEdge:F

    iput-boolean p10, p0, Llyiahf/vczjk/s16;->$isHitInMinimumTouchTargetBetter:Z

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/s16;->this$0:Llyiahf/vczjk/v16;

    iget-object v1, p0, Llyiahf/vczjk/s16;->$this_outOfBoundsHit:Llyiahf/vczjk/jl5;

    iget-object v2, p0, Llyiahf/vczjk/s16;->$hitTestSource:Llyiahf/vczjk/o16;

    invoke-interface {v2}, Llyiahf/vczjk/o16;->OooO0o0()I

    move-result v2

    invoke-static {v1, v2}, Llyiahf/vczjk/l4a;->OooO0oO(Llyiahf/vczjk/l52;I)Llyiahf/vczjk/jl5;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/s16;->$hitTestSource:Llyiahf/vczjk/o16;

    iget-wide v3, p0, Llyiahf/vczjk/s16;->$pointerPosition:J

    iget-object v5, p0, Llyiahf/vczjk/s16;->$hitTestResult:Llyiahf/vczjk/eo3;

    iget v6, p0, Llyiahf/vczjk/s16;->$pointerType:I

    iget-boolean v7, p0, Llyiahf/vczjk/s16;->$isInLayer:Z

    iget v8, p0, Llyiahf/vczjk/s16;->$distanceFromEdge:F

    iget-boolean v9, p0, Llyiahf/vczjk/s16;->$isHitInMinimumTouchTargetBetter:Z

    invoke-virtual/range {v0 .. v9}, Llyiahf/vczjk/v16;->o0000oOO(Llyiahf/vczjk/jl5;Llyiahf/vczjk/o16;JLlyiahf/vczjk/eo3;IZFZ)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method
