.class public final Llyiahf/vczjk/cg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $$changed:I

.field final synthetic $$default:I

.field final synthetic $direction:Llyiahf/vczjk/rr7;

.field final synthetic $handlesCrossed:Z

.field final synthetic $isStartHandle:Z

.field final synthetic $lineHeight:F

.field final synthetic $minTouchTargetSize:J

.field final synthetic $modifier:Llyiahf/vczjk/kl5;

.field final synthetic $offsetProvider:Llyiahf/vczjk/v86;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v86;ZLlyiahf/vczjk/rr7;ZJFLlyiahf/vczjk/kl5;II)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/cg;->$offsetProvider:Llyiahf/vczjk/v86;

    iput-boolean p2, p0, Llyiahf/vczjk/cg;->$isStartHandle:Z

    iput-object p3, p0, Llyiahf/vczjk/cg;->$direction:Llyiahf/vczjk/rr7;

    iput-boolean p4, p0, Llyiahf/vczjk/cg;->$handlesCrossed:Z

    iput-wide p5, p0, Llyiahf/vczjk/cg;->$minTouchTargetSize:J

    iput p7, p0, Llyiahf/vczjk/cg;->$lineHeight:F

    iput-object p8, p0, Llyiahf/vczjk/cg;->$modifier:Llyiahf/vczjk/kl5;

    iput p9, p0, Llyiahf/vczjk/cg;->$$changed:I

    iput p10, p0, Llyiahf/vczjk/cg;->$$default:I

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    iget-object v0, p0, Llyiahf/vczjk/cg;->$offsetProvider:Llyiahf/vczjk/v86;

    iget-boolean v1, p0, Llyiahf/vczjk/cg;->$isStartHandle:Z

    iget-object v2, p0, Llyiahf/vczjk/cg;->$direction:Llyiahf/vczjk/rr7;

    iget-boolean v3, p0, Llyiahf/vczjk/cg;->$handlesCrossed:Z

    iget-wide v4, p0, Llyiahf/vczjk/cg;->$minTouchTargetSize:J

    iget v6, p0, Llyiahf/vczjk/cg;->$lineHeight:F

    iget-object v7, p0, Llyiahf/vczjk/cg;->$modifier:Llyiahf/vczjk/kl5;

    iget p1, p0, Llyiahf/vczjk/cg;->$$changed:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget v10, p0, Llyiahf/vczjk/cg;->$$default:I

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/nqa;->OooOO0(Llyiahf/vczjk/v86;ZLlyiahf/vczjk/rr7;ZJFLlyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
