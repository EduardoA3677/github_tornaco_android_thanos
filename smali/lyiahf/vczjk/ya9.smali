.class public final Llyiahf/vczjk/ya9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $animation:Llyiahf/vczjk/yk;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/yk;"
        }
    .end annotation
.end field

.field final synthetic $block:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $durationScale:F

.field final synthetic $initialValue:Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Object;"
        }
    .end annotation
.end field

.field final synthetic $initialVelocityVector:Llyiahf/vczjk/dm;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/dm;"
        }
    .end annotation
.end field

.field final synthetic $lateInitScope:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $this_animate:Llyiahf/vczjk/xl;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/xl;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;Ljava/lang/Object;Llyiahf/vczjk/yk;Llyiahf/vczjk/dm;Llyiahf/vczjk/xl;FLlyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ya9;->$lateInitScope:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/ya9;->$initialValue:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/ya9;->$animation:Llyiahf/vczjk/yk;

    iput-object p4, p0, Llyiahf/vczjk/ya9;->$initialVelocityVector:Llyiahf/vczjk/dm;

    iput-object p5, p0, Llyiahf/vczjk/ya9;->$this_animate:Llyiahf/vczjk/xl;

    iput p6, p0, Llyiahf/vczjk/ya9;->$durationScale:F

    iput-object p7, p0, Llyiahf/vczjk/ya9;->$block:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    move-result-wide v1

    iget-object p1, p0, Llyiahf/vczjk/ya9;->$lateInitScope:Llyiahf/vczjk/hl7;

    new-instance v0, Llyiahf/vczjk/fl;

    move-wide v4, v1

    iget-object v1, p0, Llyiahf/vczjk/ya9;->$initialValue:Ljava/lang/Object;

    iget-object v2, p0, Llyiahf/vczjk/ya9;->$animation:Llyiahf/vczjk/yk;

    invoke-interface {v2}, Llyiahf/vczjk/yk;->OooO0OO()Llyiahf/vczjk/m1a;

    move-result-object v2

    iget-object v3, p0, Llyiahf/vczjk/ya9;->$initialVelocityVector:Llyiahf/vczjk/dm;

    iget-object v6, p0, Llyiahf/vczjk/ya9;->$animation:Llyiahf/vczjk/yk;

    invoke-interface {v6}, Llyiahf/vczjk/yk;->OooO0oO()Ljava/lang/Object;

    move-result-object v6

    new-instance v9, Llyiahf/vczjk/xa9;

    iget-object v7, p0, Llyiahf/vczjk/ya9;->$this_animate:Llyiahf/vczjk/xl;

    invoke-direct {v9, v7}, Llyiahf/vczjk/xa9;-><init>(Llyiahf/vczjk/xl;)V

    move-wide v7, v4

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/fl;-><init>(Ljava/lang/Object;Llyiahf/vczjk/m1a;Llyiahf/vczjk/dm;JLjava/lang/Object;JLlyiahf/vczjk/le3;)V

    iget v3, p0, Llyiahf/vczjk/ya9;->$durationScale:F

    move-wide v1, v4

    iget-object v4, p0, Llyiahf/vczjk/ya9;->$animation:Llyiahf/vczjk/yk;

    iget-object v5, p0, Llyiahf/vczjk/ya9;->$this_animate:Llyiahf/vczjk/xl;

    iget-object v6, p0, Llyiahf/vczjk/ya9;->$block:Llyiahf/vczjk/oe3;

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/vc6;->OooOOo(Llyiahf/vczjk/fl;JFLlyiahf/vczjk/yk;Llyiahf/vczjk/xl;Llyiahf/vczjk/oe3;)V

    iput-object v0, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
