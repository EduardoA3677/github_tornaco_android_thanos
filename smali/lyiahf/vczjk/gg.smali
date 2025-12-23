.class public final Llyiahf/vczjk/gg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $handleColor:J

.field final synthetic $iconVisible:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $isLeft:Z


# direct methods
.method public constructor <init>(JLlyiahf/vczjk/le3;Z)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/gg;->$handleColor:J

    iput-object p3, p0, Llyiahf/vczjk/gg;->$iconVisible:Llyiahf/vczjk/le3;

    iput-boolean p4, p0, Llyiahf/vczjk/gg;->$isLeft:Z

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 5

    check-cast p1, Llyiahf/vczjk/tm0;

    iget-object v0, p1, Llyiahf/vczjk/tm0;->OooOOO0:Llyiahf/vczjk/qj0;

    invoke-interface {v0}, Llyiahf/vczjk/qj0;->OooO0o0()J

    move-result-wide v0

    const/16 v2, 0x20

    shr-long/2addr v0, v2

    long-to-int v0, v0

    invoke-static {v0}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v0

    const/high16 v1, 0x40000000    # 2.0f

    div-float/2addr v0, v1

    invoke-static {p1, v0}, Llyiahf/vczjk/nqa;->OooOOoo(Llyiahf/vczjk/tm0;F)Llyiahf/vczjk/lu3;

    move-result-object v0

    iget-wide v1, p0, Llyiahf/vczjk/gg;->$handleColor:J

    new-instance v3, Llyiahf/vczjk/fd0;

    const/4 v4, 0x5

    invoke-direct {v3, v4, v1, v2}, Llyiahf/vczjk/fd0;-><init>(IJ)V

    new-instance v1, Llyiahf/vczjk/fg;

    iget-object v2, p0, Llyiahf/vczjk/gg;->$iconVisible:Llyiahf/vczjk/le3;

    iget-boolean v4, p0, Llyiahf/vczjk/gg;->$isLeft:Z

    invoke-direct {v1, v2, v4, v0, v3}, Llyiahf/vczjk/fg;-><init>(Llyiahf/vczjk/le3;ZLlyiahf/vczjk/lu3;Llyiahf/vczjk/fd0;)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/tm0;->OooO00o(Llyiahf/vczjk/oe3;)Llyiahf/vczjk/gg2;

    move-result-object p1

    return-object p1
.end method
