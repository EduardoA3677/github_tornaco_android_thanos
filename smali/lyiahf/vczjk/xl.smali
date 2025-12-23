.class public final Llyiahf/vczjk/xl;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/p29;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/qs5;

.field public final OooOOO0:Llyiahf/vczjk/m1a;

.field public OooOOOO:Llyiahf/vczjk/dm;

.field public OooOOOo:J

.field public OooOOo:Z

.field public OooOOo0:J


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;I)V
    .locals 9

    and-int/lit8 p4, p4, 0x4

    if-eqz p4, :cond_0

    const/4 p3, 0x0

    :cond_0
    move-object v3, p3

    const/4 v8, 0x0

    const-wide/high16 v4, -0x8000000000000000L

    const-wide/high16 v6, -0x8000000000000000L

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    invoke-direct/range {v0 .. v8}, Llyiahf/vczjk/xl;-><init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;JJZ)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/m1a;Ljava/lang/Object;Llyiahf/vczjk/dm;JJZ)V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xl;->OooOOO0:Llyiahf/vczjk/m1a;

    invoke-static {p2}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    if-eqz p3, :cond_0

    invoke-static {p3}, Llyiahf/vczjk/t51;->OooOo0O(Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    goto :goto_0

    :cond_0
    check-cast p1, Llyiahf/vczjk/n1a;

    iget-object p1, p1, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {p1, p2}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dm;

    invoke-virtual {p1}, Llyiahf/vczjk/dm;->OooO0Oo()V

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    iput-wide p4, p0, Llyiahf/vczjk/xl;->OooOOOo:J

    iput-wide p6, p0, Llyiahf/vczjk/xl;->OooOOo0:J

    iput-boolean p8, p0, Llyiahf/vczjk/xl;->OooOOo:Z

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/xl;->OooOOO0:Llyiahf/vczjk/m1a;

    check-cast v0, Llyiahf/vczjk/n1a;

    iget-object v0, v0, Llyiahf/vczjk/n1a;->OooO0O0:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/xl;->OooOOOO:Llyiahf/vczjk/dm;

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "AnimationState(value="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/xl;->OooOOO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", velocity="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p0}, Llyiahf/vczjk/xl;->OooO00o()Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", isRunning="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v1, p0, Llyiahf/vczjk/xl;->OooOOo:Z

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    const-string v1, ", lastFrameTimeNanos="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-wide v1, p0, Llyiahf/vczjk/xl;->OooOOOo:J

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v1, ", finishedTimeNanos="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-wide v1, p0, Llyiahf/vczjk/xl;->OooOOo0:J

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
