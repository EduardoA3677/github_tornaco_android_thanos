.class public final Llyiahf/vczjk/fg9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/yk;


# instance fields
.field public OooO:Llyiahf/vczjk/dm;

.field public final OooO00o:Llyiahf/vczjk/yda;

.field public final OooO0O0:Llyiahf/vczjk/m1a;

.field public OooO0OO:Ljava/lang/Object;

.field public OooO0Oo:Ljava/lang/Object;

.field public OooO0o:Llyiahf/vczjk/dm;

.field public OooO0o0:Llyiahf/vczjk/dm;

.field public final OooO0oO:Llyiahf/vczjk/dm;

.field public OooO0oo:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wl;Llyiahf/vczjk/m1a;Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/dm;)V
    .locals 0

    invoke-interface {p1, p2}, Llyiahf/vczjk/wl;->OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;

    move-result-object p1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO00o:Llyiahf/vczjk/yda;

    iput-object p2, p0, Llyiahf/vczjk/fg9;->OooO0O0:Llyiahf/vczjk/m1a;

    iput-object p4, p0, Llyiahf/vczjk/fg9;->OooO0OO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/fg9;->OooO0Oo:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/n1a;

    iget-object p1, p2, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {p1, p3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dm;

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO0o0:Llyiahf/vczjk/dm;

    iget-object p1, p2, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {p1, p4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/dm;

    iput-object p2, p0, Llyiahf/vczjk/fg9;->OooO0o:Llyiahf/vczjk/dm;

    if-eqz p5, :cond_0

    invoke-static {p5}, Llyiahf/vczjk/t51;->OooOo0O(Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    goto :goto_0

    :cond_0
    invoke-interface {p1, p3}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dm;

    invoke-virtual {p1}, Llyiahf/vczjk/dm;->OooO0OO()Llyiahf/vczjk/dm;

    move-result-object p1

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO0oO:Llyiahf/vczjk/dm;

    const-wide/16 p1, -0x1

    iput-wide p1, p0, Llyiahf/vczjk/fg9;->OooO0oo:J

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0OO:Ljava/lang/Object;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO0OO:Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0O0:Llyiahf/vczjk/m1a;

    check-cast v0, Llyiahf/vczjk/n1a;

    iget-object v0, v0, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dm;

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO0o:Llyiahf/vczjk/dm;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO:Llyiahf/vczjk/dm;

    const-wide/16 v0, -0x1

    iput-wide v0, p0, Llyiahf/vczjk/fg9;->OooO0oo:J

    :cond_0
    return-void
.end method

.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO00o:Llyiahf/vczjk/yda;

    invoke-interface {v0}, Llyiahf/vczjk/yda;->OooO00o()Z

    move-result v0

    return v0
.end method

.method public final OooO0O0()J
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/fg9;->OooO0oo:J

    const-wide/16 v2, 0x0

    cmp-long v0, v0, v2

    if-gez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0o0:Llyiahf/vczjk/dm;

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO0o:Llyiahf/vczjk/dm;

    iget-object v2, p0, Llyiahf/vczjk/fg9;->OooO0oO:Llyiahf/vczjk/dm;

    iget-object v3, p0, Llyiahf/vczjk/fg9;->OooO00o:Llyiahf/vczjk/yda;

    invoke-interface {v3, v0, v1, v2}, Llyiahf/vczjk/yda;->OooO0o0(Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)J

    move-result-wide v0

    iput-wide v0, p0, Llyiahf/vczjk/fg9;->OooO0oo:J

    :cond_0
    iget-wide v0, p0, Llyiahf/vczjk/fg9;->OooO0oo:J

    return-wide v0
.end method

.method public final OooO0OO()Llyiahf/vczjk/m1a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0O0:Llyiahf/vczjk/m1a;

    return-object v0
.end method

.method public final OooO0Oo(J)Llyiahf/vczjk/dm;
    .locals 7

    invoke-interface {p0, p1, p2}, Llyiahf/vczjk/yk;->OooO0o0(J)Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v4, p0, Llyiahf/vczjk/fg9;->OooO0o0:Llyiahf/vczjk/dm;

    iget-object v5, p0, Llyiahf/vczjk/fg9;->OooO0o:Llyiahf/vczjk/dm;

    iget-object v6, p0, Llyiahf/vczjk/fg9;->OooO0oO:Llyiahf/vczjk/dm;

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO00o:Llyiahf/vczjk/yda;

    move-wide v2, p1

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/yda;->OooOO0o(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    return-object p1

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/fg9;->OooO:Llyiahf/vczjk/dm;

    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/fg9;->OooO0o0:Llyiahf/vczjk/dm;

    iget-object p2, p0, Llyiahf/vczjk/fg9;->OooO0o:Llyiahf/vczjk/dm;

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0oO:Llyiahf/vczjk/dm;

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO00o:Llyiahf/vczjk/yda;

    invoke-interface {v1, p1, p2, v0}, Llyiahf/vczjk/yda;->OooO0oO(Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO:Llyiahf/vczjk/dm;

    :cond_1
    return-object p1
.end method

.method public final OooO0o(J)Ljava/lang/Object;
    .locals 7

    invoke-interface {p0, p1, p2}, Llyiahf/vczjk/yk;->OooO0o0(J)Z

    move-result v0

    if-nez v0, :cond_2

    iget-object v4, p0, Llyiahf/vczjk/fg9;->OooO0o0:Llyiahf/vczjk/dm;

    iget-object v5, p0, Llyiahf/vczjk/fg9;->OooO0o:Llyiahf/vczjk/dm;

    iget-object v6, p0, Llyiahf/vczjk/fg9;->OooO0oO:Llyiahf/vczjk/dm;

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO00o:Llyiahf/vczjk/yda;

    move-wide v2, p1

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/yda;->OooO0oo(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p1

    invoke-virtual {p1}, Llyiahf/vczjk/dm;->OooO0O0()I

    move-result p2

    const/4 v0, 0x0

    :goto_0
    if-ge v0, p2, :cond_1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/dm;->OooO00o(I)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    move-result v1

    if-eqz v1, :cond_0

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v4, "AnimationVector cannot contain a NaN. "

    invoke-direct {v1, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v4, ". Animation: "

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v4, ", playTimeNanos: "

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/w07;->OooO0O0(Ljava/lang/String;)V

    :cond_0
    add-int/lit8 v0, v0, 0x1

    goto :goto_0

    :cond_1
    iget-object p2, p0, Llyiahf/vczjk/fg9;->OooO0O0:Llyiahf/vczjk/m1a;

    check-cast p2, Llyiahf/vczjk/n1a;

    iget-object p2, p2, Llyiahf/vczjk/n1a;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {p2, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/fg9;->OooO0OO:Ljava/lang/Object;

    return-object p1
.end method

.method public final OooO0oO()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0OO:Ljava/lang/Object;

    return-object v0
.end method

.method public final OooO0oo(Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0Oo:Ljava/lang/Object;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO0Oo:Ljava/lang/Object;

    iget-object v0, p0, Llyiahf/vczjk/fg9;->OooO0O0:Llyiahf/vczjk/m1a;

    check-cast v0, Llyiahf/vczjk/n1a;

    iget-object v0, v0, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/dm;

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO0o0:Llyiahf/vczjk/dm;

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/fg9;->OooO:Llyiahf/vczjk/dm;

    const-wide/16 v0, -0x1

    iput-wide v0, p0, Llyiahf/vczjk/fg9;->OooO0oo:J

    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "TargetBasedAnimation: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO0Oo:Ljava/lang/Object;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " -> "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO0OO:Ljava/lang/Object;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ",initial velocity: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO0oO:Llyiahf/vczjk/dm;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", duration: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-interface {p0}, Llyiahf/vczjk/yk;->OooO0O0()J

    move-result-wide v1

    const-wide/32 v3, 0xf4240

    div-long/2addr v1, v3

    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    const-string v1, " ms,animationSpec: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/fg9;->OooO00o:Llyiahf/vczjk/yda;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
