.class public final Llyiahf/vczjk/hw2;
.super Llyiahf/vczjk/jw2;
.source "SourceFile"


# instance fields
.field public final OooO0O0:J

.field public final OooO0OO:J

.field public final OooO0Oo:Z


# direct methods
.method public constructor <init>(Ljava/util/List;JJZ)V
    .locals 1

    const-string v0, "cubics"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1}, Llyiahf/vczjk/jw2;-><init>(Ljava/util/List;)V

    iput-wide p2, p0, Llyiahf/vczjk/hw2;->OooO0O0:J

    iput-wide p4, p0, Llyiahf/vczjk/hw2;->OooO0OO:J

    iput-boolean p6, p0, Llyiahf/vczjk/hw2;->OooO0Oo:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/jw2;
    .locals 11

    invoke-static {}, Llyiahf/vczjk/r02;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/jw2;->OooO00o:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->size()I

    move-result v2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    invoke-interface {v1, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/bu1;

    invoke-virtual {v4, p1}, Llyiahf/vczjk/bu1;->OooO0o0(Llyiahf/vczjk/dy6;)Llyiahf/vczjk/jr5;

    move-result-object v4

    invoke-virtual {v0, v4}, Llyiahf/vczjk/y05;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/y05;->OooOOO0()Llyiahf/vczjk/y05;

    move-result-object v5

    iget-wide v0, p0, Llyiahf/vczjk/hw2;->OooO0O0:J

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/rl6;->OooOooO(JLlyiahf/vczjk/dy6;)J

    move-result-wide v6

    iget-wide v0, p0, Llyiahf/vczjk/hw2;->OooO0OO:J

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/rl6;->OooOooO(JLlyiahf/vczjk/dy6;)J

    move-result-wide v8

    new-instance v4, Llyiahf/vczjk/hw2;

    iget-boolean v10, p0, Llyiahf/vczjk/hw2;->OooO0Oo:Z

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/hw2;-><init>(Ljava/util/List;JJZ)V

    return-object v4
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Corner: vertex="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-wide v1, p0, Llyiahf/vczjk/hw2;->OooO0O0:J

    invoke-static {v1, v2}, Llyiahf/vczjk/v23;->OooO0O0(J)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", center="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-wide v1, p0, Llyiahf/vczjk/hw2;->OooO0OO:J

    invoke-static {v1, v2}, Llyiahf/vczjk/v23;->OooO0O0(J)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", convex="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v1, p0, Llyiahf/vczjk/hw2;->OooO0Oo:Z

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
