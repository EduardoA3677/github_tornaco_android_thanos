.class public final Llyiahf/vczjk/fk3;
.super Llyiahf/vczjk/yba;
.source "SourceFile"


# instance fields
.field public OooO:Llyiahf/vczjk/rm4;

.field public OooO0O0:[F

.field public final OooO0OO:Ljava/util/ArrayList;

.field public OooO0Oo:Z

.field public OooO0o:Ljava/util/List;

.field public OooO0o0:J

.field public OooO0oO:Z

.field public OooO0oo:Llyiahf/vczjk/qe;

.field public final OooOO0:Llyiahf/vczjk/ek3;

.field public OooOO0O:Ljava/lang/String;

.field public OooOO0o:F

.field public OooOOO:F

.field public OooOOO0:F

.field public OooOOOO:F

.field public OooOOOo:F

.field public OooOOo:F

.field public OooOOo0:F

.field public OooOOoo:Z


# direct methods
.method public constructor <init>()V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/fk3;->OooO0OO:Ljava/util/ArrayList;

    const/4 v0, 0x1

    iput-boolean v0, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    sget-wide v1, Llyiahf/vczjk/n21;->OooOO0:J

    iput-wide v1, p0, Llyiahf/vczjk/fk3;->OooO0o0:J

    sget v1, Llyiahf/vczjk/tda;->OooO00o:I

    sget-object v1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    iput-object v1, p0, Llyiahf/vczjk/fk3;->OooO0o:Ljava/util/List;

    iput-boolean v0, p0, Llyiahf/vczjk/fk3;->OooO0oO:Z

    new-instance v1, Llyiahf/vczjk/ek3;

    invoke-direct {v1, p0}, Llyiahf/vczjk/ek3;-><init>(Llyiahf/vczjk/fk3;)V

    iput-object v1, p0, Llyiahf/vczjk/fk3;->OooOO0:Llyiahf/vczjk/ek3;

    const-string v1, ""

    iput-object v1, p0, Llyiahf/vczjk/fk3;->OooOO0O:Ljava/lang/String;

    const/high16 v1, 0x3f800000    # 1.0f

    iput v1, p0, Llyiahf/vczjk/fk3;->OooOOOO:F

    iput v1, p0, Llyiahf/vczjk/fk3;->OooOOOo:F

    iput-boolean v0, p0, Llyiahf/vczjk/fk3;->OooOOoo:Z

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/hg2;)V
    .locals 7

    iget-boolean v0, p0, Llyiahf/vczjk/fk3;->OooOOoo:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/fk3;->OooO0O0:[F

    if-nez v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/ze5;->OooO00o()[F

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fk3;->OooO0O0:[F

    goto :goto_0

    :cond_0
    invoke-static {v0}, Llyiahf/vczjk/ze5;->OooO0Oo([F)V

    :goto_0
    iget v2, p0, Llyiahf/vczjk/fk3;->OooOOo0:F

    iget v3, p0, Llyiahf/vczjk/fk3;->OooOOO0:F

    add-float/2addr v2, v3

    iget v3, p0, Llyiahf/vczjk/fk3;->OooOOo:F

    iget v4, p0, Llyiahf/vczjk/fk3;->OooOOO:F

    add-float/2addr v3, v4

    invoke-static {v0, v2, v3}, Llyiahf/vczjk/ze5;->OooO([FFF)V

    iget v2, p0, Llyiahf/vczjk/fk3;->OooOO0o:F

    invoke-static {v2, v0}, Llyiahf/vczjk/ze5;->OooO0o0(F[F)V

    iget v2, p0, Llyiahf/vczjk/fk3;->OooOOOO:F

    iget v3, p0, Llyiahf/vczjk/fk3;->OooOOOo:F

    invoke-static {v0, v2, v3}, Llyiahf/vczjk/ze5;->OooO0o([FFF)V

    iget v2, p0, Llyiahf/vczjk/fk3;->OooOOO0:F

    neg-float v2, v2

    iget v3, p0, Llyiahf/vczjk/fk3;->OooOOO:F

    neg-float v3, v3

    invoke-static {v0, v2, v3}, Llyiahf/vczjk/ze5;->OooO([FFF)V

    iput-boolean v1, p0, Llyiahf/vczjk/fk3;->OooOOoo:Z

    :cond_1
    iget-boolean v0, p0, Llyiahf/vczjk/fk3;->OooO0oO:Z

    if-eqz v0, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/fk3;->OooO0o:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_3

    iget-object v0, p0, Llyiahf/vczjk/fk3;->OooO0oo:Llyiahf/vczjk/qe;

    if-nez v0, :cond_2

    invoke-static {}, Llyiahf/vczjk/se;->OooO00o()Llyiahf/vczjk/qe;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/fk3;->OooO0oo:Llyiahf/vczjk/qe;

    :cond_2
    iget-object v2, p0, Llyiahf/vczjk/fk3;->OooO0o:Ljava/util/List;

    invoke-static {v2, v0}, Llyiahf/vczjk/dr6;->OooOoO0(Ljava/util/List;Llyiahf/vczjk/bq6;)V

    :cond_3
    iput-boolean v1, p0, Llyiahf/vczjk/fk3;->OooO0oO:Z

    :cond_4
    invoke-interface {p1}, Llyiahf/vczjk/hg2;->Ooooo0o()Llyiahf/vczjk/uqa;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v2

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v4

    invoke-interface {v4}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v4, v0, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/vz5;

    iget-object v5, p0, Llyiahf/vczjk/fk3;->OooO0O0:[F
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v4, v4, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/uqa;

    if-eqz v5, :cond_5

    :try_start_1
    invoke-virtual {v4}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v6

    invoke-interface {v6, v5}, Llyiahf/vczjk/eq0;->OooO([F)V

    :cond_5
    iget-object v5, p0, Llyiahf/vczjk/fk3;->OooO0oo:Llyiahf/vczjk/qe;

    iget-object v6, p0, Llyiahf/vczjk/fk3;->OooO0o:Ljava/util/List;

    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    move-result v6

    if-nez v6, :cond_6

    if-eqz v5, :cond_6

    invoke-virtual {v4}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v4

    invoke-interface {v4, v5}, Llyiahf/vczjk/eq0;->OooOOO0(Llyiahf/vczjk/bq6;)V

    :cond_6
    iget-object v4, p0, Llyiahf/vczjk/fk3;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    move-result v5

    :goto_1
    if-ge v1, v5, :cond_7

    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/yba;

    invoke-virtual {v6, p1}, Llyiahf/vczjk/yba;->OooO00o(Llyiahf/vczjk/hg2;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    add-int/lit8 v1, v1, 0x1

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_7
    invoke-static {v0, v2, v3}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    return-void

    :goto_2
    invoke-static {v0, v2, v3}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw p1
.end method

.method public final OooO0O0()Llyiahf/vczjk/oe3;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fk3;->OooO:Llyiahf/vczjk/rm4;

    return-object v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/ek3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fk3;->OooO:Llyiahf/vczjk/rm4;

    return-void
.end method

.method public final OooO0o(J)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    const-wide/16 v0, 0x10

    cmp-long v2, p1, v0

    if-eqz v2, :cond_3

    iget-wide v2, p0, Llyiahf/vczjk/fk3;->OooO0o0:J

    cmp-long v0, v2, v0

    if-nez v0, :cond_1

    iput-wide p1, p0, Llyiahf/vczjk/fk3;->OooO0o0:J

    return-void

    :cond_1
    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    invoke-static {v2, v3}, Llyiahf/vczjk/n21;->OooO0oo(J)F

    move-result v0

    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0oo(J)F

    move-result v1

    cmpg-float v0, v0, v1

    if-nez v0, :cond_2

    invoke-static {v2, v3}, Llyiahf/vczjk/n21;->OooO0oO(J)F

    move-result v0

    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0oO(J)F

    move-result v1

    cmpg-float v0, v0, v1

    if-nez v0, :cond_2

    invoke-static {v2, v3}, Llyiahf/vczjk/n21;->OooO0o0(J)F

    move-result v0

    invoke-static {p1, p2}, Llyiahf/vczjk/n21;->OooO0o0(J)F

    move-result p1

    cmpg-float p1, v0, p1

    if-nez p1, :cond_2

    goto :goto_0

    :cond_2
    const/4 p1, 0x0

    iput-boolean p1, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    sget-wide p1, Llyiahf/vczjk/n21;->OooOO0:J

    iput-wide p1, p0, Llyiahf/vczjk/fk3;->OooO0o0:J

    :cond_3
    :goto_0
    return-void
.end method

.method public final OooO0o0(ILlyiahf/vczjk/yba;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fk3;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    move-result v1

    if-ge p1, v1, :cond_0

    invoke-virtual {v0, p1, p2}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_0
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    :goto_0
    invoke-virtual {p0, p2}, Llyiahf/vczjk/fk3;->OooO0oO(Llyiahf/vczjk/yba;)V

    iget-object p1, p0, Llyiahf/vczjk/fk3;->OooOO0:Llyiahf/vczjk/ek3;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/yba;->OooO0Oo(Llyiahf/vczjk/ek3;)V

    invoke-virtual {p0}, Llyiahf/vczjk/yba;->OooO0OO()V

    return-void
.end method

.method public final OooO0oO(Llyiahf/vczjk/yba;)V
    .locals 4

    instance-of v0, p1, Llyiahf/vczjk/cq6;

    const/4 v1, 0x0

    if-eqz v0, :cond_5

    check-cast p1, Llyiahf/vczjk/cq6;

    iget-object v0, p1, Llyiahf/vczjk/cq6;->OooO0O0:Llyiahf/vczjk/ri0;

    iget-boolean v2, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    if-nez v2, :cond_0

    goto :goto_0

    :cond_0
    if-eqz v0, :cond_2

    instance-of v2, v0, Llyiahf/vczjk/gx8;

    if-eqz v2, :cond_1

    check-cast v0, Llyiahf/vczjk/gx8;

    iget-wide v2, v0, Llyiahf/vczjk/gx8;->OooO00o:J

    invoke-virtual {p0, v2, v3}, Llyiahf/vczjk/fk3;->OooO0o(J)V

    goto :goto_0

    :cond_1
    iput-boolean v1, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    sget-wide v2, Llyiahf/vczjk/n21;->OooOO0:J

    iput-wide v2, p0, Llyiahf/vczjk/fk3;->OooO0o0:J

    :cond_2
    :goto_0
    iget-object p1, p1, Llyiahf/vczjk/cq6;->OooO0oO:Llyiahf/vczjk/ri0;

    iget-boolean v0, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    if-nez v0, :cond_3

    goto :goto_1

    :cond_3
    if-eqz p1, :cond_7

    instance-of v0, p1, Llyiahf/vczjk/gx8;

    if-eqz v0, :cond_4

    check-cast p1, Llyiahf/vczjk/gx8;

    iget-wide v0, p1, Llyiahf/vczjk/gx8;->OooO00o:J

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/fk3;->OooO0o(J)V

    return-void

    :cond_4
    iput-boolean v1, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    sget-wide v0, Llyiahf/vczjk/n21;->OooOO0:J

    iput-wide v0, p0, Llyiahf/vczjk/fk3;->OooO0o0:J

    return-void

    :cond_5
    instance-of v0, p1, Llyiahf/vczjk/fk3;

    if-eqz v0, :cond_7

    check-cast p1, Llyiahf/vczjk/fk3;

    iget-boolean v0, p1, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    if-eqz v0, :cond_6

    iget-boolean v0, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    if-eqz v0, :cond_6

    iget-wide v0, p1, Llyiahf/vczjk/fk3;->OooO0o0:J

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/fk3;->OooO0o(J)V

    return-void

    :cond_6
    iput-boolean v1, p0, Llyiahf/vczjk/fk3;->OooO0Oo:Z

    sget-wide v0, Llyiahf/vczjk/n21;->OooOO0:J

    iput-wide v0, p0, Llyiahf/vczjk/fk3;->OooO0o0:J

    :cond_7
    :goto_1
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "VGroup: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/fk3;->OooOO0O:Ljava/lang/String;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/fk3;->OooO0OO:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v2

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v2, :cond_0

    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/yba;

    const-string v5, "\t"

    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v4}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v4, "\n"

    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
