.class public abstract Llyiahf/vczjk/q65;
.super Llyiahf/vczjk/o65;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ef5;


# instance fields
.field public OooOoO:J

.field public final OooOoO0:Llyiahf/vczjk/v16;

.field public OooOoOO:Ljava/util/LinkedHashMap;

.field public OooOoo:Llyiahf/vczjk/mf5;

.field public final OooOoo0:Llyiahf/vczjk/r65;

.field public final OooOooO:Llyiahf/vczjk/zr5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v16;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/o65;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    const-wide/16 v0, 0x0

    iput-wide v0, p0, Llyiahf/vczjk/q65;->OooOoO:J

    new-instance p1, Llyiahf/vczjk/r65;

    invoke-direct {p1, p0}, Llyiahf/vczjk/r65;-><init>(Llyiahf/vczjk/q65;)V

    iput-object p1, p0, Llyiahf/vczjk/q65;->OooOoo0:Llyiahf/vczjk/r65;

    sget-object p1, Llyiahf/vczjk/a76;->OooO00o:Llyiahf/vczjk/zr5;

    new-instance p1, Llyiahf/vczjk/zr5;

    invoke-direct {p1}, Llyiahf/vczjk/zr5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q65;->OooOooO:Llyiahf/vczjk/zr5;

    return-void
.end method

.method public static final o00000OO(Llyiahf/vczjk/q65;Llyiahf/vczjk/mf5;)V
    .locals 6

    if-eqz p1, :cond_0

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getWidth()I

    move-result v0

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->getHeight()I

    move-result v1

    int-to-long v2, v0

    const/16 v0, 0x20

    shl-long/2addr v2, v0

    int-to-long v0, v1

    const-wide v4, 0xffffffffL

    and-long/2addr v0, v4

    or-long/2addr v0, v2

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/ow6;->o00O0O(J)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-nez v0, :cond_1

    const-wide/16 v0, 0x0

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/ow6;->o00O0O(J)V

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoo:Llyiahf/vczjk/mf5;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_5

    if-eqz p1, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoOO:Ljava/util/LinkedHashMap;

    if-eqz v0, :cond_2

    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_3

    :cond_2
    invoke-interface {p1}, Llyiahf/vczjk/mf5;->OooO00o()Ljava/util/Map;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_5

    :cond_3
    invoke-interface {p1}, Llyiahf/vczjk/mf5;->OooO00o()Ljava/util/Map;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/q65;->OooOoOO:Ljava/util/LinkedHashMap;

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v0, v0, Llyiahf/vczjk/w65;->OooOooo:Llyiahf/vczjk/so4;

    invoke-virtual {v0}, Llyiahf/vczjk/v4;->OooO0oO()V

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoOO:Ljava/util/LinkedHashMap;

    if-nez v0, :cond_4

    new-instance v0, Ljava/util/LinkedHashMap;

    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/q65;->OooOoOO:Ljava/util/LinkedHashMap;

    :cond_4
    invoke-interface {v0}, Ljava/util/Map;->clear()V

    invoke-interface {p1}, Llyiahf/vczjk/mf5;->OooO00o()Ljava/util/Map;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    :cond_5
    iput-object p1, p0, Llyiahf/vczjk/q65;->OooOoo:Llyiahf/vczjk/mf5;

    return-void
.end method


# virtual methods
.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final OooOoo()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->OooOoo()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OoooOo0()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final getLayoutDirection()Llyiahf/vczjk/yn4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0o0:Llyiahf/vczjk/yn4;

    return-object v0
.end method

.method public final o000000()Llyiahf/vczjk/mf5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoo:Llyiahf/vczjk/mf5;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "LookaheadDelegate has not been measured yet when measureResult is requested."

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOOOo(Ljava/lang/String;)Llyiahf/vczjk/k61;

    move-result-object v0

    throw v0
.end method

.method public final o000000O()Llyiahf/vczjk/o65;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final o000000o()J
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/q65;->OooOoO:J

    return-wide v0
.end method

.method public final o00000O()V
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/q65;->OooOoO:J

    const/4 v2, 0x0

    const/4 v3, 0x0

    invoke-virtual {p0, v0, v1, v2, v3}, Llyiahf/vczjk/q65;->o0OoOo0(JFLlyiahf/vczjk/oe3;)V

    return-void
.end method

.method public o00000Oo()V
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/q65;->o000000()Llyiahf/vczjk/mf5;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/mf5;->OooO0O0()V

    return-void
.end method

.method public final o00000o0(J)V
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/q65;->OooOoO:J

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/u14;->OooO0O0(JJ)Z

    move-result v0

    if-nez v0, :cond_1

    iput-wide p1, p0, Llyiahf/vczjk/q65;->OooOoO:J

    iget-object p1, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object p2, p1, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    iget-object p2, p2, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object p2, p2, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz p2, :cond_0

    invoke-virtual {p2}, Llyiahf/vczjk/w65;->o0OOO0o()V

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/o65;->o00000(Llyiahf/vczjk/v16;)V

    :cond_1
    iget-boolean p1, p0, Llyiahf/vczjk/o65;->OooOo00:Z

    if-nez p1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/q65;->o000000()Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/o65;->o0Oo0oo(Llyiahf/vczjk/mf5;)V

    :cond_2
    return-void
.end method

.method public final o0000Ooo(Llyiahf/vczjk/q65;Z)J
    .locals 5

    const-wide/16 v0, 0x0

    move-object v2, p0

    :goto_0
    invoke-virtual {v2, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v3

    if-nez v3, :cond_2

    iget-boolean v3, v2, Llyiahf/vczjk/o65;->OooOOo:Z

    if-eqz v3, :cond_0

    if-nez p2, :cond_1

    :cond_0
    iget-wide v3, v2, Llyiahf/vczjk/q65;->OooOoO:J

    invoke-static {v0, v1, v3, v4}, Llyiahf/vczjk/u14;->OooO0Oo(JJ)J

    move-result-wide v0

    :cond_1
    iget-object v2, v2, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v2, v2, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v2}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v2

    invoke-static {v2}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    return-wide v0
.end method

.method public final o000OOo()Llyiahf/vczjk/ro4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    return-object v0
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o000oOoO()F

    move-result v0

    return v0
.end method

.method public final o0O0O00()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoo:Llyiahf/vczjk/mf5;

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method

.method public final o0OO00O()Llyiahf/vczjk/o65;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v0

    return-object v0

    :cond_0
    const/4 v0, 0x0

    return-object v0
.end method

.method public final o0OoOo0(JFLlyiahf/vczjk/oe3;)V
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/q65;->o00000o0(J)V

    iget-boolean p1, p0, Llyiahf/vczjk/o65;->OooOOoo:Z

    if-eqz p1, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/q65;->o00000Oo()V

    return-void
.end method

.method public final oo0o0Oo()Llyiahf/vczjk/xn4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/q65;->OooOoo0:Llyiahf/vczjk/r65;

    return-object v0
.end method
