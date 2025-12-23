.class public final Llyiahf/vczjk/fk;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tv7;

.field public final OooO0O0:Llyiahf/vczjk/p13;

.field public OooO0OO:J

.field public OooO0Oo:Llyiahf/vczjk/f62;

.field public OooO0o:Llyiahf/vczjk/gi;

.field public OooO0o0:Llyiahf/vczjk/gi;

.field public OooO0oO:Llyiahf/vczjk/gi;

.field public OooO0oo:Llyiahf/vczjk/gi;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tv7;Llyiahf/vczjk/p13;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fk;->OooO00o:Llyiahf/vczjk/tv7;

    iput-object p2, p0, Llyiahf/vczjk/fk;->OooO0O0:Llyiahf/vczjk/p13;

    const-wide/16 p1, 0x0

    iput-wide p1, p0, Llyiahf/vczjk/fk;->OooO0OO:J

    new-instance p1, Llyiahf/vczjk/i62;

    const/4 p2, 0x0

    invoke-direct {p1, p2, p2}, Llyiahf/vczjk/i62;-><init>(FF)V

    iput-object p1, p0, Llyiahf/vczjk/fk;->OooO0Oo:Llyiahf/vczjk/f62;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/fk;)F
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/fk;->OooO0OO:J

    iget-object v2, p0, Llyiahf/vczjk/fk;->OooO0Oo:Llyiahf/vczjk/f62;

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO0oo:Llyiahf/vczjk/gi;

    if-nez v3, :cond_0

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO00o:Llyiahf/vczjk/tv7;

    iget-object v3, v3, Llyiahf/vczjk/ir1;->OooOOOO:Llyiahf/vczjk/lr1;

    invoke-interface {v3, v0, v1, v2}, Llyiahf/vczjk/lr1;->OooO00o(JLlyiahf/vczjk/f62;)F

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/fk;->OooO0oo:Llyiahf/vczjk/gi;

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Number;

    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    move-result p0

    return p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/fk;)F
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/fk;->OooO0OO:J

    iget-object v2, p0, Llyiahf/vczjk/fk;->OooO0Oo:Llyiahf/vczjk/f62;

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO0oO:Llyiahf/vczjk/gi;

    if-nez v3, :cond_0

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO00o:Llyiahf/vczjk/tv7;

    iget-object v3, v3, Llyiahf/vczjk/ir1;->OooOOOo:Llyiahf/vczjk/lr1;

    invoke-interface {v3, v0, v1, v2}, Llyiahf/vczjk/lr1;->OooO00o(JLlyiahf/vczjk/f62;)F

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/fk;->OooO0oO:Llyiahf/vczjk/gi;

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Number;

    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    move-result p0

    return p0
.end method

.method public static OooO0OO(Llyiahf/vczjk/fk;)F
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/fk;->OooO0OO:J

    iget-object v2, p0, Llyiahf/vczjk/fk;->OooO0Oo:Llyiahf/vczjk/f62;

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO0o:Llyiahf/vczjk/gi;

    if-nez v3, :cond_0

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO00o:Llyiahf/vczjk/tv7;

    iget-object v3, v3, Llyiahf/vczjk/ir1;->OooOOO:Llyiahf/vczjk/lr1;

    invoke-interface {v3, v0, v1, v2}, Llyiahf/vczjk/lr1;->OooO00o(JLlyiahf/vczjk/f62;)F

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/fk;->OooO0o:Llyiahf/vczjk/gi;

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Number;

    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    move-result p0

    return p0
.end method

.method public static OooO0Oo(Llyiahf/vczjk/fk;)F
    .locals 4

    iget-wide v0, p0, Llyiahf/vczjk/fk;->OooO0OO:J

    iget-object v2, p0, Llyiahf/vczjk/fk;->OooO0Oo:Llyiahf/vczjk/f62;

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO0o0:Llyiahf/vczjk/gi;

    if-nez v3, :cond_0

    iget-object v3, p0, Llyiahf/vczjk/fk;->OooO00o:Llyiahf/vczjk/tv7;

    iget-object v3, v3, Llyiahf/vczjk/ir1;->OooOOO0:Llyiahf/vczjk/lr1;

    invoke-interface {v3, v0, v1, v2}, Llyiahf/vczjk/lr1;->OooO00o(JLlyiahf/vczjk/f62;)F

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/fk;->OooO0o0:Llyiahf/vczjk/gi;

    :cond_0
    invoke-virtual {v3}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/Number;

    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    move-result p0

    return p0
.end method
