.class public abstract Llyiahf/vczjk/ch0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/js5;

.field public static final OooO0O0:Llyiahf/vczjk/js5;

.field public static final OooO0OO:Llyiahf/vczjk/wc;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    const/4 v0, 0x1

    invoke-static {v0}, Llyiahf/vczjk/ch0;->OooO0OO(Z)Llyiahf/vczjk/js5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ch0;->OooO00o:Llyiahf/vczjk/js5;

    const/4 v0, 0x0

    invoke-static {v0}, Llyiahf/vczjk/ch0;->OooO0OO(Z)Llyiahf/vczjk/js5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/ch0;->OooO0O0:Llyiahf/vczjk/js5;

    sget-object v0, Llyiahf/vczjk/wc;->OooO0oO:Llyiahf/vczjk/wc;

    sput-object v0, Llyiahf/vczjk/ch0;->OooO0OO:Llyiahf/vczjk/wc;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kl5;Llyiahf/vczjk/rf1;I)V
    .locals 6

    check-cast p1, Llyiahf/vczjk/zf1;

    const v0, -0xc96ce69

    invoke-virtual {p1, v0}, Llyiahf/vczjk/zf1;->o000oOoO(I)Llyiahf/vczjk/zf1;

    and-int/lit8 v0, p2, 0x6

    const/4 v1, 0x2

    if-nez v0, :cond_1

    invoke-virtual {p1, p0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x4

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    or-int/2addr v0, p2

    goto :goto_1

    :cond_1
    move v0, p2

    :goto_1
    and-int/lit8 v2, v0, 0x3

    const/4 v3, 0x1

    if-eq v2, v1, :cond_2

    move v1, v3

    goto :goto_2

    :cond_2
    const/4 v1, 0x0

    :goto_2
    and-int/2addr v0, v3

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result v0

    if-eqz v0, :cond_6

    iget v0, p1, Llyiahf/vczjk/zf1;->Oooo:I

    invoke-static {p1, p0}, Llyiahf/vczjk/ng0;->Oooo(Llyiahf/vczjk/rf1;Llyiahf/vczjk/kl5;)Llyiahf/vczjk/kl5;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOO0()Llyiahf/vczjk/ps6;

    move-result-object v2

    sget-object v4, Llyiahf/vczjk/af1;->OooO0Oo:Llyiahf/vczjk/ze1;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0O0:Llyiahf/vczjk/o24;

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OoooOOo()V

    iget-boolean v5, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-eqz v5, :cond_3

    invoke-virtual {p1, v4}, Llyiahf/vczjk/zf1;->OooOO0o(Llyiahf/vczjk/le3;)V

    goto :goto_3

    :cond_3
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooooo()V

    :goto_3
    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o:Llyiahf/vczjk/ye1;

    sget-object v5, Llyiahf/vczjk/ch0;->OooO0OO:Llyiahf/vczjk/wc;

    invoke-static {v5, p1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v4, Llyiahf/vczjk/ze1;->OooO0o0:Llyiahf/vczjk/ye1;

    invoke-static {v2, p1, v4}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v2, Llyiahf/vczjk/ze1;->OooO0Oo:Llyiahf/vczjk/ye1;

    invoke-static {v1, p1, v2}, Llyiahf/vczjk/er8;->OooOo00(Ljava/lang/Object;Llyiahf/vczjk/rf1;Llyiahf/vczjk/ze3;)V

    sget-object v1, Llyiahf/vczjk/ze1;->OooO0oO:Llyiahf/vczjk/ye1;

    iget-boolean v2, p1, Llyiahf/vczjk/zf1;->Oooo0oo:Z

    if-nez v2, :cond_4

    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v2

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    invoke-static {v2, v4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v2

    if-nez v2, :cond_5

    :cond_4
    invoke-static {v0, p1, v0, v1}, Llyiahf/vczjk/ix8;->OooOo00(ILlyiahf/vczjk/zf1;ILlyiahf/vczjk/ye1;)V

    :cond_5
    invoke-virtual {p1, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_4
    invoke-virtual {p1}, Llyiahf/vczjk/zf1;->OooOOo()Llyiahf/vczjk/aj7;

    move-result-object p1

    if-eqz p1, :cond_7

    new-instance v0, Llyiahf/vczjk/bh0;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/bh0;-><init>(Llyiahf/vczjk/kl5;I)V

    iput-object v0, p1, Llyiahf/vczjk/aj7;->OooO0Oo:Llyiahf/vczjk/ze3;

    :cond_7
    return-void
.end method

.method public static final OooO0O0(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ef5;Llyiahf/vczjk/yn4;IILlyiahf/vczjk/o4;)V
    .locals 7

    invoke-interface {p2}, Llyiahf/vczjk/ef5;->OooOoo()Ljava/lang/Object;

    move-result-object p2

    instance-of v0, p2, Llyiahf/vczjk/ah0;

    if-eqz v0, :cond_0

    check-cast p2, Llyiahf/vczjk/ah0;

    goto :goto_0

    :cond_0
    const/4 p2, 0x0

    :goto_0
    if-eqz p2, :cond_2

    iget-object p2, p2, Llyiahf/vczjk/ah0;->OooOoOO:Llyiahf/vczjk/o4;

    if-nez p2, :cond_1

    goto :goto_1

    :cond_1
    move-object v0, p2

    goto :goto_2

    :cond_2
    :goto_1
    move-object v0, p6

    :goto_2
    iget p2, p1, Llyiahf/vczjk/ow6;->OooOOO0:I

    iget p6, p1, Llyiahf/vczjk/ow6;->OooOOO:I

    int-to-long v1, p2

    const/16 p2, 0x20

    shl-long/2addr v1, p2

    int-to-long v3, p6

    const-wide v5, 0xffffffffL

    and-long/2addr v3, v5

    or-long/2addr v1, v3

    int-to-long v3, p4

    shl-long/2addr v3, p2

    int-to-long p4, p5

    and-long/2addr p4, v5

    or-long/2addr v3, p4

    move-object v5, p3

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/o4;->OooO00o(JJLlyiahf/vczjk/yn4;)J

    move-result-wide p2

    invoke-static {p0, p1, p2, p3}, Llyiahf/vczjk/nw6;->OooO0oO(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;J)V

    return-void
.end method

.method public static final OooO0OO(Z)Llyiahf/vczjk/js5;
    .locals 3

    new-instance v0, Llyiahf/vczjk/js5;

    const/16 v1, 0x9

    invoke-direct {v0, v1}, Llyiahf/vczjk/js5;-><init>(I)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOOO:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOOOO:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOOOo:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOOo0:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOOo:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOOoo:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOo00:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOo0:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/op3;->OooOo0O:Llyiahf/vczjk/ub0;

    new-instance v2, Llyiahf/vczjk/fh0;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/js5;->OooOO0o(Ljava/lang/Object;Ljava/lang/Object;)V

    return-object v0
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/o4;Z)Llyiahf/vczjk/lf5;
    .locals 1

    if-eqz p1, :cond_0

    sget-object v0, Llyiahf/vczjk/ch0;->OooO00o:Llyiahf/vczjk/js5;

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/ch0;->OooO0O0:Llyiahf/vczjk/js5;

    :goto_0
    invoke-virtual {v0, p0}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/lf5;

    if-nez v0, :cond_1

    new-instance v0, Llyiahf/vczjk/fh0;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/fh0;-><init>(Llyiahf/vczjk/o4;Z)V

    :cond_1
    return-object v0
.end method
