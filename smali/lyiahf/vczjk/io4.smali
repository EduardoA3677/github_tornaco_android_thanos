.class public final Llyiahf/vczjk/io4;
.super Llyiahf/vczjk/v16;
.source "SourceFile"


# static fields
.field public static final Ooooo00:Llyiahf/vczjk/ie;


# instance fields
.field public OoooOoO:Llyiahf/vczjk/go4;

.field public OoooOoo:Llyiahf/vczjk/ho4;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    invoke-static {}, Llyiahf/vczjk/c6a;->OooOOoo()Llyiahf/vczjk/ie;

    move-result-object v0

    sget v1, Llyiahf/vczjk/n21;->OooOO0O:I

    sget-wide v1, Llyiahf/vczjk/n21;->OooO0oo:J

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/ie;->OooOOOo(J)V

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ie;->OooOo0O(F)V

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/ie;->OooOo0o(I)V

    sput-object v0, Llyiahf/vczjk/io4;->Ooooo00:Llyiahf/vczjk/ie;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ro4;Llyiahf/vczjk/go4;)V
    .locals 1

    invoke-direct {p0, p1}, Llyiahf/vczjk/v16;-><init>(Llyiahf/vczjk/ro4;)V

    iput-object p2, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    iget-object p1, p1, Llyiahf/vczjk/ro4;->OooOo00:Llyiahf/vczjk/ro4;

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    new-instance v0, Llyiahf/vczjk/ho4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ho4;-><init>(Llyiahf/vczjk/io4;)V

    :cond_0
    iput-object v0, p0, Llyiahf/vczjk/io4;->OoooOoo:Llyiahf/vczjk/ho4;

    check-cast p2, Llyiahf/vczjk/jl5;

    iget-object p1, p2, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget p1, p1, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 p1, p1, 0x200

    if-nez p1, :cond_1

    return-void

    :cond_1
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1
.end method


# virtual methods
.method public final OooO0OO(I)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    iget-object v1, p0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0, p0, v1, p1}, Llyiahf/vczjk/go4;->OooOooO(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I

    move-result p1

    return p1
.end method

.method public final OooOo0(I)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    iget-object v1, p0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0, p0, v1, p1}, Llyiahf/vczjk/go4;->OoooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I

    move-result p1

    return p1
.end method

.method public final OooOo0o(I)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    iget-object v1, p0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0, p0, v1, p1}, Llyiahf/vczjk/go4;->o0OoOo0(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I

    move-result p1

    return p1
.end method

.method public final OooOoOO(J)Llyiahf/vczjk/ow6;
    .locals 2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ow6;->oo000o(J)V

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    iget-object v1, p0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0, p0, v1, p1, p2}, Llyiahf/vczjk/go4;->OooO00o(Llyiahf/vczjk/nf5;Llyiahf/vczjk/ef5;J)Llyiahf/vczjk/mf5;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/v16;->o000(Llyiahf/vczjk/mf5;)V

    invoke-virtual {p0}, Llyiahf/vczjk/v16;->o0000o()V

    return-object p0
.end method

.method public final OooooO0(I)I
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    iget-object v1, p0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0, p0, v1, p1}, Llyiahf/vczjk/go4;->OooOo00(Llyiahf/vczjk/o65;Llyiahf/vczjk/ef5;I)I

    move-result p1

    return p1
.end method

.method public final o0000()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoo:Llyiahf/vczjk/ho4;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/ho4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ho4;-><init>(Llyiahf/vczjk/io4;)V

    iput-object v0, p0, Llyiahf/vczjk/io4;->OoooOoo:Llyiahf/vczjk/ho4;

    :cond_0
    return-void
.end method

.method public final o0000O0()Llyiahf/vczjk/q65;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoo:Llyiahf/vczjk/ho4;

    return-object v0
.end method

.method public final o0000oOo(Llyiahf/vczjk/eq0;Llyiahf/vczjk/kj3;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/v16;->o00000oO(Llyiahf/vczjk/eq0;Llyiahf/vczjk/kj3;)V

    iget-object p2, p0, Llyiahf/vczjk/v16;->OooOoO0:Llyiahf/vczjk/ro4;

    invoke-static {p2}, Llyiahf/vczjk/uo4;->OooO00o(Llyiahf/vczjk/ro4;)Llyiahf/vczjk/tg6;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/xa;

    invoke-virtual {p2}, Llyiahf/vczjk/xa;->getShowLayoutBounds()Z

    move-result p2

    if-eqz p2, :cond_0

    iget-wide v0, p0, Llyiahf/vczjk/ow6;->OooOOOO:J

    const/16 p2, 0x20

    shr-long v2, v0, p2

    long-to-int p2, v2

    int-to-float p2, p2

    const/high16 v2, 0x3f000000    # 0.5f

    sub-float v6, p2, v2

    const-wide v3, 0xffffffffL

    and-long/2addr v0, v3

    long-to-int p2, v0

    int-to-float p2, p2

    sub-float v7, p2, v2

    const/high16 v4, 0x3f000000    # 0.5f

    const/high16 v5, 0x3f000000    # 0.5f

    sget-object v8, Llyiahf/vczjk/io4;->Ooooo00:Llyiahf/vczjk/ie;

    move-object v3, p1

    invoke-interface/range {v3 .. v8}, Llyiahf/vczjk/eq0;->OooO0o(FFFFLlyiahf/vczjk/ie;)V

    :cond_0
    return-void
.end method

.method public final o000O00()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/o65;->OooOOoo:Z

    if-eqz v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/v16;->o0000oO0()V

    invoke-virtual {p0}, Llyiahf/vczjk/v16;->o000000()Llyiahf/vczjk/mf5;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/mf5;->OooO0O0()V

    iget-object v0, p0, Llyiahf/vczjk/v16;->OooOoO:Llyiahf/vczjk/v16;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-void
.end method

.method public final o000O00O(Llyiahf/vczjk/go4;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    invoke-virtual {p1, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget v0, v0, Llyiahf/vczjk/jl5;->OooOOOO:I

    and-int/lit16 v0, v0, 0x200

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :cond_1
    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    return-void
.end method

.method public final o000OO()Llyiahf/vczjk/jl5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoO:Llyiahf/vczjk/go4;

    check-cast v0, Llyiahf/vczjk/jl5;

    iget-object v0, v0, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    return-object v0
.end method

.method public final o0OoOo0(JFLlyiahf/vczjk/oe3;)V
    .locals 6

    const/4 v5, 0x0

    move-object v0, p0

    move-wide v1, p1

    move v3, p3

    move-object v4, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/v16;->o0000oo0(JFLlyiahf/vczjk/oe3;Llyiahf/vczjk/kj3;)V

    invoke-virtual {p0}, Llyiahf/vczjk/io4;->o000O00()V

    return-void
.end method

.method public final o0ooOoO(Llyiahf/vczjk/p4;)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/io4;->OoooOoo:Llyiahf/vczjk/ho4;

    if-eqz v0, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/q65;->OooOooO:Llyiahf/vczjk/zr5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zr5;->OooO0Oo(Ljava/lang/Object;)I

    move-result p1

    if-ltz p1, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/zr5;->OooO0OO:[I

    aget p1, v0, p1

    return p1

    :cond_0
    const/high16 p1, -0x80000000

    return p1

    :cond_1
    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOOo(Llyiahf/vczjk/o65;Llyiahf/vczjk/p4;)I

    move-result p1

    return p1
.end method

.method public final ooOO(JFLlyiahf/vczjk/kj3;)V
    .locals 6

    const/4 v4, 0x0

    move-object v0, p0

    move-wide v1, p1

    move v3, p3

    move-object v5, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/v16;->o0000oo0(JFLlyiahf/vczjk/oe3;Llyiahf/vczjk/kj3;)V

    invoke-virtual {p0}, Llyiahf/vczjk/io4;->o000O00()V

    return-void
.end method
