.class public final Llyiahf/vczjk/db8;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:I

.field public OooO00o:Llyiahf/vczjk/sa8;

.field public OooO0O0:Llyiahf/vczjk/qg6;

.field public OooO0OO:Llyiahf/vczjk/o23;

.field public OooO0Oo:Llyiahf/vczjk/nf6;

.field public OooO0o:Llyiahf/vczjk/fz5;

.field public OooO0o0:Z

.field public final OooO0oO:Llyiahf/vczjk/na8;

.field public OooO0oo:Z

.field public OooOO0:Llyiahf/vczjk/v98;

.field public final OooOO0O:Llyiahf/vczjk/za8;

.field public final OooOO0o:Llyiahf/vczjk/bb8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/sa8;Llyiahf/vczjk/qg6;Llyiahf/vczjk/o23;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/fz5;Llyiahf/vczjk/na8;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    iput-object p2, p0, Llyiahf/vczjk/db8;->OooO0O0:Llyiahf/vczjk/qg6;

    iput-object p3, p0, Llyiahf/vczjk/db8;->OooO0OO:Llyiahf/vczjk/o23;

    iput-object p4, p0, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    iput-boolean p5, p0, Llyiahf/vczjk/db8;->OooO0o0:Z

    iput-object p6, p0, Llyiahf/vczjk/db8;->OooO0o:Llyiahf/vczjk/fz5;

    iput-object p7, p0, Llyiahf/vczjk/db8;->OooO0oO:Llyiahf/vczjk/na8;

    const/4 p1, 0x1

    iput p1, p0, Llyiahf/vczjk/db8;->OooO:I

    sget-object p1, Landroidx/compose/foundation/gestures/OooO0O0;->OooO00o:Llyiahf/vczjk/ba8;

    iput-object p1, p0, Llyiahf/vczjk/db8;->OooOO0:Llyiahf/vczjk/v98;

    new-instance p1, Llyiahf/vczjk/za8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/za8;-><init>(Llyiahf/vczjk/db8;)V

    iput-object p1, p0, Llyiahf/vczjk/db8;->OooOO0O:Llyiahf/vczjk/za8;

    new-instance p1, Llyiahf/vczjk/bb8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/bb8;-><init>(Llyiahf/vczjk/db8;)V

    iput-object p1, p0, Llyiahf/vczjk/db8;->OooOO0o:Llyiahf/vczjk/bb8;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/db8;Llyiahf/vczjk/v98;JI)J
    .locals 14

    move-wide/from16 v0, p2

    iget-object v2, p0, Llyiahf/vczjk/db8;->OooO0o:Llyiahf/vczjk/fz5;

    iget-object v2, v2, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    iget-boolean v4, v2, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v4, :cond_0

    invoke-static {v2}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/jz5;

    goto :goto_0

    :cond_0
    move-object v2, v3

    :goto_0
    const-wide/16 v4, 0x0

    move/from16 v7, p4

    if-eqz v2, :cond_1

    invoke-virtual {v2, v7, v0, v1}, Llyiahf/vczjk/jz5;->Oooo00O(IJ)J

    move-result-wide v8

    move-wide v12, v8

    goto :goto_1

    :cond_1
    move-wide v12, v4

    :goto_1
    invoke-static {v0, v1, v12, v13}, Llyiahf/vczjk/p86;->OooO0o0(JJ)J

    move-result-wide v0

    iget-object v2, p0, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v6, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    const/4 v8, 0x0

    if-ne v2, v6, :cond_2

    const/4 v2, 0x1

    :goto_2
    invoke-static {v0, v1, v8, v2}, Llyiahf/vczjk/p86;->OooO00o(JFI)J

    move-result-wide v8

    goto :goto_3

    :cond_2
    const/4 v2, 0x2

    goto :goto_2

    :goto_3
    invoke-virtual {p0, v8, v9}, Llyiahf/vczjk/db8;->OooO0Oo(J)J

    move-result-wide v8

    invoke-virtual {p0, v8, v9}, Llyiahf/vczjk/db8;->OooO0o(J)F

    move-result v2

    invoke-interface {p1, v2}, Llyiahf/vczjk/v98;->OooO00o(F)F

    move-result v2

    invoke-virtual {p0, v2}, Llyiahf/vczjk/db8;->OooO0oO(F)J

    move-result-wide v8

    invoke-virtual {p0, v8, v9}, Llyiahf/vczjk/db8;->OooO0Oo(J)J

    move-result-wide v8

    invoke-static {v0, v1, v8, v9}, Llyiahf/vczjk/p86;->OooO0o0(JJ)J

    move-result-wide v10

    iget-object p0, p0, Llyiahf/vczjk/db8;->OooO0o:Llyiahf/vczjk/fz5;

    iget-object p0, p0, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    if-eqz p0, :cond_3

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_3

    invoke-static {p0}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p0

    move-object v3, p0

    check-cast v3, Llyiahf/vczjk/jz5;

    :cond_3
    move-object v6, v3

    if-eqz v6, :cond_4

    invoke-virtual/range {v6 .. v11}, Llyiahf/vczjk/jz5;->Ooooooo(IJJ)J

    move-result-wide v4

    :cond_4
    invoke-static {v12, v13, v8, v9}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v0

    invoke-static {v0, v1, v4, v5}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v0

    return-wide v0
.end method


# virtual methods
.method public final OooO0O0(JLlyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 10

    instance-of v0, p3, Llyiahf/vczjk/wa8;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/wa8;

    iget v1, v0, Llyiahf/vczjk/wa8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/wa8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/wa8;

    invoke-direct {v0, p0, p3}, Llyiahf/vczjk/wa8;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/wa8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/wa8;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/wa8;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/gl7;

    iget-object p2, v0, Llyiahf/vczjk/wa8;->L$0:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/db8;

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object v5, p0

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance v6, Llyiahf/vczjk/gl7;

    invoke-direct {v6}, Ljava/lang/Object;-><init>()V

    iput-wide p1, v6, Llyiahf/vczjk/gl7;->element:J

    iput-boolean v3, p0, Llyiahf/vczjk/db8;->OooO0oo:Z

    sget-object p3, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    new-instance v4, Llyiahf/vczjk/ya8;

    const/4 v9, 0x0

    move-object v5, p0

    move-wide v7, p1

    invoke-direct/range {v4 .. v9}, Llyiahf/vczjk/ya8;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/gl7;JLlyiahf/vczjk/yo1;)V

    iput-object v5, v0, Llyiahf/vczjk/wa8;->L$0:Ljava/lang/Object;

    iput-object v6, v0, Llyiahf/vczjk/wa8;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/wa8;->label:I

    invoke-virtual {p0, p3, v4, v0}, Llyiahf/vczjk/db8;->OooO0o0(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    move-object p2, v5

    move-object p1, v6

    :goto_1
    const/4 p3, 0x0

    iput-boolean p3, p2, Llyiahf/vczjk/db8;->OooO0oo:Z

    iget-wide p1, p1, Llyiahf/vczjk/gl7;->element:J

    new-instance p3, Llyiahf/vczjk/fea;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object p3
.end method

.method public final OooO0OO(F)F
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/db8;->OooO0o0:Z

    if-eqz v0, :cond_0

    const/4 v0, -0x1

    int-to-float v0, v0

    mul-float/2addr p1, v0

    :cond_0
    return p1
.end method

.method public final OooO0Oo(J)J
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/db8;->OooO0o0:Z

    if-eqz v0, :cond_0

    const/high16 v0, -0x40800000    # -1.0f

    invoke-static {v0, p1, p2}, Llyiahf/vczjk/p86;->OooO0oO(FJ)J

    move-result-wide p1

    :cond_0
    return-wide p1
.end method

.method public final OooO0o(J)F
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v1, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    if-ne v0, v1, :cond_0

    const/16 v0, 0x20

    shr-long/2addr p1, v0

    :goto_0
    long-to-int p1, p1

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    return p1

    :cond_0
    const-wide v0, 0xffffffffL

    and-long/2addr p1, v0

    goto :goto_0
.end method

.method public final OooO0o0(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    new-instance v1, Llyiahf/vczjk/cb8;

    const/4 v2, 0x0

    invoke-direct {v1, v2, p2, p0}, Llyiahf/vczjk/cb8;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/db8;)V

    invoke-interface {v0, p1, v1, p3}, Llyiahf/vczjk/sa8;->OooO0OO(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final OooO0oO(F)J
    .locals 8

    const/4 v0, 0x0

    cmpg-float v1, p1, v0

    if-nez v1, :cond_0

    const-wide/16 v0, 0x0

    return-wide v0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    const-wide v3, 0xffffffffL

    const/16 v5, 0x20

    if-ne v1, v2, :cond_1

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v1, p1

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v6, p1

    shl-long v0, v1, v5

    :goto_0
    and-long v2, v6, v3

    or-long/2addr v0, v2

    return-wide v0

    :cond_1
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v0, v0

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v6, p1

    shl-long/2addr v0, v5

    goto :goto_0
.end method
