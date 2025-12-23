.class public final Llyiahf/vczjk/xc8;
.super Llyiahf/vczjk/tz9;
.source "SourceFile"


# static fields
.field public static final OooOOo:Llyiahf/vczjk/zl;

.field public static final OooOOoo:Llyiahf/vczjk/zl;


# instance fields
.field public OooO:Llyiahf/vczjk/yp0;

.field public final OooO0O0:Llyiahf/vczjk/qs5;

.field public final OooO0OO:Llyiahf/vczjk/qs5;

.field public OooO0Oo:Ljava/lang/Object;

.field public OooO0o:J

.field public OooO0o0:Llyiahf/vczjk/bz9;

.field public final OooO0oO:Llyiahf/vczjk/pc8;

.field public final OooO0oo:Llyiahf/vczjk/lr5;

.field public final OooOO0:Llyiahf/vczjk/mt5;

.field public final OooOO0O:Llyiahf/vczjk/it5;

.field public OooOO0o:J

.field public OooOOO:Llyiahf/vczjk/kc8;

.field public final OooOOO0:Llyiahf/vczjk/as5;

.field public final OooOOOO:Llyiahf/vczjk/oc8;

.field public OooOOOo:F

.field public final OooOOo0:Llyiahf/vczjk/lc8;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/zl;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/zl;-><init>(F)V

    sput-object v0, Llyiahf/vczjk/xc8;->OooOOo:Llyiahf/vczjk/zl;

    new-instance v0, Llyiahf/vczjk/zl;

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-direct {v0, v1}, Llyiahf/vczjk/zl;-><init>(F)V

    sput-object v0, Llyiahf/vczjk/xc8;->OooOOoo:Llyiahf/vczjk/zl;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ku5;)V
    .locals 2

    invoke-direct {p0}, Llyiahf/vczjk/tz9;-><init>()V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/xc8;->OooO0OO:Llyiahf/vczjk/qs5;

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooO0Oo:Ljava/lang/Object;

    new-instance p1, Llyiahf/vczjk/pc8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/pc8;-><init>(Llyiahf/vczjk/xc8;)V

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooO0oO:Llyiahf/vczjk/pc8;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooO0oo:Llyiahf/vczjk/lr5;

    new-instance p1, Llyiahf/vczjk/mt5;

    invoke-direct {p1}, Llyiahf/vczjk/mt5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooOO0:Llyiahf/vczjk/mt5;

    new-instance p1, Llyiahf/vczjk/it5;

    invoke-direct {p1}, Llyiahf/vczjk/it5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooOO0O:Llyiahf/vczjk/it5;

    const-wide/high16 v0, -0x8000000000000000L

    iput-wide v0, p0, Llyiahf/vczjk/xc8;->OooOO0o:J

    new-instance p1, Llyiahf/vczjk/as5;

    invoke-direct {p1}, Llyiahf/vczjk/as5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooOOO0:Llyiahf/vczjk/as5;

    new-instance p1, Llyiahf/vczjk/oc8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/oc8;-><init>(Llyiahf/vczjk/xc8;)V

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooOOOO:Llyiahf/vczjk/oc8;

    new-instance p1, Llyiahf/vczjk/lc8;

    invoke-direct {p1, p0}, Llyiahf/vczjk/lc8;-><init>(Llyiahf/vczjk/xc8;)V

    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooOOo0:Llyiahf/vczjk/lc8;

    return-void
.end method

.method public static final OooO(Llyiahf/vczjk/xc8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 6

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p1, Llyiahf/vczjk/vc8;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/vc8;

    iget v1, v0, Llyiahf/vczjk/vc8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/vc8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/vc8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/vc8;-><init>(Llyiahf/vczjk/xc8;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/vc8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/vc8;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/vc8;->L$1:Ljava/lang/Object;

    iget-object v0, v0, Llyiahf/vczjk/vc8;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xc8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    iget-object p0, v0, Llyiahf/vczjk/vc8;->L$1:Ljava/lang/Object;

    iget-object v2, v0, Llyiahf/vczjk/vc8;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/xc8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, p0

    move-object p0, v2

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    iput-object p0, v0, Llyiahf/vczjk/vc8;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/vc8;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/vc8;->label:I

    iget-object v2, p0, Llyiahf/vczjk/xc8;->OooOO0:Llyiahf/vczjk/mt5;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    iput-object p0, v0, Llyiahf/vczjk/vc8;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/vc8;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/vc8;->label:I

    new-instance v2, Llyiahf/vczjk/yp0;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v0

    invoke-direct {v2, v4, v0}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yp0;->OooOOoo()V

    iput-object v2, p0, Llyiahf/vczjk/xc8;->OooO:Llyiahf/vczjk/yp0;

    const/4 v0, 0x0

    iget-object v3, p0, Llyiahf/vczjk/xc8;->OooOO0:Llyiahf/vczjk/mt5;

    invoke-virtual {v3, v0}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    invoke-virtual {v2}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    move-object v5, v0

    move-object v0, p0

    move-object p0, p1

    move-object p1, v5

    :goto_3
    invoke-static {p1, p0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p0

    if-eqz p0, :cond_6

    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0

    :cond_6
    const-wide/high16 p0, -0x8000000000000000L

    iput-wide p0, v0, Llyiahf/vczjk/xc8;->OooOO0o:J

    new-instance p0, Ljava/util/concurrent/CancellationException;

    const-string p1, "targetState while waiting for composition"

    invoke-direct {p0, p1}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO0o(Llyiahf/vczjk/xc8;)V
    .locals 9

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/xc8;->OooOOO:Llyiahf/vczjk/kc8;

    const/4 v2, 0x0

    if-nez v1, :cond_4

    iget-wide v3, p0, Llyiahf/vczjk/xc8;->OooO0o:J

    const-wide/16 v5, 0x0

    cmp-long v1, v3, v5

    if-lez v1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOOO0()F

    move-result v1

    const/high16 v3, 0x3f800000    # 1.0f

    cmpg-float v1, v1, v3

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/xc8;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v3, Llyiahf/vczjk/fw8;

    invoke-virtual {v3}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    goto :goto_0

    :cond_2
    new-instance v1, Llyiahf/vczjk/kc8;

    invoke-direct {v1}, Llyiahf/vczjk/kc8;-><init>()V

    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOOO0()F

    move-result v3

    iput v3, v1, Llyiahf/vczjk/kc8;->OooO0Oo:F

    iget-wide v3, p0, Llyiahf/vczjk/xc8;->OooO0o:J

    iput-wide v3, v1, Llyiahf/vczjk/kc8;->OooO0oO:J

    long-to-double v3, v3

    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOOO0()F

    move-result v5

    float-to-double v5, v5

    const-wide/high16 v7, 0x3ff0000000000000L    # 1.0

    sub-double/2addr v7, v5

    mul-double/2addr v7, v3

    invoke-static {v7, v8}, Llyiahf/vczjk/ye5;->Oooo00o(D)J

    move-result-wide v3

    iput-wide v3, v1, Llyiahf/vczjk/kc8;->OooO0oo:J

    iget-object v3, v1, Llyiahf/vczjk/kc8;->OooO0o0:Llyiahf/vczjk/zl;

    const/4 v4, 0x0

    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOOO0()F

    move-result v5

    invoke-virtual {v3, v5, v4}, Llyiahf/vczjk/zl;->OooO0o0(FI)V

    goto :goto_1

    :cond_3
    :goto_0
    move-object v1, v2

    :cond_4
    :goto_1
    if-eqz v1, :cond_5

    iget-wide v3, p0, Llyiahf/vczjk/xc8;->OooO0o:J

    iput-wide v3, v1, Llyiahf/vczjk/kc8;->OooO0oO:J

    iget-object v3, p0, Llyiahf/vczjk/xc8;->OooOOO0:Llyiahf/vczjk/as5;

    invoke-virtual {v3, v1}, Llyiahf/vczjk/as5;->OooO0oO(Ljava/lang/Object;)V

    invoke-virtual {v0, v1}, Llyiahf/vczjk/bz9;->OooOOOO(Llyiahf/vczjk/kc8;)V

    :cond_5
    iput-object v2, p0, Llyiahf/vczjk/xc8;->OooOOO:Llyiahf/vczjk/kc8;

    return-void
.end method

.method public static final OooO0oO(Llyiahf/vczjk/xc8;Llyiahf/vczjk/kc8;J)V
    .locals 8

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-wide v0, p1, Llyiahf/vczjk/kc8;->OooO00o:J

    add-long v3, v0, p2

    iput-wide v3, p1, Llyiahf/vczjk/kc8;->OooO00o:J

    iget-wide p2, p1, Llyiahf/vczjk/kc8;->OooO0oo:J

    cmp-long p0, v3, p2

    const/high16 v0, 0x3f800000    # 1.0f

    if-ltz p0, :cond_0

    iput v0, p1, Llyiahf/vczjk/kc8;->OooO0Oo:F

    return-void

    :cond_0
    iget-object v2, p1, Llyiahf/vczjk/kc8;->OooO0O0:Llyiahf/vczjk/bea;

    const/4 p0, 0x0

    if-eqz v2, :cond_2

    sget-object v6, Llyiahf/vczjk/xc8;->OooOOoo:Llyiahf/vczjk/zl;

    iget-object p2, p1, Llyiahf/vczjk/kc8;->OooO0o:Llyiahf/vczjk/zl;

    if-nez p2, :cond_1

    sget-object p2, Llyiahf/vczjk/xc8;->OooOOo:Llyiahf/vczjk/zl;

    :cond_1
    move-object v7, p2

    iget-object v5, p1, Llyiahf/vczjk/kc8;->OooO0o0:Llyiahf/vczjk/zl;

    invoke-interface/range {v2 .. v7}, Llyiahf/vczjk/yda;->OooO0oo(JLlyiahf/vczjk/dm;Llyiahf/vczjk/dm;Llyiahf/vczjk/dm;)Llyiahf/vczjk/dm;

    move-result-object p2

    check-cast p2, Llyiahf/vczjk/zl;

    invoke-virtual {p2, p0}, Llyiahf/vczjk/zl;->OooO00o(I)F

    move-result p0

    const/4 p2, 0x0

    invoke-static {p0, p2, v0}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p0

    iput p0, p1, Llyiahf/vczjk/kc8;->OooO0Oo:F

    return-void

    :cond_2
    iget-object v1, p1, Llyiahf/vczjk/kc8;->OooO0o0:Llyiahf/vczjk/zl;

    invoke-virtual {v1, p0}, Llyiahf/vczjk/zl;->OooO00o(I)F

    move-result p0

    long-to-float v1, v3

    long-to-float p2, p2

    div-float/2addr v1, p2

    const/4 p2, 0x1

    int-to-float p2, p2

    sub-float/2addr p2, v1

    mul-float/2addr p2, p0

    mul-float/2addr v1, v0

    add-float/2addr v1, p2

    iput v1, p1, Llyiahf/vczjk/kc8;->OooO0Oo:F

    return-void
.end method

.method public static final OooO0oo(Llyiahf/vczjk/xc8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 10

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p1, Llyiahf/vczjk/qc8;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/qc8;

    iget v1, v0, Llyiahf/vczjk/qc8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/qc8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/qc8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/qc8;-><init>(Llyiahf/vczjk/xc8;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/qc8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/qc8;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x2

    const/4 v5, 0x1

    const-wide/high16 v6, -0x8000000000000000L

    if-eqz v2, :cond_3

    if-eq v2, v5, :cond_2

    if-ne v2, v4, :cond_1

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    :goto_1
    iget-object p0, v0, Llyiahf/vczjk/qc8;->L$0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/xc8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/xc8;->OooOOO0:Llyiahf/vczjk/as5;

    invoke-virtual {p1}, Llyiahf/vczjk/c76;->OooO0Oo()Z

    move-result p1

    if-eqz p1, :cond_4

    iget-object p1, p0, Llyiahf/vczjk/xc8;->OooOOO:Llyiahf/vczjk/kc8;

    if-nez p1, :cond_4

    return-object v3

    :cond_4
    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->OooOoOO(Llyiahf/vczjk/or1;)F

    move-result p1

    const/4 v2, 0x0

    cmpg-float p1, p1, v2

    if-nez p1, :cond_5

    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOO0o()V

    iput-wide v6, p0, Llyiahf/vczjk/xc8;->OooOO0o:J

    return-object v3

    :cond_5
    iget-wide v8, p0, Llyiahf/vczjk/xc8;->OooOO0o:J

    cmp-long p1, v8, v6

    if-nez p1, :cond_6

    iput-object p0, v0, Llyiahf/vczjk/qc8;->L$0:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/qc8;->label:I

    invoke-interface {v0}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object p1

    iget-object v2, p0, Llyiahf/vczjk/xc8;->OooOOOO:Llyiahf/vczjk/oc8;

    invoke-interface {p1, v0, v2}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_6

    goto :goto_4

    :cond_6
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/xc8;->OooOOO0:Llyiahf/vczjk/as5;

    invoke-virtual {p1}, Llyiahf/vczjk/c76;->OooO0o0()Z

    move-result p1

    if-nez p1, :cond_8

    iget-object p1, p0, Llyiahf/vczjk/xc8;->OooOOO:Llyiahf/vczjk/kc8;

    if-eqz p1, :cond_7

    goto :goto_3

    :cond_7
    iput-wide v6, p0, Llyiahf/vczjk/xc8;->OooOO0o:J

    return-object v3

    :cond_8
    :goto_3
    iput-object p0, v0, Llyiahf/vczjk/qc8;->L$0:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/qc8;->label:I

    invoke-virtual {p0, v0}, Llyiahf/vczjk/xc8;->OooOO0O(Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_6

    :goto_4
    return-object v1
.end method

.method public static final OooOO0(Llyiahf/vczjk/xc8;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 7

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p1, Llyiahf/vczjk/wc8;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/wc8;

    iget v1, v0, Llyiahf/vczjk/wc8;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/wc8;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/wc8;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/wc8;-><init>(Llyiahf/vczjk/xc8;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/wc8;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/wc8;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/wc8;->L$1:Ljava/lang/Object;

    iget-object v0, v0, Llyiahf/vczjk/wc8;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/xc8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    iget-object p0, v0, Llyiahf/vczjk/wc8;->L$1:Ljava/lang/Object;

    iget-object v2, v0, Llyiahf/vczjk/wc8;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/xc8;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    iput-object p0, v0, Llyiahf/vczjk/wc8;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/wc8;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/wc8;->label:I

    iget-object v2, p0, Llyiahf/vczjk/xc8;->OooOO0:Llyiahf/vczjk/mt5;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/mt5;->OooO0oO(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object v2

    if-ne v2, v1, :cond_4

    goto :goto_2

    :cond_4
    move-object v2, p0

    move-object p0, p1

    :goto_1
    iget-object p1, v2, Llyiahf/vczjk/xc8;->OooO0Oo:Ljava/lang/Object;

    invoke-static {p0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    const/4 v5, 0x0

    iget-object v6, v2, Llyiahf/vczjk/xc8;->OooOO0:Llyiahf/vczjk/mt5;

    if-eqz p1, :cond_5

    invoke-virtual {v6, v5}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    goto :goto_4

    :cond_5
    iput-object v2, v0, Llyiahf/vczjk/wc8;->L$0:Ljava/lang/Object;

    iput-object p0, v0, Llyiahf/vczjk/wc8;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/wc8;->label:I

    new-instance p1, Llyiahf/vczjk/yp0;

    invoke-static {v0}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object v0

    invoke-direct {p1, v4, v0}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {p1}, Llyiahf/vczjk/yp0;->OooOOoo()V

    iput-object p1, v2, Llyiahf/vczjk/xc8;->OooO:Llyiahf/vczjk/yp0;

    invoke-virtual {v6, v5}, Llyiahf/vczjk/mt5;->OooO0Oo(Ljava/lang/Object;)V

    invoke-virtual {p1}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_6

    :goto_2
    return-object v1

    :cond_6
    move-object v0, v2

    :goto_3
    invoke-static {p1, p0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_7

    :goto_4
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0

    :cond_7
    const-wide/high16 v1, -0x8000000000000000L

    iput-wide v1, v0, Llyiahf/vczjk/xc8;->OooOO0o:J

    new-instance v0, Ljava/util/concurrent/CancellationException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "snapTo() was canceled because state was changed to "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " instead of "

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-direct {v0, p0}, Ljava/util/concurrent/CancellationException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0O0()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO(Ljava/lang/Object;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooO0Oo(Llyiahf/vczjk/bz9;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    if-eqz v0, :cond_1

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    goto :goto_1

    :cond_1
    :goto_0
    const/4 v0, 0x1

    :goto_1
    if-nez v0, :cond_2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "An instance of SeekableTransitionState has been used in different Transitions. Previous instance: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", new instance: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/w07;->OooO0O0(Ljava/lang/String;)V

    :cond_2
    iput-object p1, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    return-void
.end method

.method public final OooO0o0()V
    .locals 1

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    sget-object v0, Llyiahf/vczjk/oz9;->OooO00o:Ljava/lang/Object;

    invoke-interface {v0}, Llyiahf/vczjk/kp4;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/yw8;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/yw8;->OooO0OO(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooOO0O(Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 3

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->OooOoOO(Llyiahf/vczjk/or1;)F

    move-result v0

    const/4 v1, 0x0

    cmpg-float v1, v0, v1

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-gtz v1, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOO0o()V

    return-object v2

    :cond_0
    iput v0, p0, Llyiahf/vczjk/xc8;->OooOOOo:F

    invoke-interface {p1}, Llyiahf/vczjk/yo1;->getContext()Llyiahf/vczjk/or1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/vc6;->OooOoo0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/xn5;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/xc8;->OooOOo0:Llyiahf/vczjk/lc8;

    invoke-interface {v0, p1, v1}, Llyiahf/vczjk/xn5;->o0ooOO0(Llyiahf/vczjk/yo1;Llyiahf/vczjk/oe3;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_1

    return-object p1

    :cond_1
    return-object v2
.end method

.method public final OooOO0o()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooO0OO()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooOOO0:Llyiahf/vczjk/as5;

    invoke-virtual {v0}, Llyiahf/vczjk/as5;->OooO()V

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooOOO:Llyiahf/vczjk/kc8;

    if-eqz v0, :cond_1

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/xc8;->OooOOO:Llyiahf/vczjk/kc8;

    const/high16 v0, 0x3f800000    # 1.0f

    invoke-virtual {p0, v0}, Llyiahf/vczjk/xc8;->OooOOOo(F)V

    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOOOO()V

    :cond_1
    return-void
.end method

.method public final OooOOO(FLjava/lang/Object;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 8

    const/4 v0, 0x0

    cmpg-float v0, v0, p1

    if-gtz v0, :cond_0

    const/high16 v0, 0x3f800000    # 1.0f

    cmpg-float v0, p1, v0

    if-gtz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Expecting fraction between 0 and 1. Got "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/w07;->OooO00o(Ljava/lang/String;)V

    :goto_0
    iget-object v5, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-nez v5, :cond_1

    move-object v4, p0

    goto :goto_1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/xc8;->OooO0O0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v3

    new-instance v1, Llyiahf/vczjk/tc8;

    const/4 v7, 0x0

    move-object v4, p0

    move v6, p1

    move-object v2, p2

    invoke-direct/range {v1 .. v7}, Llyiahf/vczjk/tc8;-><init>(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/xc8;Llyiahf/vczjk/bz9;FLlyiahf/vczjk/yo1;)V

    iget-object p1, v4, Llyiahf/vczjk/xc8;->OooOO0O:Llyiahf/vczjk/it5;

    invoke-static {p1, v1, p3}, Llyiahf/vczjk/it5;->OooO00o(Llyiahf/vczjk/it5;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_2

    return-object p1

    :cond_2
    :goto_1
    return-object v0
.end method

.method public final OooOOO0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0oo:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    return v0
.end method

.method public final OooOOOO()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0o0:Llyiahf/vczjk/bz9;

    if-nez v0, :cond_0

    return-void

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/xc8;->OooOOO0()F

    move-result v1

    float-to-double v1, v1

    invoke-virtual {v0}, Llyiahf/vczjk/bz9;->OooO0oo()J

    move-result-wide v3

    long-to-double v3, v3

    mul-double/2addr v1, v3

    invoke-static {v1, v2}, Llyiahf/vczjk/ye5;->Oooo00o(D)J

    move-result-wide v1

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/bz9;->OooOOO(J)V

    return-void
.end method

.method public final OooOOOo(F)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xc8;->OooO0oo:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-void
.end method
