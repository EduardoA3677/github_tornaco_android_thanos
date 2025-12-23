.class public final Llyiahf/vczjk/kb9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/f62;
.implements Llyiahf/vczjk/yo1;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/nb9;

.field public final OooOOO0:Llyiahf/vczjk/yp0;

.field public OooOOOO:Llyiahf/vczjk/yp0;

.field public OooOOOo:Llyiahf/vczjk/fy6;

.field public final synthetic OooOOo:Llyiahf/vczjk/nb9;

.field public final OooOOo0:Llyiahf/vczjk/wm2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nb9;Llyiahf/vczjk/yp0;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iput-object p2, p0, Llyiahf/vczjk/kb9;->OooOOO0:Llyiahf/vczjk/yp0;

    iput-object p1, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    sget-object p1, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    iput-object p1, p0, Llyiahf/vczjk/kb9;->OooOOOo:Llyiahf/vczjk/fy6;

    sget-object p1, Llyiahf/vczjk/wm2;->OooOOO0:Llyiahf/vczjk/wm2;

    iput-object p1, p0, Llyiahf/vczjk/kb9;->OooOOo0:Llyiahf/vczjk/wm2;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Llyiahf/vczjk/yp0;

    invoke-static {p2}, Llyiahf/vczjk/dn8;->ooOO(Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p2

    const/4 v1, 0x1

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/yp0;-><init>(ILlyiahf/vczjk/yo1;)V

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOoo()V

    iput-object p1, p0, Llyiahf/vczjk/kb9;->OooOOOo:Llyiahf/vczjk/fy6;

    iput-object v0, p0, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    invoke-virtual {v0}, Llyiahf/vczjk/yp0;->OooOOo()Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final OooO0O0()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-virtual {v0}, Llyiahf/vczjk/nb9;->OooO0O0()F

    move-result v0

    return v0
.end method

.method public final OooO0OO()J
    .locals 10

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0o:Llyiahf/vczjk/gga;

    invoke-interface {v1}, Llyiahf/vczjk/gga;->OooO0Oo()J

    move-result-wide v1

    invoke-interface {v0, v1, v2}, Llyiahf/vczjk/f62;->o00oO0o(J)J

    move-result-wide v1

    iget-wide v3, v0, Llyiahf/vczjk/nb9;->Oooo0O0:J

    const/16 v0, 0x20

    shr-long v5, v1, v0

    long-to-int v5, v5

    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v5

    shr-long v6, v3, v0

    long-to-int v6, v6

    int-to-float v6, v6

    sub-float/2addr v5, v6

    const/4 v6, 0x0

    invoke-static {v6, v5}, Ljava/lang/Math;->max(FF)F

    move-result v5

    const/high16 v7, 0x40000000    # 2.0f

    div-float/2addr v5, v7

    const-wide v8, 0xffffffffL

    and-long/2addr v1, v8

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    and-long v2, v3, v8

    long-to-int v2, v2

    int-to-float v2, v2

    sub-float/2addr v1, v2

    invoke-static {v6, v1}, Ljava/lang/Math;->max(FF)F

    move-result v1

    div-float/2addr v1, v7

    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v2

    int-to-long v2, v2

    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v4, v1

    shl-long v0, v2, v0

    and-long v2, v4, v8

    or-long/2addr v0, v2

    return-wide v0
.end method

.method public final OooO0Oo()Llyiahf/vczjk/gga;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0o:Llyiahf/vczjk/gga;

    return-object v0
.end method

.method public final OooO0o(JLlyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 6

    instance-of v0, p4, Llyiahf/vczjk/hb9;

    if-eqz v0, :cond_0

    move-object v0, p4

    check-cast v0, Llyiahf/vczjk/hb9;

    iget v1, v0, Llyiahf/vczjk/hb9;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/hb9;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/hb9;

    invoke-direct {v0, p0, p4}, Llyiahf/vczjk/hb9;-><init>(Llyiahf/vczjk/kb9;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p4, v0, Llyiahf/vczjk/hb9;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/hb9;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/hb9;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/v74;

    :try_start_0
    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p2

    goto :goto_2

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    const-wide/16 v4, 0x0

    cmp-long p4, p1, v4

    if-gtz p4, :cond_3

    iget-object p4, p0, Llyiahf/vczjk/kb9;->OooOOOO:Llyiahf/vczjk/yp0;

    if-eqz p4, :cond_3

    new-instance v2, Llyiahf/vczjk/gy6;

    invoke-direct {v2, p1, p2}, Llyiahf/vczjk/gy6;-><init>(J)V

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object v2

    invoke-virtual {p4, v2}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_3
    iget-object p4, p0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    invoke-virtual {p4}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object p4

    new-instance v2, Llyiahf/vczjk/ib9;

    const/4 v4, 0x0

    invoke-direct {v2, p1, p2, p0, v4}, Llyiahf/vczjk/ib9;-><init>(JLlyiahf/vczjk/kb9;Llyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {p4, v4, v4, v2, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object p1

    :try_start_1
    iput-object p1, v0, Llyiahf/vczjk/hb9;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/hb9;->label:I

    invoke-interface {p3, p0, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    if-ne p4, v1, :cond_4

    return-object v1

    :cond_4
    :goto_1
    sget-object p2, Llyiahf/vczjk/pp0;->OooOOO0:Llyiahf/vczjk/pp0;

    invoke-interface {p1, p2}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    return-object p4

    :goto_2
    sget-object p3, Llyiahf/vczjk/pp0;->OooOOO0:Llyiahf/vczjk/pp0;

    invoke-interface {p1, p3}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    throw p2
.end method

.method public final OooO0oO(JLlyiahf/vczjk/ff9;Llyiahf/vczjk/p70;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p4, Llyiahf/vczjk/jb9;

    if-eqz v0, :cond_0

    move-object v0, p4

    check-cast v0, Llyiahf/vczjk/jb9;

    iget v1, v0, Llyiahf/vczjk/jb9;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/jb9;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/jb9;

    invoke-direct {v0, p0, p4}, Llyiahf/vczjk/jb9;-><init>(Llyiahf/vczjk/kb9;Llyiahf/vczjk/p70;)V

    :goto_0
    iget-object p4, v0, Llyiahf/vczjk/jb9;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/jb9;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    :try_start_0
    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Llyiahf/vczjk/gy6; {:try_start_0 .. :try_end_0} :catch_0

    return-object p4

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :try_start_1
    iput v3, v0, Llyiahf/vczjk/jb9;->label:I

    invoke-virtual {p0, p1, p2, p3, v0}, Llyiahf/vczjk/kb9;->OooO0o(JLlyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1
    :try_end_1
    .catch Llyiahf/vczjk/gy6; {:try_start_1 .. :try_end_1} :catch_0

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    return-object p1

    :catch_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final OooOOO(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOOO(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final OooOOOO(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOOO(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final OooOOo0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->OooOOo0(J)F

    move-result p1

    return p1
.end method

.method public final OooOooo(F)J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->OooOooo(F)J

    move-result-wide v0

    return-wide v0
.end method

.method public final Oooo0OO(I)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->Oooo0OO(I)F

    move-result p1

    return p1
.end method

.method public final Oooo0o(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-virtual {v0}, Llyiahf/vczjk/nb9;->OooO0O0()F

    move-result v0

    div-float/2addr p1, v0

    return p1
.end method

.method public final Ooooo00(F)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-virtual {v0}, Llyiahf/vczjk/nb9;->OooO0O0()F

    move-result v0

    mul-float/2addr v0, p1

    return v0
.end method

.method public final getContext()Llyiahf/vczjk/or1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOo0:Llyiahf/vczjk/wm2;

    return-object v0
.end method

.method public final o000oOoO()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-virtual {v0}, Llyiahf/vczjk/nb9;->o000oOoO()F

    move-result v0

    return v0
.end method

.method public final o00Oo0(F)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1}, Llyiahf/vczjk/f62;->o00Oo0(F)I

    move-result p1

    return p1
.end method

.method public final o00oO0o(J)J
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o00oO0o(J)J

    move-result-wide p1

    return-wide p1
.end method

.method public final o0ooOO0(J)F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO:Llyiahf/vczjk/nb9;

    invoke-interface {v0, p1, p2}, Llyiahf/vczjk/f62;->o0ooOO0(J)F

    move-result p1

    return p1
.end method

.method public final resumeWith(Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-object v1, v0, Llyiahf/vczjk/nb9;->Oooo00O:Llyiahf/vczjk/ws5;

    monitor-enter v1

    :try_start_0
    iget-object v0, v0, Llyiahf/vczjk/nb9;->Oooo000:Llyiahf/vczjk/ws5;

    invoke-virtual {v0, p0}, Llyiahf/vczjk/ws5;->OooOO0(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit v1

    iget-object v0, p0, Llyiahf/vczjk/kb9;->OooOOO0:Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void

    :catchall_0
    move-exception p1

    monitor-exit v1

    throw p1
.end method
