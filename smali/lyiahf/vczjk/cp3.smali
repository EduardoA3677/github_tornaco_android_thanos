.class public final Llyiahf/vczjk/cp3;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ny6;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/rr5;

.field public OooOoo0:Llyiahf/vczjk/wo3;


# direct methods
.method public static final o00000OO(Llyiahf/vczjk/cp3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p1, Llyiahf/vczjk/yo3;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/yo3;

    iget v1, v0, Llyiahf/vczjk/yo3;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/yo3;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/yo3;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/yo3;-><init>(Llyiahf/vczjk/cp3;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/yo3;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/yo3;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/yo3;->L$1:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/wo3;

    iget-object v0, v0, Llyiahf/vczjk/yo3;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cp3;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, p0

    move-object p0, v0

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/cp3;->OooOoo0:Llyiahf/vczjk/wo3;

    if-nez p1, :cond_4

    new-instance p1, Llyiahf/vczjk/wo3;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    iget-object v2, p0, Llyiahf/vczjk/cp3;->OooOoOO:Llyiahf/vczjk/rr5;

    iput-object p0, v0, Llyiahf/vczjk/yo3;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/yo3;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/yo3;->label:I

    check-cast v2, Llyiahf/vczjk/sr5;

    invoke-virtual {v2, p1, v0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    iput-object p1, p0, Llyiahf/vczjk/cp3;->OooOoo0:Llyiahf/vczjk/wo3;

    :cond_4
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final o00000Oo(Llyiahf/vczjk/cp3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 4

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p1, Llyiahf/vczjk/zo3;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/zo3;

    iget v1, v0, Llyiahf/vczjk/zo3;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/zo3;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/zo3;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/zo3;-><init>(Llyiahf/vczjk/cp3;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/zo3;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/zo3;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/zo3;->L$0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/cp3;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/cp3;->OooOoo0:Llyiahf/vczjk/wo3;

    if-eqz p1, :cond_4

    new-instance v2, Llyiahf/vczjk/xo3;

    invoke-direct {v2, p1}, Llyiahf/vczjk/xo3;-><init>(Llyiahf/vczjk/wo3;)V

    iget-object p1, p0, Llyiahf/vczjk/cp3;->OooOoOO:Llyiahf/vczjk/rr5;

    iput-object p0, v0, Llyiahf/vczjk/zo3;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/zo3;->label:I

    check-cast p1, Llyiahf/vczjk/sr5;

    invoke-virtual {p1, v2, v0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/cp3;->OooOoo0:Llyiahf/vczjk/wo3;

    :cond_4
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final OooOoo0()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/cp3;->o00000o0()V

    return-void
.end method

.method public final o00000o0()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/cp3;->OooOoo0:Llyiahf/vczjk/wo3;

    if-eqz v0, :cond_0

    new-instance v1, Llyiahf/vczjk/xo3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/xo3;-><init>(Llyiahf/vczjk/wo3;)V

    iget-object v0, p0, Llyiahf/vczjk/cp3;->OooOoOO:Llyiahf/vczjk/rr5;

    check-cast v0, Llyiahf/vczjk/sr5;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/cp3;->OooOoo0:Llyiahf/vczjk/wo3;

    :cond_0
    return-void
.end method

.method public final o000OOo()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/cp3;->o00000o0()V

    return-void
.end method

.method public final ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 0

    sget-object p3, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    if-ne p2, p3, :cond_1

    iget p1, p1, Llyiahf/vczjk/ey6;->OooO0Oo:I

    const/4 p2, 0x4

    const/4 p3, 0x3

    const/4 p4, 0x0

    if-ne p1, p2, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/ap3;

    invoke-direct {p2, p0, p4}, Llyiahf/vczjk/ap3;-><init>(Llyiahf/vczjk/cp3;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, p4, p4, p2, p3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void

    :cond_0
    const/4 p2, 0x5

    if-ne p1, p2, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object p1

    new-instance p2, Llyiahf/vczjk/bp3;

    invoke-direct {p2, p0, p4}, Llyiahf/vczjk/bp3;-><init>(Llyiahf/vczjk/cp3;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, p4, p4, p2, p3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    return-void
.end method
