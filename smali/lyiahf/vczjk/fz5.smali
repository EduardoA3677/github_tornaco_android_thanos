.class public final Llyiahf/vczjk/fz5;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO00o:Llyiahf/vczjk/jz5;

.field public OooO0O0:Llyiahf/vczjk/jz5;

.field public OooO0OO:Llyiahf/vczjk/rm4;

.field public OooO0Oo:Llyiahf/vczjk/xr1;


# direct methods
.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/cz5;

    invoke-direct {v0, p0}, Llyiahf/vczjk/cz5;-><init>(Llyiahf/vczjk/fz5;)V

    iput-object v0, p0, Llyiahf/vczjk/fz5;->OooO0OO:Llyiahf/vczjk/rm4;

    return-void
.end method


# virtual methods
.method public final OooO00o(JJLlyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p5, Llyiahf/vczjk/dz5;

    if-eqz v0, :cond_0

    move-object v0, p5

    check-cast v0, Llyiahf/vczjk/dz5;

    iget v1, v0, Llyiahf/vczjk/dz5;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/dz5;->label:I

    :goto_0
    move-object v6, v0

    goto :goto_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/dz5;

    invoke-direct {v0, p0, p5}, Llyiahf/vczjk/dz5;-><init>(Llyiahf/vczjk/fz5;Llyiahf/vczjk/zo1;)V

    goto :goto_0

    :goto_1
    iget-object p5, v6, Llyiahf/vczjk/dz5;->result:Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, v6, Llyiahf/vczjk/dz5;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v3, :cond_2

    if-ne v1, v2, :cond_1

    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_5

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_3
    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p5, p0, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    const/4 v1, 0x0

    if-eqz p5, :cond_4

    iget-boolean v4, p5, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v4, :cond_4

    invoke-static {p5}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p5

    check-cast p5, Llyiahf/vczjk/jz5;

    goto :goto_2

    :cond_4
    move-object p5, v1

    :goto_2
    const-wide/16 v4, 0x0

    if-nez p5, :cond_6

    iget-object v1, p0, Llyiahf/vczjk/fz5;->OooO0O0:Llyiahf/vczjk/jz5;

    if-eqz v1, :cond_a

    iput v3, v6, Llyiahf/vczjk/dz5;->label:I

    move-wide v2, p1

    move-wide v4, p3

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/jz5;->OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p5

    if-ne p5, v0, :cond_5

    goto :goto_4

    :cond_5
    :goto_3
    check-cast p5, Llyiahf/vczjk/fea;

    iget-wide v4, p5, Llyiahf/vczjk/fea;->OooO00o:J

    goto :goto_6

    :cond_6
    move-wide v7, p1

    move p1, v2

    move-wide v2, v7

    move-wide v7, v4

    move-wide v4, p3

    move-wide p2, v7

    iget-object p4, p0, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    if-eqz p4, :cond_7

    iget-boolean p5, p4, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz p5, :cond_7

    invoke-static {p4}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p4

    move-object v1, p4

    check-cast v1, Llyiahf/vczjk/jz5;

    :cond_7
    if-eqz v1, :cond_9

    iput p1, v6, Llyiahf/vczjk/dz5;->label:I

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/jz5;->OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p5

    if-ne p5, v0, :cond_8

    :goto_4
    return-object v0

    :cond_8
    :goto_5
    check-cast p5, Llyiahf/vczjk/fea;

    iget-wide v4, p5, Llyiahf/vczjk/fea;->OooO00o:J

    goto :goto_6

    :cond_9
    move-wide v4, p2

    :cond_a
    :goto_6
    new-instance p1, Llyiahf/vczjk/fea;

    invoke-direct {p1, v4, v5}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object p1
.end method

.method public final OooO0O0(JLlyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p3, Llyiahf/vczjk/ez5;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/ez5;

    iget v1, v0, Llyiahf/vczjk/ez5;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ez5;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ez5;

    invoke-direct {v0, p0, p3}, Llyiahf/vczjk/ez5;-><init>(Llyiahf/vczjk/fz5;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/ez5;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ez5;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p3, p0, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    const/4 v2, 0x0

    if-eqz p3, :cond_3

    iget-boolean v4, p3, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v4, :cond_3

    invoke-static {p3}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p3

    move-object v2, p3

    check-cast v2, Llyiahf/vczjk/jz5;

    :cond_3
    if-eqz v2, :cond_5

    iput v3, v0, Llyiahf/vczjk/ez5;->label:I

    invoke-virtual {v2, p1, p2, v0}, Llyiahf/vczjk/jz5;->OoooOO0(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p3

    if-ne p3, v1, :cond_4

    return-object v1

    :cond_4
    :goto_1
    check-cast p3, Llyiahf/vczjk/fea;

    iget-wide p1, p3, Llyiahf/vczjk/fea;->OooO00o:J

    goto :goto_2

    :cond_5
    const-wide/16 p1, 0x0

    :goto_2
    new-instance p3, Llyiahf/vczjk/fea;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object p3
.end method

.method public final OooO0OO()Llyiahf/vczjk/xr1;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fz5;->OooO0OO:Llyiahf/vczjk/rm4;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/xr1;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "in order to access nested coroutine scope you need to attach dispatcher to the `Modifier.nestedScroll` first."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
