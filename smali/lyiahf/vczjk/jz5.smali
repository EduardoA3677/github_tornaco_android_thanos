.class public final Llyiahf/vczjk/jz5;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/c0a;
.implements Llyiahf/vczjk/bz5;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/bz5;

.field public OooOoo:Llyiahf/vczjk/jz5;

.field public OooOoo0:Llyiahf/vczjk/fz5;

.field public final OooOooO:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/jz5;->OooOoOO:Llyiahf/vczjk/bz5;

    if-nez p2, :cond_0

    new-instance p2, Llyiahf/vczjk/fz5;

    invoke-direct {p2}, Llyiahf/vczjk/fz5;-><init>()V

    :cond_0
    iput-object p2, p0, Llyiahf/vczjk/jz5;->OooOoo0:Llyiahf/vczjk/fz5;

    const-string p1, "androidx.compose.ui.input.nestedscroll.NestedScrollNode"

    iput-object p1, p0, Llyiahf/vczjk/jz5;->OooOooO:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooOO0O()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/jz5;->OooOooO:Ljava/lang/String;

    return-object v0
.end method

.method public final OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 10

    instance-of v0, p5, Llyiahf/vczjk/gz5;

    if-eqz v0, :cond_0

    move-object v0, p5

    check-cast v0, Llyiahf/vczjk/gz5;

    iget v1, v0, Llyiahf/vczjk/gz5;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/gz5;->label:I

    :goto_0
    move-object v6, v0

    goto :goto_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/gz5;

    check-cast p5, Llyiahf/vczjk/zo1;

    invoke-direct {v0, p0, p5}, Llyiahf/vczjk/gz5;-><init>(Llyiahf/vczjk/jz5;Llyiahf/vczjk/zo1;)V

    goto :goto_0

    :goto_1
    iget-object p5, v6, Llyiahf/vczjk/gz5;->result:Ljava/lang/Object;

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, v6, Llyiahf/vczjk/gz5;->label:I

    const/4 v7, 0x2

    const/4 v2, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v2, :cond_2

    if-ne v1, v7, :cond_1

    iget-wide p1, v6, Llyiahf/vczjk/gz5;->J$0:J

    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto/16 :goto_6

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-wide p3, v6, Llyiahf/vczjk/gz5;->J$1:J

    iget-wide p1, v6, Llyiahf/vczjk/gz5;->J$0:J

    iget-object v1, v6, Llyiahf/vczjk/gz5;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/jz5;

    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_3
    invoke-static {p5}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/jz5;->OooOoOO:Llyiahf/vczjk/bz5;

    iput-object p0, v6, Llyiahf/vczjk/gz5;->L$0:Ljava/lang/Object;

    iput-wide p1, v6, Llyiahf/vczjk/gz5;->J$0:J

    iput-wide p3, v6, Llyiahf/vczjk/gz5;->J$1:J

    iput v2, v6, Llyiahf/vczjk/gz5;->label:I

    move-wide v2, p1

    move-wide v4, p3

    invoke-interface/range {v1 .. v6}, Llyiahf/vczjk/bz5;->OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p5

    if-ne p5, v0, :cond_4

    goto :goto_5

    :cond_4
    move-object v1, p0

    move-wide p1, v2

    move-wide p3, v4

    :goto_2
    check-cast p5, Llyiahf/vczjk/fea;

    iget-wide v8, p5, Llyiahf/vczjk/fea;->OooO00o:J

    iget-boolean p5, v1, Llyiahf/vczjk/jl5;->OooOoO:Z

    const/4 v2, 0x0

    if-eqz p5, :cond_6

    if-eqz p5, :cond_5

    if-eqz p5, :cond_5

    invoke-static {v1}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p5

    check-cast p5, Llyiahf/vczjk/jz5;

    goto :goto_3

    :cond_5
    move-object p5, v2

    :goto_3
    move-object v1, p5

    goto :goto_4

    :cond_6
    iget-object p5, v1, Llyiahf/vczjk/jz5;->OooOoo:Llyiahf/vczjk/jz5;

    goto :goto_3

    :goto_4
    if-eqz v1, :cond_8

    invoke-static {p1, p2, v8, v9}, Llyiahf/vczjk/fea;->OooO0o0(JJ)J

    move-result-wide p1

    invoke-static {p3, p4, v8, v9}, Llyiahf/vczjk/fea;->OooO0Oo(JJ)J

    move-result-wide v4

    iput-object v2, v6, Llyiahf/vczjk/gz5;->L$0:Ljava/lang/Object;

    iput-wide v8, v6, Llyiahf/vczjk/gz5;->J$0:J

    iput v7, v6, Llyiahf/vczjk/gz5;->label:I

    move-wide v2, p1

    invoke-virtual/range {v1 .. v6}, Llyiahf/vczjk/jz5;->OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p5

    if-ne p5, v0, :cond_7

    :goto_5
    return-object v0

    :cond_7
    move-wide p1, v8

    :goto_6
    check-cast p5, Llyiahf/vczjk/fea;

    iget-wide p3, p5, Llyiahf/vczjk/fea;->OooO00o:J

    move-wide v8, p1

    goto :goto_7

    :cond_8
    const-wide/16 p3, 0x0

    :goto_7
    invoke-static {v8, v9, p3, p4}, Llyiahf/vczjk/fea;->OooO0o0(JJ)J

    move-result-wide p1

    new-instance p3, Llyiahf/vczjk/fea;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object p3
.end method

.method public final Oooo00O(IJ)J
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object v0

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/jz5;

    :cond_0
    if-eqz v1, :cond_1

    invoke-virtual {v1, p1, p2, p3}, Llyiahf/vczjk/jz5;->Oooo00O(IJ)J

    move-result-wide v0

    goto :goto_0

    :cond_1
    const-wide/16 v0, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/jz5;->OooOoOO:Llyiahf/vczjk/bz5;

    invoke-static {p2, p3, v0, v1}, Llyiahf/vczjk/p86;->OooO0o0(JJ)J

    move-result-wide p2

    invoke-interface {v2, p1, p2, p3}, Llyiahf/vczjk/bz5;->Oooo00O(IJ)J

    move-result-wide p1

    invoke-static {v0, v1, p1, p2}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide p1

    return-wide p1
.end method

.method public final OoooOO0(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p3, Llyiahf/vczjk/hz5;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/hz5;

    iget v1, v0, Llyiahf/vczjk/hz5;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/hz5;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/hz5;

    check-cast p3, Llyiahf/vczjk/zo1;

    invoke-direct {v0, p0, p3}, Llyiahf/vczjk/hz5;-><init>(Llyiahf/vczjk/jz5;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/hz5;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/hz5;->label:I

    const/4 v3, 0x0

    const/4 v4, 0x2

    const/4 v5, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v5, :cond_2

    if-ne v2, v4, :cond_1

    iget-wide p1, v0, Llyiahf/vczjk/hz5;->J$0:J

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_6

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-wide p1, v0, Llyiahf/vczjk/hz5;->J$0:J

    iget-object v2, v0, Llyiahf/vczjk/hz5;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/jz5;

    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_3
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-boolean p3, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz p3, :cond_4

    if-eqz p3, :cond_4

    invoke-static {p0}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p3

    check-cast p3, Llyiahf/vczjk/jz5;

    goto :goto_1

    :cond_4
    move-object p3, v3

    :goto_1
    if-eqz p3, :cond_6

    iput-object p0, v0, Llyiahf/vczjk/hz5;->L$0:Ljava/lang/Object;

    iput-wide p1, v0, Llyiahf/vczjk/hz5;->J$0:J

    iput v5, v0, Llyiahf/vczjk/hz5;->label:I

    invoke-virtual {p3, p1, p2, v0}, Llyiahf/vczjk/jz5;->OoooOO0(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p3

    if-ne p3, v1, :cond_5

    goto :goto_5

    :cond_5
    move-object v2, p0

    :goto_2
    check-cast p3, Llyiahf/vczjk/fea;

    iget-wide v5, p3, Llyiahf/vczjk/fea;->OooO00o:J

    :goto_3
    move-wide v7, v5

    move-wide v5, p1

    move-wide p1, v7

    goto :goto_4

    :cond_6
    const-wide/16 v5, 0x0

    move-object v2, p0

    goto :goto_3

    :goto_4
    iget-object p3, v2, Llyiahf/vczjk/jz5;->OooOoOO:Llyiahf/vczjk/bz5;

    invoke-static {v5, v6, p1, p2}, Llyiahf/vczjk/fea;->OooO0Oo(JJ)J

    move-result-wide v5

    iput-object v3, v0, Llyiahf/vczjk/hz5;->L$0:Ljava/lang/Object;

    iput-wide p1, v0, Llyiahf/vczjk/hz5;->J$0:J

    iput v4, v0, Llyiahf/vczjk/hz5;->label:I

    invoke-interface {p3, v5, v6, v0}, Llyiahf/vczjk/bz5;->OoooOO0(JLlyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p3

    if-ne p3, v1, :cond_7

    :goto_5
    return-object v1

    :cond_7
    :goto_6
    check-cast p3, Llyiahf/vczjk/fea;

    iget-wide v0, p3, Llyiahf/vczjk/fea;->OooO00o:J

    invoke-static {p1, p2, v0, v1}, Llyiahf/vczjk/fea;->OooO0o0(JJ)J

    move-result-wide p1

    new-instance p3, Llyiahf/vczjk/fea;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object p3
.end method

.method public final Ooooooo(IJJ)J
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/jz5;->OooOoOO:Llyiahf/vczjk/bz5;

    move v1, p1

    move-wide v2, p2

    move-wide v4, p4

    invoke-interface/range {v0 .. v5}, Llyiahf/vczjk/bz5;->Ooooooo(IJJ)J

    move-result-wide p1

    iget-boolean p3, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    const/4 p4, 0x0

    if-eqz p3, :cond_0

    if-eqz p3, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object p3

    move-object p4, p3

    check-cast p4, Llyiahf/vczjk/jz5;

    :cond_0
    move-object v0, p4

    if-eqz v0, :cond_1

    invoke-static {v2, v3, p1, p2}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v2

    invoke-static {v4, v5, p1, p2}, Llyiahf/vczjk/p86;->OooO0o0(JJ)J

    move-result-wide v4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/jz5;->Ooooooo(IJJ)J

    move-result-wide p3

    goto :goto_0

    :cond_1
    const-wide/16 p3, 0x0

    :goto_0
    invoke-static {p1, p2, p3, p4}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide p1

    return-wide p1
.end method

.method public final o00000OO()Llyiahf/vczjk/xr1;
    .locals 2

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/er8;->OooOOO0(Llyiahf/vczjk/c0a;)Llyiahf/vczjk/c0a;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/jz5;

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/jz5;->o00000OO()Llyiahf/vczjk/xr1;

    move-result-object v0

    return-object v0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/jz5;->OooOoo0:Llyiahf/vczjk/fz5;

    iget-object v0, v0, Llyiahf/vczjk/fz5;->OooO0Oo:Llyiahf/vczjk/xr1;

    if-eqz v0, :cond_2

    return-object v0

    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "in order to access nested coroutine scope you need to attach dispatcher to the `Modifier.nestedScroll` first."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final o000OOo()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/hl7;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    new-instance v1, Llyiahf/vczjk/kz5;

    invoke-direct {v1, v0}, Llyiahf/vczjk/kz5;-><init>(Llyiahf/vczjk/hl7;)V

    invoke-static {p0, v1}, Llyiahf/vczjk/er8;->OooOo0o(Llyiahf/vczjk/c0a;Llyiahf/vczjk/oe3;)V

    iget-object v0, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/c0a;

    check-cast v0, Llyiahf/vczjk/jz5;

    iput-object v0, p0, Llyiahf/vczjk/jz5;->OooOoo:Llyiahf/vczjk/jz5;

    iget-object v1, p0, Llyiahf/vczjk/jz5;->OooOoo0:Llyiahf/vczjk/fz5;

    iput-object v0, v1, Llyiahf/vczjk/fz5;->OooO0O0:Llyiahf/vczjk/jz5;

    iget-object v0, v1, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    if-ne v0, p0, :cond_0

    const/4 v0, 0x0

    iput-object v0, v1, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    :cond_0
    return-void
.end method

.method public final o0O0O00()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/jz5;->OooOoo0:Llyiahf/vczjk/fz5;

    iput-object p0, v0, Llyiahf/vczjk/fz5;->OooO00o:Llyiahf/vczjk/jz5;

    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/fz5;->OooO0O0:Llyiahf/vczjk/jz5;

    iput-object v1, p0, Llyiahf/vczjk/jz5;->OooOoo:Llyiahf/vczjk/jz5;

    new-instance v1, Llyiahf/vczjk/iz5;

    invoke-direct {v1, p0}, Llyiahf/vczjk/iz5;-><init>(Llyiahf/vczjk/jz5;)V

    iput-object v1, v0, Llyiahf/vczjk/fz5;->OooO0OO:Llyiahf/vczjk/rm4;

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/fz5;->OooO0Oo:Llyiahf/vczjk/xr1;

    return-void
.end method
