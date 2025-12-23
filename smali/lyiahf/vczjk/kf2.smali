.class public abstract Llyiahf/vczjk/kf2;
.super Llyiahf/vczjk/m52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ny6;


# instance fields
.field public OooOoo:Llyiahf/vczjk/nf6;

.field public OooOooO:Llyiahf/vczjk/rm4;

.field public OooOooo:Z

.field public Oooo0:Z

.field public Oooo000:Llyiahf/vczjk/rr5;

.field public Oooo00O:Llyiahf/vczjk/jj0;

.field public Oooo00o:Llyiahf/vczjk/mf2;

.field public Oooo0O0:Llyiahf/vczjk/nb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/m52;-><init>()V

    iput-object p4, p0, Llyiahf/vczjk/kf2;->OooOoo:Llyiahf/vczjk/nf6;

    check-cast p1, Llyiahf/vczjk/rm4;

    iput-object p1, p0, Llyiahf/vczjk/kf2;->OooOooO:Llyiahf/vczjk/rm4;

    iput-boolean p2, p0, Llyiahf/vczjk/kf2;->OooOooo:Z

    iput-object p3, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    return-void
.end method

.method public static final o00000oO(Llyiahf/vczjk/kf2;Llyiahf/vczjk/le2;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 6

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p2, Llyiahf/vczjk/gf2;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/gf2;

    iget v1, v0, Llyiahf/vczjk/gf2;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/gf2;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/gf2;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/gf2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/gf2;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/gf2;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/gf2;->L$2:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/mf2;

    iget-object p1, v0, Llyiahf/vczjk/gf2;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/le2;

    iget-object v0, v0, Llyiahf/vczjk/gf2;->L$0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/kf2;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    iget-object p0, v0, Llyiahf/vczjk/gf2;->L$1:Ljava/lang/Object;

    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/le2;

    iget-object p0, v0, Llyiahf/vczjk/gf2;->L$0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/kf2;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    if-eqz p2, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    if-eqz v2, :cond_4

    new-instance v5, Llyiahf/vczjk/lf2;

    invoke-direct {v5, p2}, Llyiahf/vczjk/lf2;-><init>(Llyiahf/vczjk/mf2;)V

    iput-object p0, v0, Llyiahf/vczjk/gf2;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/gf2;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/gf2;->label:I

    check-cast v2, Llyiahf/vczjk/sr5;

    invoke-virtual {v2, v5, v0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    new-instance p2, Llyiahf/vczjk/mf2;

    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    iget-object v2, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    if-eqz v2, :cond_6

    iput-object p0, v0, Llyiahf/vczjk/gf2;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/gf2;->L$1:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/gf2;->L$2:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/gf2;->label:I

    check-cast v2, Llyiahf/vczjk/sr5;

    invoke-virtual {v2, p2, v0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v0

    if-ne v0, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    move-object v0, p0

    move-object p0, p2

    :goto_3
    move-object p2, p0

    move-object p0, v0

    :cond_6
    iput-object p2, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    iget-wide p1, p1, Llyiahf/vczjk/le2;->OooO00o:J

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/kf2;->o0000oo(J)V

    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final o00000oo(Llyiahf/vczjk/kf2;Llyiahf/vczjk/me2;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p2, Llyiahf/vczjk/hf2;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/hf2;

    iget v1, v0, Llyiahf/vczjk/hf2;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/hf2;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/hf2;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/hf2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/hf2;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/hf2;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/hf2;->L$1:Ljava/lang/Object;

    move-object p1, p0

    check-cast p1, Llyiahf/vczjk/me2;

    iget-object p0, v0, Llyiahf/vczjk/hf2;->L$0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/kf2;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    if-eqz p2, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    if-eqz v2, :cond_3

    new-instance v4, Llyiahf/vczjk/nf2;

    invoke-direct {v4, p2}, Llyiahf/vczjk/nf2;-><init>(Llyiahf/vczjk/mf2;)V

    iput-object p0, v0, Llyiahf/vczjk/hf2;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/hf2;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/hf2;->label:I

    check-cast v2, Llyiahf/vczjk/sr5;

    invoke-virtual {v2, v4, v0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    const/4 p2, 0x0

    iput-object p2, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    :cond_4
    iget-wide p1, p1, Llyiahf/vczjk/me2;->OooO00o:J

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/kf2;->o0000oO(J)V

    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method

.method public static final o0000Ooo(Llyiahf/vczjk/kf2;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 5

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    instance-of v0, p1, Llyiahf/vczjk/ff2;

    if-eqz v0, :cond_0

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ff2;

    iget v1, v0, Llyiahf/vczjk/ff2;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ff2;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ff2;

    invoke-direct {v0, p0, p1}, Llyiahf/vczjk/ff2;-><init>(Llyiahf/vczjk/kf2;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p1, v0, Llyiahf/vczjk/ff2;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ff2;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/ff2;->L$0:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/kf2;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    if-eqz p1, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    if-eqz v2, :cond_3

    new-instance v4, Llyiahf/vczjk/lf2;

    invoke-direct {v4, p1}, Llyiahf/vczjk/lf2;-><init>(Llyiahf/vczjk/mf2;)V

    iput-object p0, v0, Llyiahf/vczjk/ff2;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/ff2;->label:I

    check-cast v2, Llyiahf/vczjk/sr5;

    invoke-virtual {v2, v4, v0}, Llyiahf/vczjk/sr5;->OooO0O0(Llyiahf/vczjk/j24;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    :cond_4
    const-wide/16 v0, 0x0

    invoke-virtual {p0, v0, v1}, Llyiahf/vczjk/kf2;->o0000oO(J)V

    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final OooOoo0()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/kf2;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/nb9;->OooOoo0()V

    :cond_0
    return-void
.end method

.method public final o0000()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    if-eqz v0, :cond_1

    iget-object v1, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    if-eqz v1, :cond_0

    new-instance v2, Llyiahf/vczjk/lf2;

    invoke-direct {v2, v0}, Llyiahf/vczjk/lf2;-><init>(Llyiahf/vczjk/mf2;)V

    check-cast v1, Llyiahf/vczjk/sr5;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/kf2;->Oooo00o:Llyiahf/vczjk/mf2;

    :cond_1
    return-void
.end method

.method public abstract o0000O0()Z
.end method

.method public abstract o0000O00(Llyiahf/vczjk/if2;Llyiahf/vczjk/jf2;)Ljava/lang/Object;
.end method

.method public final o0000O0O(Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;Z)V
    .locals 1

    check-cast p1, Llyiahf/vczjk/rm4;

    iput-object p1, p0, Llyiahf/vczjk/kf2;->OooOooO:Llyiahf/vczjk/rm4;

    iget-boolean p1, p0, Llyiahf/vczjk/kf2;->OooOooo:Z

    const/4 v0, 0x1

    if-eq p1, p2, :cond_2

    iput-boolean p2, p0, Llyiahf/vczjk/kf2;->OooOooo:Z

    if-nez p2, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/kf2;->o0000()V

    iget-object p1, p0, Llyiahf/vczjk/kf2;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-eqz p1, :cond_0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/m52;->o00000Oo(Llyiahf/vczjk/l52;)V

    :cond_0
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/kf2;->Oooo0O0:Llyiahf/vczjk/nb9;

    :cond_1
    move p5, v0

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    invoke-static {p1, p3}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-nez p1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/kf2;->o0000()V

    iput-object p3, p0, Llyiahf/vczjk/kf2;->Oooo000:Llyiahf/vczjk/rr5;

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/kf2;->OooOoo:Llyiahf/vczjk/nf6;

    if-eq p1, p4, :cond_4

    iput-object p4, p0, Llyiahf/vczjk/kf2;->OooOoo:Llyiahf/vczjk/nf6;

    goto :goto_0

    :cond_4
    move v0, p5

    :goto_0
    if-eqz v0, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/kf2;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-eqz p1, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/nb9;->o00000o0()V

    :cond_5
    return-void
.end method

.method public abstract o0000oO(J)V
.end method

.method public abstract o0000oo(J)V
.end method

.method public final o000OOo()V
    .locals 1

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/kf2;->Oooo0:Z

    invoke-virtual {p0}, Llyiahf/vczjk/kf2;->o0000()V

    return-void
.end method

.method public ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/kf2;->OooOooo:Z

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/kf2;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/o0000O0;

    const/4 v1, 0x2

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/o0000O0;-><init>(Ljava/lang/Object;I)V

    sget-object v1, Llyiahf/vczjk/gb9;->OooO00o:Llyiahf/vczjk/ey6;

    new-instance v1, Llyiahf/vczjk/nb9;

    const/4 v2, 0x0

    invoke-direct {v1, v2, v2, v0}, Llyiahf/vczjk/nb9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)V

    invoke-virtual {p0, v1}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object v1, p0, Llyiahf/vczjk/kf2;->Oooo0O0:Llyiahf/vczjk/nb9;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/kf2;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-eqz v0, :cond_1

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/nb9;->ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V

    :cond_1
    return-void
.end method
