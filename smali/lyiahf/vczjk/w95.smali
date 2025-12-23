.class public final Llyiahf/vczjk/w95;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/gi3;
.implements Llyiahf/vczjk/fg2;
.implements Llyiahf/vczjk/ne8;
.implements Llyiahf/vczjk/l86;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/xk9;

.field public OooOoo:Llyiahf/vczjk/ix6;

.field public OooOoo0:Llyiahf/vczjk/yk9;

.field public OooOooO:Landroid/view/View;

.field public OooOooo:Llyiahf/vczjk/f62;

.field public Oooo0:J

.field public Oooo000:Llyiahf/vczjk/hx6;

.field public final Oooo00O:Llyiahf/vczjk/qs5;

.field public Oooo00o:Llyiahf/vczjk/w62;

.field public Oooo0O0:Llyiahf/vczjk/b24;

.field public Oooo0OO:Llyiahf/vczjk/jj0;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xk9;Llyiahf/vczjk/yk9;Llyiahf/vczjk/ix6;)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/w95;->OooOoOO:Llyiahf/vczjk/xk9;

    iput-object p2, p0, Llyiahf/vczjk/w95;->OooOoo0:Llyiahf/vczjk/yk9;

    iput-object p3, p0, Llyiahf/vczjk/w95;->OooOoo:Llyiahf/vczjk/ix6;

    sget-object p1, Llyiahf/vczjk/e86;->OooOOo0:Llyiahf/vczjk/e86;

    const/4 p2, 0x0

    invoke-static {p2, p1}, Landroidx/compose/runtime/OooO0o;->OooO(Ljava/lang/Object;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/w95;->Oooo00O:Llyiahf/vczjk/qs5;

    const-wide p1, 0x7fc000007fc00000L    # 2.247117487993712E307

    iput-wide p1, p0, Llyiahf/vczjk/w95;->Oooo0:J

    return-void
.end method


# virtual methods
.method public final OooOo0o(Llyiahf/vczjk/to4;)V
    .locals 1

    invoke-virtual {p1}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-object p1, p0, Llyiahf/vczjk/w95;->Oooo0OO:Llyiahf/vczjk/jj0;

    if-eqz p1, :cond_0

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-interface {p1, v0}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method

.method public final OooOoO0(Llyiahf/vczjk/v16;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo00O:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    return-void
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 2

    sget-object v0, Llyiahf/vczjk/x95;->OooO00o:Llyiahf/vczjk/ze8;

    new-instance v1, Llyiahf/vczjk/t95;

    invoke-direct {v1, p0}, Llyiahf/vczjk/t95;-><init>(Llyiahf/vczjk/w95;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    return-void
.end method

.method public final Oooooo()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/v95;

    invoke-direct {v0, p0}, Llyiahf/vczjk/v95;-><init>(Llyiahf/vczjk/w95;)V

    invoke-static {p0, v0}, Llyiahf/vczjk/bua;->Oooo000(Llyiahf/vczjk/jl5;Llyiahf/vczjk/le3;)V

    return-void
.end method

.method public final o00000OO()J
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo00o:Llyiahf/vczjk/w62;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/s95;

    invoke-direct {v0, p0}, Llyiahf/vczjk/s95;-><init>(Llyiahf/vczjk/w95;)V

    invoke-static {v0}, Landroidx/compose/runtime/OooO0o;->OooO0Oo(Llyiahf/vczjk/le3;)Llyiahf/vczjk/w62;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/w95;->Oooo00o:Llyiahf/vczjk/w62;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo00o:Llyiahf/vczjk/w62;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p86;

    iget-wide v0, v0, Llyiahf/vczjk/p86;->OooO00o:J

    return-wide v0

    :cond_1
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    return-wide v0
.end method

.method public final o00000Oo()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/jx6;

    invoke-virtual {v0}, Llyiahf/vczjk/jx6;->OooO0O0()V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/w95;->OooOooO:Landroid/view/View;

    if-nez v0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/ye5;->OooOooO(Llyiahf/vczjk/l52;)Landroid/view/View;

    move-result-object v0

    :cond_1
    iput-object v0, p0, Llyiahf/vczjk/w95;->OooOooO:Landroid/view/View;

    iget-object v1, p0, Llyiahf/vczjk/w95;->OooOooo:Llyiahf/vczjk/f62;

    if-nez v1, :cond_2

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    :cond_2
    iput-object v1, p0, Llyiahf/vczjk/w95;->OooOooo:Llyiahf/vczjk/f62;

    iget-object v2, p0, Llyiahf/vczjk/w95;->OooOoo:Llyiahf/vczjk/ix6;

    invoke-interface {v2, v0, v1}, Llyiahf/vczjk/ix6;->OooO0OO(Landroid/view/View;Llyiahf/vczjk/f62;)Llyiahf/vczjk/hx6;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    invoke-virtual {p0}, Llyiahf/vczjk/w95;->o0000Ooo()V

    return-void
.end method

.method public final o00000o0()V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/w95;->OooOooo:Llyiahf/vczjk/f62;

    if-nez v0, :cond_0

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    iput-object v0, p0, Llyiahf/vczjk/w95;->OooOooo:Llyiahf/vczjk/f62;

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/w95;->OooOoOO:Llyiahf/vczjk/xk9;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/xk9;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p86;

    iget-wide v0, v0, Llyiahf/vczjk/p86;->OooO00o:J

    const-wide v2, 0x7fffffff7fffffffL

    and-long v4, v0, v2

    const-wide v6, 0x7fc000007fc00000L    # 2.247117487993712E307

    cmp-long v4, v4, v6

    if-eqz v4, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/w95;->o00000OO()J

    move-result-wide v4

    and-long/2addr v2, v4

    cmp-long v2, v2, v6

    if-eqz v2, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/w95;->o00000OO()J

    move-result-wide v2

    invoke-static {v2, v3, v0, v1}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v0

    iput-wide v0, p0, Llyiahf/vczjk/w95;->Oooo0:J

    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-nez v0, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/w95;->o00000Oo()V

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-eqz v0, :cond_2

    iget-wide v1, p0, Llyiahf/vczjk/w95;->Oooo0:J

    invoke-interface {v0, v1, v2, v6, v7}, Llyiahf/vczjk/hx6;->OooO00o(JJ)V

    :cond_2
    invoke-virtual {p0}, Llyiahf/vczjk/w95;->o0000Ooo()V

    return-void

    :cond_3
    iput-wide v6, p0, Llyiahf/vczjk/w95;->Oooo0:J

    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-eqz v0, :cond_4

    check-cast v0, Llyiahf/vczjk/jx6;

    invoke-virtual {v0}, Llyiahf/vczjk/jx6;->OooO0O0()V

    :cond_4
    return-void
.end method

.method public final o0000Ooo()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/w95;->OooOooo:Llyiahf/vczjk/f62;

    if-nez v1, :cond_1

    :goto_0
    return-void

    :cond_1
    check-cast v0, Llyiahf/vczjk/jx6;

    invoke-virtual {v0}, Llyiahf/vczjk/jx6;->OooO0OO()J

    move-result-wide v2

    iget-object v4, p0, Llyiahf/vczjk/w95;->Oooo0O0:Llyiahf/vczjk/b24;

    if-nez v4, :cond_2

    goto :goto_1

    :cond_2
    iget-wide v4, v4, Llyiahf/vczjk/b24;->OooO00o:J

    cmp-long v2, v2, v4

    if-eqz v2, :cond_3

    :goto_1
    iget-object v2, p0, Llyiahf/vczjk/w95;->OooOoo0:Llyiahf/vczjk/yk9;

    invoke-virtual {v0}, Llyiahf/vczjk/jx6;->OooO0OO()J

    move-result-wide v3

    invoke-static {v3, v4}, Llyiahf/vczjk/e16;->Oooo0oO(J)J

    move-result-wide v3

    invoke-interface {v1, v3, v4}, Llyiahf/vczjk/f62;->OooOOOO(J)J

    move-result-wide v3

    new-instance v1, Llyiahf/vczjk/ae2;

    invoke-direct {v1, v3, v4}, Llyiahf/vczjk/ae2;-><init>(J)V

    invoke-virtual {v2, v1}, Llyiahf/vczjk/yk9;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/jx6;->OooO0OO()J

    move-result-wide v0

    new-instance v2, Llyiahf/vczjk/b24;

    invoke-direct {v2, v0, v1}, Llyiahf/vczjk/b24;-><init>(J)V

    iput-object v2, p0, Llyiahf/vczjk/w95;->Oooo0O0:Llyiahf/vczjk/b24;

    :cond_3
    return-void
.end method

.method public final o000OOo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/jx6;

    invoke-virtual {v0}, Llyiahf/vczjk/jx6;->OooO0O0()V

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/w95;->Oooo000:Llyiahf/vczjk/hx6;

    return-void
.end method

.method public final o0O0O00()V
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/w95;->Oooooo()V

    const/4 v0, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x7

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/tg0;->OooO0o0(IILlyiahf/vczjk/aj0;)Llyiahf/vczjk/jj0;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/w95;->Oooo0OO:Llyiahf/vczjk/jj0;

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    sget-object v2, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v3, Llyiahf/vczjk/u95;

    invoke-direct {v3, p0, v1}, Llyiahf/vczjk/u95;-><init>(Llyiahf/vczjk/w95;Llyiahf/vczjk/yo1;)V

    const/4 v4, 0x1

    invoke-static {v0, v1, v2, v3, v4}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
