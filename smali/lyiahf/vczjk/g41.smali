.class public final Llyiahf/vczjk/g41;
.super Llyiahf/vczjk/o0000O0O;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ug1;


# instance fields
.field public OoooO:Ljava/lang/String;

.field public OoooOO0:Llyiahf/vczjk/le3;

.field public OoooOOO:Z

.field public final OoooOOo:Llyiahf/vczjk/vr5;

.field public final OoooOo0:Llyiahf/vczjk/vr5;

.field public o000oOoO:Llyiahf/vczjk/le3;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/px3;Llyiahf/vczjk/rr5;Llyiahf/vczjk/gu7;ZZ)V
    .locals 7

    move-object v0, p0

    move-object v4, p2

    move-object v6, p3

    move-object v2, p6

    move-object v1, p7

    move-object v5, p8

    move/from16 v3, p10

    invoke-direct/range {v0 .. v6}, Llyiahf/vczjk/o0000O0O;-><init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLjava/lang/String;Llyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V

    iput-object p1, p0, Llyiahf/vczjk/g41;->OoooO:Ljava/lang/String;

    iput-object p4, p0, Llyiahf/vczjk/g41;->OoooOO0:Llyiahf/vczjk/le3;

    iput-object p5, p0, Llyiahf/vczjk/g41;->o000oOoO:Llyiahf/vczjk/le3;

    move/from16 p1, p9

    iput-boolean p1, p0, Llyiahf/vczjk/g41;->OoooOOO:Z

    sget p1, Llyiahf/vczjk/u55;->OooO00o:I

    new-instance p1, Llyiahf/vczjk/vr5;

    const/4 p2, 0x6

    invoke-direct {p1, p2}, Llyiahf/vczjk/vr5;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/g41;->OoooOOo:Llyiahf/vczjk/vr5;

    new-instance p1, Llyiahf/vczjk/vr5;

    invoke-direct {p1, p2}, Llyiahf/vczjk/vr5;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/g41;->OoooOo0:Llyiahf/vczjk/vr5;

    return-void
.end method


# virtual methods
.method public final o000000()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/g41;->o0000O0O()V

    return-void
.end method

.method public final o00000oO(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 10

    iget-boolean v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    iget-object v2, p0, Llyiahf/vczjk/g41;->o000oOoO:Llyiahf/vczjk/le3;

    if-eqz v2, :cond_0

    new-instance v2, Llyiahf/vczjk/a41;

    invoke-direct {v2, p0}, Llyiahf/vczjk/a41;-><init>(Llyiahf/vczjk/g41;)V

    move-object v7, v2

    goto :goto_0

    :cond_0
    move-object v7, v1

    :goto_0
    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/g41;->OoooOO0:Llyiahf/vczjk/le3;

    if-eqz v0, :cond_1

    new-instance v0, Llyiahf/vczjk/b41;

    invoke-direct {v0, p0}, Llyiahf/vczjk/b41;-><init>(Llyiahf/vczjk/g41;)V

    move-object v6, v0

    goto :goto_1

    :cond_1
    move-object v6, v1

    :goto_1
    new-instance v5, Llyiahf/vczjk/c41;

    invoke-direct {v5, p0, v1}, Llyiahf/vczjk/c41;-><init>(Llyiahf/vczjk/g41;Llyiahf/vczjk/yo1;)V

    new-instance v8, Llyiahf/vczjk/d41;

    invoke-direct {v8, p0}, Llyiahf/vczjk/d41;-><init>(Llyiahf/vczjk/g41;)V

    sget-object v0, Llyiahf/vczjk/dg9;->OooO00o:Llyiahf/vczjk/df9;

    new-instance v3, Llyiahf/vczjk/yf9;

    const/4 v9, 0x0

    move-object v4, p1

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/yf9;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bf3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    invoke-static {v3, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-ne p1, p2, :cond_2

    goto :goto_2

    :cond_2
    move-object p1, v0

    :goto_2
    if-ne p1, p2, :cond_3

    return-object p1

    :cond_3
    return-object v0
.end method

.method public final o0000O00()V
    .locals 0

    invoke-virtual {p0}, Llyiahf/vczjk/g41;->o0000O0O()V

    return-void
.end method

.method public final o0000O0O()V
    .locals 23

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/g41;->OoooOOo:Llyiahf/vczjk/vr5;

    iget-object v2, v1, Llyiahf/vczjk/vr5;->OooO0OO:[Ljava/lang/Object;

    iget-object v3, v1, Llyiahf/vczjk/vr5;->OooO00o:[J

    array-length v4, v3

    add-int/lit8 v4, v4, -0x2

    const/4 v9, 0x7

    const-wide v10, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    const/16 v12, 0x8

    const/4 v13, 0x0

    if-ltz v4, :cond_3

    move v14, v13

    const-wide/16 v15, 0x80

    :goto_0
    aget-wide v5, v3, v14

    const-wide/16 v17, 0xff

    not-long v7, v5

    shl-long/2addr v7, v9

    and-long/2addr v7, v5

    and-long/2addr v7, v10

    cmp-long v7, v7, v10

    if-eqz v7, :cond_2

    sub-int v7, v14, v4

    not-int v7, v7

    ushr-int/lit8 v7, v7, 0x1f

    rsub-int/lit8 v7, v7, 0x8

    move v8, v13

    :goto_1
    if-ge v8, v7, :cond_1

    and-long v19, v5, v17

    cmp-long v19, v19, v15

    if-gez v19, :cond_0

    shl-int/lit8 v19, v14, 0x3

    add-int v19, v19, v8

    aget-object v19, v2, v19

    check-cast v19, Llyiahf/vczjk/v74;

    invoke-static/range {v19 .. v19}, Llyiahf/vczjk/qqa;->OooOOoo(Llyiahf/vczjk/v74;)V

    :cond_0
    shr-long/2addr v5, v12

    add-int/lit8 v8, v8, 0x1

    goto :goto_1

    :cond_1
    if-ne v7, v12, :cond_4

    :cond_2
    if-eq v14, v4, :cond_4

    add-int/lit8 v14, v14, 0x1

    goto :goto_0

    :cond_3
    const-wide/16 v15, 0x80

    const-wide/16 v17, 0xff

    :cond_4
    invoke-virtual {v1}, Llyiahf/vczjk/vr5;->OooO00o()V

    iget-object v1, v0, Llyiahf/vczjk/g41;->OoooOo0:Llyiahf/vczjk/vr5;

    iget-object v2, v1, Llyiahf/vczjk/vr5;->OooO0OO:[Ljava/lang/Object;

    iget-object v3, v1, Llyiahf/vczjk/vr5;->OooO00o:[J

    array-length v4, v3

    add-int/lit8 v4, v4, -0x2

    if-ltz v4, :cond_8

    move v5, v13

    :goto_2
    aget-wide v6, v3, v5

    move v8, v9

    move-wide/from16 v19, v10

    not-long v9, v6

    shl-long/2addr v9, v8

    and-long/2addr v9, v6

    and-long v9, v9, v19

    cmp-long v9, v9, v19

    if-eqz v9, :cond_7

    sub-int v9, v5, v4

    not-int v9, v9

    ushr-int/lit8 v9, v9, 0x1f

    rsub-int/lit8 v9, v9, 0x8

    move v10, v13

    :goto_3
    if-ge v10, v9, :cond_6

    and-long v21, v6, v17

    cmp-long v11, v21, v15

    if-gez v11, :cond_5

    shl-int/lit8 v11, v5, 0x3

    add-int/2addr v11, v10

    aget-object v11, v2, v11

    check-cast v11, Llyiahf/vczjk/y31;

    iget-object v11, v11, Llyiahf/vczjk/y31;->OooO00o:Llyiahf/vczjk/r09;

    invoke-static {v11}, Llyiahf/vczjk/qqa;->OooOOoo(Llyiahf/vczjk/v74;)V

    :cond_5
    shr-long/2addr v6, v12

    add-int/lit8 v10, v10, 0x1

    goto :goto_3

    :cond_6
    if-ne v9, v12, :cond_8

    :cond_7
    if-eq v5, v4, :cond_8

    add-int/lit8 v5, v5, 0x1

    move v9, v8

    move-wide/from16 v10, v19

    goto :goto_2

    :cond_8
    invoke-virtual {v1}, Llyiahf/vczjk/vr5;->OooO00o()V

    return-void
.end method

.method public final o0000Ooo(Llyiahf/vczjk/af8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/g41;->OoooOO0:Llyiahf/vczjk/le3;

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/g41;->OoooO:Ljava/lang/String;

    new-instance v1, Llyiahf/vczjk/z31;

    invoke-direct {v1, p0}, Llyiahf/vczjk/z31;-><init>(Llyiahf/vczjk/g41;)V

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ie8;->OooO0OO:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v0, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public final o0000oO(Landroid/view/KeyEvent;)V
    .locals 7

    invoke-static {p1}, Llyiahf/vczjk/yi4;->o000oOoO(Landroid/view/KeyEvent;)J

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/g41;->OoooOOo:Llyiahf/vczjk/vr5;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object v2

    const/4 v3, 0x0

    const/4 v4, 0x0

    if-eqz v2, :cond_2

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/v74;

    if-eqz v2, :cond_1

    invoke-interface {v2}, Llyiahf/vczjk/v74;->OooO0Oo()Z

    move-result v5

    if-eqz v5, :cond_0

    invoke-interface {v2, v3}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    goto :goto_0

    :cond_0
    const/4 v4, 0x1

    :cond_1
    :goto_0
    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/vr5;->OooO0o(J)Ljava/lang/Object;

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/g41;->o000oOoO:Llyiahf/vczjk/le3;

    if-eqz p1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/g41;->OoooOo0:Llyiahf/vczjk/vr5;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_3

    if-nez v4, :cond_6

    new-instance v2, Llyiahf/vczjk/y31;

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/f41;

    invoke-direct {v5, p0, v0, v1, v3}, Llyiahf/vczjk/f41;-><init>(Llyiahf/vczjk/g41;JLlyiahf/vczjk/yo1;)V

    const/4 v6, 0x3

    invoke-static {v4, v3, v3, v5, v6}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v3

    invoke-direct {v2, v3}, Llyiahf/vczjk/y31;-><init>(Llyiahf/vczjk/r09;)V

    invoke-virtual {p1, v0, v1, v2}, Llyiahf/vczjk/vr5;->OooO0oO(JLjava/lang/Object;)V

    return-void

    :cond_3
    if-nez v4, :cond_4

    iget-object v2, p0, Llyiahf/vczjk/g41;->o000oOoO:Llyiahf/vczjk/le3;

    if-eqz v2, :cond_4

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_4
    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/vr5;->OooO0o(J)Ljava/lang/Object;

    return-void

    :cond_5
    if-nez v4, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/o0000O0O;->Oooo00o:Llyiahf/vczjk/le3;

    invoke-interface {p1}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_6
    return-void
.end method

.method public final o0000oo(Landroid/view/KeyEvent;)Z
    .locals 7

    invoke-static {p1}, Llyiahf/vczjk/yi4;->o000oOoO(Landroid/view/KeyEvent;)J

    move-result-wide v0

    iget-object p1, p0, Llyiahf/vczjk/g41;->OoooOO0:Llyiahf/vczjk/le3;

    const/4 v2, 0x0

    if-eqz p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/g41;->OoooOOo:Llyiahf/vczjk/vr5;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object v3

    if-nez v3, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/e41;

    invoke-direct {v4, p0, v2}, Llyiahf/vczjk/e41;-><init>(Llyiahf/vczjk/g41;Llyiahf/vczjk/yo1;)V

    const/4 v5, 0x3

    invoke-static {v3, v2, v2, v4, v5}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v3

    invoke-virtual {p1, v0, v1, v3}, Llyiahf/vczjk/vr5;->OooO0oO(JLjava/lang/Object;)V

    const/4 p1, 0x1

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    iget-object v3, p0, Llyiahf/vczjk/g41;->OoooOo0:Llyiahf/vczjk/vr5;

    invoke-virtual {v3, v0, v1}, Llyiahf/vczjk/vr5;->OooO0Oo(J)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/y31;

    if-eqz v4, :cond_2

    iget-object v5, v4, Llyiahf/vczjk/y31;->OooO00o:Llyiahf/vczjk/r09;

    invoke-virtual {v5}, Llyiahf/vczjk/k84;->OooO0Oo()Z

    move-result v6

    if-eqz v6, :cond_1

    invoke-virtual {v5, v2}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    iget-boolean v2, v4, Llyiahf/vczjk/y31;->OooO0O0:Z

    if-nez v2, :cond_2

    iget-object v2, p0, Llyiahf/vczjk/o0000O0O;->Oooo00o:Llyiahf/vczjk/le3;

    invoke-interface {v2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    invoke-virtual {v3, v0, v1}, Llyiahf/vczjk/vr5;->OooO0o(J)Ljava/lang/Object;

    return p1

    :cond_1
    invoke-virtual {v3, v0, v1}, Llyiahf/vczjk/vr5;->OooO0o(J)Ljava/lang/Object;

    :cond_2
    return p1
.end method
