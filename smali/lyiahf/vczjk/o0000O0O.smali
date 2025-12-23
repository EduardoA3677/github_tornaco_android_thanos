.class public abstract Llyiahf/vczjk/o0000O0O;
.super Llyiahf/vczjk/m52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ny6;
.implements Llyiahf/vczjk/bj4;
.implements Llyiahf/vczjk/ne8;
.implements Llyiahf/vczjk/c0a;


# static fields
.field public static final OoooO0O:Llyiahf/vczjk/sp3;


# instance fields
.field public OooOoo:Llyiahf/vczjk/rr5;

.field public OooOooO:Llyiahf/vczjk/px3;

.field public OooOooo:Ljava/lang/String;

.field public Oooo:Llyiahf/vczjk/rr5;

.field public final Oooo0:Llyiahf/vczjk/n93;

.field public Oooo000:Llyiahf/vczjk/gu7;

.field public Oooo00O:Z

.field public Oooo00o:Llyiahf/vczjk/le3;

.field public Oooo0O0:Llyiahf/vczjk/nb9;

.field public Oooo0OO:Llyiahf/vczjk/l52;

.field public Oooo0o:Llyiahf/vczjk/wo3;

.field public Oooo0o0:Llyiahf/vczjk/q37;

.field public final Oooo0oO:Llyiahf/vczjk/vr5;

.field public Oooo0oo:J

.field public final OoooO0:Llyiahf/vczjk/sp3;

.field public OoooO00:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/sp3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/o0000O0O;->OoooO0O:Llyiahf/vczjk/sp3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLjava/lang/String;Llyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V
    .locals 8

    invoke-direct {p0}, Llyiahf/vczjk/m52;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    iput-object p2, p0, Llyiahf/vczjk/o0000O0O;->OooOooO:Llyiahf/vczjk/px3;

    iput-object p4, p0, Llyiahf/vczjk/o0000O0O;->OooOooo:Ljava/lang/String;

    iput-object p5, p0, Llyiahf/vczjk/o0000O0O;->Oooo000:Llyiahf/vczjk/gu7;

    iput-boolean p3, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    iput-object p6, p0, Llyiahf/vczjk/o0000O0O;->Oooo00o:Llyiahf/vczjk/le3;

    new-instance p2, Llyiahf/vczjk/n93;

    new-instance v0, Llyiahf/vczjk/o00000;

    const-string v5, "onFocusChange(Z)V"

    const/4 v6, 0x0

    const/4 v1, 0x1

    const-class v3, Llyiahf/vczjk/o0000O0O;

    const-string v4, "onFocusChange"

    const/4 v7, 0x0

    move-object v2, p0

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/o00000;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    const/4 p3, 0x0

    invoke-direct {p2, p1, p3, v0}, Llyiahf/vczjk/n93;-><init>(Llyiahf/vczjk/rr5;ILlyiahf/vczjk/o00000;)V

    iput-object p2, v2, Llyiahf/vczjk/o0000O0O;->Oooo0:Llyiahf/vczjk/n93;

    sget p1, Llyiahf/vczjk/u55;->OooO00o:I

    new-instance p1, Llyiahf/vczjk/vr5;

    const/4 p2, 0x6

    invoke-direct {p1, p2}, Llyiahf/vczjk/vr5;-><init>(I)V

    iput-object p1, v2, Llyiahf/vczjk/o0000O0O;->Oooo0oO:Llyiahf/vczjk/vr5;

    const-wide/16 p1, 0x0

    iput-wide p1, v2, Llyiahf/vczjk/o0000O0O;->Oooo0oo:J

    iget-object p1, v2, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    iput-object p1, v2, Llyiahf/vczjk/o0000O0O;->Oooo:Llyiahf/vczjk/rr5;

    if-nez p1, :cond_0

    iget-object p1, v2, Llyiahf/vczjk/o0000O0O;->OooOooO:Llyiahf/vczjk/px3;

    if-eqz p1, :cond_0

    const/4 p3, 0x1

    :cond_0
    iput-boolean p3, v2, Llyiahf/vczjk/o0000O0O;->OoooO00:Z

    sget-object p1, Llyiahf/vczjk/o0000O0O;->OoooO0O:Llyiahf/vczjk/sp3;

    iput-object p1, v2, Llyiahf/vczjk/o0000O0O;->OoooO0:Llyiahf/vczjk/sp3;

    return-void
.end method


# virtual methods
.method public final OooO0oO(Landroid/view/KeyEvent;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final OooOO0O()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->OoooO0:Llyiahf/vczjk/sp3;

    return-object v0
.end method

.method public final OooOOo(Landroid/view/KeyEvent;)Z
    .locals 10

    invoke-virtual {p0}, Llyiahf/vczjk/o0000O0O;->o0000()V

    invoke-static {p1}, Llyiahf/vczjk/yi4;->o000oOoO(Landroid/view/KeyEvent;)J

    move-result-wide v0

    iget-boolean v2, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    const/4 v3, 0x3

    const/4 v4, 0x0

    iget-object v5, p0, Llyiahf/vczjk/o0000O0O;->Oooo0oO:Llyiahf/vczjk/vr5;

    const/4 v6, 0x1

    const/4 v7, 0x0

    if-eqz v2, :cond_2

    invoke-static {p1}, Llyiahf/vczjk/yi4;->OoooOOo(Landroid/view/KeyEvent;)I

    move-result v2

    const/4 v8, 0x2

    if-ne v2, v8, :cond_2

    invoke-static {p1}, Landroidx/compose/foundation/OooO00o;->OooOO0(Landroid/view/KeyEvent;)Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-virtual {v5, v0, v1}, Llyiahf/vczjk/vr5;->OooO0O0(J)Z

    move-result v2

    if-nez v2, :cond_1

    new-instance v2, Llyiahf/vczjk/q37;

    iget-wide v8, p0, Llyiahf/vczjk/o0000O0O;->Oooo0oo:J

    invoke-direct {v2, v8, v9}, Llyiahf/vczjk/q37;-><init>(J)V

    invoke-virtual {v5, v0, v1, v2}, Llyiahf/vczjk/vr5;->OooO0oO(JLjava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    if-eqz v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/o0000Ooo;

    invoke-direct {v1, p0, v2, v4}, Llyiahf/vczjk/o0000Ooo;-><init>(Llyiahf/vczjk/o0000O0O;Llyiahf/vczjk/q37;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v4, v4, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_0
    move v0, v6

    goto :goto_0

    :cond_1
    move v0, v7

    :goto_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/o0000O0O;->o0000oo(Landroid/view/KeyEvent;)Z

    move-result p1

    if-nez p1, :cond_5

    if-eqz v0, :cond_6

    goto :goto_1

    :cond_2
    iget-boolean v2, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    if-eqz v2, :cond_6

    invoke-static {p1}, Llyiahf/vczjk/yi4;->OoooOOo(Landroid/view/KeyEvent;)I

    move-result v2

    if-ne v2, v6, :cond_6

    invoke-static {p1}, Landroidx/compose/foundation/OooO00o;->OooOO0(Landroid/view/KeyEvent;)Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-virtual {v5, v0, v1}, Llyiahf/vczjk/vr5;->OooO0o(J)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/q37;

    if-eqz v0, :cond_4

    iget-object v1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    if-eqz v1, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/o0000;

    invoke-direct {v2, p0, v0, v4}, Llyiahf/vczjk/o0000;-><init>(Llyiahf/vczjk/o0000O0O;Llyiahf/vczjk/q37;Llyiahf/vczjk/yo1;)V

    invoke-static {v1, v4, v4, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_3
    invoke-virtual {p0, p1}, Llyiahf/vczjk/o0000O0O;->o0000oO(Landroid/view/KeyEvent;)V

    :cond_4
    if-eqz v0, :cond_6

    :cond_5
    :goto_1
    return v6

    :cond_6
    return v7
.end method

.method public final OooOoo0()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/o0000O0O;->Oooo0o:Llyiahf/vczjk/wo3;

    if-eqz v1, :cond_0

    new-instance v2, Llyiahf/vczjk/xo3;

    invoke-direct {v2, v1}, Llyiahf/vczjk/xo3;-><init>(Llyiahf/vczjk/wo3;)V

    check-cast v0, Llyiahf/vczjk/sr5;

    invoke-virtual {v0, v2}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    :cond_0
    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0o:Llyiahf/vczjk/wo3;

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/nb9;->OooOoo0()V

    :cond_1
    return-void
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo000:Llyiahf/vczjk/gu7;

    if-eqz v0, :cond_0

    iget v0, v0, Llyiahf/vczjk/gu7;->OooO00o:I

    invoke-static {p1, v0}, Llyiahf/vczjk/ye8;->OooO0o(Llyiahf/vczjk/af8;I)V

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->OooOooo:Ljava/lang/String;

    new-instance v1, Llyiahf/vczjk/o000OOo;

    invoke-direct {v1, p0}, Llyiahf/vczjk/o000OOo;-><init>(Llyiahf/vczjk/o0000O0O;)V

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ie8;->OooO0O0:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v0, v1}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/je8;

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-boolean v1, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    if-eqz v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0:Llyiahf/vczjk/n93;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/n93;->OooooO0(Llyiahf/vczjk/af8;)V

    goto :goto_0

    :cond_1
    sget-object v1, Llyiahf/vczjk/ve8;->OooO:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, v1, v2}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :goto_0
    invoke-virtual {p0, p1}, Llyiahf/vczjk/o0000O0O;->o0000Ooo(Llyiahf/vczjk/af8;)V

    return-void
.end method

.method public final o0000()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0OO:Llyiahf/vczjk/l52;

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->OooOooO:Llyiahf/vczjk/px3;

    if-eqz v0, :cond_2

    iget-object v1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    if-nez v1, :cond_1

    new-instance v1, Llyiahf/vczjk/sr5;

    invoke-direct {v1}, Llyiahf/vczjk/sr5;-><init>()V

    iput-object v1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/o0000O0O;->Oooo0:Llyiahf/vczjk/n93;

    iget-object v2, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/n93;->o00000oo(Llyiahf/vczjk/rr5;)V

    iget-object v1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-interface {v0, v1}, Llyiahf/vczjk/px3;->OooO00o(Llyiahf/vczjk/n24;)Llyiahf/vczjk/l52;

    move-result-object v0

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0OO:Llyiahf/vczjk/l52;

    :cond_2
    :goto_0
    return-void
.end method

.method public abstract o00000oO(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
.end method

.method public final o00000oo()V
    .locals 17

    move-object/from16 v0, p0

    iget-object v1, v0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    iget-object v2, v0, Llyiahf/vczjk/o0000O0O;->Oooo0oO:Llyiahf/vczjk/vr5;

    if-eqz v1, :cond_5

    iget-object v3, v0, Llyiahf/vczjk/o0000O0O;->Oooo0o0:Llyiahf/vczjk/q37;

    if-eqz v3, :cond_0

    new-instance v4, Llyiahf/vczjk/p37;

    invoke-direct {v4, v3}, Llyiahf/vczjk/p37;-><init>(Llyiahf/vczjk/q37;)V

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/sr5;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    :cond_0
    iget-object v3, v0, Llyiahf/vczjk/o0000O0O;->Oooo0o:Llyiahf/vczjk/wo3;

    if-eqz v3, :cond_1

    new-instance v4, Llyiahf/vczjk/xo3;

    invoke-direct {v4, v3}, Llyiahf/vczjk/xo3;-><init>(Llyiahf/vczjk/wo3;)V

    move-object v3, v1

    check-cast v3, Llyiahf/vczjk/sr5;

    invoke-virtual {v3, v4}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    :cond_1
    iget-object v3, v2, Llyiahf/vczjk/vr5;->OooO0OO:[Ljava/lang/Object;

    iget-object v4, v2, Llyiahf/vczjk/vr5;->OooO00o:[J

    array-length v5, v4

    add-int/lit8 v5, v5, -0x2

    if-ltz v5, :cond_5

    const/4 v6, 0x0

    move v7, v6

    :goto_0
    aget-wide v8, v4, v7

    not-long v10, v8

    const/4 v12, 0x7

    shl-long/2addr v10, v12

    and-long/2addr v10, v8

    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v10, v12

    cmp-long v10, v10, v12

    if-eqz v10, :cond_4

    sub-int v10, v7, v5

    not-int v10, v10

    ushr-int/lit8 v10, v10, 0x1f

    const/16 v11, 0x8

    rsub-int/lit8 v10, v10, 0x8

    move v12, v6

    :goto_1
    if-ge v12, v10, :cond_3

    const-wide/16 v13, 0xff

    and-long/2addr v13, v8

    const-wide/16 v15, 0x80

    cmp-long v13, v13, v15

    if-gez v13, :cond_2

    shl-int/lit8 v13, v7, 0x3

    add-int/2addr v13, v12

    aget-object v13, v3, v13

    check-cast v13, Llyiahf/vczjk/q37;

    new-instance v14, Llyiahf/vczjk/p37;

    invoke-direct {v14, v13}, Llyiahf/vczjk/p37;-><init>(Llyiahf/vczjk/q37;)V

    move-object v13, v1

    check-cast v13, Llyiahf/vczjk/sr5;

    invoke-virtual {v13, v14}, Llyiahf/vczjk/sr5;->OooO0OO(Llyiahf/vczjk/j24;)Z

    :cond_2
    shr-long/2addr v8, v11

    add-int/lit8 v12, v12, 0x1

    goto :goto_1

    :cond_3
    if-ne v10, v11, :cond_5

    :cond_4
    if-eq v7, v5, :cond_5

    add-int/lit8 v7, v7, 0x1

    goto :goto_0

    :cond_5
    const/4 v1, 0x0

    iput-object v1, v0, Llyiahf/vczjk/o0000O0O;->Oooo0o0:Llyiahf/vczjk/q37;

    iput-object v1, v0, Llyiahf/vczjk/o0000O0O;->Oooo0o:Llyiahf/vczjk/wo3;

    invoke-virtual {v2}, Llyiahf/vczjk/vr5;->OooO00o()V

    return-void
.end method

.method public final o0000O0(Llyiahf/vczjk/rr5;Llyiahf/vczjk/px3;ZLjava/lang/String;Llyiahf/vczjk/gu7;Llyiahf/vczjk/le3;)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo:Llyiahf/vczjk/rr5;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/o0000O0O;->o00000oo()V

    iput-object p1, p0, Llyiahf/vczjk/o0000O0O;->Oooo:Llyiahf/vczjk/rr5;

    iput-object p1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    move p1, v2

    goto :goto_0

    :cond_0
    move p1, v1

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->OooOooO:Llyiahf/vczjk/px3;

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_1

    iput-object p2, p0, Llyiahf/vczjk/o0000O0O;->OooOooO:Llyiahf/vczjk/px3;

    move p1, v2

    :cond_1
    iget-boolean p2, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0:Llyiahf/vczjk/n93;

    if-eq p2, p3, :cond_3

    if-eqz p3, :cond_2

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    goto :goto_1

    :cond_2
    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000Oo(Llyiahf/vczjk/l52;)V

    invoke-virtual {p0}, Llyiahf/vczjk/o0000O0O;->o00000oo()V

    :goto_1
    invoke-static {p0}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    iput-boolean p3, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    :cond_3
    iget-object p2, p0, Llyiahf/vczjk/o0000O0O;->OooOooo:Ljava/lang/String;

    invoke-static {p2, p4}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_4

    iput-object p4, p0, Llyiahf/vczjk/o0000O0O;->OooOooo:Ljava/lang/String;

    invoke-static {p0}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    :cond_4
    iget-object p2, p0, Llyiahf/vczjk/o0000O0O;->Oooo000:Llyiahf/vczjk/gu7;

    invoke-static {p2, p5}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_5

    iput-object p5, p0, Llyiahf/vczjk/o0000O0O;->Oooo000:Llyiahf/vczjk/gu7;

    invoke-static {p0}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    :cond_5
    iput-object p6, p0, Llyiahf/vczjk/o0000O0O;->Oooo00o:Llyiahf/vczjk/le3;

    iget-boolean p2, p0, Llyiahf/vczjk/o0000O0O;->OoooO00:Z

    iget-object p3, p0, Llyiahf/vczjk/o0000O0O;->Oooo:Llyiahf/vczjk/rr5;

    if-nez p3, :cond_6

    iget-object p4, p0, Llyiahf/vczjk/o0000O0O;->OooOooO:Llyiahf/vczjk/px3;

    if-eqz p4, :cond_6

    move p4, v2

    goto :goto_2

    :cond_6
    move p4, v1

    :goto_2
    if-eq p2, p4, :cond_8

    if-nez p3, :cond_7

    iget-object p2, p0, Llyiahf/vczjk/o0000O0O;->OooOooO:Llyiahf/vczjk/px3;

    if-eqz p2, :cond_7

    move v1, v2

    :cond_7
    iput-boolean v1, p0, Llyiahf/vczjk/o0000O0O;->OoooO00:Z

    if-nez v1, :cond_8

    iget-object p2, p0, Llyiahf/vczjk/o0000O0O;->Oooo0OO:Llyiahf/vczjk/l52;

    if-nez p2, :cond_8

    goto :goto_3

    :cond_8
    move v2, p1

    :goto_3
    if-eqz v2, :cond_b

    iget-object p1, p0, Llyiahf/vczjk/o0000O0O;->Oooo0OO:Llyiahf/vczjk/l52;

    if-nez p1, :cond_9

    iget-boolean p2, p0, Llyiahf/vczjk/o0000O0O;->OoooO00:Z

    if-nez p2, :cond_b

    :cond_9
    if-eqz p1, :cond_a

    invoke-virtual {p0, p1}, Llyiahf/vczjk/m52;->o00000Oo(Llyiahf/vczjk/l52;)V

    :cond_a
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/o0000O0O;->Oooo0OO:Llyiahf/vczjk/l52;

    invoke-virtual {p0}, Llyiahf/vczjk/o0000O0O;->o0000()V

    :cond_b
    iget-object p1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/n93;->o00000oo(Llyiahf/vczjk/rr5;)V

    return-void
.end method

.method public o0000O00()V
    .locals 0

    return-void
.end method

.method public o0000Ooo(Llyiahf/vczjk/af8;)V
    .locals 0

    return-void
.end method

.method public abstract o0000oO(Landroid/view/KeyEvent;)V
.end method

.method public abstract o0000oo(Landroid/view/KeyEvent;)Z
.end method

.method public final o000OOo()V
    .locals 2

    invoke-virtual {p0}, Llyiahf/vczjk/o0000O0O;->o00000oo()V

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo:Llyiahf/vczjk/rr5;

    const/4 v1, 0x0

    if-nez v0, :cond_0

    iput-object v1, p0, Llyiahf/vczjk/o0000O0O;->OooOoo:Llyiahf/vczjk/rr5;

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0OO:Llyiahf/vczjk/l52;

    if-eqz v0, :cond_1

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000Oo(Llyiahf/vczjk/l52;)V

    :cond_1
    iput-object v1, p0, Llyiahf/vczjk/o0000O0O;->Oooo0OO:Llyiahf/vczjk/l52;

    return-void
.end method

.method public final o0O0O00()V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/o0000O0O;->OoooO00:Z

    if-nez v0, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/o0000O0O;->o0000()V

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0:Llyiahf/vczjk/n93;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    :cond_1
    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final o0ooOoO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 8

    const/16 v0, 0x21

    shr-long v1, p3, v0

    const/16 v3, 0x20

    shl-long/2addr v1, v3

    shl-long v4, p3, v3

    shr-long/2addr v4, v0

    const-wide v6, 0xffffffffL

    and-long/2addr v4, v6

    or-long v0, v1, v4

    shr-long v4, v0, v3

    long-to-int v2, v4

    int-to-float v2, v2

    and-long/2addr v0, v6

    long-to-int v0, v0

    int-to-float v0, v0

    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v1

    int-to-long v1, v1

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v4, v0

    shl-long v0, v1, v3

    and-long v2, v4, v6

    or-long/2addr v0, v2

    iput-wide v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0oo:J

    invoke-virtual {p0}, Llyiahf/vczjk/o0000O0O;->o0000()V

    iget-boolean v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo00O:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    sget-object v0, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    if-ne p2, v0, :cond_1

    iget v0, p1, Llyiahf/vczjk/ey6;->OooO0Oo:I

    const/4 v2, 0x4

    const/4 v3, 0x3

    if-ne v0, v2, :cond_0

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/o0000O00;

    invoke-direct {v2, p0, v1}, Llyiahf/vczjk/o0000O00;-><init>(Llyiahf/vczjk/o0000O0O;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v1, v1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    goto :goto_0

    :cond_0
    const/4 v2, 0x5

    if-ne v0, v2, :cond_1

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v2, Llyiahf/vczjk/o0000oo;

    invoke-direct {v2, p0, v1}, Llyiahf/vczjk/o0000oo;-><init>(Llyiahf/vczjk/o0000O0O;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v1, v1, v2, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    :cond_1
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-nez v0, :cond_2

    new-instance v0, Llyiahf/vczjk/o0000O0;

    const/4 v2, 0x0

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/o0000O0;-><init>(Ljava/lang/Object;I)V

    sget-object v2, Llyiahf/vczjk/gb9;->OooO00o:Llyiahf/vczjk/ey6;

    new-instance v2, Llyiahf/vczjk/nb9;

    invoke-direct {v2, v1, v1, v0}, Llyiahf/vczjk/nb9;-><init>(Ljava/lang/Object;Ljava/lang/Object;Landroidx/compose/ui/input/pointer/PointerInputEventHandler;)V

    invoke-virtual {p0, v2}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object v2, p0, Llyiahf/vczjk/o0000O0O;->Oooo0O0:Llyiahf/vczjk/nb9;

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/o0000O0O;->Oooo0O0:Llyiahf/vczjk/nb9;

    if-eqz v0, :cond_3

    invoke-virtual {v0, p1, p2, p3, p4}, Llyiahf/vczjk/nb9;->ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V

    :cond_3
    return-void
.end method
