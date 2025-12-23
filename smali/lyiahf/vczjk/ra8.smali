.class public final Llyiahf/vczjk/ra8;
.super Llyiahf/vczjk/kf2;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bj4;
.implements Llyiahf/vczjk/ne8;
.implements Llyiahf/vczjk/ug1;


# instance fields
.field public final Oooo:Llyiahf/vczjk/db8;

.field public Oooo0OO:Llyiahf/vczjk/qg6;

.field public final Oooo0o:Llyiahf/vczjk/fz5;

.field public Oooo0o0:Llyiahf/vczjk/o23;

.field public final Oooo0oO:Llyiahf/vczjk/aa8;

.field public final Oooo0oo:Llyiahf/vczjk/f22;

.field public OoooO:Llyiahf/vczjk/qa8;

.field public final OoooO0:Llyiahf/vczjk/um1;

.field public final OoooO00:Llyiahf/vczjk/fa8;

.field public OoooO0O:Llyiahf/vczjk/pa8;

.field public OoooOO0:Llyiahf/vczjk/tp5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/o23;Llyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;Llyiahf/vczjk/qg6;Llyiahf/vczjk/rk6;Llyiahf/vczjk/sa8;ZZ)V
    .locals 9

    move/from16 v8, p7

    sget-object v0, Llyiahf/vczjk/o68;->OooOo:Llyiahf/vczjk/o68;

    invoke-direct {p0, v0, v8, p2, p3}, Llyiahf/vczjk/kf2;-><init>(Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;)V

    iput-object p4, p0, Llyiahf/vczjk/ra8;->Oooo0OO:Llyiahf/vczjk/qg6;

    iput-object p1, p0, Llyiahf/vczjk/ra8;->Oooo0o0:Llyiahf/vczjk/o23;

    new-instance v6, Llyiahf/vczjk/fz5;

    invoke-direct {v6}, Llyiahf/vczjk/fz5;-><init>()V

    iput-object v6, p0, Llyiahf/vczjk/ra8;->Oooo0o:Llyiahf/vczjk/fz5;

    new-instance v0, Llyiahf/vczjk/aa8;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-boolean v8, v0, Llyiahf/vczjk/aa8;->OooOoOO:Z

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object v0, p0, Llyiahf/vczjk/ra8;->Oooo0oO:Llyiahf/vczjk/aa8;

    new-instance v0, Llyiahf/vczjk/f22;

    new-instance v1, Llyiahf/vczjk/fk7;

    sget-object v2, Landroidx/compose/foundation/gestures/OooO0O0;->OooO0OO:Llyiahf/vczjk/mm6;

    invoke-direct {v1, v2}, Llyiahf/vczjk/fk7;-><init>(Llyiahf/vczjk/f62;)V

    new-instance v2, Llyiahf/vczjk/t02;

    invoke-direct {v2, v1}, Llyiahf/vczjk/t02;-><init>(Llyiahf/vczjk/fk7;)V

    invoke-direct {v0, v2}, Llyiahf/vczjk/f22;-><init>(Llyiahf/vczjk/t02;)V

    iput-object v0, p0, Llyiahf/vczjk/ra8;->Oooo0oo:Llyiahf/vczjk/f22;

    iget-object v2, p0, Llyiahf/vczjk/ra8;->Oooo0OO:Llyiahf/vczjk/qg6;

    iget-object v1, p0, Llyiahf/vczjk/ra8;->Oooo0o0:Llyiahf/vczjk/o23;

    if-nez v1, :cond_0

    move-object v3, v0

    goto :goto_0

    :cond_0
    move-object v3, v1

    :goto_0
    new-instance v0, Llyiahf/vczjk/db8;

    new-instance v7, Llyiahf/vczjk/na8;

    invoke-direct {v7, p0}, Llyiahf/vczjk/na8;-><init>(Llyiahf/vczjk/ra8;)V

    move-object v4, p3

    move-object v1, p6

    move/from16 v5, p8

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/db8;-><init>(Llyiahf/vczjk/sa8;Llyiahf/vczjk/qg6;Llyiahf/vczjk/o23;Llyiahf/vczjk/nf6;ZLlyiahf/vczjk/fz5;Llyiahf/vczjk/na8;)V

    iput-object v0, p0, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    new-instance v1, Llyiahf/vczjk/fa8;

    invoke-direct {v1, v0, v8}, Llyiahf/vczjk/fa8;-><init>(Llyiahf/vczjk/db8;Z)V

    iput-object v1, p0, Llyiahf/vczjk/ra8;->OoooO00:Llyiahf/vczjk/fa8;

    new-instance v2, Llyiahf/vczjk/um1;

    invoke-direct {v2, p3, v0, v5, p5}, Llyiahf/vczjk/um1;-><init>(Llyiahf/vczjk/nf6;Llyiahf/vczjk/db8;ZLlyiahf/vczjk/rk6;)V

    invoke-virtual {p0, v2}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object v2, p0, Llyiahf/vczjk/ra8;->OoooO0:Llyiahf/vczjk/um1;

    new-instance v0, Llyiahf/vczjk/jz5;

    invoke-direct {v0, v1, v6}, Llyiahf/vczjk/jz5;-><init>(Llyiahf/vczjk/bz5;Llyiahf/vczjk/fz5;)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    new-instance v0, Llyiahf/vczjk/d93;

    const/4 v1, 0x4

    const/4 v3, 0x2

    const/4 v4, 0x0

    invoke-direct {v0, v3, v4, v1}, Llyiahf/vczjk/d93;-><init>(ILlyiahf/vczjk/fa;I)V

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    new-instance v0, Llyiahf/vczjk/di0;

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object v2, v0, Llyiahf/vczjk/di0;->OooOoOO:Llyiahf/vczjk/um1;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    new-instance v0, Llyiahf/vczjk/o93;

    new-instance v1, Llyiahf/vczjk/ga8;

    invoke-direct {v1, p0}, Llyiahf/vczjk/ga8;-><init>(Llyiahf/vczjk/ra8;)V

    invoke-direct {v0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object v1, v0, Llyiahf/vczjk/o93;->OooOoOO:Llyiahf/vczjk/ga8;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    return-void
.end method


# virtual methods
.method public final OooO0Oo()V
    .locals 3

    invoke-virtual {p0}, Llyiahf/vczjk/kf2;->OooOoo0()V

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    iget-object v1, p0, Llyiahf/vczjk/ra8;->Oooo0oo:Llyiahf/vczjk/f22;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/fk7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/fk7;-><init>(Llyiahf/vczjk/f62;)V

    new-instance v0, Llyiahf/vczjk/t02;

    invoke-direct {v0, v2}, Llyiahf/vczjk/t02;-><init>(Llyiahf/vczjk/fk7;)V

    iput-object v0, v1, Llyiahf/vczjk/f22;->OooO00o:Llyiahf/vczjk/t02;

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ra8;->OoooOO0:Llyiahf/vczjk/tp5;

    if-eqz v0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    iput-object v1, v0, Llyiahf/vczjk/tp5;->OooO0Oo:Llyiahf/vczjk/f62;

    :cond_1
    return-void
.end method

.method public final OooO0oO(Landroid/view/KeyEvent;)Z
    .locals 0

    const/4 p1, 0x0

    return p1
.end method

.method public final OooOOo(Landroid/view/KeyEvent;)Z
    .locals 11

    iget-boolean v0, p0, Llyiahf/vczjk/kf2;->OooOooo:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_5

    invoke-static {p1}, Llyiahf/vczjk/yi4;->o000oOoO(Landroid/view/KeyEvent;)J

    move-result-wide v2

    sget-wide v4, Llyiahf/vczjk/mi4;->OooOOO:J

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/mi4;->OooO00o(JJ)Z

    move-result v0

    if-nez v0, :cond_0

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/ye5;->OooO0o0(I)J

    move-result-wide v2

    sget-wide v4, Llyiahf/vczjk/mi4;->OooOOO0:J

    invoke-static {v2, v3, v4, v5}, Llyiahf/vczjk/mi4;->OooO00o(JJ)Z

    move-result v0

    if-eqz v0, :cond_5

    :cond_0
    invoke-static {p1}, Llyiahf/vczjk/yi4;->OoooOOo(Landroid/view/KeyEvent;)I

    move-result v0

    const/4 v2, 0x2

    if-ne v0, v2, :cond_5

    invoke-virtual {p1}, Landroid/view/KeyEvent;->isCtrlPressed()Z

    move-result v0

    if-nez v0, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    iget-object v0, v0, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v2, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    const/4 v3, 0x1

    if-ne v0, v2, :cond_1

    move v1, v3

    :cond_1
    const/4 v0, 0x0

    iget-object v2, p0, Llyiahf/vczjk/ra8;->OoooO0:Llyiahf/vczjk/um1;

    const/16 v4, 0x20

    const-wide v5, 0xffffffffL

    if-eqz v1, :cond_3

    iget-wide v1, v2, Llyiahf/vczjk/um1;->Oooo0:J

    and-long/2addr v1, v5

    long-to-int v1, v1

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/ye5;->OooO0o0(I)J

    move-result-wide v7

    sget-wide v9, Llyiahf/vczjk/mi4;->OooOOO0:J

    invoke-static {v7, v8, v9, v10}, Llyiahf/vczjk/mi4;->OooO00o(JJ)Z

    move-result p1

    if-eqz p1, :cond_2

    int-to-float p1, v1

    goto :goto_0

    :cond_2
    int-to-float p1, v1

    neg-float p1, p1

    :goto_0
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v0

    int-to-long v0, v0

    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v7, p1

    shl-long/2addr v0, v4

    :goto_1
    and-long v4, v7, v5

    or-long/2addr v0, v4

    goto :goto_3

    :cond_3
    iget-wide v1, v2, Llyiahf/vczjk/um1;->Oooo0:J

    shr-long/2addr v1, v4

    long-to-int v1, v1

    invoke-virtual {p1}, Landroid/view/KeyEvent;->getKeyCode()I

    move-result p1

    invoke-static {p1}, Llyiahf/vczjk/ye5;->OooO0o0(I)J

    move-result-wide v7

    sget-wide v9, Llyiahf/vczjk/mi4;->OooOOO0:J

    invoke-static {v7, v8, v9, v10}, Llyiahf/vczjk/mi4;->OooO00o(JJ)Z

    move-result p1

    if-eqz p1, :cond_4

    int-to-float p1, v1

    goto :goto_2

    :cond_4
    int-to-float p1, v1

    neg-float p1, p1

    :goto_2
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v1, p1

    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result p1

    int-to-long v7, p1

    shl-long v0, v1, v4

    goto :goto_1

    :goto_3
    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object p1

    new-instance v2, Llyiahf/vczjk/la8;

    const/4 v4, 0x0

    invoke-direct {v2, p0, v0, v1, v4}, Llyiahf/vczjk/la8;-><init>(Llyiahf/vczjk/ra8;JLlyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {p1, v4, v4, v2, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return v3

    :cond_5
    return v1
.end method

.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 4

    iget-boolean v0, p0, Llyiahf/vczjk/kf2;->OooOooo:Z

    const/4 v1, 0x0

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/ra8;->OoooO0O:Llyiahf/vczjk/pa8;

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/ra8;->OoooO:Llyiahf/vczjk/qa8;

    if-nez v0, :cond_1

    :cond_0
    new-instance v0, Llyiahf/vczjk/pa8;

    invoke-direct {v0, p0}, Llyiahf/vczjk/pa8;-><init>(Llyiahf/vczjk/ra8;)V

    iput-object v0, p0, Llyiahf/vczjk/ra8;->OoooO0O:Llyiahf/vczjk/pa8;

    new-instance v0, Llyiahf/vczjk/qa8;

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/qa8;-><init>(Llyiahf/vczjk/ra8;Llyiahf/vczjk/yo1;)V

    iput-object v0, p0, Llyiahf/vczjk/ra8;->OoooO:Llyiahf/vczjk/qa8;

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/ra8;->OoooO0O:Llyiahf/vczjk/pa8;

    if-eqz v0, :cond_2

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v2, Llyiahf/vczjk/ie8;->OooO0Oo:Llyiahf/vczjk/ze8;

    new-instance v3, Llyiahf/vczjk/o0O00O;

    invoke-direct {v3, v1, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/je8;

    invoke-virtual {v0, v2, v3}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/ra8;->OoooO:Llyiahf/vczjk/qa8;

    if-eqz v0, :cond_3

    sget-object v1, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    sget-object v1, Llyiahf/vczjk/ie8;->OooO0o0:Llyiahf/vczjk/ze8;

    check-cast p1, Llyiahf/vczjk/je8;

    invoke-virtual {p1, v1, v0}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_3
    return-void
.end method

.method public final o0000O0()Z
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    iget-object v1, v0, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v1}, Llyiahf/vczjk/sa8;->OooO00o()Z

    move-result v1

    if-nez v1, :cond_8

    iget-object v0, v0, Llyiahf/vczjk/db8;->OooO0O0:Llyiahf/vczjk/qg6;

    if-eqz v0, :cond_7

    check-cast v0, Llyiahf/vczjk/cd;

    iget-object v0, v0, Llyiahf/vczjk/cd;->OooO0OO:Llyiahf/vczjk/nk2;

    iget-object v1, v0, Llyiahf/vczjk/nk2;->OooO0Oo:Landroid/widget/EdgeEffect;

    const/16 v2, 0x1f

    const/4 v3, 0x0

    if-eqz v1, :cond_1

    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v4, v2, :cond_0

    invoke-static {v1}, Llyiahf/vczjk/yo;->OooO0O0(Landroid/widget/EdgeEffect;)F

    move-result v1

    goto :goto_0

    :cond_0
    move v1, v3

    :goto_0
    cmpg-float v1, v1, v3

    if-nez v1, :cond_8

    :cond_1
    iget-object v1, v0, Llyiahf/vczjk/nk2;->OooO0o0:Landroid/widget/EdgeEffect;

    if-eqz v1, :cond_3

    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v4, v2, :cond_2

    invoke-static {v1}, Llyiahf/vczjk/yo;->OooO0O0(Landroid/widget/EdgeEffect;)F

    move-result v1

    goto :goto_1

    :cond_2
    move v1, v3

    :goto_1
    cmpg-float v1, v1, v3

    if-nez v1, :cond_8

    :cond_3
    iget-object v1, v0, Llyiahf/vczjk/nk2;->OooO0o:Landroid/widget/EdgeEffect;

    if-eqz v1, :cond_5

    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v4, v2, :cond_4

    invoke-static {v1}, Llyiahf/vczjk/yo;->OooO0O0(Landroid/widget/EdgeEffect;)F

    move-result v1

    goto :goto_2

    :cond_4
    move v1, v3

    :goto_2
    cmpg-float v1, v1, v3

    if-nez v1, :cond_8

    :cond_5
    iget-object v0, v0, Llyiahf/vczjk/nk2;->OooO0oO:Landroid/widget/EdgeEffect;

    if-eqz v0, :cond_7

    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    if-lt v1, v2, :cond_6

    invoke-static {v0}, Llyiahf/vczjk/yo;->OooO0O0(Landroid/widget/EdgeEffect;)F

    move-result v0

    goto :goto_3

    :cond_6
    move v0, v3

    :goto_3
    cmpg-float v0, v0, v3

    if-nez v0, :cond_8

    :cond_7
    const/4 v0, 0x0

    return v0

    :cond_8
    const/4 v0, 0x1

    return v0
.end method

.method public final o0000O00(Llyiahf/vczjk/if2;Llyiahf/vczjk/jf2;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/at5;->OooOOO:Llyiahf/vczjk/at5;

    new-instance v1, Llyiahf/vczjk/ia8;

    iget-object v2, p0, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    const/4 v3, 0x0

    invoke-direct {v1, v3, p1, v2}, Llyiahf/vczjk/ia8;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/ze3;Llyiahf/vczjk/db8;)V

    invoke-virtual {v2, v0, v1, p2}, Llyiahf/vczjk/db8;->OooO0o0(Llyiahf/vczjk/at5;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

.method public final o0000oO(J)V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ra8;->Oooo0o:Llyiahf/vczjk/fz5;

    invoke-virtual {v0}, Llyiahf/vczjk/fz5;->OooO0OO()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/ja8;

    const/4 v2, 0x0

    invoke-direct {v1, p0, p1, p2, v2}, Llyiahf/vczjk/ja8;-><init>(Llyiahf/vczjk/ra8;JLlyiahf/vczjk/yo1;)V

    const/4 p1, 0x3

    invoke-static {v0, v2, v2, v1, p1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final o0000oo(J)V
    .locals 0

    return-void
.end method

.method public final o000OO(Llyiahf/vczjk/o23;Llyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;Llyiahf/vczjk/qg6;Llyiahf/vczjk/rk6;Llyiahf/vczjk/sa8;ZZ)V
    .locals 11

    move-object/from16 v2, p6

    move/from16 v3, p7

    move/from16 v4, p8

    iget-boolean v5, p0, Llyiahf/vczjk/kf2;->OooOooo:Z

    const/4 v6, 0x1

    const/4 v7, 0x0

    if-eq v5, v3, :cond_0

    iget-object v5, p0, Llyiahf/vczjk/ra8;->OoooO00:Llyiahf/vczjk/fa8;

    iput-boolean v3, v5, Llyiahf/vczjk/fa8;->OooOOO:Z

    iget-object v5, p0, Llyiahf/vczjk/ra8;->Oooo0oO:Llyiahf/vczjk/aa8;

    iput-boolean v3, v5, Llyiahf/vczjk/aa8;->OooOoOO:Z

    move v8, v6

    goto :goto_0

    :cond_0
    move v8, v7

    :goto_0
    if-nez p1, :cond_1

    iget-object v5, p0, Llyiahf/vczjk/ra8;->Oooo0oo:Llyiahf/vczjk/f22;

    goto :goto_1

    :cond_1
    move-object v5, p1

    :goto_1
    iget-object v9, p0, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    iget-object v10, v9, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-static {v10, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v10

    if-nez v10, :cond_2

    iput-object v2, v9, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    move v7, v6

    :cond_2
    iput-object p4, v9, Llyiahf/vczjk/db8;->OooO0O0:Llyiahf/vczjk/qg6;

    iget-object v2, v9, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    if-eq v2, p3, :cond_3

    iput-object p3, v9, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    move v7, v6

    :cond_3
    iget-boolean v2, v9, Llyiahf/vczjk/db8;->OooO0o0:Z

    if-eq v2, v4, :cond_4

    iput-boolean v4, v9, Llyiahf/vczjk/db8;->OooO0o0:Z

    goto :goto_2

    :cond_4
    move v6, v7

    :goto_2
    iput-object v5, v9, Llyiahf/vczjk/db8;->OooO0OO:Llyiahf/vczjk/o23;

    iget-object v2, p0, Llyiahf/vczjk/ra8;->Oooo0o:Llyiahf/vczjk/fz5;

    iput-object v2, v9, Llyiahf/vczjk/db8;->OooO0o:Llyiahf/vczjk/fz5;

    iget-object v2, p0, Llyiahf/vczjk/ra8;->OoooO0:Llyiahf/vczjk/um1;

    iput-object p3, v2, Llyiahf/vczjk/um1;->OooOoOO:Llyiahf/vczjk/nf6;

    iput-boolean v4, v2, Llyiahf/vczjk/um1;->OooOoo:Z

    move-object/from16 v0, p5

    iput-object v0, v2, Llyiahf/vczjk/um1;->OooOooO:Llyiahf/vczjk/rk6;

    iput-object p4, p0, Llyiahf/vczjk/ra8;->Oooo0OO:Llyiahf/vczjk/qg6;

    iput-object p1, p0, Llyiahf/vczjk/ra8;->Oooo0o0:Llyiahf/vczjk/o23;

    sget-object v1, Llyiahf/vczjk/o68;->OooOo:Llyiahf/vczjk/o68;

    iget-object p1, v9, Llyiahf/vczjk/db8;->OooO0Oo:Llyiahf/vczjk/nf6;

    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    if-ne p1, v0, :cond_5

    :goto_3
    move-object v4, v0

    move v2, v3

    move v5, v6

    move-object v0, p0

    move-object v3, p2

    goto :goto_4

    :cond_5
    sget-object v0, Llyiahf/vczjk/nf6;->OooOOO:Llyiahf/vczjk/nf6;

    goto :goto_3

    :goto_4
    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/kf2;->o0000O0O(Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rr5;Llyiahf/vczjk/nf6;Z)V

    if-eqz v8, :cond_6

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/ra8;->OoooO0O:Llyiahf/vczjk/pa8;

    iput-object p1, p0, Llyiahf/vczjk/ra8;->OoooO:Llyiahf/vczjk/qa8;

    invoke-static {p0}, Llyiahf/vczjk/ll6;->OooO(Llyiahf/vczjk/ne8;)V

    :cond_6
    return-void
.end method

.method public final o0O0O00()V
    .locals 3

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    iget-object v1, p0, Llyiahf/vczjk/ra8;->Oooo0oo:Llyiahf/vczjk/f22;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v2, Llyiahf/vczjk/fk7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/fk7;-><init>(Llyiahf/vczjk/f62;)V

    new-instance v0, Llyiahf/vczjk/t02;

    invoke-direct {v0, v2}, Llyiahf/vczjk/t02;-><init>(Llyiahf/vczjk/fk7;)V

    iput-object v0, v1, Llyiahf/vczjk/f22;->OooO00o:Llyiahf/vczjk/t02;

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/ra8;->OoooOO0:Llyiahf/vczjk/tp5;

    if-eqz v0, :cond_1

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    iput-object v1, v0, Llyiahf/vczjk/tp5;->OooO0Oo:Llyiahf/vczjk/f62;

    :cond_1
    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V
    .locals 17

    move-object/from16 v2, p0

    move-object/from16 v8, p1

    move-object/from16 v9, p2

    iget-object v0, v8, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/util/Collection;->size()I

    move-result v1

    const/4 v10, 0x0

    move v3, v10

    :goto_0
    if-ge v3, v1, :cond_1

    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ky6;

    iget-object v5, v2, Llyiahf/vczjk/kf2;->OooOooO:Llyiahf/vczjk/rm4;

    invoke-interface {v5, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/Boolean;

    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v4

    if-eqz v4, :cond_0

    invoke-super/range {p0 .. p4}, Llyiahf/vczjk/kf2;->ooOO(Llyiahf/vczjk/ey6;Llyiahf/vczjk/fy6;J)V

    goto :goto_1

    :cond_0
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    :cond_1
    :goto_1
    iget-boolean v0, v2, Llyiahf/vczjk/kf2;->OooOooo:Z

    if-eqz v0, :cond_c

    sget-object v0, Llyiahf/vczjk/fy6;->OooOOO0:Llyiahf/vczjk/fy6;

    const/4 v11, 0x6

    if-ne v9, v0, :cond_3

    iget v0, v8, Llyiahf/vczjk/ey6;->OooO0Oo:I

    if-ne v0, v11, :cond_3

    iget-object v0, v2, Llyiahf/vczjk/ra8;->OoooOO0:Llyiahf/vczjk/tp5;

    if-nez v0, :cond_2

    new-instance v12, Llyiahf/vczjk/tp5;

    new-instance v13, Llyiahf/vczjk/vz5;

    invoke-static {v2}, Llyiahf/vczjk/ye5;->OooOooO(Llyiahf/vczjk/l52;)Landroid/view/View;

    move-result-object v0

    invoke-virtual {v0}, Landroid/view/View;->getContext()Landroid/content/Context;

    move-result-object v0

    invoke-static {v0}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    move-result-object v0

    const/4 v1, 0x4

    invoke-direct {v13, v0, v1}, Llyiahf/vczjk/vz5;-><init>(Ljava/lang/Object;I)V

    new-instance v0, Llyiahf/vczjk/v81;

    const-class v3, Llyiahf/vczjk/ra8;

    const-string v4, "onWheelScrollStopped"

    const/4 v1, 0x2

    const-string v5, "onWheelScrollStopped-TH1AsA0(J)V"

    const/4 v6, 0x4

    const/4 v7, 0x2

    invoke-direct/range {v0 .. v7}, Llyiahf/vczjk/v81;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    invoke-static {v2}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0OO:Llyiahf/vczjk/f62;

    iget-object v3, v2, Llyiahf/vczjk/ra8;->Oooo:Llyiahf/vczjk/db8;

    invoke-direct {v12, v3, v13, v0, v1}, Llyiahf/vczjk/tp5;-><init>(Llyiahf/vczjk/db8;Llyiahf/vczjk/vz5;Llyiahf/vczjk/v81;Llyiahf/vczjk/f62;)V

    iput-object v12, v2, Llyiahf/vczjk/ra8;->OoooOO0:Llyiahf/vczjk/tp5;

    :cond_2
    iget-object v0, v2, Llyiahf/vczjk/ra8;->OoooOO0:Llyiahf/vczjk/tp5;

    if-eqz v0, :cond_3

    invoke-virtual {v2}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v1

    iget-object v3, v0, Llyiahf/vczjk/tp5;->OooO0oO:Llyiahf/vczjk/r09;

    if-nez v3, :cond_3

    new-instance v3, Llyiahf/vczjk/op5;

    const/4 v4, 0x0

    invoke-direct {v3, v0, v4}, Llyiahf/vczjk/op5;-><init>(Llyiahf/vczjk/tp5;Llyiahf/vczjk/yo1;)V

    const/4 v5, 0x3

    invoke-static {v1, v4, v4, v3, v5}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/tp5;->OooO0oO:Llyiahf/vczjk/r09;

    :cond_3
    iget-object v0, v2, Llyiahf/vczjk/ra8;->OoooOO0:Llyiahf/vczjk/tp5;

    if-eqz v0, :cond_c

    sget-object v1, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    if-ne v9, v1, :cond_c

    iget v1, v8, Llyiahf/vczjk/ey6;->OooO0Oo:I

    if-ne v1, v11, :cond_c

    iget-object v1, v8, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v3

    move v4, v10

    :goto_2
    if-ge v4, v3, :cond_5

    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/ky6;

    invoke-virtual {v5}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v5

    if-eqz v5, :cond_4

    goto/16 :goto_b

    :cond_4
    add-int/lit8 v4, v4, 0x1

    goto :goto_2

    :cond_5
    iget-object v3, v0, Llyiahf/vczjk/tp5;->OooO0Oo:Llyiahf/vczjk/f62;

    sget v4, Landroid/os/Build$VERSION;->SDK_INT:I

    iget-object v5, v0, Llyiahf/vczjk/tp5;->OooO0O0:Llyiahf/vczjk/vz5;

    iget-object v5, v5, Llyiahf/vczjk/vz5;->OooOOO:Ljava/lang/Object;

    check-cast v5, Landroid/view/ViewConfiguration;

    const/16 v6, 0x40

    const/16 v7, 0x1a

    if-le v4, v7, :cond_6

    invoke-static {v5}, Llyiahf/vczjk/d31;->OooOO0(Landroid/view/ViewConfiguration;)F

    move-result v8

    :goto_3
    neg-float v8, v8

    goto :goto_4

    :cond_6
    int-to-float v8, v6

    invoke-interface {v3, v8}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v8

    goto :goto_3

    :goto_4
    if-le v4, v7, :cond_7

    invoke-static {v5}, Llyiahf/vczjk/d31;->OooO0o(Landroid/view/ViewConfiguration;)F

    move-result v3

    :goto_5
    neg-float v3, v3

    goto :goto_6

    :cond_7
    int-to-float v4, v6

    invoke-interface {v3, v4}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v3

    goto :goto_5

    :goto_6
    new-instance v4, Llyiahf/vczjk/p86;

    const-wide/16 v5, 0x0

    invoke-direct {v4, v5, v6}, Llyiahf/vczjk/p86;-><init>(J)V

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v5

    move v6, v10

    :goto_7
    iget-wide v11, v4, Llyiahf/vczjk/p86;->OooO00o:J

    if-ge v6, v5, :cond_8

    invoke-interface {v1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/ky6;

    iget-wide v13, v4, Llyiahf/vczjk/ky6;->OooOO0:J

    invoke-static {v11, v12, v13, v14}, Llyiahf/vczjk/p86;->OooO0o(JJ)J

    move-result-wide v11

    new-instance v4, Llyiahf/vczjk/p86;

    invoke-direct {v4, v11, v12}, Llyiahf/vczjk/p86;-><init>(J)V

    add-int/lit8 v6, v6, 0x1

    goto :goto_7

    :cond_8
    const/16 v4, 0x20

    shr-long v5, v11, v4

    long-to-int v5, v5

    invoke-static {v5}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v5

    mul-float/2addr v5, v3

    const-wide v6, 0xffffffffL

    and-long/2addr v11, v6

    long-to-int v3, v11

    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v3

    mul-float/2addr v3, v8

    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v5

    int-to-long v8, v5

    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    move-result v3

    int-to-long v11, v3

    shl-long v3, v8, v4

    and-long v5, v11, v6

    or-long v12, v3, v5

    iget-object v3, v0, Llyiahf/vczjk/tp5;->OooO00o:Llyiahf/vczjk/db8;

    invoke-virtual {v3, v12, v13}, Llyiahf/vczjk/db8;->OooO0Oo(J)J

    move-result-wide v4

    invoke-virtual {v3, v4, v5}, Llyiahf/vczjk/db8;->OooO0o(J)F

    move-result v4

    const/4 v5, 0x0

    cmpg-float v6, v4, v5

    if-nez v6, :cond_9

    move v3, v10

    goto :goto_8

    :cond_9
    cmpl-float v4, v4, v5

    if-lez v4, :cond_a

    iget-object v3, v3, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v3}, Llyiahf/vczjk/sa8;->OooO0Oo()Z

    move-result v3

    goto :goto_8

    :cond_a
    iget-object v3, v3, Llyiahf/vczjk/db8;->OooO00o:Llyiahf/vczjk/sa8;

    invoke-interface {v3}, Llyiahf/vczjk/sa8;->OooO0O0()Z

    move-result v3

    :goto_8
    if-eqz v3, :cond_b

    iget-object v0, v0, Llyiahf/vczjk/tp5;->OooO0o0:Llyiahf/vczjk/jj0;

    new-instance v11, Llyiahf/vczjk/fp5;

    invoke-static {v1}, Llyiahf/vczjk/d21;->o00o0O(Ljava/util/List;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ky6;

    iget-wide v14, v3, Llyiahf/vczjk/ky6;->OooO0O0:J

    const/16 v16, 0x0

    invoke-direct/range {v11 .. v16}, Llyiahf/vczjk/fp5;-><init>(JJZ)V

    invoke-interface {v0, v11}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    instance-of v0, v0, Llyiahf/vczjk/it0;

    xor-int/lit8 v0, v0, 0x1

    goto :goto_9

    :cond_b
    iget-boolean v0, v0, Llyiahf/vczjk/tp5;->OooO0o:Z

    :goto_9
    if-eqz v0, :cond_c

    invoke-interface {v1}, Ljava/util/Collection;->size()I

    move-result v0

    :goto_a
    if-ge v10, v0, :cond_c

    invoke-interface {v1, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ky6;

    invoke-virtual {v3}, Llyiahf/vczjk/ky6;->OooO00o()V

    add-int/lit8 v10, v10, 0x1

    goto :goto_a

    :cond_c
    :goto_b
    return-void
.end method
