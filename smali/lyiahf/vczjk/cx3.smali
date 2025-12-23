.class public final Llyiahf/vczjk/cx3;
.super Llyiahf/vczjk/i70;
.source "SourceFile"


# instance fields
.field public Oooo:Llyiahf/vczjk/gi;

.field public OoooO:F

.field public OoooO0:Llyiahf/vczjk/gi;

.field public OoooO00:Llyiahf/vczjk/gi;

.field public OoooO0O:Llyiahf/vczjk/r09;

.field public final OoooOO0:Llyiahf/vczjk/rm0;


# direct methods
.method public constructor <init>(JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFFF)V
    .locals 10

    move-object v0, p0

    move-wide v1, p1

    move-wide v3, p3

    move-object v5, p5

    move-object/from16 v6, p6

    move/from16 v7, p7

    move/from16 v8, p9

    move/from16 v9, p10

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/i70;-><init>(JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFF)V

    const/4 p1, 0x0

    const/high16 p2, 0x3f800000    # 1.0f

    move/from16 p3, p8

    invoke-static {p3, p1, p2}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    iput p1, p0, Llyiahf/vczjk/cx3;->OoooO:F

    new-instance p1, Llyiahf/vczjk/uw3;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/uw3;-><init>(Llyiahf/vczjk/cx3;I)V

    new-instance p2, Llyiahf/vczjk/rm0;

    new-instance p3, Llyiahf/vczjk/tm0;

    invoke-direct {p3}, Llyiahf/vczjk/tm0;-><init>()V

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/rm0;-><init>(Llyiahf/vczjk/tm0;Llyiahf/vczjk/oe3;)V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object p2, p0, Llyiahf/vczjk/cx3;->OoooOO0:Llyiahf/vczjk/rm0;

    return-void
.end method


# virtual methods
.method public final o000OOo()V
    .locals 1

    const/4 v0, 0x0

    iput-object v0, p0, Llyiahf/vczjk/cx3;->Oooo:Llyiahf/vczjk/gi;

    iput-object v0, p0, Llyiahf/vczjk/cx3;->OoooO00:Llyiahf/vczjk/gi;

    iput-object v0, p0, Llyiahf/vczjk/cx3;->OoooO0:Llyiahf/vczjk/gi;

    const/4 v0, -0x1

    iput v0, p0, Llyiahf/vczjk/i70;->Oooo0oo:I

    return-void
.end method

.method public final o0O0O00()V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/cx3;->OoooO0O:Llyiahf/vczjk/r09;

    if-eqz v0, :cond_0

    invoke-static {v0}, Llyiahf/vczjk/qqa;->OooOOoo(Llyiahf/vczjk/v74;)V

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_5

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OoooOoO(Llyiahf/vczjk/xr1;)Z

    move-result v0

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/cx3;->Oooo:Llyiahf/vczjk/gi;

    const/4 v1, 0x0

    if-nez v0, :cond_2

    invoke-static {v1}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v0

    :cond_2
    iput-object v0, p0, Llyiahf/vczjk/cx3;->Oooo:Llyiahf/vczjk/gi;

    iget-object v0, p0, Llyiahf/vczjk/cx3;->OoooO00:Llyiahf/vczjk/gi;

    if-nez v0, :cond_3

    invoke-static {v1}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v0

    :cond_3
    iput-object v0, p0, Llyiahf/vczjk/cx3;->OoooO00:Llyiahf/vczjk/gi;

    iget-object v0, p0, Llyiahf/vczjk/cx3;->OoooO0:Llyiahf/vczjk/gi;

    if-nez v0, :cond_4

    const v0, 0x3dcccccd    # 0.1f

    invoke-static {v0}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v0

    :cond_4
    iput-object v0, p0, Llyiahf/vczjk/cx3;->OoooO0:Llyiahf/vczjk/gi;

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/bx3;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/bx3;-><init>(Llyiahf/vczjk/cx3;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/cx3;->OoooO0O:Llyiahf/vczjk/r09;

    :cond_5
    :goto_0
    return-void
.end method
