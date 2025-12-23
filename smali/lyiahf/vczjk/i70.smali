.class public abstract Llyiahf/vczjk/i70;
.super Llyiahf/vczjk/m52;
.source "SourceFile"


# instance fields
.field public OooOoo:J

.field public OooOooO:J

.field public OooOooo:Llyiahf/vczjk/h79;

.field public Oooo0:F

.field public Oooo000:Llyiahf/vczjk/h79;

.field public Oooo00O:F

.field public Oooo00o:F

.field public final Oooo0O0:Llyiahf/vczjk/rx0;

.field public final Oooo0OO:Llyiahf/vczjk/hx0;

.field public Oooo0o:Llyiahf/vczjk/gi;

.field public final Oooo0o0:Llyiahf/vczjk/lr5;

.field public Oooo0oO:Llyiahf/vczjk/r09;

.field public Oooo0oo:I


# direct methods
.method public constructor <init>(JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFF)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/m52;-><init>()V

    iput-wide p1, p0, Llyiahf/vczjk/i70;->OooOoo:J

    iput-wide p3, p0, Llyiahf/vczjk/i70;->OooOooO:J

    iput-object p5, p0, Llyiahf/vczjk/i70;->OooOooo:Llyiahf/vczjk/h79;

    iput-object p6, p0, Llyiahf/vczjk/i70;->Oooo000:Llyiahf/vczjk/h79;

    iput p7, p0, Llyiahf/vczjk/i70;->Oooo00O:F

    iput p8, p0, Llyiahf/vczjk/i70;->Oooo00o:F

    iput p9, p0, Llyiahf/vczjk/i70;->Oooo0:F

    new-instance p1, Llyiahf/vczjk/rx0;

    invoke-direct {p1}, Llyiahf/vczjk/rx0;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i70;->Oooo0O0:Llyiahf/vczjk/rx0;

    new-instance p1, Llyiahf/vczjk/hx0;

    invoke-direct {p1}, Llyiahf/vczjk/hx0;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i70;->Oooo0OO:Llyiahf/vczjk/hx0;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooO0o(F)Llyiahf/vczjk/lr5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/i70;->Oooo0o0:Llyiahf/vczjk/lr5;

    const/4 p1, -0x1

    iput p1, p0, Llyiahf/vczjk/i70;->Oooo0oo:I

    return-void
.end method


# virtual methods
.method public final o0000Ooo()V
    .locals 5

    iget-object v0, p0, Llyiahf/vczjk/i70;->Oooo0oO:Llyiahf/vczjk/r09;

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    invoke-virtual {v0, v1}, Llyiahf/vczjk/k84;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    :cond_0
    iput-object v1, p0, Llyiahf/vczjk/i70;->Oooo0oO:Llyiahf/vczjk/r09;

    iput-object v1, p0, Llyiahf/vczjk/i70;->Oooo0o:Llyiahf/vczjk/gi;

    iget-boolean v0, p0, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz v0, :cond_3

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/v34;->OoooOoO(Llyiahf/vczjk/xr1;)Z

    move-result v0

    if-eqz v0, :cond_3

    move-object v0, p0

    check-cast v0, Llyiahf/vczjk/cx3;

    iget v0, v0, Llyiahf/vczjk/cx3;->OoooO:F

    const/4 v2, 0x0

    cmpl-float v0, v0, v2

    if-lez v0, :cond_3

    iget v0, p0, Llyiahf/vczjk/i70;->Oooo0:F

    const/4 v3, 0x0

    int-to-float v3, v3

    invoke-static {v0, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    iget-object v4, p0, Llyiahf/vczjk/i70;->Oooo0o0:Llyiahf/vczjk/lr5;

    if-lez v0, :cond_2

    iget v0, p0, Llyiahf/vczjk/i70;->Oooo00o:F

    invoke-static {v0, v3}, Ljava/lang/Float;->compare(FF)I

    move-result v0

    if-lez v0, :cond_2

    iget v0, p0, Llyiahf/vczjk/i70;->Oooo0oo:I

    if-lez v0, :cond_2

    iget v2, p0, Llyiahf/vczjk/i70;->Oooo00o:F

    iget v3, p0, Llyiahf/vczjk/i70;->Oooo0:F

    div-float/2addr v2, v3

    const/16 v3, 0x3e8

    int-to-float v3, v3

    mul-float/2addr v2, v3

    int-to-float v0, v0

    mul-float/2addr v2, v0

    invoke-static {v2}, Ljava/lang/Math;->round(F)I

    move-result v0

    const/16 v2, 0x32

    if-ge v0, v2, :cond_1

    move v0, v2

    :cond_1
    check-cast v4, Llyiahf/vczjk/zv8;

    invoke-virtual {v4}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v2

    invoke-static {v2}, Llyiahf/vczjk/mc4;->OooO0O0(F)Llyiahf/vczjk/gi;

    move-result-object v3

    iput-object v3, p0, Llyiahf/vczjk/i70;->Oooo0o:Llyiahf/vczjk/gi;

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v3

    new-instance v4, Llyiahf/vczjk/h70;

    invoke-direct {v4, p0, v2, v0, v1}, Llyiahf/vczjk/h70;-><init>(Llyiahf/vczjk/i70;FILlyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {v3, v1, v1, v4, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/i70;->Oooo0oO:Llyiahf/vczjk/r09;

    return-void

    :cond_2
    check-cast v4, Llyiahf/vczjk/zv8;

    invoke-virtual {v4, v2}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    :cond_3
    return-void
.end method
