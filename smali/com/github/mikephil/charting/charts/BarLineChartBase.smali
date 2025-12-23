.class public abstract Lcom/github/mikephil/charting/charts/BarLineChartBase;
.super Lcom/github/mikephil/charting/charts/Chart;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u50;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "RtlHardcoded"
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Llyiahf/vczjk/t50;",
        ">",
        "Lcom/github/mikephil/charting/charts/Chart<",
        "TT;>;",
        "Llyiahf/vczjk/u50;"
    }
.end annotation


# instance fields
.field public Oooo:Z

.field public Oooo0OO:I

.field public Oooo0o:Z

.field public Oooo0o0:Z

.field public Oooo0oO:Z

.field public Oooo0oo:Z

.field public OoooO:Landroid/graphics/Paint;

.field public OoooO0:Z

.field public OoooO00:Z

.field public OoooO0O:Landroid/graphics/Paint;

.field public OoooOO0:F

.field public OoooOOO:Llyiahf/vczjk/ota;

.field public OoooOOo:Llyiahf/vczjk/ota;

.field public OoooOo0:Llyiahf/vczjk/pta;

.field public OoooOoO:Llyiahf/vczjk/pta;

.field public OoooOoo:Llyiahf/vczjk/mi;

.field public Ooooo00:Llyiahf/vczjk/mi;

.field public Ooooo0o:Llyiahf/vczjk/wsa;

.field public final OooooO0:Landroid/graphics/RectF;

.field public final OooooOO:Llyiahf/vczjk/n95;

.field public final OooooOo:Llyiahf/vczjk/n95;

.field public final Oooooo0:[F

.field public o000oOoO:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 1

    invoke-direct {p0, p1, p2}, Lcom/github/mikephil/charting/charts/Chart;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    const/16 p1, 0x64

    iput p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0OO:I

    const/4 p1, 0x0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0o0:Z

    const/4 p2, 0x1

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0o:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oO:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oo:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO00:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO0:Z

    const/high16 p2, 0x41700000    # 15.0f

    iput p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOO0:F

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->o000oOoO:Z

    new-instance p1, Landroid/graphics/RectF;

    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooO0:Landroid/graphics/RectF;

    new-instance p1, Landroid/graphics/Matrix;

    invoke-direct {p1}, Landroid/graphics/Matrix;-><init>()V

    new-instance p1, Landroid/graphics/Matrix;

    invoke-direct {p1}, Landroid/graphics/Matrix;-><init>()V

    const-wide/16 p1, 0x0

    invoke-static {p1, p2, p1, p2}, Llyiahf/vczjk/n95;->OooO0O0(DD)Llyiahf/vczjk/n95;

    move-result-object v0

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooOO:Llyiahf/vczjk/n95;

    invoke-static {p1, p2, p1, p2}, Llyiahf/vczjk/n95;->OooO0O0(DD)Llyiahf/vczjk/n95;

    move-result-object p1

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooOo:Llyiahf/vczjk/n95;

    const/4 p1, 0x2

    new-array p1, p1, [F

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooooo0:[F

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Lcom/github/mikephil/charting/charts/Chart;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    const/16 p1, 0x64

    iput p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0OO:I

    const/4 p1, 0x0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0o0:Z

    const/4 p2, 0x1

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0o:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oO:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oo:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO00:Z

    iput-boolean p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO0:Z

    const/high16 p2, 0x41700000    # 15.0f

    iput p2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOO0:F

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->o000oOoO:Z

    new-instance p1, Landroid/graphics/RectF;

    invoke-direct {p1}, Landroid/graphics/RectF;-><init>()V

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooO0:Landroid/graphics/RectF;

    new-instance p1, Landroid/graphics/Matrix;

    invoke-direct {p1}, Landroid/graphics/Matrix;-><init>()V

    new-instance p1, Landroid/graphics/Matrix;

    invoke-direct {p1}, Landroid/graphics/Matrix;-><init>()V

    const-wide/16 p1, 0x0

    invoke-static {p1, p2, p1, p2}, Llyiahf/vczjk/n95;->OooO0O0(DD)Llyiahf/vczjk/n95;

    move-result-object p3

    iput-object p3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooOO:Llyiahf/vczjk/n95;

    invoke-static {p1, p2, p1, p2}, Llyiahf/vczjk/n95;->OooO0O0(DD)Llyiahf/vczjk/n95;

    move-result-object p1

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooOo:Llyiahf/vczjk/n95;

    const/4 p1, 0x2

    new-array p1, p1, [F

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooooo0:[F

    return-void
.end method


# virtual methods
.method public OooO0OO()V
    .locals 6

    invoke-super {p0}, Lcom/github/mikephil/charting/charts/Chart;->OooO0OO()V

    new-instance v0, Llyiahf/vczjk/ota;

    const/4 v1, 0x1

    invoke-direct {v0, v1}, Llyiahf/vczjk/ota;-><init>(I)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    new-instance v0, Llyiahf/vczjk/ota;

    const/4 v1, 0x2

    invoke-direct {v0, v1}, Llyiahf/vczjk/ota;-><init>(I)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    new-instance v0, Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    invoke-direct {v0, v1}, Llyiahf/vczjk/mi;-><init>(Llyiahf/vczjk/eia;)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    new-instance v0, Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    invoke-direct {v0, v1}, Llyiahf/vczjk/mi;-><init>(Llyiahf/vczjk/eia;)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Ooooo00:Llyiahf/vczjk/mi;

    new-instance v0, Llyiahf/vczjk/pta;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/pta;-><init>(Llyiahf/vczjk/eia;Llyiahf/vczjk/ota;Llyiahf/vczjk/mi;)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOo0:Llyiahf/vczjk/pta;

    new-instance v0, Llyiahf/vczjk/pta;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Ooooo00:Llyiahf/vczjk/mi;

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/pta;-><init>(Llyiahf/vczjk/eia;Llyiahf/vczjk/ota;Llyiahf/vczjk/mi;)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoO:Llyiahf/vczjk/pta;

    new-instance v0, Llyiahf/vczjk/wsa;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/wsa;-><init>(Llyiahf/vczjk/eia;Llyiahf/vczjk/vsa;Llyiahf/vczjk/mi;)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Ooooo0o:Llyiahf/vczjk/wsa;

    new-instance v0, Llyiahf/vczjk/hu0;

    invoke-direct {v0, p0}, Llyiahf/vczjk/hu0;-><init>(Llyiahf/vczjk/u50;)V

    invoke-virtual {p0, v0}, Lcom/github/mikephil/charting/charts/Chart;->setHighlighter(Llyiahf/vczjk/hu0;)V

    new-instance v0, Llyiahf/vczjk/s50;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v1, v1, Llyiahf/vczjk/eia;->OooO00o:Landroid/graphics/Matrix;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ku0;-><init>(Lcom/github/mikephil/charting/charts/Chart;)V

    new-instance v2, Landroid/graphics/Matrix;

    invoke-direct {v2}, Landroid/graphics/Matrix;-><init>()V

    iput-object v2, v0, Llyiahf/vczjk/s50;->OooOOOo:Landroid/graphics/Matrix;

    new-instance v2, Landroid/graphics/Matrix;

    invoke-direct {v2}, Landroid/graphics/Matrix;-><init>()V

    iput-object v2, v0, Llyiahf/vczjk/s50;->OooOOo0:Landroid/graphics/Matrix;

    const/4 v2, 0x0

    invoke-static {v2, v2}, Llyiahf/vczjk/o95;->OooO0O0(FF)Llyiahf/vczjk/o95;

    move-result-object v3

    iput-object v3, v0, Llyiahf/vczjk/s50;->OooOOo:Llyiahf/vczjk/o95;

    invoke-static {v2, v2}, Llyiahf/vczjk/o95;->OooO0O0(FF)Llyiahf/vczjk/o95;

    move-result-object v3

    iput-object v3, v0, Llyiahf/vczjk/s50;->OooOOoo:Llyiahf/vczjk/o95;

    const/high16 v3, 0x3f800000    # 1.0f

    iput v3, v0, Llyiahf/vczjk/s50;->OooOo00:F

    iput v3, v0, Llyiahf/vczjk/s50;->OooOo0:F

    iput v3, v0, Llyiahf/vczjk/s50;->OooOo0O:F

    const-wide/16 v4, 0x0

    iput-wide v4, v0, Llyiahf/vczjk/s50;->OooOo:J

    invoke-static {v2, v2}, Llyiahf/vczjk/o95;->OooO0O0(FF)Llyiahf/vczjk/o95;

    move-result-object v4

    iput-object v4, v0, Llyiahf/vczjk/s50;->OooOoO0:Llyiahf/vczjk/o95;

    invoke-static {v2, v2}, Llyiahf/vczjk/o95;->OooO0O0(FF)Llyiahf/vczjk/o95;

    move-result-object v2

    iput-object v2, v0, Llyiahf/vczjk/s50;->OooOoO:Llyiahf/vczjk/o95;

    iput-object v1, v0, Llyiahf/vczjk/s50;->OooOOOo:Landroid/graphics/Matrix;

    const/high16 v1, 0x40400000    # 3.0f

    invoke-static {v1}, Llyiahf/vczjk/rba;->OooO0O0(F)F

    move-result v1

    iput v1, v0, Llyiahf/vczjk/s50;->OooOoOO:F

    const/high16 v1, 0x40600000    # 3.5f

    invoke-static {v1}, Llyiahf/vczjk/rba;->OooO0O0(F)F

    move-result v1

    iput v1, v0, Llyiahf/vczjk/s50;->OooOoo0:F

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0o:Llyiahf/vczjk/ku0;

    new-instance v0, Landroid/graphics/Paint;

    invoke-direct {v0}, Landroid/graphics/Paint;-><init>()V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO0O:Landroid/graphics/Paint;

    sget-object v1, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO0O:Landroid/graphics/Paint;

    const/16 v1, 0xf0

    invoke-static {v1, v1, v1}, Landroid/graphics/Color;->rgb(III)I

    move-result v1

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V

    new-instance v0, Landroid/graphics/Paint;

    invoke-direct {v0}, Landroid/graphics/Paint;-><init>()V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO:Landroid/graphics/Paint;

    sget-object v1, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO:Landroid/graphics/Paint;

    const/high16 v1, -0x1000000

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setColor(I)V

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO:Landroid/graphics/Paint;

    invoke-static {v3}, Llyiahf/vczjk/rba;->OooO0O0(F)F

    move-result v1

    invoke-virtual {v0, v1}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    return-void
.end method

.method public final OooO0Oo()V
    .locals 2

    iget-boolean v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOO0:Z

    if-eqz v0, :cond_0

    const-string v0, "MPAndroidChart"

    const-string v1, "Preparing... DATA NOT SET."

    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :cond_0
    return-void
.end method

.method public final OooO0o(Landroid/graphics/RectF;)V
    .locals 4

    const/4 v0, 0x0

    iput v0, p1, Landroid/graphics/RectF;->left:F

    iput v0, p1, Landroid/graphics/RectF;->right:F

    iput v0, p1, Landroid/graphics/RectF;->top:F

    iput v0, p1, Landroid/graphics/RectF;->bottom:F

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    if-eqz v0, :cond_9

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v0, v0, Llyiahf/vczjk/ox4;->OooO0o:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    const/4 v1, 0x2

    if-eqz v0, :cond_6

    const/4 v2, 0x1

    if-eq v0, v2, :cond_0

    goto/16 :goto_0

    :cond_0
    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v0, v0, Llyiahf/vczjk/ox4;->OooO0Oo:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    if-eqz v0, :cond_5

    if-eq v0, v2, :cond_2

    if-eq v0, v1, :cond_1

    goto/16 :goto_0

    :cond_1
    iget v0, p1, Landroid/graphics/RectF;->right:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v1, Llyiahf/vczjk/ox4;->OooO0oo:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget v3, v3, Llyiahf/vczjk/eia;->OooO0OO:F

    iget v1, v1, Llyiahf/vczjk/ox4;->OooO0oO:F

    mul-float/2addr v3, v1

    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    move-result v1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v2, Llyiahf/vczjk/y61;->OooO00o:F

    add-float/2addr v1, v2

    add-float/2addr v1, v0

    iput v1, p1, Landroid/graphics/RectF;->right:F

    return-void

    :cond_2
    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v0, v0, Llyiahf/vczjk/ox4;->OooO0o0:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    if-eqz v0, :cond_4

    if-eq v0, v1, :cond_3

    goto/16 :goto_0

    :cond_3
    iget v0, p1, Landroid/graphics/RectF;->bottom:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v1, Llyiahf/vczjk/ox4;->OooO:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget v3, v3, Llyiahf/vczjk/eia;->OooO0Oo:F

    iget v1, v1, Llyiahf/vczjk/ox4;->OooO0oO:F

    mul-float/2addr v3, v1

    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    move-result v1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v2, Llyiahf/vczjk/y61;->OooO0O0:F

    add-float/2addr v1, v2

    add-float/2addr v1, v0

    iput v1, p1, Landroid/graphics/RectF;->bottom:F

    return-void

    :cond_4
    iget v0, p1, Landroid/graphics/RectF;->top:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v1, Llyiahf/vczjk/ox4;->OooO:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget v3, v3, Llyiahf/vczjk/eia;->OooO0Oo:F

    iget v1, v1, Llyiahf/vczjk/ox4;->OooO0oO:F

    mul-float/2addr v3, v1

    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    move-result v1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v2, Llyiahf/vczjk/y61;->OooO0O0:F

    add-float/2addr v1, v2

    add-float/2addr v1, v0

    iput v1, p1, Landroid/graphics/RectF;->top:F

    return-void

    :cond_5
    iget v0, p1, Landroid/graphics/RectF;->left:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v1, Llyiahf/vczjk/ox4;->OooO0oo:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget v3, v3, Llyiahf/vczjk/eia;->OooO0OO:F

    iget v1, v1, Llyiahf/vczjk/ox4;->OooO0oO:F

    mul-float/2addr v3, v1

    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    move-result v1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v2, Llyiahf/vczjk/y61;->OooO00o:F

    add-float/2addr v1, v2

    add-float/2addr v1, v0

    iput v1, p1, Landroid/graphics/RectF;->left:F

    return-void

    :cond_6
    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v0, v0, Llyiahf/vczjk/ox4;->OooO0o0:I

    invoke-static {v0}, Llyiahf/vczjk/ix8;->OooOo(I)I

    move-result v0

    if-eqz v0, :cond_8

    if-eq v0, v1, :cond_7

    goto :goto_0

    :cond_7
    iget v0, p1, Landroid/graphics/RectF;->bottom:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v1, Llyiahf/vczjk/ox4;->OooO:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget v3, v3, Llyiahf/vczjk/eia;->OooO0Oo:F

    iget v1, v1, Llyiahf/vczjk/ox4;->OooO0oO:F

    mul-float/2addr v3, v1

    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    move-result v1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v2, Llyiahf/vczjk/y61;->OooO0O0:F

    add-float/2addr v1, v2

    add-float/2addr v1, v0

    iput v1, p1, Landroid/graphics/RectF;->bottom:F

    return-void

    :cond_8
    iget v0, p1, Landroid/graphics/RectF;->top:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v1, Llyiahf/vczjk/ox4;->OooO:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget v3, v3, Llyiahf/vczjk/eia;->OooO0Oo:F

    iget v1, v1, Llyiahf/vczjk/ox4;->OooO0oO:F

    mul-float/2addr v3, v1

    invoke-static {v2, v3}, Ljava/lang/Math;->min(FF)F

    move-result v1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0O:Llyiahf/vczjk/ox4;

    iget v2, v2, Llyiahf/vczjk/y61;->OooO0O0:F

    add-float/2addr v1, v2

    add-float/2addr v1, v0

    iput v1, p1, Landroid/graphics/RectF;->top:F

    :cond_9
    :goto_0
    return-void
.end method

.method public OooO0oO()V
    .locals 9

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooO0:Landroid/graphics/RectF;

    invoke-virtual {p0, v0}, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooO0o(Landroid/graphics/RectF;)V

    iget v1, v0, Landroid/graphics/RectF;->left:F

    const/4 v2, 0x0

    add-float/2addr v1, v2

    iget v3, v0, Landroid/graphics/RectF;->top:F

    add-float/2addr v3, v2

    iget v4, v0, Landroid/graphics/RectF;->right:F

    add-float/2addr v4, v2

    iget v0, v0, Landroid/graphics/RectF;->bottom:F

    add-float/2addr v0, v2

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    invoke-virtual {v2}, Llyiahf/vczjk/ota;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_0

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    iget-object v5, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOo0:Llyiahf/vczjk/pta;

    iget-object v5, v5, Llyiahf/vczjk/i20;->OooO0O0:Landroid/graphics/Paint;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/ota;->OooO0O0(Landroid/graphics/Paint;)F

    move-result v2

    add-float/2addr v1, v2

    :cond_0
    iget-object v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    invoke-virtual {v2}, Llyiahf/vczjk/ota;->OooO0OO()Z

    move-result v2

    if-eqz v2, :cond_1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    iget-object v5, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoO:Llyiahf/vczjk/pta;

    iget-object v5, v5, Llyiahf/vczjk/i20;->OooO0O0:Landroid/graphics/Paint;

    invoke-virtual {v2, v5}, Llyiahf/vczjk/ota;->OooO0O0(Landroid/graphics/Paint;)F

    move-result v2

    add-float/2addr v4, v2

    :cond_1
    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget-boolean v5, v2, Llyiahf/vczjk/h20;->OooO0o:Z

    if-eqz v5, :cond_4

    iget v5, v2, Llyiahf/vczjk/vsa;->OooOO0O:I

    int-to-float v5, v5

    iget v6, v2, Llyiahf/vczjk/y61;->OooO0O0:F

    add-float/2addr v5, v6

    iget v2, v2, Llyiahf/vczjk/vsa;->OooOO0o:I

    const/4 v6, 0x2

    if-ne v2, v6, :cond_2

    add-float/2addr v0, v5

    goto :goto_1

    :cond_2
    const/4 v6, 0x1

    if-ne v2, v6, :cond_3

    :goto_0
    add-float/2addr v3, v5

    goto :goto_1

    :cond_3
    const/4 v6, 0x3

    if-ne v2, v6, :cond_4

    add-float/2addr v0, v5

    goto :goto_0

    :cond_4
    :goto_1
    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/Chart;->getExtraTopOffset()F

    move-result v2

    add-float/2addr v2, v3

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/Chart;->getExtraRightOffset()F

    move-result v3

    add-float/2addr v3, v4

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/Chart;->getExtraBottomOffset()F

    move-result v4

    add-float/2addr v4, v0

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/Chart;->getExtraLeftOffset()F

    move-result v0

    add-float/2addr v0, v1

    iget v1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOO0:F

    invoke-static {v1}, Llyiahf/vczjk/rba;->OooO0O0(F)F

    move-result v1

    iget-object v5, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    invoke-static {v1, v0}, Ljava/lang/Math;->max(FF)F

    move-result v6

    invoke-static {v1, v2}, Ljava/lang/Math;->max(FF)F

    move-result v7

    invoke-static {v1, v3}, Ljava/lang/Math;->max(FF)F

    move-result v8

    invoke-static {v1, v4}, Ljava/lang/Math;->max(FF)F

    move-result v1

    invoke-virtual {v5, v6, v7, v8, v1}, Llyiahf/vczjk/eia;->OooO0Oo(FFFF)V

    iget-boolean v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOO0:Z

    if-eqz v1, :cond_5

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v5, "offsetLeft: "

    invoke-direct {v1, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v0, ", offsetTop: "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v0, ", offsetRight: "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v0, ", offsetBottom: "

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "MPAndroidChart"

    invoke-static {v1, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v2, "Content: "

    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v2, v2, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    invoke-virtual {v2}, Landroid/graphics/RectF;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :cond_5
    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Ooooo00:Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/mi;->Oooo00O()V

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0}, Llyiahf/vczjk/mi;->Oooo00O()V

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooO0oo()V

    return-void
.end method

.method public OooO0oo()V
    .locals 5

    iget-boolean v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOO0:Z

    if-eqz v0, :cond_0

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Preparing Value-Px Matrix, xmin: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v1, v1, Llyiahf/vczjk/h20;->OooO0oo:F

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v1, ", xmax: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v1, v1, Llyiahf/vczjk/h20;->OooO0oO:F

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    const-string v1, ", xdelta: "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v1, v1, Llyiahf/vczjk/h20;->OooO:F

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    const-string v1, "MPAndroidChart"

    invoke-static {v1, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :cond_0
    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Ooooo00:Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v2, v1, Llyiahf/vczjk/h20;->OooO0oo:F

    iget v1, v1, Llyiahf/vczjk/h20;->OooO:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    iget v4, v3, Llyiahf/vczjk/h20;->OooO:F

    iget v3, v3, Llyiahf/vczjk/h20;->OooO0oo:F

    invoke-virtual {v0, v2, v1, v4, v3}, Llyiahf/vczjk/mi;->Oooo00o(FFFF)V

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v2, v1, Llyiahf/vczjk/h20;->OooO0oo:F

    iget v1, v1, Llyiahf/vczjk/h20;->OooO:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    iget v4, v3, Llyiahf/vczjk/h20;->OooO:F

    iget v3, v3, Llyiahf/vczjk/h20;->OooO0oo:F

    invoke-virtual {v0, v2, v1, v4, v3}, Llyiahf/vczjk/mi;->Oooo00o(FFFF)V

    return-void
.end method

.method public final computeScroll()V
    .locals 14

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOo0o:Llyiahf/vczjk/ku0;

    instance-of v1, v0, Llyiahf/vczjk/s50;

    if-eqz v1, :cond_5

    check-cast v0, Llyiahf/vczjk/s50;

    iget-object v1, v0, Llyiahf/vczjk/s50;->OooOoO:Llyiahf/vczjk/o95;

    iget v2, v1, Llyiahf/vczjk/o95;->OooO0O0:F

    const/4 v3, 0x0

    cmpl-float v2, v2, v3

    if-nez v2, :cond_0

    iget v2, v1, Llyiahf/vczjk/o95;->OooO0OO:F

    cmpl-float v2, v2, v3

    if-nez v2, :cond_0

    goto/16 :goto_3

    :cond_0
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    move-result-wide v4

    iget v2, v1, Llyiahf/vczjk/o95;->OooO0O0:F

    iget-object v12, v0, Llyiahf/vczjk/ku0;->OooOOOO:Lcom/github/mikephil/charting/charts/Chart;

    move-object v13, v12

    check-cast v13, Lcom/github/mikephil/charting/charts/BarLineChartBase;

    invoke-virtual {v13}, Lcom/github/mikephil/charting/charts/Chart;->getDragDecelerationFrictionCoef()F

    move-result v6

    mul-float/2addr v6, v2

    iput v6, v1, Llyiahf/vczjk/o95;->OooO0O0:F

    iget v2, v1, Llyiahf/vczjk/o95;->OooO0OO:F

    invoke-virtual {v13}, Lcom/github/mikephil/charting/charts/Chart;->getDragDecelerationFrictionCoef()F

    move-result v6

    mul-float/2addr v6, v2

    iput v6, v1, Llyiahf/vczjk/o95;->OooO0OO:F

    iget-wide v7, v0, Llyiahf/vczjk/s50;->OooOo:J

    sub-long v7, v4, v7

    long-to-float v2, v7

    const/high16 v7, 0x447a0000    # 1000.0f

    div-float/2addr v2, v7

    iget v7, v1, Llyiahf/vczjk/o95;->OooO0O0:F

    mul-float/2addr v7, v2

    mul-float/2addr v6, v2

    iget-object v2, v0, Llyiahf/vczjk/s50;->OooOoO0:Llyiahf/vczjk/o95;

    iget v8, v2, Llyiahf/vczjk/o95;->OooO0O0:F

    add-float v9, v8, v7

    iput v9, v2, Llyiahf/vczjk/o95;->OooO0O0:F

    iget v7, v2, Llyiahf/vczjk/o95;->OooO0OO:F

    add-float v10, v7, v6

    iput v10, v2, Llyiahf/vczjk/o95;->OooO0OO:F

    const/4 v8, 0x2

    const/4 v11, 0x0

    move-wide v6, v4

    invoke-static/range {v4 .. v11}, Landroid/view/MotionEvent;->obtain(JJIFFI)Landroid/view/MotionEvent;

    move-result-object v6

    iget-boolean v7, v13, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oo:Z

    iget-object v8, v0, Llyiahf/vczjk/s50;->OooOOo:Llyiahf/vczjk/o95;

    if-eqz v7, :cond_1

    iget v7, v2, Llyiahf/vczjk/o95;->OooO0O0:F

    iget v9, v8, Llyiahf/vczjk/o95;->OooO0O0:F

    sub-float/2addr v7, v9

    goto :goto_0

    :cond_1
    move v7, v3

    :goto_0
    iget-boolean v9, v13, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo:Z

    if-eqz v9, :cond_2

    iget v2, v2, Llyiahf/vczjk/o95;->OooO0OO:F

    iget v8, v8, Llyiahf/vczjk/o95;->OooO0OO:F

    sub-float/2addr v2, v8

    goto :goto_1

    :cond_2
    move v2, v3

    :goto_1
    iget-object v8, v0, Llyiahf/vczjk/s50;->OooOOOo:Landroid/graphics/Matrix;

    iget-object v9, v0, Llyiahf/vczjk/s50;->OooOOo0:Landroid/graphics/Matrix;

    invoke-virtual {v8, v9}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    iget-object v8, v0, Llyiahf/vczjk/ku0;->OooOOOO:Lcom/github/mikephil/charting/charts/Chart;

    check-cast v8, Lcom/github/mikephil/charting/charts/BarLineChartBase;

    invoke-virtual {v8}, Lcom/github/mikephil/charting/charts/Chart;->getOnChartGestureListener()Llyiahf/vczjk/ja6;

    iget-object v8, v0, Llyiahf/vczjk/ku0;->OooOOOO:Lcom/github/mikephil/charting/charts/Chart;

    check-cast v8, Lcom/github/mikephil/charting/charts/BarLineChartBase;

    iget-object v9, v8, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    invoke-virtual {v9}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v8, v8, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    invoke-virtual {v8}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v8, v0, Llyiahf/vczjk/s50;->OooOOOo:Landroid/graphics/Matrix;

    invoke-virtual {v8, v7, v2}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    invoke-virtual {v6}, Landroid/view/MotionEvent;->recycle()V

    invoke-virtual {v13}, Lcom/github/mikephil/charting/charts/Chart;->getViewPortHandler()Llyiahf/vczjk/eia;

    move-result-object v2

    iget-object v6, v0, Llyiahf/vczjk/s50;->OooOOOo:Landroid/graphics/Matrix;

    const/4 v7, 0x0

    invoke-virtual {v2, v6, v12, v7}, Llyiahf/vczjk/eia;->OooO0OO(Landroid/graphics/Matrix;Landroid/view/View;Z)V

    iput-object v6, v0, Llyiahf/vczjk/s50;->OooOOOo:Landroid/graphics/Matrix;

    iput-wide v4, v0, Llyiahf/vczjk/s50;->OooOo:J

    iget v2, v1, Llyiahf/vczjk/o95;->OooO0O0:F

    invoke-static {v2}, Ljava/lang/Math;->abs(F)F

    move-result v2

    float-to-double v4, v2

    const-wide v6, 0x3f847ae147ae147bL    # 0.01

    cmpl-double v2, v4, v6

    if-gez v2, :cond_4

    iget v1, v1, Llyiahf/vczjk/o95;->OooO0OO:F

    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    move-result v1

    float-to-double v1, v1

    cmpl-double v1, v1, v6

    if-ltz v1, :cond_3

    goto :goto_2

    :cond_3
    invoke-virtual {v13}, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooO0oO()V

    invoke-virtual {v13}, Landroid/view/View;->postInvalidate()V

    iget-object v0, v0, Llyiahf/vczjk/s50;->OooOoO:Llyiahf/vczjk/o95;

    iput v3, v0, Llyiahf/vczjk/o95;->OooO0O0:F

    iput v3, v0, Llyiahf/vczjk/o95;->OooO0OO:F

    return-void

    :cond_4
    :goto_2
    sget-object v0, Llyiahf/vczjk/rba;->OooO00o:Landroid/util/DisplayMetrics;

    invoke-virtual {v12}, Landroid/view/View;->postInvalidateOnAnimation()V

    :cond_5
    :goto_3
    return-void
.end method

.method public getAxisLeft()Llyiahf/vczjk/ota;
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    return-object v0
.end method

.method public getAxisRight()Llyiahf/vczjk/ota;
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    return-object v0
.end method

.method public bridge synthetic getData()Llyiahf/vczjk/t50;
    .locals 1

    invoke-super {p0}, Lcom/github/mikephil/charting/charts/Chart;->getData()Llyiahf/vczjk/gu0;

    const/4 v0, 0x0

    return-object v0
.end method

.method public getDrawListener()Llyiahf/vczjk/ra6;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public getHighestVisibleX()F
    .locals 4

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v1, v1, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    iget v2, v1, Landroid/graphics/RectF;->right:F

    iget v1, v1, Landroid/graphics/RectF;->bottom:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooOo:Llyiahf/vczjk/n95;

    invoke-virtual {v0, v2, v1, v3}, Llyiahf/vczjk/mi;->OooOoO(FFLlyiahf/vczjk/n95;)V

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v0, v0, Llyiahf/vczjk/h20;->OooO0oO:F

    float-to-double v0, v0

    iget-wide v2, v3, Llyiahf/vczjk/n95;->OooO0O0:D

    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->min(DD)D

    move-result-wide v0

    double-to-float v0, v0

    return v0
.end method

.method public getLowestVisibleX()F
    .locals 4

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v1, v1, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    iget v2, v1, Landroid/graphics/RectF;->left:F

    iget v1, v1, Landroid/graphics/RectF;->bottom:F

    iget-object v3, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooooOO:Llyiahf/vczjk/n95;

    invoke-virtual {v0, v2, v1, v3}, Llyiahf/vczjk/mi;->OooOoO(FFLlyiahf/vczjk/n95;)V

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v0, v0, Llyiahf/vczjk/h20;->OooO0oo:F

    float-to-double v0, v0

    iget-wide v2, v3, Llyiahf/vczjk/n95;->OooO0O0:D

    invoke-static {v0, v1, v2, v3}, Ljava/lang/Math;->max(DD)D

    move-result-wide v0

    double-to-float v0, v0

    return v0
.end method

.method public getMaxVisibleCount()I
    .locals 1

    iget v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0OO:I

    return v0
.end method

.method public getMinOffset()F
    .locals 1

    iget v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOO0:F

    return v0
.end method

.method public getRendererLeftYAxis()Llyiahf/vczjk/pta;
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOo0:Llyiahf/vczjk/pta;

    return-object v0
.end method

.method public getRendererRightYAxis()Llyiahf/vczjk/pta;
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoO:Llyiahf/vczjk/pta;

    return-object v0
.end method

.method public getRendererXAxis()Llyiahf/vczjk/wsa;
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Ooooo0o:Llyiahf/vczjk/wsa;

    return-object v0
.end method

.method public getScaleX()F
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    if-nez v0, :cond_0

    const/high16 v0, 0x3f800000    # 1.0f

    return v0

    :cond_0
    iget v0, v0, Llyiahf/vczjk/eia;->OooO:F

    return v0
.end method

.method public getScaleY()F
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    if-nez v0, :cond_0

    const/high16 v0, 0x3f800000    # 1.0f

    return v0

    :cond_0
    iget v0, v0, Llyiahf/vczjk/eia;->OooOO0:F

    return v0
.end method

.method public getVisibleXRange()F
    .locals 2

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/BarLineChartBase;->getHighestVisibleX()F

    move-result v0

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/BarLineChartBase;->getLowestVisibleX()F

    move-result v1

    sub-float/2addr v0, v1

    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    move-result v0

    return v0
.end method

.method public getYChartMax()F
    .locals 2

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    iget v0, v0, Llyiahf/vczjk/h20;->OooO0oO:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    iget v1, v1, Llyiahf/vczjk/h20;->OooO0oO:F

    invoke-static {v0, v1}, Ljava/lang/Math;->max(FF)F

    move-result v0

    return v0
.end method

.method public getYChartMin()F
    .locals 2

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOO:Llyiahf/vczjk/ota;

    iget v0, v0, Llyiahf/vczjk/h20;->OooO0oo:F

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOOo:Llyiahf/vczjk/ota;

    iget v1, v1, Llyiahf/vczjk/h20;->OooO0oo:F

    invoke-static {v0, v1}, Ljava/lang/Math;->min(FF)F

    move-result v0

    return v0
.end method

.method public final onSizeChanged(IIII)V
    .locals 5

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooooo0:[F

    const/4 v1, 0x1

    const/4 v2, 0x0

    aput v2, v0, v1

    const/4 v3, 0x0

    aput v2, v0, v3

    iget-boolean v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->o000oOoO:Z

    if-eqz v2, :cond_0

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object v2, v2, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    iget v4, v2, Landroid/graphics/RectF;->left:F

    aput v4, v0, v3

    iget v2, v2, Landroid/graphics/RectF;->top:F

    aput v2, v0, v1

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/mi;->Oooo000([F)V

    :cond_0
    invoke-super {p0, p1, p2, p3, p4}, Lcom/github/mikephil/charting/charts/Chart;->onSizeChanged(IIII)V

    iget-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->o000oOoO:Z

    if-eqz p1, :cond_1

    iget-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoo:Llyiahf/vczjk/mi;

    iget-object p2, p1, Llyiahf/vczjk/mi;->OooOOO0:Ljava/lang/Object;

    check-cast p2, Landroid/graphics/Matrix;

    invoke-virtual {p2, v0}, Landroid/graphics/Matrix;->mapPoints([F)V

    iget-object p2, p1, Llyiahf/vczjk/mi;->OooOOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/eia;

    iget-object p2, p2, Llyiahf/vczjk/eia;->OooO00o:Landroid/graphics/Matrix;

    invoke-virtual {p2, v0}, Landroid/graphics/Matrix;->mapPoints([F)V

    iget-object p1, p1, Llyiahf/vczjk/mi;->OooOOO:Ljava/lang/Object;

    check-cast p1, Landroid/graphics/Matrix;

    invoke-virtual {p1, v0}, Landroid/graphics/Matrix;->mapPoints([F)V

    iget-object p1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object p2, p1, Llyiahf/vczjk/eia;->OooOOO:Landroid/graphics/Matrix;

    invoke-virtual {p2}, Landroid/graphics/Matrix;->reset()V

    iget-object p3, p1, Llyiahf/vczjk/eia;->OooO00o:Landroid/graphics/Matrix;

    invoke-virtual {p2, p3}, Landroid/graphics/Matrix;->set(Landroid/graphics/Matrix;)V

    aget p3, v0, v3

    iget-object p4, p1, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    iget v2, p4, Landroid/graphics/RectF;->left:F

    sub-float/2addr p3, v2

    aget v0, v0, v1

    iget p4, p4, Landroid/graphics/RectF;->top:F

    sub-float/2addr v0, p4

    neg-float p3, p3

    neg-float p4, v0

    invoke-virtual {p2, p3, p4}, Landroid/graphics/Matrix;->postTranslate(FF)Z

    invoke-virtual {p1, p2, p0, v1}, Llyiahf/vczjk/eia;->OooO0OO(Landroid/graphics/Matrix;Landroid/view/View;Z)V

    return-void

    :cond_1
    iget-object p1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    iget-object p2, p1, Llyiahf/vczjk/eia;->OooO00o:Landroid/graphics/Matrix;

    invoke-virtual {p1, p2, p0, v1}, Llyiahf/vczjk/eia;->OooO0OO(Landroid/graphics/Matrix;Landroid/view/View;Z)V

    return-void
.end method

.method public final onTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 0

    invoke-super {p0, p1}, Landroid/view/View;->onTouchEvent(Landroid/view/MotionEvent;)Z

    const/4 p1, 0x0

    return p1
.end method

.method public setAutoScaleMinMaxEnabled(Z)V
    .locals 0

    return-void
.end method

.method public setBorderColor(I)V
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO:Landroid/graphics/Paint;

    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setColor(I)V

    return-void
.end method

.method public setBorderWidth(F)V
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO:Landroid/graphics/Paint;

    invoke-static {p1}, Llyiahf/vczjk/rba;->OooO0O0(F)F

    move-result p1

    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    return-void
.end method

.method public setClipValuesToContent(Z)V
    .locals 0

    return-void
.end method

.method public setDoubleTapToZoomEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0o:Z

    return-void
.end method

.method public setDragEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oo:Z

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo:Z

    return-void
.end method

.method public setDragOffsetX(F)V
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/rba;->OooO0O0(F)F

    move-result p1

    iput p1, v0, Llyiahf/vczjk/eia;->OooOO0o:F

    return-void
.end method

.method public setDragOffsetY(F)V
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {p1}, Llyiahf/vczjk/rba;->OooO0O0(F)F

    move-result p1

    iput p1, v0, Llyiahf/vczjk/eia;->OooOOO0:F

    return-void
.end method

.method public setDragXEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oo:Z

    return-void
.end method

.method public setDragYEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo:Z

    return-void
.end method

.method public setDrawBorders(Z)V
    .locals 0

    return-void
.end method

.method public setDrawGridBackground(Z)V
    .locals 0

    return-void
.end method

.method public setGridBackgroundColor(I)V
    .locals 1

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO0O:Landroid/graphics/Paint;

    invoke-virtual {v0, p1}, Landroid/graphics/Paint;->setColor(I)V

    return-void
.end method

.method public setHighlightPerDragEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0oO:Z

    return-void
.end method

.method public setKeepPositionOnRotation(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->o000oOoO:Z

    return-void
.end method

.method public setMaxVisibleValueCount(I)V
    .locals 0

    iput p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0OO:I

    return-void
.end method

.method public setMinOffset(F)V
    .locals 0

    iput p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOO0:F

    return-void
.end method

.method public setOnDrawListener(Llyiahf/vczjk/ra6;)V
    .locals 0

    return-void
.end method

.method public setPinchZoom(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Oooo0o0:Z

    return-void
.end method

.method public setRendererLeftYAxis(Llyiahf/vczjk/pta;)V
    .locals 0

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOo0:Llyiahf/vczjk/pta;

    return-void
.end method

.method public setRendererRightYAxis(Llyiahf/vczjk/pta;)V
    .locals 0

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooOoO:Llyiahf/vczjk/pta;

    return-void
.end method

.method public setScaleEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO00:Z

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO0:Z

    return-void
.end method

.method public setScaleXEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO00:Z

    return-void
.end method

.method public setScaleYEnabled(Z)V
    .locals 0

    iput-boolean p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OoooO0:Z

    return-void
.end method

.method public setVisibleXRangeMaximum(F)V
    .locals 3

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v0, v0, Llyiahf/vczjk/h20;->OooO:F

    div-float/2addr v0, p1

    iget-object p1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/high16 v1, 0x3f800000    # 1.0f

    cmpg-float v2, v0, v1

    if-gez v2, :cond_0

    move v0, v1

    :cond_0
    iput v0, p1, Llyiahf/vczjk/eia;->OooO0oO:F

    iget-object v0, p1, Llyiahf/vczjk/eia;->OooO00o:Landroid/graphics/Matrix;

    iget-object v1, p1, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/eia;->OooO00o(Landroid/graphics/Matrix;Landroid/graphics/RectF;)V

    return-void
.end method

.method public setVisibleXRangeMinimum(F)V
    .locals 2

    iget-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOOoo:Llyiahf/vczjk/vsa;

    iget v0, v0, Llyiahf/vczjk/h20;->OooO:F

    div-float/2addr v0, p1

    iget-object p1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    cmpl-float v1, v0, v1

    if-nez v1, :cond_0

    const v0, 0x7f7fffff    # Float.MAX_VALUE

    :cond_0
    iput v0, p1, Llyiahf/vczjk/eia;->OooO0oo:F

    iget-object v0, p1, Llyiahf/vczjk/eia;->OooO00o:Landroid/graphics/Matrix;

    iget-object v1, p1, Llyiahf/vczjk/eia;->OooO0O0:Landroid/graphics/RectF;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/eia;->OooO00o(Landroid/graphics/Matrix;Landroid/graphics/RectF;)V

    return-void
.end method

.method public setXAxisRenderer(Llyiahf/vczjk/wsa;)V
    .locals 0

    iput-object p1, p0, Lcom/github/mikephil/charting/charts/BarLineChartBase;->Ooooo0o:Llyiahf/vczjk/wsa;

    return-void
.end method
