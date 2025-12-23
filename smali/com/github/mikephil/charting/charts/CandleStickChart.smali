.class public Lcom/github/mikephil/charting/charts/CandleStickChart;
.super Lcom/github/mikephil/charting/charts/BarLineChartBase;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lcom/github/mikephil/charting/charts/BarLineChartBase<",
        "Llyiahf/vczjk/cq0;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;)V
    .locals 0

    invoke-direct {p0, p1, p2}, Lcom/github/mikephil/charting/charts/BarLineChartBase;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V
    .locals 0

    invoke-direct {p0, p1, p2, p3}, Lcom/github/mikephil/charting/charts/BarLineChartBase;-><init>(Landroid/content/Context;Landroid/util/AttributeSet;I)V

    return-void
.end method


# virtual methods
.method public final OooO0OO()V
    .locals 4

    invoke-super {p0}, Lcom/github/mikephil/charting/charts/BarLineChartBase;->OooO0OO()V

    new-instance v0, Llyiahf/vczjk/dq0;

    iget-object v1, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo:Llyiahf/vczjk/fu0;

    iget-object v2, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoo0:Llyiahf/vczjk/eia;

    const/4 v3, 0x0

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/dq0;-><init>(Llyiahf/vczjk/fu0;Llyiahf/vczjk/eia;I)V

    iput-object v0, p0, Lcom/github/mikephil/charting/charts/Chart;->OooOoO:Llyiahf/vczjk/xx1;

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/Chart;->getXAxis()Llyiahf/vczjk/vsa;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p0}, Lcom/github/mikephil/charting/charts/Chart;->getXAxis()Llyiahf/vczjk/vsa;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    return-void
.end method

.method public getCandleData()Llyiahf/vczjk/cq0;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method
