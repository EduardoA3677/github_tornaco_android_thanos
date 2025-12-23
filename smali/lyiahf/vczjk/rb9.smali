.class public final Llyiahf/vczjk/rb9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $indicatorHeight:I

.field final synthetic $indicatorRefreshTrigger:F

.field final synthetic $offset$delegate:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field final synthetic $scale:Z

.field final synthetic $state:Llyiahf/vczjk/jc9;


# direct methods
.method public constructor <init>(IZLlyiahf/vczjk/jc9;FLlyiahf/vczjk/qs5;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/rb9;->$indicatorHeight:I

    iput-boolean p2, p0, Llyiahf/vczjk/rb9;->$scale:Z

    iput-object p3, p0, Llyiahf/vczjk/rb9;->$state:Llyiahf/vczjk/jc9;

    iput p4, p0, Llyiahf/vczjk/rb9;->$indicatorRefreshTrigger:F

    iput-object p5, p0, Llyiahf/vczjk/rb9;->$offset$delegate:Llyiahf/vczjk/qs5;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/ft7;

    const-string v0, "$this$graphicsLayer"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/rb9;->$offset$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iget v1, p0, Llyiahf/vczjk/rb9;->$indicatorHeight:I

    int-to-float v1, v1

    sub-float/2addr v0, v1

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ft7;->OooOo0(F)V

    iget-boolean v0, p0, Llyiahf/vczjk/rb9;->$scale:Z

    const/high16 v1, 0x3f800000    # 1.0f

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/rb9;->$state:Llyiahf/vczjk/jc9;

    invoke-virtual {v0}, Llyiahf/vczjk/jc9;->OooO0O0()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/rb9;->$offset$delegate:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    iget v2, p0, Llyiahf/vczjk/rb9;->$indicatorRefreshTrigger:F

    cmpg-float v3, v2, v1

    if-gez v3, :cond_0

    move v2, v1

    :cond_0
    div-float/2addr v0, v2

    sget-object v2, Llyiahf/vczjk/jk2;->OooO0O0:Llyiahf/vczjk/cu1;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/cu1;->OooO00o(F)F

    move-result v0

    const/4 v2, 0x0

    invoke-static {v0, v2, v1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v1

    :cond_1
    invoke-virtual {p1, v1}, Llyiahf/vczjk/ft7;->OooO0oO(F)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ft7;->OooOO0O(F)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
