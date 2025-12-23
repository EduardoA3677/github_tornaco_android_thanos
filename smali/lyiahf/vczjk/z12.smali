.class public final Llyiahf/vczjk/z12;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/z12;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/z12;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/z12;->OooO00o:Llyiahf/vczjk/z12;

    return-void
.end method


# virtual methods
.method public final OooO00o(JFLlyiahf/vczjk/rf1;I)J
    .locals 3

    check-cast p4, Llyiahf/vczjk/zf1;

    const p5, -0x648f4fbd

    invoke-virtual {p4, p5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p5, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-virtual {p4, p5}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p5

    check-cast p5, Llyiahf/vczjk/k31;

    const/4 v0, 0x0

    int-to-float v1, v0

    invoke-static {p3, v1}, Ljava/lang/Float;->compare(FF)I

    move-result v1

    if-lez v1, :cond_0

    invoke-virtual {p5}, Llyiahf/vczjk/k31;->OooO0Oo()Z

    move-result p5

    if-nez p5, :cond_0

    const p5, 0x45adcc4b

    invoke-virtual {p4, p5}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p5, Llyiahf/vczjk/il2;->OooO00o:Llyiahf/vczjk/l39;

    const/4 p5, 0x1

    int-to-float p5, p5

    add-float/2addr p3, p5

    float-to-double v1, p3

    invoke-static {v1, v2}, Ljava/lang/Math;->log(D)D

    move-result-wide v1

    double-to-float p3, v1

    const/high16 p5, 0x40900000    # 4.5f

    mul-float/2addr p3, p5

    const/high16 p5, 0x40000000    # 2.0f

    add-float/2addr p3, p5

    const/high16 p5, 0x42c80000    # 100.0f

    div-float/2addr p3, p5

    invoke-static {p1, p2, p4}, Llyiahf/vczjk/m31;->OooO00o(JLlyiahf/vczjk/rf1;)J

    move-result-wide v1

    invoke-static {p3, v1, v2}, Llyiahf/vczjk/n21;->OooO0O0(FJ)J

    move-result-wide v1

    invoke-static {v1, v2, p1, p2}, Llyiahf/vczjk/v34;->OooOooO(JJ)J

    move-result-wide p1

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_0

    :cond_0
    const p3, 0x45afe957

    invoke-virtual {p4, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_0
    invoke-virtual {p4, v0}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-wide p1
.end method
