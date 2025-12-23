.class public final Llyiahf/vczjk/ml6;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $containerConstraints:J

.field final synthetic $this_null:Llyiahf/vczjk/st4;

.field final synthetic $totalHorizontalPadding:I

.field final synthetic $totalVerticalPadding:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/st4;JII)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ml6;->$this_null:Llyiahf/vczjk/st4;

    iput-wide p2, p0, Llyiahf/vczjk/ml6;->$containerConstraints:J

    iput p4, p0, Llyiahf/vczjk/ml6;->$totalHorizontalPadding:I

    iput p5, p0, Llyiahf/vczjk/ml6;->$totalVerticalPadding:I

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    check-cast p3, Llyiahf/vczjk/oe3;

    iget-object v0, p0, Llyiahf/vczjk/ml6;->$this_null:Llyiahf/vczjk/st4;

    iget-wide v1, p0, Llyiahf/vczjk/ml6;->$containerConstraints:J

    iget v3, p0, Llyiahf/vczjk/ml6;->$totalHorizontalPadding:I

    add-int/2addr p1, v3

    invoke-static {p1, v1, v2}, Llyiahf/vczjk/uk1;->OooO0oO(IJ)I

    move-result p1

    iget-wide v1, p0, Llyiahf/vczjk/ml6;->$containerConstraints:J

    iget v3, p0, Llyiahf/vczjk/ml6;->$totalVerticalPadding:I

    add-int/2addr p2, v3

    invoke-static {p2, v1, v2}, Llyiahf/vczjk/uk1;->OooO0o(IJ)I

    move-result p2

    sget-object v1, Llyiahf/vczjk/bn2;->OooOOO0:Llyiahf/vczjk/bn2;

    check-cast v0, Llyiahf/vczjk/tt4;

    iget-object v0, v0, Llyiahf/vczjk/tt4;->OooOOO:Llyiahf/vczjk/e89;

    invoke-interface {v0, p1, p2, v1, p3}, Llyiahf/vczjk/nf5;->Oooo(IILjava/util/Map;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/mf5;

    move-result-object p1

    return-object p1
.end method
