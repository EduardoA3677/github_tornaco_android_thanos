.class public final Llyiahf/vczjk/xj;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/qj8;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/fk;

.field public final OooOOO0:Llyiahf/vczjk/qs5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fk;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xj;->OooOOO:Llyiahf/vczjk/fk;

    new-instance p1, Llyiahf/vczjk/m01;

    const/4 v0, 0x0

    const/high16 v1, 0x3f800000    # 1.0f

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/m01;-><init>(FF)V

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/xj;->OooOOO0:Llyiahf/vczjk/qs5;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/n01;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/xj;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n01;

    return-object v0
.end method

.method public final OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/xj;->OooOOO:Llyiahf/vczjk/fk;

    iput-wide p1, v0, Llyiahf/vczjk/fk;->OooO0OO:J

    const-wide v1, 0xffffffffL

    and-long/2addr v1, p1

    long-to-int v1, v1

    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result v1

    const/4 v2, 0x2

    int-to-float v2, v2

    div-float/2addr v1, v2

    new-instance v2, Llyiahf/vczjk/m01;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v1}, Llyiahf/vczjk/m01;-><init>(FF)V

    iget-object v1, p0, Llyiahf/vczjk/xj;->OooOOO0:Llyiahf/vczjk/qs5;

    check-cast v1, Llyiahf/vczjk/fw8;

    invoke-virtual {v1, v2}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/fk;->OooO0Oo(Llyiahf/vczjk/fk;)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {p0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    invoke-static {v0}, Llyiahf/vczjk/fk;->OooO0OO(Llyiahf/vczjk/fk;)F

    move-result v2

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    invoke-virtual {p0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v3

    invoke-static {v2, v3}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v2

    check-cast v2, Ljava/lang/Number;

    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    move-result v2

    invoke-static {v0}, Llyiahf/vczjk/fk;->OooO0O0(Llyiahf/vczjk/fk;)F

    move-result v3

    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v3

    invoke-virtual {p0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    invoke-static {v0}, Llyiahf/vczjk/fk;->OooO00o(Llyiahf/vczjk/fk;)F

    move-result v0

    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v4

    invoke-static {v0, v4}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    sget-object v4, Llyiahf/vczjk/uv7;->OooO00o:Llyiahf/vczjk/tv7;

    new-instance v4, Llyiahf/vczjk/tv7;

    new-instance v5, Llyiahf/vczjk/qf7;

    invoke-direct {v5, v1}, Llyiahf/vczjk/qf7;-><init>(F)V

    new-instance v1, Llyiahf/vczjk/qf7;

    invoke-direct {v1, v2}, Llyiahf/vczjk/qf7;-><init>(F)V

    new-instance v2, Llyiahf/vczjk/qf7;

    invoke-direct {v2, v0}, Llyiahf/vczjk/qf7;-><init>(F)V

    new-instance v0, Llyiahf/vczjk/qf7;

    invoke-direct {v0, v3}, Llyiahf/vczjk/qf7;-><init>(F)V

    invoke-direct {v4, v5, v1, v2, v0}, Llyiahf/vczjk/ir1;-><init>(Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;Llyiahf/vczjk/lr1;)V

    invoke-virtual {v4, p1, p2, p3, p4}, Llyiahf/vczjk/ir1;->OooooOo(JLlyiahf/vczjk/yn4;Llyiahf/vczjk/f62;)Llyiahf/vczjk/qqa;

    move-result-object p1

    return-object p1
.end method
