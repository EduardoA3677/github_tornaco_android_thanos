.class public final synthetic Llyiahf/vczjk/ko3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:F

.field public final synthetic OooOOO0:Llyiahf/vczjk/xj;

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:Llyiahf/vczjk/ow6;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/xj;FFLlyiahf/vczjk/ow6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ko3;->OooOOO0:Llyiahf/vczjk/xj;

    iput p2, p0, Llyiahf/vczjk/ko3;->OooOOO:F

    iput p3, p0, Llyiahf/vczjk/ko3;->OooOOOO:F

    iput-object p4, p0, Llyiahf/vczjk/ko3;->OooOOOo:Llyiahf/vczjk/ow6;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/ko3;->OooOOO0:Llyiahf/vczjk/xj;

    iget-object v1, v0, Llyiahf/vczjk/xj;->OooOOO:Llyiahf/vczjk/fk;

    invoke-static {v1}, Llyiahf/vczjk/fk;->OooO0Oo(Llyiahf/vczjk/fk;)F

    move-result v1

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {v0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v2

    invoke-static {v1, v2}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    iget-object v2, v0, Llyiahf/vczjk/xj;->OooOOO:Llyiahf/vczjk/fk;

    invoke-static {v2}, Llyiahf/vczjk/fk;->OooO0OO(Llyiahf/vczjk/fk;)F

    move-result v3

    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v3

    invoke-virtual {v0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v4

    invoke-static {v3, v4}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v3

    check-cast v3, Ljava/lang/Number;

    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    move-result v3

    invoke-static {v2}, Llyiahf/vczjk/fk;->OooO0O0(Llyiahf/vczjk/fk;)F

    move-result v4

    invoke-static {v4}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v4

    invoke-virtual {v0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v5

    invoke-static {v4, v5}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v4

    check-cast v4, Ljava/lang/Number;

    invoke-virtual {v4}, Ljava/lang/Number;->floatValue()F

    move-result v4

    invoke-static {v2}, Llyiahf/vczjk/fk;->OooO00o(Llyiahf/vczjk/fk;)F

    move-result v2

    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v2

    invoke-virtual {v0}, Llyiahf/vczjk/xj;->OooO00o()Llyiahf/vczjk/n01;

    move-result-object v0

    invoke-static {v2, v0}, Llyiahf/vczjk/vt6;->OooOo0(Ljava/lang/Comparable;Llyiahf/vczjk/n01;)Ljava/lang/Comparable;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    add-float/2addr v1, v4

    const/4 v2, 0x2

    int-to-float v2, v2

    div-float/2addr v1, v2

    add-float/2addr v3, v0

    div-float/2addr v3, v2

    const v0, 0x3de147ae    # 0.11f

    sub-float/2addr v1, v3

    mul-float/2addr v1, v0

    iget v0, p0, Llyiahf/vczjk/ko3;->OooOOO:F

    iget v2, p0, Llyiahf/vczjk/ko3;->OooOOOO:F

    invoke-static {v1, v0, v2}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/ko3;->OooOOOo:Llyiahf/vczjk/ow6;

    const/4 v2, 0x0

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
