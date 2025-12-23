.class public final Llyiahf/vczjk/aa7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $backgroundColor:J

.field final synthetic $color:J

.field final synthetic $firstLineHead$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $firstLineTail$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $secondLineHead$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $secondLineTail$delegate:Llyiahf/vczjk/p29;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/p29;"
        }
    .end annotation
.end field

.field final synthetic $strokeCap:I


# direct methods
.method public constructor <init>(JIJLlyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;Llyiahf/vczjk/dy3;)V
    .locals 0

    iput-wide p1, p0, Llyiahf/vczjk/aa7;->$backgroundColor:J

    iput p3, p0, Llyiahf/vczjk/aa7;->$strokeCap:I

    iput-wide p4, p0, Llyiahf/vczjk/aa7;->$color:J

    iput-object p6, p0, Llyiahf/vczjk/aa7;->$firstLineHead$delegate:Llyiahf/vczjk/p29;

    iput-object p7, p0, Llyiahf/vczjk/aa7;->$firstLineTail$delegate:Llyiahf/vczjk/p29;

    iput-object p8, p0, Llyiahf/vczjk/aa7;->$secondLineHead$delegate:Llyiahf/vczjk/p29;

    iput-object p9, p0, Llyiahf/vczjk/aa7;->$secondLineTail$delegate:Llyiahf/vczjk/p29;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/hg2;

    invoke-interface {v0}, Llyiahf/vczjk/hg2;->OooO0o0()J

    move-result-wide v1

    invoke-static {v1, v2}, Llyiahf/vczjk/tq8;->OooO0O0(J)F

    move-result v5

    iget-wide v3, p0, Llyiahf/vczjk/aa7;->$backgroundColor:J

    iget v6, p0, Llyiahf/vczjk/aa7;->$strokeCap:I

    const/4 v1, 0x0

    const/high16 v2, 0x3f800000    # 1.0f

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/fa7;->OooO0Oo(Llyiahf/vczjk/hg2;FFJFI)V

    iget-object p1, p0, Llyiahf/vczjk/aa7;->$firstLineHead$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    iget-object v1, p0, Llyiahf/vczjk/aa7;->$firstLineTail$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    sub-float/2addr p1, v1

    const/4 v7, 0x0

    cmpl-float p1, p1, v7

    if-lez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/aa7;->$firstLineHead$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    iget-object p1, p0, Llyiahf/vczjk/aa7;->$firstLineTail$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result v2

    iget-wide v3, p0, Llyiahf/vczjk/aa7;->$color:J

    iget v6, p0, Llyiahf/vczjk/aa7;->$strokeCap:I

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/fa7;->OooO0Oo(Llyiahf/vczjk/hg2;FFJFI)V

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/aa7;->$secondLineHead$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    iget-object v1, p0, Llyiahf/vczjk/aa7;->$secondLineTail$delegate:Llyiahf/vczjk/p29;

    invoke-interface {v1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/Number;

    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    sub-float/2addr p1, v1

    cmpl-float p1, p1, v7

    if-lez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/aa7;->$secondLineHead$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result v1

    iget-object p1, p0, Llyiahf/vczjk/aa7;->$secondLineTail$delegate:Llyiahf/vczjk/p29;

    invoke-interface {p1}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result v2

    iget-wide v3, p0, Llyiahf/vczjk/aa7;->$color:J

    iget v6, p0, Llyiahf/vczjk/aa7;->$strokeCap:I

    invoke-static/range {v0 .. v6}, Llyiahf/vczjk/fa7;->OooO0Oo(Llyiahf/vczjk/hg2;FFJFI)V

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
