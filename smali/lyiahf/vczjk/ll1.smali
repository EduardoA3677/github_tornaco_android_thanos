.class public final Llyiahf/vczjk/ll1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bz5;


# instance fields
.field public final OooOOO:Z

.field public final OooOOO0:Z

.field public final OooOOOO:Llyiahf/vczjk/km6;


# direct methods
.method public constructor <init>(ZZLlyiahf/vczjk/km6;)V
    .locals 1

    const-string v0, "pagerState"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/ll1;->OooOOO0:Z

    iput-boolean p2, p0, Llyiahf/vczjk/ll1;->OooOOO:Z

    iput-object p3, p0, Llyiahf/vczjk/ll1;->OooOOOO:Llyiahf/vczjk/km6;

    return-void
.end method


# virtual methods
.method public final OooOoOO(JJLlyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/ll1;->OooOOOO:Llyiahf/vczjk/km6;

    iget-object p1, p1, Llyiahf/vczjk/km6;->OooO0o0:Llyiahf/vczjk/w62;

    invoke-virtual {p1}, Llyiahf/vczjk/w62;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    const/4 p2, 0x0

    cmpg-float p1, p1, p2

    if-nez p1, :cond_2

    iget-boolean p1, p0, Llyiahf/vczjk/ll1;->OooOOO0:Z

    if-eqz p1, :cond_0

    invoke-static {p3, p4}, Llyiahf/vczjk/fea;->OooO0O0(J)F

    move-result p1

    goto :goto_0

    :cond_0
    move p1, p2

    :goto_0
    iget-boolean p5, p0, Llyiahf/vczjk/ll1;->OooOOO:Z

    if-eqz p5, :cond_1

    invoke-static {p3, p4}, Llyiahf/vczjk/fea;->OooO0OO(J)F

    move-result p2

    :cond_1
    invoke-static {p1, p2}, Llyiahf/vczjk/kh6;->OooO0o(FF)J

    move-result-wide p1

    goto :goto_1

    :cond_2
    const-wide/16 p1, 0x0

    :goto_1
    new-instance p3, Llyiahf/vczjk/fea;

    invoke-direct {p3, p1, p2}, Llyiahf/vczjk/fea;-><init>(J)V

    return-object p3
.end method

.method public final Ooooooo(IJJ)J
    .locals 2

    const/4 p2, 0x2

    if-ne p1, p2, :cond_2

    iget-boolean p1, p0, Llyiahf/vczjk/ll1;->OooOOO0:Z

    const/4 p2, 0x0

    if-eqz p1, :cond_0

    const/16 p1, 0x20

    shr-long v0, p4, p1

    long-to-int p1, v0

    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    move-result p1

    goto :goto_0

    :cond_0
    move p1, p2

    :goto_0
    iget-boolean p3, p0, Llyiahf/vczjk/ll1;->OooOOO:Z

    if-eqz p3, :cond_1

    invoke-static {p4, p5}, Llyiahf/vczjk/p86;->OooO0Oo(J)F

    move-result p2

    :cond_1
    invoke-static {p1, p2}, Llyiahf/vczjk/sb;->OooOO0o(FF)J

    move-result-wide p1

    return-wide p1

    :cond_2
    const-wide/16 p1, 0x0

    return-wide p1
.end method
