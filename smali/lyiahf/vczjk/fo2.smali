.class public final Llyiahf/vczjk/fo2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $enter:Llyiahf/vczjk/ep2;

.field final synthetic $exit:Llyiahf/vczjk/ct2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fo2;->$enter:Llyiahf/vczjk/ep2;

    iput-object p2, p0, Llyiahf/vczjk/fo2;->$exit:Llyiahf/vczjk/ct2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/co2;

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    const/4 v0, 0x0

    const/high16 v1, 0x3f800000    # 1.0f

    if-eqz p1, :cond_2

    const/4 v2, 0x1

    if-eq p1, v2, :cond_0

    const/4 v2, 0x2

    if-ne p1, v2, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/fo2;->$exit:Llyiahf/vczjk/ct2;

    check-cast p1, Llyiahf/vczjk/dt2;

    iget-object p1, p1, Llyiahf/vczjk/dt2;->OooO0OO:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO00o:Llyiahf/vczjk/iv2;

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    move v0, v1

    goto :goto_0

    :cond_1
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/fo2;->$enter:Llyiahf/vczjk/ep2;

    check-cast p1, Llyiahf/vczjk/fp2;

    iget-object p1, p1, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO00o:Llyiahf/vczjk/iv2;

    if-eqz p1, :cond_0

    :goto_0
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    return-object p1
.end method
