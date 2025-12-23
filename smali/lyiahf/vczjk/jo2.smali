.class public final Llyiahf/vczjk/jo2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $enter:Llyiahf/vczjk/ep2;

.field final synthetic $exit:Llyiahf/vczjk/ct2;

.field final synthetic $transformOriginWhenVisible:Llyiahf/vczjk/ey9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ey9;Llyiahf/vczjk/ep2;Llyiahf/vczjk/ct2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jo2;->$transformOriginWhenVisible:Llyiahf/vczjk/ey9;

    iput-object p2, p0, Llyiahf/vczjk/jo2;->$enter:Llyiahf/vczjk/ep2;

    iput-object p3, p0, Llyiahf/vczjk/jo2;->$exit:Llyiahf/vczjk/ct2;

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

    if-eqz p1, :cond_3

    const/4 v1, 0x1

    if-eq p1, v1, :cond_2

    const/4 v1, 0x2

    if-ne p1, v1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/jo2;->$exit:Llyiahf/vczjk/ct2;

    check-cast p1, Llyiahf/vczjk/dt2;

    iget-object p1, p1, Llyiahf/vczjk/dt2;->OooO0OO:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0Oo:Llyiahf/vczjk/s78;

    if-eqz p1, :cond_0

    new-instance v0, Llyiahf/vczjk/ey9;

    iget-wide v1, p1, Llyiahf/vczjk/s78;->OooO00o:J

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ey9;-><init>(J)V

    goto :goto_0

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/jo2;->$enter:Llyiahf/vczjk/ep2;

    check-cast p1, Llyiahf/vczjk/fp2;

    iget-object p1, p1, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0Oo:Llyiahf/vczjk/s78;

    if-eqz p1, :cond_5

    new-instance v0, Llyiahf/vczjk/ey9;

    iget-wide v1, p1, Llyiahf/vczjk/s78;->OooO00o:J

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ey9;-><init>(J)V

    goto :goto_0

    :cond_1
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/jo2;->$transformOriginWhenVisible:Llyiahf/vczjk/ey9;

    goto :goto_0

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/jo2;->$enter:Llyiahf/vczjk/ep2;

    check-cast p1, Llyiahf/vczjk/fp2;

    iget-object p1, p1, Llyiahf/vczjk/fp2;->OooO0O0:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0Oo:Llyiahf/vczjk/s78;

    if-eqz p1, :cond_4

    new-instance v0, Llyiahf/vczjk/ey9;

    iget-wide v1, p1, Llyiahf/vczjk/s78;->OooO00o:J

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ey9;-><init>(J)V

    goto :goto_0

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/jo2;->$exit:Llyiahf/vczjk/ct2;

    check-cast p1, Llyiahf/vczjk/dt2;

    iget-object p1, p1, Llyiahf/vczjk/dt2;->OooO0OO:Llyiahf/vczjk/fz9;

    iget-object p1, p1, Llyiahf/vczjk/fz9;->OooO0Oo:Llyiahf/vczjk/s78;

    if-eqz p1, :cond_5

    new-instance v0, Llyiahf/vczjk/ey9;

    iget-wide v1, p1, Llyiahf/vczjk/s78;->OooO00o:J

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/ey9;-><init>(J)V

    :cond_5
    :goto_0
    if-eqz v0, :cond_6

    iget-wide v0, v0, Llyiahf/vczjk/ey9;->OooO00o:J

    goto :goto_1

    :cond_6
    sget-wide v0, Llyiahf/vczjk/ey9;->OooO0O0:J

    :goto_1
    new-instance p1, Llyiahf/vczjk/ey9;

    invoke-direct {p1, v0, v1}, Llyiahf/vczjk/ey9;-><init>(J)V

    return-object p1
.end method
