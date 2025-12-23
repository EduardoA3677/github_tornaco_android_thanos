.class public final Llyiahf/vczjk/sz1;
.super Llyiahf/vczjk/qz1;
.source "SourceFile"


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qz1;->OooOooO(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/util/Date;

    move-result-object p1

    if-nez p1, :cond_0

    const/4 p1, 0x0

    return-object p1

    :cond_0
    new-instance p2, Ljava/sql/Date;

    invoke-virtual {p1}, Ljava/util/Date;->getTime()J

    move-result-wide v0

    invoke-direct {p2, v0, v1}, Ljava/sql/Date;-><init>(J)V

    return-object p2
.end method

.method public final OoooOOO(Ljava/text/DateFormat;Ljava/lang/String;)Llyiahf/vczjk/qz1;
    .locals 1

    new-instance v0, Llyiahf/vczjk/sz1;

    invoke-direct {v0, p0, p1, p2}, Llyiahf/vczjk/qz1;-><init>(Llyiahf/vczjk/qz1;Ljava/text/DateFormat;Ljava/lang/String;)V

    return-object v0
.end method
