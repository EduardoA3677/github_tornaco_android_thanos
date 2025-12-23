.class public final Llyiahf/vczjk/zp2;
.super Llyiahf/vczjk/ij1;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/hy0;

.field public final OooO0OO:Llyiahf/vczjk/qt5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hy0;Llyiahf/vczjk/qt5;)V
    .locals 1

    new-instance v0, Llyiahf/vczjk/xn6;

    invoke-direct {v0, p1, p2}, Llyiahf/vczjk/xn6;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    invoke-direct {p0, v0}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/zp2;->OooO0O0:Llyiahf/vczjk/hy0;

    iput-object p2, p0, Llyiahf/vczjk/zp2;->OooO0OO:Llyiahf/vczjk/qt5;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/cm5;)Llyiahf/vczjk/uk4;
    .locals 2

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/zp2;->OooO0O0:Llyiahf/vczjk/hy0;

    invoke-static {p1, v0}, Llyiahf/vczjk/r02;->OooOOo0(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hy0;)Llyiahf/vczjk/by0;

    move-result-object p1

    if-eqz p1, :cond_1

    sget v1, Llyiahf/vczjk/n72;->OooO00o:I

    sget-object v1, Llyiahf/vczjk/ly0;->OooOOOO:Llyiahf/vczjk/ly0;

    invoke-static {p1, v1}, Llyiahf/vczjk/n72;->OooOOO(Llyiahf/vczjk/v02;Llyiahf/vczjk/ly0;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    :goto_0
    if-eqz p1, :cond_1

    invoke-interface {p1}, Llyiahf/vczjk/by0;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object p1

    if-eqz p1, :cond_1

    return-object p1

    :cond_1
    sget-object p1, Llyiahf/vczjk/tq2;->Oooo0OO:Llyiahf/vczjk/tq2;

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->toString()Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/zp2;->OooO0OO:Llyiahf/vczjk/qt5;

    iget-object v1, v1, Llyiahf/vczjk/qt5;->OooOOO0:Ljava/lang/String;

    filled-new-array {v0, v1}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object p1

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/zp2;->OooO0O0:Llyiahf/vczjk/hy0;

    invoke-virtual {v1}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x2e

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/zp2;->OooO0OO:Llyiahf/vczjk/qt5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
