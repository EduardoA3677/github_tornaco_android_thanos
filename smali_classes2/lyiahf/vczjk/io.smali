.class public final Llyiahf/vczjk/io;
.super Llyiahf/vczjk/ij1;
.source "SourceFile"


# direct methods
.method public constructor <init>(Llyiahf/vczjk/un;)V
    .locals 1

    const-string v0, "value"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0, p1}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/cm5;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/ij1;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/un;

    invoke-interface {p1}, Llyiahf/vczjk/un;->getType()Llyiahf/vczjk/uk4;

    move-result-object p1

    return-object p1
.end method
