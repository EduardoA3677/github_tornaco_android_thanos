.class public final Llyiahf/vczjk/vq2;
.super Llyiahf/vczjk/ij1;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-direct {p0, v0}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    iput-object p1, p0, Llyiahf/vczjk/vq2;->OooO0O0:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/cm5;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/tq2;->OooOooO:Llyiahf/vczjk/tq2;

    iget-object v0, p0, Llyiahf/vczjk/vq2;->OooO0O0:Ljava/lang/String;

    filled-new-array {v0}, [Ljava/lang/String;

    move-result-object v0

    invoke-static {p1, v0}, Llyiahf/vczjk/uq2;->OooO0OO(Llyiahf/vczjk/tq2;[Ljava/lang/String;)Llyiahf/vczjk/rq2;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0()Ljava/lang/Object;
    .locals 1

    new-instance v0, Ljava/lang/UnsupportedOperationException;

    invoke-direct {v0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    throw v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vq2;->OooO0O0:Ljava/lang/String;

    return-object v0
.end method
