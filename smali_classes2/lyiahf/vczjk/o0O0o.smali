.class public final Llyiahf/vczjk/o0O0o;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/n3a;


# instance fields
.field public final synthetic OooO00o:Llyiahf/vczjk/v82;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v82;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/o0O0o;->OooO00o:Llyiahf/vczjk/v82;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/gz0;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o0O0o;->OooO00o:Llyiahf/vczjk/v82;

    return-object v0
.end method

.method public final OooO0O0()Ljava/util/Collection;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/o0O0o;->OooO00o:Llyiahf/vczjk/v82;

    invoke-virtual {v0}, Llyiahf/vczjk/v82;->o000OO()Llyiahf/vczjk/dp8;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object v0

    const-string v1, "getSupertypes(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final OooO0OO()Ljava/util/List;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o0O0o;->OooO00o:Llyiahf/vczjk/v82;

    iget-object v0, v0, Llyiahf/vczjk/v82;->OooOooo:Ljava/util/List;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    const-string v0, "typeConstructorParameters"

    invoke-static {v0}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0
.end method

.method public final OooO0Oo()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooOO0O()Llyiahf/vczjk/hk4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/o0O0o;->OooO00o:Llyiahf/vczjk/v82;

    invoke-static {v0}, Llyiahf/vczjk/p72;->OooO0o0(Llyiahf/vczjk/v02;)Llyiahf/vczjk/hk4;

    move-result-object v0

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "[typealias "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/o0O0o;->OooO00o:Llyiahf/vczjk/v82;

    invoke-virtual {v1}, Llyiahf/vczjk/w02;->getName()Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/qt5;->OooO0O0()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const/16 v1, 0x5d

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
