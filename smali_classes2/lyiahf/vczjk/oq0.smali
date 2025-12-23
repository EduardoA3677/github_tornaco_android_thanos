.class public final Llyiahf/vczjk/oq0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/nq0;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/z4a;

.field public OooO0O0:Llyiahf/vczjk/n06;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/z4a;)V
    .locals 1

    const-string v0, "projection"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oq0;->OooO00o:Llyiahf/vczjk/z4a;

    invoke-virtual {p1}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    sget-object p1, Llyiahf/vczjk/cda;->OooOOO0:Llyiahf/vczjk/cda;

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO00o()Llyiahf/vczjk/gz0;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooO0O0()Ljava/util/Collection;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/oq0;->OooO00o:Llyiahf/vczjk/z4a;

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO00o()Llyiahf/vczjk/cda;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    if-ne v1, v2, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v0

    goto :goto_0

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/oq0;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/hk4;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object v0

    :goto_0
    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    invoke-static {v0}, Llyiahf/vczjk/r02;->OooOo(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0OO()Ljava/util/List;
    .locals 1

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object v0
.end method

.method public final OooO0Oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public final OooO0o0()Llyiahf/vczjk/z4a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/oq0;->OooO00o:Llyiahf/vczjk/z4a;

    return-object v0
.end method

.method public final OooOO0O()Llyiahf/vczjk/hk4;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/oq0;->OooO00o:Llyiahf/vczjk/z4a;

    invoke-virtual {v0}, Llyiahf/vczjk/z4a;->OooO0O0()Llyiahf/vczjk/uk4;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/n3a;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object v0

    const-string v1, "getBuiltIns(...)"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "CapturedTypeConstructor("

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/oq0;->OooO00o:Llyiahf/vczjk/z4a;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const/16 v1, 0x29

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
