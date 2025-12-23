.class public final Llyiahf/vczjk/sq2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/n3a;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/tq2;

.field public final OooO0O0:[Ljava/lang/String;

.field public final OooO0OO:Ljava/lang/String;


# direct methods
.method public varargs constructor <init>(Llyiahf/vczjk/tq2;[Ljava/lang/String;)V
    .locals 2

    const-string v0, "kind"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "formatParams"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/sq2;->OooO00o:Llyiahf/vczjk/tq2;

    iput-object p2, p0, Llyiahf/vczjk/sq2;->OooO0O0:[Ljava/lang/String;

    sget-object v0, Llyiahf/vczjk/gq2;->OooOOo0:Llyiahf/vczjk/gq2;

    invoke-virtual {v0}, Llyiahf/vczjk/gq2;->OooO00o()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {p1}, Llyiahf/vczjk/tq2;->OooO00o()Ljava/lang/String;

    move-result-object p1

    array-length v1, p2

    invoke-static {p2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    array-length v1, p2

    invoke-static {p2, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p2

    invoke-static {p1, p2}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const/4 p2, 0x1

    invoke-static {p1, p2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    move-result-object p1

    invoke-static {v0, p1}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/sq2;->OooO0OO:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/gz0;
    .locals 1

    sget-object v0, Llyiahf/vczjk/uq2;->OooO00o:Llyiahf/vczjk/uq2;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/uq2;->OooO0OO:Llyiahf/vczjk/eq2;

    return-object v0
.end method

.method public final OooO0O0()Ljava/util/Collection;
    .locals 1

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

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

.method public final OooOO0O()Llyiahf/vczjk/hk4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/k12;->OooO0o:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/k12;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/sq2;->OooO0OO:Ljava/lang/String;

    return-object v0
.end method
