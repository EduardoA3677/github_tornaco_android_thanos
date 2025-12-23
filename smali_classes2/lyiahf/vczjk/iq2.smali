.class public final Llyiahf/vczjk/iq2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cm5;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/qt5;

.field public static final OooOOO0:Llyiahf/vczjk/iq2;

.field public static final OooOOOO:Llyiahf/vczjk/an2;

.field public static final OooOOOo:Llyiahf/vczjk/sc9;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/iq2;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/iq2;->OooOOO0:Llyiahf/vczjk/iq2;

    sget-object v0, Llyiahf/vczjk/gq2;->OooOOOO:Llyiahf/vczjk/gq2;

    invoke-virtual {v0}, Llyiahf/vczjk/gq2;->OooO00o()Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/qt5;->OooO0oO(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/iq2;->OooOOO:Llyiahf/vczjk/qt5;

    sget-object v0, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    sput-object v0, Llyiahf/vczjk/iq2;->OooOOOO:Llyiahf/vczjk/an2;

    sget-object v0, Llyiahf/vczjk/dk0;->OooOOoo:Llyiahf/vczjk/dk0;

    invoke-static {v0}, Llyiahf/vczjk/jp8;->Oooo0(Llyiahf/vczjk/le3;)Llyiahf/vczjk/sc9;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/iq2;->OooOOOo:Llyiahf/vczjk/sc9;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/v02;
    .locals 0

    return-object p0
.end method

.method public final OooO0oo(Llyiahf/vczjk/hc3;Llyiahf/vczjk/oe3;)Ljava/util/Collection;
    .locals 0

    const-string p2, "fqName"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object p1, Llyiahf/vczjk/an2;->OooOOO0:Llyiahf/vczjk/an2;

    return-object p1
.end method

.method public final OooOO0O()Llyiahf/vczjk/hk4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/iq2;->OooOOOo:Llyiahf/vczjk/sc9;

    invoke-virtual {v0}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/hk4;

    return-object v0
.end method

.method public final OooOO0o()Llyiahf/vczjk/v02;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    sget-object v0, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    return-object v0
.end method

.method public final OoooOoO(Llyiahf/vczjk/z02;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public final OoooOoo(Llyiahf/vczjk/mm3;)Ljava/lang/Object;
    .locals 1

    const-string v0, "capability"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return-object p1
.end method

.method public final Ooooo00(Llyiahf/vczjk/cm5;)Z
    .locals 1

    const-string v0, "targetModule"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 p1, 0x0

    return p1
.end method

.method public final OooooO0(Llyiahf/vczjk/hc3;)Llyiahf/vczjk/vh6;
    .locals 1

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "Should not be called!"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public final getName()Llyiahf/vczjk/qt5;
    .locals 1

    sget-object v0, Llyiahf/vczjk/iq2;->OooOOO:Llyiahf/vczjk/qt5;

    return-object v0
.end method

.method public final o00o0O()Ljava/util/List;
    .locals 1

    sget-object v0, Llyiahf/vczjk/iq2;->OooOOOO:Llyiahf/vczjk/an2;

    return-object v0
.end method
