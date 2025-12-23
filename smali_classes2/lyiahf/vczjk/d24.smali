.class public final Llyiahf/vczjk/d24;
.super Llyiahf/vczjk/g24;
.source "SourceFile"


# direct methods
.method public constructor <init>(I)V
    .locals 0

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-direct {p0, p1}, Llyiahf/vczjk/ij1;-><init>(Ljava/lang/Object;)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/cm5;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "module"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/cm5;->OooOO0O()Llyiahf/vczjk/hk4;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/q47;->OooOOo:Llyiahf/vczjk/q47;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/hk4;->OooOo00(Llyiahf/vczjk/q47;)Llyiahf/vczjk/dp8;

    move-result-object p1

    return-object p1
.end method
