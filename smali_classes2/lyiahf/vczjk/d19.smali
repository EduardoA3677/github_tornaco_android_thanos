.class public final Llyiahf/vczjk/d19;
.super Llyiahf/vczjk/z4a;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/dp8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hk4;)V
    .locals 1

    const-string v0, "kotlinBuiltIns"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1}, Llyiahf/vczjk/hk4;->OooOOOo()Llyiahf/vczjk/dp8;

    move-result-object p1

    const-string v0, "getNullableAnyType(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iput-object p1, p0, Llyiahf/vczjk/d19;->OooO00o:Llyiahf/vczjk/dp8;

    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/cda;
    .locals 1

    sget-object v0, Llyiahf/vczjk/cda;->OooOOOO:Llyiahf/vczjk/cda;

    return-object v0
.end method

.method public final OooO0O0()Llyiahf/vczjk/uk4;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/d19;->OooO00o:Llyiahf/vczjk/dp8;

    return-object v0
.end method

.method public final OooO0OO()Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0Oo(Llyiahf/vczjk/al4;)Llyiahf/vczjk/z4a;
    .locals 1

    const-string v0, "kotlinTypeRefiner"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p0
.end method
