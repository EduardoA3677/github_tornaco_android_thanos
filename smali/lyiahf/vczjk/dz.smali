.class public Llyiahf/vczjk/dz;
.super Llyiahf/vczjk/yy;
.source "SourceFile"


# instance fields
.field public final OooO0Oo:Ljava/lang/String;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/d4a;Llyiahf/vczjk/db0;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    invoke-direct {p0, p1, p2, v0}, Llyiahf/vczjk/yy;-><init>(Llyiahf/vczjk/d4a;Llyiahf/vczjk/db0;I)V

    iput-object p3, p0, Llyiahf/vczjk/dz;->OooO0Oo:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public bridge synthetic OooO00o(Llyiahf/vczjk/db0;)Llyiahf/vczjk/d5a;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dz;->OooO0oo(Llyiahf/vczjk/db0;)Llyiahf/vczjk/dz;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0O0()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/dz;->OooO0Oo:Ljava/lang/String;

    return-object v0
.end method

.method public OooO0OO()Llyiahf/vczjk/kc4;
    .locals 1

    sget-object v0, Llyiahf/vczjk/kc4;->OooOOO0:Llyiahf/vczjk/kc4;

    return-object v0
.end method

.method public bridge synthetic OooO0oO(Llyiahf/vczjk/db0;)Llyiahf/vczjk/yy;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/dz;->OooO0oo(Llyiahf/vczjk/db0;)Llyiahf/vczjk/dz;

    move-result-object p1

    return-object p1
.end method

.method public OooO0oo(Llyiahf/vczjk/db0;)Llyiahf/vczjk/dz;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/e5a;->OooO0O0:Llyiahf/vczjk/db0;

    if-ne v0, p1, :cond_0

    return-object p0

    :cond_0
    new-instance v0, Llyiahf/vczjk/dz;

    iget-object v1, p0, Llyiahf/vczjk/e5a;->OooO00o:Llyiahf/vczjk/d4a;

    iget-object v2, p0, Llyiahf/vczjk/dz;->OooO0Oo:Ljava/lang/String;

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/dz;-><init>(Llyiahf/vczjk/d4a;Llyiahf/vczjk/db0;Ljava/lang/String;)V

    return-object v0
.end method
