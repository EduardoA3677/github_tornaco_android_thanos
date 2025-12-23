.class public final Llyiahf/vczjk/ps1;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/yn;

.field public final OooO0O0:Llyiahf/vczjk/gn;

.field public final OooO0OO:I

.field public final OooO0Oo:[Llyiahf/vczjk/uqa;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/uqa;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ps1;->OooO00o:Llyiahf/vczjk/yn;

    iput-object p2, p0, Llyiahf/vczjk/ps1;->OooO0O0:Llyiahf/vczjk/gn;

    iput-object p3, p0, Llyiahf/vczjk/ps1;->OooO0Oo:[Llyiahf/vczjk/uqa;

    iput p4, p0, Llyiahf/vczjk/ps1;->OooO0OO:I

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/eb0;)Llyiahf/vczjk/ps1;
    .locals 8

    invoke-virtual {p1}, Llyiahf/vczjk/gn;->o000000()I

    move-result v0

    new-array v1, v0, [Llyiahf/vczjk/uqa;

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_1

    invoke-virtual {p1, v2}, Llyiahf/vczjk/gn;->o000OOo(I)Llyiahf/vczjk/vm;

    move-result-object v3

    invoke-virtual {p0, v3}, Llyiahf/vczjk/yn;->OooOOOo(Llyiahf/vczjk/pm;)Llyiahf/vczjk/t54;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/uqa;

    if-nez p2, :cond_0

    const/4 v6, 0x0

    goto :goto_1

    :cond_0
    aget-object v6, p2, v2

    :goto_1
    const/16 v7, 0x12

    invoke-direct {v5, v3, v6, v7, v4}, Llyiahf/vczjk/uqa;-><init>(Ljava/lang/Object;Ljava/lang/Object;ILjava/lang/Object;)V

    aput-object v5, v1, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    new-instance p2, Llyiahf/vczjk/ps1;

    invoke-direct {p2, p0, p1, v1, v0}, Llyiahf/vczjk/ps1;-><init>(Llyiahf/vczjk/yn;Llyiahf/vczjk/gn;[Llyiahf/vczjk/uqa;I)V

    return-object p2
.end method


# virtual methods
.method public final OooO0O0(I)Llyiahf/vczjk/xa7;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ps1;->OooO0Oo:[Llyiahf/vczjk/uqa;

    aget-object p1, v0, p1

    iget-object p1, p1, Llyiahf/vczjk/uqa;->OooOOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/eb0;

    if-eqz p1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/eb0;->getFullName()Llyiahf/vczjk/xa7;

    move-result-object p1

    return-object p1

    :cond_0
    const/4 p1, 0x0

    return-object p1
.end method

.method public final toString()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ps1;->OooO0O0:Llyiahf/vczjk/gn;

    invoke-virtual {v0}, Llyiahf/vczjk/u34;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
